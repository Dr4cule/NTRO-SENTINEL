"""CSV ingest: endpoint-bearing flow CSVs -> conn events; endpoint-less aggregates -> summary.

Two honest paths, decided by header inspection (no guessing, no fabricated endpoints):

1. Endpoint CSV (has src + dst IP columns, e.g. Zeek conn.log exported as CSV or a
   flow CSV that kept its address columns) -> yields ``kind=conn`` events identical in
   shape to what tailer/pcap_to_events emit, so the Pipeline/detectors run unchanged.

2. Aggregate CSV (CIC-IDS2017-style: 78 flow statistics + Label, addresses stripped)
   -> per-flow attribution is impossible without endpoints, so NO alerts are produced.
   ``analyze_aggregate`` instead returns a DDoS-relevant traffic assessment (label
   census, victim-port concentration, SYN-heavy fraction, rate/volume stats) which the
   upload endpoint returns as data, not as flow alerts.

Header matching is tolerant: BOM/whitespace/case-insensitive, with alias lists per field.
"""
from __future__ import annotations
import csv
import math
import time
from datetime import datetime

CSV_EXT = {'.csv'}

# normalized-header -> candidate aliases (all compared lowercased/stripped)
_ALIASES = {
    'src_ip': ['source ip', 'src ip', 'srcip', 'src_ip', 'sourceip', 'id.orig_h', 'src', 'source address'],
    'src_port': ['source port', 'src port', 'srcport', 'src_port', 'id.orig_p', 'sport'],
    'dst_ip': ['destination ip', 'dst ip', 'dstip', 'dst_ip', 'destinationip', 'id.resp_h', 'dst', 'destination address'],
    'dst_port': ['destination port', 'dst port', 'dstport', 'dst_port', 'id.resp_p', 'dport'],
    'proto': ['protocol', 'proto'],
    'ts': ['timestamp', 'ts', 'time', 'datetime'],
    'orig_bytes': ['total length of fwd packets', 'totlen fwd pkts', 'orig_bytes', 'orig_ip_bytes',
                   'fwd bytes', 'subflow fwd bytes', 'total fwd bytes'],
    'resp_bytes': ['total length of bwd packets', 'totlen bwd pkts', 'resp_bytes', 'resp_ip_bytes',
                   'bwd bytes', 'subflow bwd bytes', 'total bwd bytes'],
    'duration': ['flow duration', 'duration'],
    'syn': ['syn flag count', 'syn'],
    'ack': ['ack flag count', 'ack'],
    'fin': ['fin flag count', 'fin'],
    'rst': ['rst flag count', 'rst'],
    'query': ['query', 'dns_query', 'dns query'],
    'label': ['label', 'class'],
}

_PROTO_NUM = {'6': 'tcp', '17': 'udp', '1': 'icmp'}


def _norm(h):
    return (h or '').replace('\ufeff', '').strip().lower()


def _colmap(fieldnames):
    """Map our field -> actual CSV column name (first alias that matches)."""
    normed = {_norm(c): c for c in (fieldnames or [])}
    out = {}
    for field, aliases in _ALIASES.items():
        for a in aliases:
            if a in normed:
                out[field] = normed[a]
                break
    return out


def has_endpoints(fieldnames):
    """True when a header carries the per-flow attribution detectors group on."""
    m = _colmap(fieldnames)
    return 'src_ip' in m and 'dst_ip' in m


def _num(v, default=0):
    try:
        x = float(str(v).strip())
        return int(x) if x.is_integer() else x
    except (TypeError, ValueError, AttributeError):
        return default


def _fnum(v):
    """Finite float or None (CICFlowMeter writes 'Infinity' for zero-duration flows)."""
    try:
        x = float(str(v).strip())
        return x if math.isfinite(x) else None
    except (TypeError, ValueError, AttributeError):
        return None


def _parse_ts(v, fallback):
    if v is None or str(v).strip() == '':
        return fallback
    s = str(v).strip()
    try:
        return float(s)  # epoch seconds
    except ValueError:
        pass
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f', '%d/%m/%Y %H:%M',
                '%d/%m/%Y %H:%M:%S', '%m/%d/%Y %H:%M', '%m/%d/%Y %H:%M:%S'):
        try:
            return datetime.strptime(s.split('.')[0] if '.' not in fmt else s, fmt).timestamp()
        except ValueError:
            continue
    return fallback


def _conn_state(syn, ack, fin, rst):
    if rst >= 1:
        return 'REJ'
    if syn >= 1 and ack == 0 and fin == 0:
        return 'S0'
    if fin >= 1 or ack >= 1:
        return 'SF'
    return 'OTH'


def read_conn_events(path, max_rows=None):
    """Yield normalized conn events from an endpoint-bearing CSV.

    Raises ValueError naming the missing columns when endpoints are absent
    (caller should fall back to analyze_aggregate instead of fabricating flows).
    """
    with open(path, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        m = _colmap(reader.fieldnames)
        missing = [k for k in ('src_ip', 'dst_ip') if k not in m]
        if missing:
            have = sorted({_norm(c) for c in (reader.fieldnames or [])})
            raise ValueError(
                'CSV has no endpoint columns (%s); cannot attribute flows. '
                'Present columns include: %s. Endpoint-less aggregates use the '
                'aggregate-analysis path instead.' % (', '.join(missing), ', '.join(have[:12])))
        base_ts = time.time()
        for i, row in enumerate(reader):
            if max_rows is not None and i >= max_rows:
                break
            get = lambda k, d='': (row.get(m[k], d) if k in m else d)
            proto = str(get('proto', '')).strip().lower()
            proto = _PROTO_NUM.get(proto, proto)
            syn, ack, fin, rst = (_num(get(k, 0)) for k in ('syn', 'ack', 'fin', 'rst'))
            state = _conn_state(syn, ack, fin, rst)
            dur = _num(get('duration', 0))
            if 'duration' in m and _norm(m['duration']) == 'flow duration' and dur >= 1000:
                dur = dur / 1e6  # CICFlowMeter reports microseconds
            yield {
                'ts': _parse_ts(get('ts'), base_ts + i * 1e-3),
                'kind': 'conn',
                'src_ip': str(get('src_ip')).strip(),
                'src_port': _num(get('src_port', 0)),
                'dst_ip': str(get('dst_ip')).strip(),
                'dst_port': _num(get('dst_port', 0)),
                'proto': proto,
                'orig_bytes': _num(get('orig_bytes', 0)),
                'resp_bytes': _num(get('resp_bytes', 0)),
                'conn_state': state,
                'duration': dur,
                'tcp_flags': state[:1],
            }


def analyze_aggregate(path, max_rows=None):
    """DDoS-relevant assessment of an endpoint-less flow-feature CSV (no alerts).

    Returns label census, victim-port concentration (Destination Port IS present in
    CIC-style releases), SYN-heavy fraction, and volume/rate summaries — all computed
    in one streaming pass, stdlib only.
    """
    port_key = dst_lbl = lbl_key = syn_key = dur_key = fps_key = fwd_key = None
    rows = 0
    labels = {}
    syn_heavy = 0
    dur_sum = fps_sum = fwd_sum = 0.0
    dur_n = fps_n = fwd_n = 0
    ports = {}
    with open(path, newline='', encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        m = _colmap(reader.fieldnames)
        port_key, lbl_key = m.get('dst_port'), m.get('label')
        syn_key, dur_key = m.get('syn'), m.get('duration')
        fps_key = next((c for k, c in
                        [(_norm(c), c) for c in (reader.fieldnames or [])]
                        if k == 'flow packets/s'), None)
        fwd_key = m.get('orig_bytes')
        for row in reader:
            if max_rows is not None and rows >= max_rows:
                break
            rows += 1
            if lbl_key:
                lab = (row.get(lbl_key) or '').strip() or 'UNKNOWN'
                labels[lab] = labels.get(lab, 0) + 1
            if syn_key and _num(row.get(syn_key, 0)) >= 1:
                syn_heavy += 1
            if dur_key:
                d = _fnum(row.get(dur_key))
                if d is not None:
                    dur_sum += d / 1e6 if d >= 1000 else d  # CICFlowMeter microseconds
                    dur_n += 1
            if fps_key:
                v = _fnum(row.get(fps_key))
                if v is not None:
                    fps_sum += v
                    fps_n += 1
            if fwd_key:
                v = _fnum(row.get(fwd_key))
                if v is not None:
                    fwd_sum += v
                    fwd_n += 1
            if port_key:
                p = str(row.get(port_key) or '').strip().split('.')[0]
                if p:
                    e = ports.setdefault(p, {'flows': 0, 'ddos': 0})
                    e['flows'] += 1
                    if lbl_key and (row.get(lbl_key) or '').strip().lower() not in ('benign', ''):
                        e['ddos'] += 1
    top_ports = sorted(ports.items(), key=lambda kv: -kv[1]['flows'])[:10]
    ddos_total = sum(v for k, v in labels.items() if k.strip().lower() not in ('benign', 'unknown'))
    return {
        'rows': rows,
        'label_census': dict(sorted(labels.items(), key=lambda kv: -kv[1])),
        'ddos_share': round(ddos_total / rows, 4) if rows else 0.0,
        'syn_heavy_flows': syn_heavy,
        'syn_heavy_share': round(syn_heavy / rows, 4) if rows else 0.0,
        'mean_flow_duration_s': round(dur_sum / dur_n, 3) if dur_n else None,
        'mean_flow_packets_per_s': round(fps_sum / fps_n, 1) if fps_n else None,
        'mean_fwd_bytes': round(fwd_sum / fwd_n, 1) if fwd_n else None,
        'top_destination_ports': [
            {'port': p, 'flows': e['flows'],
             'ddos_share': round(e['ddos'] / e['flows'], 4)}
            for p, e in top_ports],
        'reading': ('Aggregate flow statistics only (no IPs/timestamp): per-flow attribution '
                    'is impossible, so no detector alerts were produced. Victim-port '
                    'concentration + label census above are the DDoS-relevant signal.'),
    }
