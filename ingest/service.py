"""24/7 ingest service: live capture + file replay -> one detection Pipeline -> AlertStore.

Single writer (one consumer thread) so the tamper-evident hash chain stays serialized while
many sources feed it. Everything it stores lands in the same artifacts/sentinel.db the API/
dashboard already reads, so alerts show up live (WebSocket polls the store every ~1s).

Sources (any combination, run together):
  --live IFACE     sniff a NIC continuously (needs root / CAP_NET_RAW)
  --watch DIR      drop .pcap/.pcapng/.csv or .jsonl/Zeek-json files in; ingested then moved to processed/
  --file PATH      ingest a file now (repeatable); with --once, ingest those and exit
  CSVs come in two flavors (ingest/csv_to_events.py): endpoint-bearing -> conn events
  through the normal Pipeline; endpoint-less CIC-style aggregates -> honest traffic
  assessment only (no fabricated flow alerts).

  python -m ingest.service --file capture.pcap --once          # one-shot: populate dashboard, exit
  python -m ingest.service --live eth0 --watch artifacts/inbox # 24/7: live + drop-in files
"""
from __future__ import annotations
import argparse, json, os, queue, sys, tempfile, threading, time
from pathlib import Path
from engine.stream_consumer import Pipeline
from engine.metrics import StreamMetrics
from alertstore.store import AlertStore
from ingest.pcap_to_events import ingest_packet, _conn_event, build_events
from ingest.tailer import normalize
from ingest.csv_to_events import has_endpoints

STOP = threading.Event()
PCAP_EXT = {'.pcap', '.pcapng', '.cap'}

def consumer(q, store, pipeline, metrics, stop=STOP, lag_fn=None):
    """The ONLY writer to the store -> hash chain stays consistent. `stop` defaults to the
    global STOP (live/CLI runs); an upload passes its own event so repeated calls are isolated."""
    last_metric = 0.0
    last_reported_suppressed = 0
    def _telemetry(**kw):
        # A telemetry write must never be able to kill the only consumer thread. It used to be
        # unguarded, so one failed INSERT (e.g. the store's -wal file briefly unwritable) raised
        # here, unwound the thread, and left the process alive and "active" while ingesting
        # NOTHING -- systemd saw a healthy service, so nothing ever restarted it. Telemetry is
        # observability, not detection: degrade it loudly on stderr, keep detecting.
        try: store.metric(**kw)
        except Exception as ex: print(f'[service] telemetry write failed (detection continues): {ex!r}', file=sys.stderr)
    while not (stop.is_set() and q.empty()):
        try: e = q.get(timeout=.5)
        except queue.Empty: continue
        t = time.perf_counter()
        alerts = pipeline.process(e)
        for a in alerts: store.append(a)
        metrics.observe((time.perf_counter() - t) * 1000, len(alerts))
        now = time.time()
        if now - last_metric >= 2:
            # F08: metrics.snapshot() defaults lag to 0, so the dashboard displayed a
            # reassuring "stream lag 0" that was never measured. Report the real queue depth.
            snap=metrics.snapshot(lag=lag_fn() if lag_fn else 0)
            _telemetry(**snap); last_metric = now
        # Report budget-suppressed repeats rather than dropping them invisibly: an analyst
        # should be able to tell "nothing happened" from "this peer is still talking, we have
        # simply already reported it N times".
        suppressed = getattr(pipeline, 'budget_suppressed', 0)
        if suppressed != last_reported_suppressed:
            by = getattr(pipeline, 'budget_suppressed_by', {})
            print(f'[budget] {suppressed} repeat alert(s) suppressed (budget '
                  f'{getattr(pipeline, "budget_n", 0)} per src|dst per '
                  f'{int(getattr(pipeline, "budget_window", 0))}s) {by}', file=sys.stderr)
            last_reported_suppressed = suppressed
        q.task_done()
    _telemetry(**metrics.snapshot())

def ingest_file(path, q, suffix=None):
    """Replay a pcap, endpoint-CSV, or line-delimited Zeek/event JSON file into the queue.

    `suffix` overrides the parser choice (an upload spools to a temp file whose real extension
    is meaningless, so the caller passes the name the client sent). Returns None, or the
    aggregate-analysis dict for endpoint-less CSVs (which yield no per-flow events by design)."""
    p = Path(path)
    ext = (suffix or p.suffix).lower()
    if ext in PCAP_EXT:
        for e in build_events(str(p), int(os.getenv('MAX_PACKETS', '2000000'))): q.put(e)
    elif ext == '.csv':
        from ingest.csv_to_events import read_conn_events, analyze_aggregate
        try:
            for e in read_conn_events(str(p), int(os.getenv('MAX_CSV_ROWS', '2000000'))): q.put(e)
        except ValueError:
            info = analyze_aggregate(str(p), int(os.getenv('MAX_CSV_ROWS', '2000000')))
            print(f"[csv] aggregate-only {p.name}: {info['rows']} flows, "
                  f"DDoS share {info['ddos_share']}, top ports {info['top_destination_ports'][:3]}", file=sys.stderr)
            return info
    else:
        with p.open() as f:
            for line in f:
                if line.strip():
                    rec = json.loads(line)
                    q.put(rec if 'kind' in rec else normalize(rec, p.stem))
    print(f'[file] ingested {p}', file=sys.stderr)

_UPLOAD_LOCK = threading.Lock()
# how long an upload may spend draining its queue before we call it stalled (see below)
_UPLOAD_DRAIN_SECONDS = int(os.getenv('UPLOAD_DRAIN_SECONDS', '300'))
# The old 300MB cap was larger than the api container's own 256M memory limit, so a large
# upload could only ever OOM-kill the process. Default is now comfortably under it, and the
# body is streamed to disk (never fully buffered) in ingest.api/main.py.
MAX_UPLOAD_BYTES = int(os.getenv('MAX_UPLOAD_MB', '100')) * 1024 * 1024

def _csv_needs_aggregate(path):
    """Header-only sniff: does this CSV lack per-flow endpoint columns?"""
    import csv as _csv
    with open(path, newline='', encoding='utf-8-sig') as f:
        return not has_endpoints(_csv.DictReader(f).fieldnames)

def ingest_upload_path(filename, path):
    """Analyze one uploaded file already spooled to disk -> detect -> append to the same
    artifacts/sentinel.db the dashboard reads. Serialized (one writer at a time) so the
    tamper-evident hash chain stays consistent.

    Accepts a PATH (not bytes) so the caller can stream a large body straight to disk and
    never hold it in memory. Returns {'file','alerts_added','total_alerts'} plus, for an
    endpoint-less aggregate CSV, {'analysis','note'}."""
    name = Path(filename or 'upload.jsonl').name
    suffix = Path(name).suffix.lower()
    if suffix not in PCAP_EXT and suffix not in {'.jsonl', '.json', '.log', '.csv'}:
        suffix = '.jsonl'  # unknown -> line-json
    if suffix == '.csv' and _csv_needs_aggregate(path):
        from ingest.csv_to_events import analyze_aggregate
        with _UPLOAD_LOCK:
            before = AlertStore().summary()['total_alerts']
            info = analyze_aggregate(path, int(os.getenv('MAX_CSV_ROWS', '2000000')))
        return {'file': name, 'alerts_added': 0, 'total_alerts': before,
                'analysis': info,
                'note': 'Endpoint-less aggregate CSV: assessment only, no flow alerts (see analysis).'}
    with _UPLOAD_LOCK:
        store, pipeline, metrics = AlertStore(), Pipeline(), StreamMetrics()
        before = store.summary()['total_alerts']
        q = queue.Queue(maxsize=100000); stop = threading.Event()
        ct = threading.Thread(target=consumer, args=(q, store, pipeline, metrics, stop), daemon=True); ct.start()
        try:
            ingest_file(path, q, suffix=suffix)
            # Bounded drain. A bare q.join() waits forever if the consumer dies -- and it dies
            # on any store write error, because append() runs unguarded in its loop. That held
            # _UPLOAD_LOCK for good, so one unwritable store turned EVERY later upload into a
            # hang rather than an error. Wait with a deadline and fail loudly instead.
            deadline = time.time() + _UPLOAD_DRAIN_SECONDS
            while q.unfinished_tasks and time.time() < deadline and ct.is_alive():
                time.sleep(.1)
            if q.unfinished_tasks:
                raise RuntimeError(
                    f'ingest stalled: {q.unfinished_tasks} event(s) unprocessed '
                    f'(consumer_alive={ct.is_alive()})')
        finally: stop.set(); ct.join(timeout=60)
        total = store.summary()['total_alerts']
    return {'file': name, 'alerts_added': total - before, 'total_alerts': total}

def ingest_upload(filename, data):
    """Bytes convenience wrapper (dashboard preview server, tests). Spools to a temp file and
    delegates to ingest_upload_path, so both entry points share one code path and one cap."""
    if not data: raise ValueError('empty upload')
    if len(data) > MAX_UPLOAD_BYTES: raise ValueError(f'upload exceeds {MAX_UPLOAD_BYTES // (1024*1024)} MB cap')
    with tempfile.NamedTemporaryFile(suffix='.upload', delete=False) as tf:
        tf.write(data); tmp = tf.name
    try:
        return ingest_upload_path(filename, tmp)
    finally:
        try: os.unlink(tmp)
        except OSError: pass

def watch_inbox(inbox, q, seen):
    box = Path(inbox); (box / 'processed').mkdir(parents=True, exist_ok=True)
    print(f'[watch] drop pcap/csv/jsonl into {box}', file=sys.stderr)
    while not STOP.is_set():
        for p in sorted(box.glob('*')):
            if p.is_file() and p.name not in seen:
                seen.add(p.name)
                try: ingest_file(p, q); p.rename(box / 'processed' / p.name)
                except Exception as ex: print(f'[watch] {p.name} failed: {ex}', file=sys.stderr)
        STOP.wait(2)

class LiveCapture:
    """Streaming flow assembler over a live NIC. Flows are emitted as conn events once idle
    (finalization latency ~= idle seconds), matching how Zeek closes a connection."""
    def __init__(self, iface, q, idle=10, max_flows=50000):
        self.iface, self.q, self.idle, self.max_flows = iface, q, idle, max_flows
        self.flows = {}; self.lock = threading.Lock(); self.sniffer = None
    def _on(self, pkt):
        dns_out = []
        with self.lock: ingest_packet(pkt, self.flows, dns_out)
        for d in dns_out: self.q.put(d)
    def _flush(self, now, final=False):
        with self.lock:
            over = len(self.flows) > self.max_flows  # bound memory on 24/7 runs
            due = list(self.flows) if (final or over) else [k for k, f in self.flows.items() if now - f['last'] >= self.idle]
            for k in due: self.q.put(_conn_event(k, self.flows.pop(k)))
    def _flush_loop(self):
        while not STOP.is_set(): STOP.wait(max(self.idle / 2, 1)); self._flush(time.time())
        self._flush(time.time(), final=True)
    def start(self):
        from scapy.all import AsyncSniffer, get_if_list
        ifaces = get_if_list()  # fail loud on a bad iface, else the sniffer captures nothing silently
        if self.iface not in ifaces:
            raise ValueError(f"interface {self.iface!r} not found — available: {', '.join(sorted(ifaces))}")
        if hasattr(os, 'geteuid') and os.geteuid() != 0:
            print('[live] warning: not root — live capture usually needs root or CAP_NET_RAW', file=sys.stderr)
        self.sniffer = AsyncSniffer(iface=self.iface, prn=self._on, store=False); self.sniffer.start()
        threading.Thread(target=self._flush_loop, daemon=True).start()
        print(f'[live] capturing on {self.iface}', file=sys.stderr)

def main():
    ap = argparse.ArgumentParser(description='24/7 ingest: live capture + file replay -> dashboard')
    ap.add_argument('--live', metavar='IFACE', action='append', default=[],
                    help='sniff this interface continuously, needs root (repeatable: a real sensor '
                         'watches a mirror port plus any local test segment)')
    ap.add_argument('--watch', metavar='DIR', help='watch dir for drop-in pcap/jsonl files')
    ap.add_argument('--file', action='append', default=[], help='ingest a file now (repeatable)')
    ap.add_argument('--once', action='store_true', help='ingest --file args, then exit (no live/watch)')
    args = ap.parse_args()
    q = queue.Queue(maxsize=100000)
    store, pipeline, metrics = AlertStore(), Pipeline(), StreamMetrics()
    ct = threading.Thread(target=consumer, args=(q, store, pipeline, metrics, STOP, q.qsize),
                         daemon=True); ct.start()
    for fp in args.file: ingest_file(fp, q)
    if args.once:
        q.join(); STOP.set(); ct.join(timeout=10)
        print(f'[service] done: {store.summary()["total_alerts"]} alerts in store', file=sys.stderr); return
    if args.watch: threading.Thread(target=watch_inbox, args=(args.watch, q, set()), daemon=True).start()
    lives = []
    for iface in args.live:
        lc = LiveCapture(iface, q)
        try: lc.start()
        except Exception as ex: print(f'[live] disabled: {ex}', file=sys.stderr)
        else: lives.append(lc)
    if args.live and not lives: print('[live] NO interface is capturing — nothing will ever be detected', file=sys.stderr)
    print('[service] running — Ctrl-C to stop. Dashboard: http://localhost:8000', file=sys.stderr)
    try:
        while True:
            time.sleep(1)
            # The consumer is the only writer and the only thing that drains the queue. If it
            # dies (a store write it cannot recover from, say), the main loop would happily
            # keep sleeping and the process would look perfectly healthy to systemd while
            # ingesting nothing -- the worst possible failure for a sensor, because nothing
            # restarts it. Exit instead and let the unit's Restart=always bring it back.
            if not ct.is_alive():
                print('[service] consumer thread died — exiting so systemd restarts the sensor', file=sys.stderr)
                os._exit(1)
    except KeyboardInterrupt:
        print('\n[service] draining…', file=sys.stderr); STOP.set()
        for lc in lives:
            if lc.sniffer:
                try: lc.sniffer.stop()  # scapy can't always stop an AsyncSniffer socket cleanly
                except Exception:
                    exc = getattr(lc.sniffer, 'exception', None)
                    if exc: print(f'[live] sniffer error on {lc.iface}: {exc!r}', file=sys.stderr)
        ct.join(timeout=5)  # daemon sniffer thread dies with us; bounded drain won't hang on a live socket

if __name__ == '__main__':
    main()

