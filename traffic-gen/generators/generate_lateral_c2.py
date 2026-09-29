"""Generate the LATERAL C2 scenario (F-09): a beacon from an internal host to another
internal host, on a port nothing legitimate runs.

This is the case `rules.c2` cannot see today, because it skips every RFC1918 destination. The
gate exists for good reason (see `generate_benign_internal.py`), so this fixture is the proof
that a port-profile-based loosening separates the two:

  benign internal  -> AD/DNS :53, SMB :445, RDP :3389, NTP :123, mesh VPN :41641, ...
  lateral C2       -> an implant on 10.0.0.5 calling 10.0.0.99:4444 every 60 s with a few
                      hundred bytes each way

The distinguishing signal is the DESTINATION PORT, not the address range. Timing is identical
in both fixtures; only the port profile differs.
"""
from __future__ import annotations
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / 'scenarios' / 'lateral_c2.jsonl'


def main():
    lines = []
    # Classic implant ports. Each stream is written CONTIGUOUSLY with its own cadence, because
    # the C2 feature window is keyed on (src, dst) and evicts by time: interleaving two
    # cadences into one window makes the earlier stream age out mid-file, which corrupts
    # persistence_seconds and iat_cv and hides the detection. Real traffic from one host to
    # several ports is likewise observed in time order, not batched by fixture.
    for dst, port, period, n, out_b, resp_b, t0 in (
            ('10.0.0.99', 4444, 60.0, 12, 180, 220, 1000.0),   # Metasploit default
            ('10.0.0.99', 1337, 45.0, 12, 150, 190, 2000.0),   # common backdoor port
            ('10.0.0.77', 9001, 90.0, 10, 260, 310, 3000.0)):  # uncommon service port
        for i in range(n):
            lines.append(json.dumps({
                'kind': 'conn', 'ts': t0 + i * period,
                'src_ip': '10.0.0.5', 'src_port': 50000 + i,
                'dst_ip': dst, 'dst_port': port, 'proto': 'tcp',
                'orig_bytes': out_b, 'resp_bytes': resp_b,
                'conn_state': 'SF', 'tls': False}))
    lines.sort(key=lambda l: json.loads(l)['ts'])
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text('\n'.join(lines) + '\n')
    print(f'wrote {OUT} ({len(lines)} events)')


if __name__ == '__main__':
    main()
