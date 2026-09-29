"""Generate benign INTERNAL-traffic fixtures (F-09).

Why this file exists
--------------------
`rules.c2` deliberately skipped every RFC1918/CGNAT destination, because doing otherwise on
real enterprise traffic produced a 118-alert false-positive storm (see
`experiments/datasets.yml`). The cost of that gate is that LATERAL C2 — malware beaconing to
`10.x` / `192.168.x` — is invisible.

The gate can only be loosened safely if the benign internal traffic that motivated it is
available as a regression fixture. Otherwise "does this fire on domain controllers and file
servers?" can only be answered by reasoning, and the obvious failure mode of loosening the
gate is exactly that traffic starting to alert.

This generator produces the ADVERSARY of the change: a `benign_internal.jsonl` scenario in
which an internal host talks periodically to domain-controller DNS, SMB, NTP, RDP, LLMNR and a
mesh VPN, and fans out across internal services the way a software update agent does. Every
pattern here is periodic-by-design and must remain silent.

`traffic-gen/generators/generate_scenarios.py` writes it alongside the existing nine scenarios
so `eval.run_suite.py` treats it as a benign case (EXPECTED['benign_internal'] = None).
"""
from __future__ import annotations
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / 'scenarios' / 'benign_internal.jsonl'
SRC = '10.0.0.5'          # a workstation
STEP = 30.0               # 30 s cadence, low jitter


def flows(dst, port, *, n=12, proto='tcp', out_bytes=120, resp_bytes=180, state='SF', t0=1000.0):
    """A periodic series between one internal pair, with exactly zero jitter (cv = 0)."""
    return [json.dumps({'kind': 'conn', 'ts': t0 + i * STEP, 'src_ip': SRC, 'src_port': 51000,
                        'dst_ip': dst, 'dst_port': port, 'proto': proto,
                        'orig_bytes': out_bytes, 'resp_bytes': resp_bytes,
                        'conn_state': state, 'tls': port in (443, 8443)}) for i in range(n)]


def main():
    lines = []
    # --- infrastructure with a permanent idle channel: must never alert -------------------
    lines += flows('10.0.0.10', 53, out_bytes=90, resp_bytes=260)        # AD/DNS to the DC
    lines += flows('10.0.0.10', 123, proto='udp', out_bytes=76, resp_bytes=76)   # NTP
    lines += flows('10.0.0.20', 445, out_bytes=4096, resp_bytes=65536)   # SMB
    lines += flows('10.0.0.20', 3389, out_bytes=300, resp_bytes=120)      # RDP keepalive
    lines += flows('10.0.0.10', 389, proto='udp', out_bytes=110, resp_bytes=90)   # LDAP
    lines += flows('10.0.0.10', 5355, proto='udp', out_bytes=110, resp_bytes=90)  # LLMNR
    lines += flows('100.101.102.103', 41641, out_bytes=140, resp_bytes=150)       # mesh VPN
    # --- internal services an agent legitimately polls --------------------------------------
    lines += flows('10.0.0.30', 3128, out_bytes=220, resp_bytes=400)      # egress proxy
    lines += flows('10.0.0.40', 443, out_bytes=180, resp_bytes=9000)    # internal web (TLS)
    # --- broadcast / multicast internal chatter ---------------------------------------------
    for i in range(6):
        lines.append(json.dumps({'kind': 'conn', 'ts': 1000.0 + i * 30, 'src_ip': SRC,
                                 'src_port': 5353, 'dst_ip': '192.168.0.255', 'dst_port': 5353,
                                 'proto': 'udp', 'orig_bytes': 90, 'resp_bytes': 90,
                                 'conn_state': 'SF'}))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text('\n'.join(lines) + '\n')
    print(f'wrote {OUT} ({len(lines)} events)')


if __name__ == '__main__':
    main()
