"""Verify the F25 correlation corrections: no invented window, no invented threat class."""
import sys

sys.path.insert(0, '/opt/ntro-sentinel')
from correlation.engine import Correlator
from engine.contracts import alert as mk


def A(ts, cls, conf=0.6, i=0, src='10.0.0.9'):
    from datetime import datetime, timezone
    iso = datetime.fromtimestamp(ts, timezone.utc).isoformat()
    return mk({'src_ip': src, 'src_port': 1, 'dst_ip': '198.51.100.1', 'dst_port': 1,
               'proto': 'tcp', 'event_ts': iso}, cls, cls, conf, {}, [], 't')


def main():
    ok = True

    r = Correlator(clock=lambda: 1e9).process(
        [A(1000, 'recon_scan', 0.9, 1), A(1100, 'exfiltration', 0.6, 2),
         A(1300, 'dga_dns_tunnel', 0.5, 3)], now=2000)[0]
    e = r['supporting_evidence']
    good = r['threat_class'] != 'c2_beaconing'
    ok &= good
    print(f"  [{'PASS' if good else 'FAIL'}] recon+exfil+dga is NOT reported as c2_beaconing "
          f"(class={r['threat_class']}, most severe observed)")
    good = e['window_seconds'] == 300.0 and 'observed span' in e['window_seconds_basis']
    ok &= good
    print(f"  [{'PASS' if good else 'FAIL'}] window_seconds is the OBSERVED span, not a literal "
          f"(got {e['window_seconds']})")

    far = Correlator(clock=lambda: 1e9).process(
        [A(0, 'recon_scan', 0.9, 1), A(86400, 'exfiltration', 0.6, 2),
         A(172800, 'dga_dns_tunnel', 0.5, 3)], now=200000)
    good = len(far) == 0
    ok &= good
    print(f"  [{'PASS' if good else 'FAIL'}] 3 alerts 3 DAYS apart do not corroborate each other "
          f"(raised {len(far)}, pre-fix 1)")

    keep = Correlator(clock=lambda: 1e9).process(
        [A(1000, 'c2_beaconing', 0.9, 1), A(1100, 'recon_scan', 0.6, 2),
         A(1300, 'exfiltration', 0.5, 3)], now=2000)[0]
    good = keep['threat_class'] == 'c2_beaconing'
    ok &= good
    print(f"  [{'PASS' if good else 'FAIL'}] a genuine beacon is still named as one "
          f"(class={keep['threat_class']})")

    print('\n' + ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
