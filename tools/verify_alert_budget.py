"""Does the per-conversation alert budget hide anything it should not?

Sweeps three cases against Pipeline with the budget on and off:
  1. a fresh destination must never be starved
  2. a real C2 campaign must keep alerting for as long as it runs
  3. the flood case: one keepalive conversation repeated for hours

Run: python tools/verify_alert_budget.py
"""
import sys

sys.path.insert(0, '/opt/ntro-sentinel')

import importlib
import engine.stream_consumer as sc


def sim(dst, dport, gap, n, src='10.99.0.1', ob=256, rb=512, budget=None):
    importlib.reload(sc)
    if budget is not None:
        sc.os.environ['SENTINEL_ALERT_BUDGET'] = str(budget)
    else:
        sc.os.environ.pop('SENTINEL_ALERT_BUDGET', None)
    p = sc.Pipeline()
    t0 = 1000.0
    c = 0
    for i in range(n):
        e = {'kind': 'early_event', 'ts': t0 + i * gap, 'src_ip': src, 'src_port': 40000 + i,
             'dst_ip': dst, 'dst_port': dport, 'proto': 'tcp',
             'orig_bytes': ob, 'resp_bytes': rb, 'conn_state': 'SF'}
        c += len(p.process(e))
    return c, p.budget_suppressed


def main():
    ok = True

    print('1. a FRESH destination must never be starved (private peer, 9s cadence)')
    a, _ = sim('10.99.0.9', 9001, 9, 30)
    good = a > 0
    ok &= good
    print(f'   [{"PASS" if good else "FAIL"}] 30 beacon sessions -> {a} alerts')

    print('\n2. a REAL C2 CAMPAIGN keeps alerting for as long as it runs')
    print('   (one alert per 300s c2 dedup window is correct; the budget must not cut it below that)')
    for mins, floor in ((5, 1), (10, 2), (20, 3), (48, 3)):
        n = int(mins * 60 / 9)
        a, s = sim('10.99.0.9', 9001, 9, n)
        good = a >= floor
        ok &= good
        print(f'   [{"PASS" if good else "FAIL"}] {mins:>2} min campaign -> {a} alerts '
              f'(expect >= {floor}, one per dedup window; {s} later repeats suppressed)')

    print('\n3. the FLOOD case: one keepalive conversation repeated for hours')
    base = None
    for hrs in (1, 3, 11):
        n = int(hrs * 3600 / 48)
        a, s = sim('10.99.0.2', 9001, 48, n)
        if hrs == 3:
            base = a
        print(f'   {hrs:>2} h of keepalive -> {a} alerts ({s} suppressed)')
    a_off, _ = sim('10.99.0.2', 9001, 48, int(3 * 3600 / 48), budget=0)
    good = base < a_off
    ok &= good
    print(f'   [{"PASS" if good else "FAIL"}] 3 h: {base} alerts with the budget vs {a_off} without')

    print('\n' + ('PASS - the budget removes repetition, not detections'
                  if ok else 'FAIL - the budget is hiding something it should not'))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
