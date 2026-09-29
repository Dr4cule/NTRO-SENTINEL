"""Regression guard: the tamper-evident chain must survive CONCURRENT multi-process writers.

This is the regression test for a real bug: AlertStore.append() used to read the chain head and
insert without taking a write lock, so two writers (the live-capture consumer and a concurrent
API upload) could read the SAME head and both chain from it, forking the chain. On the pre-fix
code this test fails with "CHAIN FORKED at seq 122"; see alertstore/store.py _begin_immediate.

Usage: python tools/verify_chain_under_concurrency.py
"""
import multiprocessing as mp
import os
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WRITERS, PER_WRITER = 8, 60


def writer(db, tag):
    os.environ['ALERT_DB'] = db
    from alertstore.store import AlertStore
    s = AlertStore()
    for i in range(PER_WRITER):
        s.append({
            'alert_id': f'{tag}-{i}-{uuid.uuid4()}',
            'timestamp': '2026-01-01T00:00:00+00:00',
            'flow_id': {'src_ip': f'10.0.0.{i % 254}', 'dst_ip': '198.51.100.1'},
            'threat_class': 'recon_scan', 'subtype': 'vertical_scan',
            'confidence': 0.5, 'severity': 'medium',
            'supporting_evidence': {}, 'mitre_attack': ['T1046'],
            'model_version': 'concurrency-test',
        })


if __name__ == '__main__':
    db = os.path.join(tempfile.mkdtemp(), 'chain_race.db')
    procs = [mp.Process(target=writer, args=(db, f'w{i}')) for i in range(WRITERS)]
    for p in procs:
        p.start()
    for p in procs:
        p.join()

    os.environ['ALERT_DB'] = db
    from alertstore.store import AlertStore
    s = AlertStore()
    total = s.summary()['total_alerts']
    chain = s.verify_chain()
    expected = WRITERS * PER_WRITER
    print(f'writers={WRITERS} appends_each={PER_WRITER} expected={expected} stored={total}')
    print(f'chain: {chain}')
    assert total == expected, f'LOST WRITES: {total} != {expected}'
    assert chain['valid'], f'CHAIN FORKED at seq {chain.get("failed_sequence")}'
    assert chain['checked'] == total, 'checked != stored'
    print('PASS: no lost writes, chain intact across concurrent writer processes')
