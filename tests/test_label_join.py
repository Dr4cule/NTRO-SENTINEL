"""Tests for eval/label_join.py — the external-scoring harness.

The important property to protect is not the arithmetic; it is that the harness REFUSES to
produce a number when the ground-truth join is too thin. A harness that always emits an F1
would invite quoting a figure derived from three alerts.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from eval.label_join import ground_truth_windows, wilson

EV = [{'kind': 'early_event', 'ts': 1000.0 + i, 'src_ip': '172.16.0.1', 'src_port': 1000 + i,
       'dst_ip': '10.0.0.5', 'dst_port': 1 + i, 'proto': 'tcp', 'conn_state': 'S0'} for i in range(40)]
EV += [{'kind': 'early_event', 'ts': 2050.0 + i, 'src_ip': '172.16.0.1', 'src_port': 2000 + i,
        'dst_ip': '10.0.0.7', 'dst_port': 1 + i, 'proto': 'tcp', 'conn_state': 'S0'} for i in range(40)]
EV += [{'kind': 'early_event', 'ts': 1500.0 + i, 'src_ip': '192.168.10.50', 'src_port': 3000 + i,
        'dst_ip': '142.250.1.1', 'dst_port': 443, 'proto': 'tcp', 'conn_state': 'SF'} for i in range(60)]

LABELS = 'label,start,end\nDDoS,1000,1200\nPortScan,2000,2200\n'


def run(argv):
    return subprocess.run([sys.executable, '-m', 'eval.label_join', *argv],
                          capture_output=True, text=True, timeout=180)


class Wilson(unittest.TestCase):
    def test_zero_and_full(self):
        self.assertEqual(wilson(0, 0), (0.0, 0.0))
        # 10/10 must NOT give lo==1.0: Wilson deliberately keeps the lower bound below 1 so a
        # small perfect sample is not reported as certain. That is the point of using Wilson.
        lo, hi = wilson(10, 10)
        self.assertLess(lo, 1.0)
        self.assertGreater(lo, 0.7)
        self.assertEqual(hi, 1.0)
        lo2, _ = wilson(1000, 1000)
        self.assertGreater(lo2, lo, 'more samples must tighten the interval inward')

    def test_interval_contains_point_estimate(self):
        for k, n in ((1, 3), (5, 10), (40, 60), (3, 300)):
            lo, hi = wilson(k, n)
            self.assertLessEqual(lo, k / n)
            self.assertGreaterEqual(hi, k / n)

    def test_narrower_with_more_samples(self):
        a = wilson(50, 100)
        b = wilson(500, 1000)
        self.assertLess((b[1] - b[0]), (a[1] - a[0]))


class LabelParsing(unittest.TestCase):
    def test_time_windows_are_extracted(self):
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as f:
            f.write(LABELS); p = f.name
        windows, class_only = ground_truth_windows(
            [{'label': 'DDoS', 'start': '1000', 'end': '1200'},
             {'label': 'PortScan', 'start': '2000', 'end': '2200'}])
        self.assertEqual(len(windows), 2)
        self.assertEqual(class_only, [])
        self.assertEqual({w['class'] for w in windows}, {'ddos', 'recon_scan'})

    def test_unparseable_times_fall_back_to_class_only(self):
        windows, class_only = ground_truth_windows([{'label': 'DDoS'}])
        self.assertEqual(windows, [])
        self.assertEqual(len(class_only), 1)

    def test_unmapped_label_yields_no_sentinel_class(self):
        # A label we cannot map still yields a WINDOW, but with class=None so it is never
        # counted as a detection target. Getting this wrong would score an unmappable label
        # as a false negative and silently penalise recall.
        windows, _ = ground_truth_windows([{'label': 'Web Attack - XSS', 'start': '1', 'end': '2'}])
        self.assertEqual(len(windows), 1)
        self.assertIsNone(windows[0]['class'])
        self.assertEqual(windows[0]['raw'], 'Web Attack - XSS')


class HarnessRefuses(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.events = Path(self.d) / 'e.jsonl'
        self.events.write_text('\n'.join(json.dumps(x) for x in EV[:30]))
        self.labels = Path(self.d) / 'l.csv'
        self.labels.write_text(LABELS)
        self.out = Path(self.d) / 'o.json'

    def test_refuses_without_attack_ips(self):
        r = run(['--events', str(self.events), '--labels', str(self.labels), '--output', str(self.out)])
        self.assertEqual(r.returncode, 2)
        self.assertIn('required', r.stderr)

    def test_refuses_when_join_is_too_thin(self):
        r = run(['--events', str(self.events), '--labels', str(self.labels),
                 '--attack-ips', '172.16.0.1', '--output', str(self.out)])
        self.assertEqual(r.returncode, 0)
        data = json.loads(self.out.read_text())
        self.assertFalse(data['reportable'], 'a 30-event join must not be reported')
        self.assertIn('NOT reportable', data['verdict'])

    def test_reports_when_adequate(self):
        events = Path(self.d) / 'full.jsonl'
        events.write_text('\n'.join(json.dumps(x) for x in EV))
        r = run(['--events', str(events), '--labels', str(self.labels),
                 '--attack-ips', '172.16.0.1', '--victim-ips', '192.168.10.50', '--output', str(self.out)])
        self.assertEqual(r.returncode, 0, r.stderr)
        data = json.loads(self.out.read_text())
        self.assertTrue(data['reportable'])
        self.assertEqual(data['join']['events_joined'], 140)
        self.assertTrue((self.out.parent / 'o.md').exists())

    def test_confidence_intervals_present(self):
        events = Path(self.d) / 'full.jsonl'
        events.write_text('\n'.join(json.dumps(x) for x in EV))
        run(['--events', str(events), '--labels', str(self.labels), '--attack-ips', '172.16.0.1',
             '--victim-ips', '192.168.10.50', '--output', str(self.out)])
        data = json.loads(self.out.read_text())
        for cls, v in data['per_class'].items():
            if v['recall'] is not None:
                self.assertEqual(len(v['recall_ci95']), 2, cls)
            if v['precision'] is not None:
                self.assertEqual(len(v['precision_ci95']), 2, cls)

    def test_labels_never_influence_detection(self):
        """Ground truth is read only after the pipeline runs. A trivially-detectable capture
        with labels must score the same as the same capture with flipped labels' ordering."""
        events = Path(self.d) / 'full.jsonl'
        events.write_text('\n'.join(json.dumps(x) for x in EV))
        run(['--events', str(events), '--labels', str(self.labels), '--attack-ips', '172.16.0.1',
             '--victim-ips', '192.168.10.50', '--output', str(self.out)])
        a = json.loads(self.out.read_text())['inputs']['alerts']
        run(['--events', str(events), '--labels', str(self.labels), '--attack-ips', '10.0.0.5',
             '--victim-ips', '192.168.10.50', '--output', str(self.out)])
        b = json.loads(self.out.read_text())['inputs']['alerts']
        self.assertEqual(a, b, 'alert count must not depend on which IPs are labelled as attacker')


if __name__ == '__main__':
    unittest.main()
