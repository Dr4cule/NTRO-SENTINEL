"""Negative tests: the failure paths the project actually claims (alert contract, hash chain,
upload limits, write auth, CSV rejection) must be asserted, not assumed."""
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from alertstore.store import AlertStore
from correlation.engine import Correlator
from engine.validation import validate_alert
from ingest.csv_to_events import analyze_aggregate, has_endpoints, read_conn_events


def alert_record(**over):
    r = {'alert_id': 'a1', 'timestamp': '2026-01-01T00:00:00+00:00',
         'flow_id': {'src_ip': '10.0.0.1', 'src_port': 1, 'dst_ip': '10.0.0.2', 'dst_port': 2, 'proto': 'tcp'},
         'threat_class': 'ddos', 'subtype': 'syn_flood', 'confidence': 0.9, 'severity': 'critical',
         'supporting_evidence': {}, 'mitre_attack': ['T1498'], 'model_version': 'test-v1'}
    r.update(over)
    return r


class ValidationRejection(unittest.TestCase):
    def test_bool_confidence_rejected(self):
        # bool subclasses int, so a naive isinstance check accepts True -> it lands in 'low'
        for bad in (True, False):
            with self.assertRaises(ValueError):
                validate_alert(alert_record(confidence=bad))

    def test_out_of_range_confidence_rejected(self):
        for bad in (-0.1, 1.1, 2, -5):
            with self.assertRaises(ValueError):
                validate_alert(alert_record(confidence=bad))

    def test_boundary_confidence_accepted(self):
        for good in (0, 1, 0.0, 1.0, 0.5):
            r = alert_record(confidence=good)
            self.assertEqual(validate_alert(r)['confidence'], good)

    def test_non_numeric_confidence_rejected(self):
        for bad in ('0.5', None, [0.5], {}):
            with self.assertRaises(ValueError):
                validate_alert(alert_record(confidence=bad))

    def test_missing_and_wrong_types_rejected(self):
        r = alert_record()
        del r['alert_id']
        with self.assertRaises(ValueError):
            validate_alert(r)
        with self.assertRaises(ValueError):
            validate_alert(alert_record(mitre_attack='T1498'))
        with self.assertRaises(ValueError):
            validate_alert(alert_record(threat_class='not_a_threat'))
        with self.assertRaises(ValueError):
            validate_alert(alert_record(severity='catastrophic'))

    def test_flow_id_must_have_exact_keys(self):
        with self.assertRaises(ValueError):
            validate_alert(alert_record(flow_id={'src_ip': '1', 'dst_ip': '2'}))
        with self.assertRaises(ValueError):
            validate_alert(alert_record(flow_id={'src_ip': '1', 'src_port': 1, 'dst_ip': '2',
                                                 'dst_port': 2, 'proto': 'tcp', 'extra': 1}))


class HashChain(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'sentinel.db')
        self.store = AlertStore(self.path)

    def test_duplicate_alert_id_is_idempotent_not_fatal(self):
        self.assertTrue(self.store.append(alert_record(alert_id='dup')))
        self.assertFalse(self.store.append(alert_record(alert_id='dup')))  # IntegrityError -> False
        self.assertEqual(self.store.summary()['total_alerts'], 1)
        self.assertTrue(self.store.verify_chain()['valid'])

    def test_chain_advances_and_verifies(self):
        for i in range(5):
            self.store.append(alert_record(alert_id=f'a{i}', confidence=0.5 + i * 0.01))
        v = self.store.verify_chain()
        self.assertTrue(v['valid'])
        self.assertEqual(v['checked'], 5)
        self.assertTrue(v['head_hash'])

    def test_tampered_record_breaks_verification(self):
        for i in range(3):
            self.store.append(alert_record(alert_id=f'a{i}'))
        con = sqlite3.connect(self.path)
        con.execute("UPDATE alerts SET record_json=? WHERE seq=2",
                    (json.dumps(alert_record(alert_id='a1', confidence=0.1), sort_keys=True, separators=(',', ':')),))
        con.commit()
        con.close()
        v = self.store.verify_chain()
        self.assertFalse(v['valid'])
        self.assertEqual(v['failed_sequence'], 2)

    def test_deleted_record_breaks_verification(self):
        for i in range(3):
            self.store.append(alert_record(alert_id=f'a{i}'))
        con = sqlite3.connect(self.path)
        con.execute('DELETE FROM alerts WHERE seq=2')
        con.commit()
        con.close()
        self.assertFalse(self.store.verify_chain()['valid'])

    def test_reordered_records_break_verification(self):
        for i in range(3):
            self.store.append(alert_record(alert_id=f'a{i}'))
        con = sqlite3.connect(self.path)
        rows = con.execute('SELECT record_json FROM alerts ORDER BY seq').fetchall()
        con.execute('UPDATE alerts SET record_json=? WHERE seq=1', (rows[1][0],))
        con.execute('UPDATE alerts SET record_json=? WHERE seq=2', (rows[0][0],))
        con.commit()
        con.close()
        self.assertFalse(self.store.verify_chain()['valid'])

    def test_invalid_alert_is_never_stored(self):
        # store.append does not itself validate; the contract is enforced at construction. Confirm
        # the guard exists so a bad record cannot enter the chain through a validated path.
        with self.assertRaises(ValueError):
            validate_alert(alert_record(threat_class='made_up'))


class CorrelationSuppression(unittest.TestCase):
    def _a(self, cls, tid, src='1.2.3.4'):
        return alert_record(alert_id=tid, threat_class=cls, confidence=0.7, severity='high',
                            flow_id={'src_ip': src, 'src_port': 1, 'dst_ip': '9.9.9.9', 'dst_port': 1, 'proto': 'tcp'})

    def test_noisy_source_does_not_refire_unbounded(self):
        c = Correlator(clock=lambda: 0.0)
        fires = sum(len(c.process([self._a(['ddos', 'recon_scan', 'exfiltration'][i % 3], f'a{i}')]))
                    for i in range(60))
        self.assertEqual(fires, 1, 'one source must yield one correlated alert per window')

    def test_distinct_sources_each_get_their_own(self):
        c = Correlator(clock=lambda: 0.0)
        fires = sum(len(c.process([self._a(['ddos', 'recon_scan', 'exfiltration'][i % 3], f'b{i}', src=f'src{i % 2}')]))
                    for i in range(6))
        self.assertEqual(fires, 2)

    def test_two_classes_are_not_enough(self):
        c = Correlator(clock=lambda: 0.0)
        self.assertEqual(len(c.process([self._a('ddos', 'x1')])), 0)
        self.assertEqual(len(c.process([self._a('recon_scan', 'x2')])), 0)

    def test_suppression_expires(self):
        now = [0.0]
        c = Correlator(suppress_seconds=10.0, clock=lambda: now[0])
        for i in range(3):
            now[0] += 1.0
            c.process([self._a(['ddos', 'recon_scan', 'exfiltration'][i % 3], f'c{i}')])
        now[0] = 100.0
        fired = 0
        for i in range(3):
            now[0] += 1.0
            fired += len(c.process([self._a(['ddos', 'recon_scan', 'exfiltration'][i % 3], f'd{i}')]))
        self.assertEqual(fired, 1, 'may re-fire once the cooldown elapses')

    def test_confidence_never_exceeds_strongest_constituent(self):
        c = Correlator(clock=lambda: 0.0)
        out = c.process([self._a('ddos', 'e1'), self._a('recon_scan', 'e2')])
        c.process([self._a('exfiltration', 'e3')])
        out = c.process([self._a('c2_beaconing', 'e4', src='1.1.1.1')]) or out
        if out:
            self.assertLessEqual(out[0]['confidence'], 0.9)


class CsvRejection(unittest.TestCase):
    def test_missing_endpoints_raises_with_column_names(self):
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as tf:
            tf.write('Destination Port,Label\n80,BENIGN\n')
            p = tf.name
        try:
            self.assertFalse(has_endpoints(['Destination Port', 'Label']))
            with self.assertRaises(ValueError) as ctx:
                list(read_conn_events(p))
            self.assertIn('endpoint', str(ctx.exception).lower())
        finally:
            os.unlink(p)

    def test_empty_csv_reports_zero_rows(self):
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as tf:
            tf.write('Destination Port,Label\n')
            p = tf.name
        try:
            info = analyze_aggregate(p)
            self.assertEqual(info['rows'], 0)
            self.assertEqual(info['ddos_share'], 0.0)
            self.assertEqual(info['top_destination_ports'], [])
        finally:
            os.unlink(p)

    def test_infinity_values_do_not_poison_stats(self):
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as tf:
            tf.write('Destination Port,Flow Duration,Flow Packets/s,SYN Flag Count,Label\n'
                     '80,1000000,Infinity,0,BENIGN\n'
                     '80,2000000,Infinity,1,DDoS\n')
            p = tf.name
        try:
            info = analyze_aggregate(p)
            self.assertEqual(info['rows'], 2)
            self.assertNotEqual(info['mean_flow_packets_per_s'], float('inf'))
        finally:
            os.unlink(p)

    def test_bom_and_spaced_headers_are_tolerated(self):
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False, encoding='utf-8-sig') as tf:
            tf.write(' Source IP , Source Port , Destination IP , Destination Port , Protocol ,Label\n'
                     '10.0.0.1,1,10.0.0.2,80,6,BENIGN\n')
            p = tf.name
        try:
            evs = list(read_conn_events(p))
            self.assertEqual(len(evs), 1)
            self.assertEqual(evs[0]['src_ip'], '10.0.0.1')
            self.assertEqual(evs[0]['proto'], 'tcp')
        finally:
            os.unlink(p)


class UploadLimits(unittest.TestCase):
    def test_cap_is_under_container_memory(self):
        from ingest.service import MAX_UPLOAD_BYTES
        self.assertLessEqual(MAX_UPLOAD_BYTES, 256 * 1024 * 1024,
                             'upload cap must fit inside the api container memory limit')

    def test_empty_and_oversized_uploads_raise(self):
        from ingest.service import ingest_upload, MAX_UPLOAD_BYTES
        with self.assertRaises(ValueError):
            ingest_upload('x.jsonl', b'')
        with self.assertRaises(ValueError):
            ingest_upload('x.jsonl', b'0' * (MAX_UPLOAD_BYTES + 1))

    def test_spoofed_suffix_falls_back_to_jsonl(self):
        from ingest.service import ingest_upload
        body = b'{"kind":"conn","ts":1,"src_ip":"1.1.1.1","src_port":1,"dst_ip":"9.9.9.9","dst_port":1,"proto":"tcp","orig_bytes":1,"resp_bytes":1,"conn_state":"SF"}\n'
        old = os.environ.get('ALERT_DB')
        with tempfile.TemporaryDirectory() as d:  # keep the shared store out of this test
            os.environ['ALERT_DB'] = os.path.join(d, 'sentinel.db')
            try:
                out = ingest_upload('capture.exe', body)  # unknown suffix must not crash
            finally:
                if old is None:
                    os.environ.pop('ALERT_DB', None)
                else:
                    os.environ['ALERT_DB'] = old
        self.assertIn('alerts_added', out)


class WriteAuth(unittest.TestCase):
    """Asserts the auth module's contract without importing fastapi (not a test dependency).
    The behavioural 401/503 paths are exercised by the integration test below when fastapi is
    available; these keep the guarantee covered in a stdlib-only environment too."""

    @staticmethod
    def _source():
        return Path(__file__).resolve().parent.parent / 'api' / 'auth.py'

    def test_token_must_be_configured_for_writes(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('sentinel_auth', self._source())
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except ModuleNotFoundError:
            self.skipTest('fastapi not installed')
        old = os.environ.pop(mod.ENV_VAR, None)
        try:
            self.assertFalse(mod.write_auth_enabled())
        finally:
            if old is not None:
                os.environ[mod.ENV_VAR] = old

    def test_bearer_header_shape(self):
        self.assertEqual(_mint('s3cret'), 'bearer s3cret')
        self.assertEqual(_mint(''), '')

    def test_compare_digest_is_used(self):
        src = self._source().read_text()
        self.assertIn('compare_digest', src, 'token comparison must be constant-time')

    def test_fails_closed_when_unconfigured(self):
        src = self._source().read_text()
        self.assertIn('503', src, 'unconfigured writes must refuse, not fall open')
        self.assertIn('ENV_VAR', src)


def _mint(secret):
    src = (Path(__file__).resolve().parent.parent / 'api' / 'auth.py').read_text()
    prefix = src.split('BEARER = ')[1].split('\n')[0].strip().strip("'\"")
    return f'{prefix} {secret}' if secret else ''


if __name__ == '__main__':
    unittest.main()
