"""API-level tests: write auth (401/503/201) and the streamed upload cap (413).

Skipped unless fastapi is installed, so the stdlib-only environment still runs the suite.
"""
import os
import unittest

IMPORT_ERROR = None
try:
    from fastapi.testclient import TestClient
except ImportError as exc:  # pragma: no cover - optional dep
    TestClient = None
    IMPORT_ERROR = str(exc)


def _fresh_client(token=None):
    """Import api.main with a clean module state so the env var is read per test."""
    import importlib
    import api.auth
    import api.main
    importlib.reload(api.auth)
    if token is None:
        os.environ.pop(api.auth.ENV_VAR, None)
    else:
        os.environ[api.auth.ENV_VAR] = token
    importlib.reload(api.main)
    return TestClient(api.main.app)


@unittest.skipIf(TestClient is None, f'fastapi not installed ({IMPORT_ERROR})')
class WriteAuthEndpoints(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.dir = tempfile.TemporaryDirectory()
        self._old_db = os.environ.get('ALERT_DB')
        os.environ['ALERT_DB'] = os.path.join(self.dir.name, 'sentinel.db')

    def tearDown(self):
        if self._old_db is None:
            os.environ.pop('ALERT_DB', None)
        else:
            os.environ['ALERT_DB'] = self._old_db
        os.environ.pop('SENTINEL_API_TOKEN', None)
        self.dir.cleanup()

    BODY = {'alert_id': 'x1', 'timestamp': '2026-01-01T00:00:00+00:00',
            'flow_id': {'src_ip': '10.0.0.1', 'src_port': 1, 'dst_ip': '10.0.0.2', 'dst_port': 2, 'proto': 'tcp'},
            'threat_class': 'ddos', 'subtype': 'syn_flood', 'confidence': 0.9, 'severity': 'critical',
            'supporting_evidence': {}, 'mitre_attack': ['T1498'], 'model_version': 'test-v1'}

    def test_writes_refused_when_no_token_configured(self):
        c = _fresh_client(None)
        self.assertEqual(c.post('/api/alerts', json=self.BODY).status_code, 503)
        self.assertEqual(c.post('/api/ingest', content=b'x').status_code, 503)

    def test_writes_refused_without_authorization_header(self):
        c = _fresh_client('s3cret')
        self.assertEqual(c.post('/api/alerts', json=self.BODY).status_code, 401)

    def test_writes_refused_with_wrong_token(self):
        c = _fresh_client('s3cret')
        r = c.post('/api/alerts', json=self.BODY, headers={'Authorization': 'Bearer wrong'})
        self.assertEqual(r.status_code, 401)

    def test_write_accepted_with_correct_token(self):
        c = _fresh_client('s3cret')
        r = c.post('/api/alerts', json=self.BODY, headers={'Authorization': 'Bearer s3cret'})
        self.assertEqual(r.status_code, 201, r.text)
        self.assertTrue(r.json()['created'])

    def test_reads_stay_open(self):
        c = _fresh_client('s3cret')  # no Authorization header sent
        for path in ('/api/alerts', '/api/dashboard/summary', '/api/metrics', '/api/evidence/verify', '/health'):
            self.assertEqual(c.get(path).status_code, 200, path)

    def test_health_reports_auth_and_cap(self):
        c = _fresh_client('s3cret')
        body = c.get('/health').json()
        self.assertTrue(body['write_auth'])
        self.assertGreaterEqual(body['max_upload_mb'], 1)

    def test_oversized_upload_rejected_413(self):
        c = _fresh_client('s3cret')
        from api.main import MAX_UPLOAD_BYTES
        payload = b'0' * (MAX_UPLOAD_BYTES + 1024)
        r = c.post('/api/ingest', content=payload,
                   headers={'Authorization': 'Bearer s3cret', 'X-Filename': 'big.jsonl'})
        self.assertEqual(r.status_code, 413)

    def test_empty_upload_rejected_400(self):
        c = _fresh_client('s3cret')
        r = c.post('/api/ingest', content=b'',
                   headers={'Authorization': 'Bearer s3cret', 'X-Filename': 'e.jsonl'})
        self.assertEqual(r.status_code, 400)

    def test_aggregate_csv_upload_returns_assessment(self):
        c = _fresh_client('s3cret')
        body = ('Destination Port,Flow Duration,SYN Flag Count,Label\n'
                '80,1000000,0,BENIGN\n80,2000000,1,DDoS\n').encode()
        r = c.post('/api/ingest', content=body,
                   headers={'Authorization': 'Bearer s3cret', 'X-Filename': 'x.csv'})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn('analysis', r.json())
        self.assertEqual(r.json()['alerts_added'], 0)


if __name__ == '__main__':
    unittest.main()
