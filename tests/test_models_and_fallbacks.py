"""Tests for the ML train/evaluate split (F-06), the exfil reputation ranking, and the
metadata-only encrypted_malware fallback (F-10).

The F-06 tests are deliberately strict: the original bug was that train and evaluate shared
the same benign vocabulary, so the reported F1=1.0 measured memorisation. Any future edit that
re-introduces vocabulary overlap must fail here.
"""
import unittest

from detectors import rules
from models.holdout import (DGA_ALPHABET, DGA_LENGTHS, EVAL_BENIGN, TRAIN_BENIGN)


class TrainEvalSplitIsDisjoint(unittest.TestCase):
    def test_benign_vocabularies_do_not_overlap(self):
        overlap = set(TRAIN_BENIGN) & set(EVAL_BENIGN)
        self.assertEqual(overlap, set(), f'F-06 regression: {overlap} appear in both splits')

    def test_holdout_is_held_out(self):
        self.assertTrue(len(EVAL_BENIGN) >= 10, 'holdout needs enough distinct labels to mean anything')
        self.assertNotEqual(tuple(TRAIN_BENIGN), tuple(EVAL_BENIGN))

    def test_holdout_is_not_trivially_easy(self):
        """The holdout is deliberately longer/hyphenated than training, so a model that only
        learned 'short word == benign' fails on it. That is the whole point of the split."""
        self.assertGreater(max(map(len, EVAL_BENIGN)), max(map(len, TRAIN_BENIGN)))
        self.assertTrue(any('-' in w for w in EVAL_BENIGN))

    def test_dga_lengths_are_varied(self):
        self.assertGreater(len(set(DGA_LENGTHS)), 1, 'fixed-length DGA is trivially separable')

    def test_build_holdout_is_reproducible_and_disjoint(self):
        from models.evaluate_models import build_holdout
        a, la = build_holdout(seed=1, n_dga=20, repeats=2)
        b, lb = build_holdout(seed=1, n_dga=20, repeats=2)
        self.assertEqual(a, b)
        self.assertEqual(la, lb)
        c, _ = build_holdout(seed=2, n_dga=20, repeats=2)
        self.assertNotEqual(a, c, 'a different seed must yield a different holdout')

    def test_holdout_benign_labels_are_all_held_out(self):
        from models.evaluate_models import build_holdout
        texts, labels = build_holdout(seed=1, n_dga=20, repeats=2)
        benign_labels = {t for t, l in zip(texts, labels) if l == 0}
        self.assertEqual(benign_labels, set(EVAL_BENIGN))
        self.assertEqual(benign_labels & set(TRAIN_BENIGN), set())


class ExfilReputation(unittest.TestCase):
    def _f(self, **o):
        f = {'window_seconds': 300, 'outbound_bytes': 1_006_243, 'inbound_bytes': 68_000,
             'outbound_inbound_ratio': 14.77, 'session_count': 23, 'destination': 'x'}
        f.update(o)
        return f

    def _e(self, ip):
        return {'kind': 'conn', 'src_ip': '172.168.1.142', 'src_port': 1, 'dst_ip': ip,
                'dst_port': 443, 'proto': 'tcp'}

    def test_provider_upload_is_downgraded_not_suppressed(self):
        a = rules.exfil(self._e('104.21.21.127'), self._f(destination='104.21.21.127'))
        self.assertIsNotNone(a, 'must still alert — a CDN upload can be real exfil')
        self.assertIn(a['severity'], ('low', 'medium'),
                      'a provider destination must never rank high')
        self.assertLessEqual(a['confidence'], 0.7)
        self.assertEqual(a['supporting_evidence']['asn_name'], 'Cloudflare')
        self.assertIn('downgrade_reason', a['supporting_evidence'])

    def test_exfil_confidence_scales_with_evidence(self):
        """Continuous scoring: a bigger, more asymmetric, longer transfer must never score lower."""
        small = rules.exfil(self._e('198.51.100.77'),
                            self._f(outbound_bytes=520_000, outbound_inbound_ratio=5.5, session_count=3))
        big = rules.exfil(self._e('198.51.100.77'),
                          self._f(outbound_bytes=5_000_000, outbound_inbound_ratio=50, session_count=30))
        self.assertGreater(big['confidence'], small['confidence'])
        self.assertIn(big['severity'], ('high', 'critical'))

    def test_unknown_host_upload_stays_high_or_critical(self):
        """An unattributable destination must never be downgraded. It scores 0.8, or 0.9 when
        the ML second opinion flags it as an outlier — both are 'medium' or worse, and the ML
        path only ever RAISES confidence, so a fresh model must not weaken the alert."""
        a = rules.exfil(self._e('198.51.100.77'), self._f(destination='198.51.100.77'))
        self.assertIn(a['severity'], ('high', 'critical'), a['severity'])
        self.assertGreaterEqual(a['confidence'], 0.8)
        self.assertEqual(a['supporting_evidence']['reputation'], 'unknown')

    def test_unknown_host_is_never_below_the_provider_case(self):
        unknown = rules.exfil(self._e('198.51.100.77'), self._f(destination='198.51.100.77'))
        provider = rules.exfil(self._e('104.21.21.127'), self._f(destination='104.21.21.127'))
        self.assertGreaterEqual(unknown['confidence'], provider['confidence'])

    def test_volume_gate_unchanged(self):
        for o in ({'outbound_bytes': 1000}, {'outbound_inbound_ratio': 1.0}, {'session_count': 1}):
            self.assertIsNone(rules.exfil(self._e('198.51.100.77'), self._f(**o)), o)

    def test_reputation_never_silences_exfil(self):
        """A provider destination lowers the SCORE, never the alert. This is the invariant."""
        for ip in ('104.21.21.127', '8.8.8.8', '140.82.113.26', '198.51.100.77'):
            self.assertIsNotNone(rules.exfil(self._e(ip), self._f(destination=ip)), ip)


class EncryptedFallback(unittest.TestCase):
    def _e(self, **o):
        e = {'kind': 'conn', 'src_ip': '10.1.1.1', 'src_port': 1, 'dst_ip': '198.51.100.9',
             'dst_port': 443, 'proto': 'tcp', 'tls': True}
        e.update(o)
        return e

    def _f(self, **o):
        f = {'window_seconds': 30, 'ja3': '', 'ja4': '', 'tls_version': 'TLSv1.3', 'sni': '',
             'outbound_inbound_ratio': 20.0, 'duration': 1, 'host_sessions': 1}
        f.update(o)
        return f

    def test_fingerprint_match_is_the_strong_path(self):
        a = rules.encrypted(self._e(suspicious_fingerprint=True, ja3='x'), self._f())
        self.assertEqual(a['subtype'], 'metadata_anomaly')
        self.assertEqual(a['confidence'], 0.7)
        self.assertEqual(a['model_version'], 'tls-metadata-v1')

    def test_no_ja3_path_is_no_longer_dead(self):
        """F-10 regression guard: the old rule required suspicious_fingerprint, which the
        scapy/live path can never produce, so encrypted_malware never fired outside Zeek."""
        a = rules.encrypted(self._e(), self._f())
        self.assertIsNotNone(a, 'metadata-only fallback must fire without a JA3')
        self.assertEqual(a['subtype'], 'upload_channel_anomaly')
        self.assertEqual(a['model_version'], 'tls-metadata-heuristic-v1')

    def test_fallback_scores_below_a_fingerprint_match(self):
        weak = rules.encrypted(self._e(), self._f())
        strong = rules.encrypted(self._e(suspicious_fingerprint=True, ja3='x'), self._f())
        self.assertLess(weak['confidence'], strong['confidence'])

    def test_requires_all_three_signals(self):
        self.assertIsNone(rules.encrypted(self._e(), self._f(outbound_inbound_ratio=1.2)))
        self.assertIsNone(rules.encrypted(self._e(), self._f(host_sessions=9)))
        self.assertIsNone(rules.encrypted(self._e(dst_ip='104.21.21.127'), self._f()),
                          'a provider destination is where backups/sync legitimately go')

    def test_ratio_alone_never_fires(self):
        for ratio in (50.0, 100.0):
            e = self._e(dst_ip='104.21.21.127')
            self.assertIsNone(rules.encrypted(e, self._f(outbound_inbound_ratio=ratio)), ratio)

    def test_non_tls_never_fires(self):
        e = self._e()
        del e['tls']
        self.assertIsNone(rules.encrypted(e, self._f()))


if __name__ == '__main__':
    unittest.main()
