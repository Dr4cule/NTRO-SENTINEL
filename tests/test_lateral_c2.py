"""F-09: lateral C2 must be detected, benign internal traffic must stay silent.

These two fixtures are the entire justification for loosening the C2 rule's RFC1918 skip, and
they are deliberately near-identical in every dimension EXCEPT the destination port:

  benign_internal : AD/DNS 53, SMB 445, RDP 3389, NTP 123, LDAP 389, proxy 3128, mesh 41641
  lateral_c2      : 4444, 1337, 9001 - nothing legitimate runs on these

Both are perfectly periodic (cv = 0) and both are internal. Only the port profile separates
them, which is why the change is a port allowlist rather than a removal of the address gate.
"""
import json
import unittest
from pathlib import Path

from detectors import rules
from engine.stream_consumer import Pipeline

SCEN = Path('traffic-gen/scenarios')


def replay(name):
    p = Pipeline()
    out = []
    for line in (SCEN / name).read_text().splitlines():
        if line.strip():
            out.extend(p.process(json.loads(line)))
    return out


class LateralC2IsDetected(unittest.TestCase):
    """The blind spot this change closes: internal-to-internal beaconing."""

    def test_lateral_fixture_fires(self):
        alerts = replay('lateral_c2.jsonl')
        lateral = [a for a in alerts if a['subtype'] == 'lateral_beacon']
        self.assertTrue(lateral, 'lateral C2 must be detected')

    def test_subtype_mitre_and_confidence(self):
        lateral = [a for a in replay('lateral_c2.jsonl') if a['subtype'] == 'lateral_beacon']
        a = lateral[0]
        self.assertEqual(a['threat_class'], 'c2_beaconing')   # stays inside the 6-class enum
        self.assertEqual(a['mitre_attack'], ['T1021'])         # lateral movement, not web C2
        self.assertGreaterEqual(a['confidence'], 0.7)
        self.assertEqual(a['supporting_evidence']['dst_scope'], 'internal')
        self.assertIn('destination_port', a['supporting_evidence'])

    def test_evidence_explains_the_decision(self):
        a = [x for x in replay('lateral_c2.jsonl') if x['subtype'] == 'lateral_beacon'][0]
        r = a['supporting_evidence']['rationale']
        self.assertIn(str(a['supporting_evidence']['destination_port']), r)
        self.assertIn('lateral', r.lower())


class BenignInternalStaysSilent(unittest.TestCase):
    """The reason the gate existed in the first place. If this fails, the change is unsafe."""

    def test_benign_internal_fixture_is_quiet(self):
        self.assertEqual(replay('benign_internal.jsonl'), [],
                         'domain controllers, SMB, RDP, NTP, proxies and mesh VPNs are '
                         'periodic by design and must never alert')

    def test_known_service_ports_are_never_lateral(self):
        for port in (53, 123, 389, 445, 3128, 3389, 8472, 41641, 51820):
            e = {'kind': 'conn', 'ts': 1000.0, 'src_ip': '10.0.0.5', 'src_port': 5000,
                 'dst_ip': '10.0.0.10', 'dst_port': port, 'proto': 'tcp',
                 'orig_bytes': 120, 'resp_bytes': 160, 'conn_state': 'SF'}
            f = {'window_seconds': 300, 'session_count': 8, 'iat_mean': 30.0, 'iat_cv': 0.0,
                 'period_seconds': 30.0, 'destination': '10.0.0.10', 'destination_port_count': 1,
                 'persistence_seconds': 210.0, 'outbound_bytes': 960, 'inbound_bytes': 1280,
                 'outbound_inbound_ratio': 0.75, 'mean_outbound_bytes': 120.0,
                 'mean_inbound_bytes': 160.0}
            self.assertIsNone(rules.c2(e, f), f'internal service port {port} must stay silent')

    def test_implant_ports_do_fire_internally(self):
        for port in (1337, 4444, 9001):
            e = {'kind': 'conn', 'ts': 1000.0, 'src_ip': '10.0.0.5', 'src_port': 5000,
                 'dst_ip': '10.0.0.99', 'dst_port': port, 'proto': 'tcp',
                 'orig_bytes': 120, 'resp_bytes': 160, 'conn_state': 'SF'}
            f = {'window_seconds': 300, 'session_count': 8, 'iat_mean': 30.0, 'iat_cv': 0.0,
                 'period_seconds': 30.0, 'destination': '10.0.0.99', 'destination_port_count': 1,
                 'persistence_seconds': 210.0, 'outbound_bytes': 960, 'inbound_bytes': 1280,
                 'outbound_inbound_ratio': 0.75, 'mean_outbound_bytes': 120.0,
                 'mean_inbound_bytes': 160.0}
            a = rules.c2(e, f)
            self.assertIsNotNone(a, f'implant port {port} must be detected')
            self.assertEqual(a['subtype'], 'lateral_beacon')

    def test_structural_gates_still_apply_internally(self):
        """Loosening the address check must not loosen the timing/size gates."""
        base = {'window_seconds': 300, 'session_count': 8, 'iat_mean': 30.0, 'iat_cv': 0.0,
                'period_seconds': 30.0, 'destination': '10.0.0.99', 'destination_port_count': 1,
                'persistence_seconds': 210.0, 'outbound_bytes': 960, 'inbound_bytes': 1280,
                'outbound_inbound_ratio': 0.75, 'mean_outbound_bytes': 120.0,
                'mean_inbound_bytes': 160.0}
        e = {'kind': 'conn', 'ts': 1000.0, 'src_ip': '10.0.0.5', 'src_port': 5000,
             'dst_ip': '10.0.0.99', 'dst_port': 4444, 'proto': 'tcp',
             'orig_bytes': 120, 'resp_bytes': 160, 'conn_state': 'SF'}
        for over in ({'session_count': 2}, {'iat_cv': 0.4}, {'persistence_seconds': 30},
                     {'mean_outbound_bytes': 40_000}, {'mean_inbound_bytes': 40_000}):
            self.assertIsNone(rules.c2(e, {**base, **over}), over)


class InternetPathUnaffected(unittest.TestCase):
    def test_public_beacon_still_high(self):
        e = {'kind': 'conn', 'ts': 1000.0, 'src_ip': '10.9.9.9', 'src_port': 5000,
             'dst_ip': '198.51.100.50', 'dst_port': 443, 'proto': 'tcp',
             'orig_bytes': 120, 'resp_bytes': 160, 'conn_state': 'SF'}
        f = {'window_seconds': 300, 'session_count': 8, 'iat_mean': 30.0, 'iat_cv': 0.0,
             'period_seconds': 30.0, 'destination': '198.51.100.50', 'destination_port_count': 1,
             'persistence_seconds': 210.0, 'outbound_bytes': 960, 'inbound_bytes': 1280,
             'outbound_inbound_ratio': 0.75, 'mean_outbound_bytes': 120.0,
             'mean_inbound_bytes': 160.0}
        a = rules.c2(e, f)
        self.assertEqual(a['subtype'], 'periodic_beacon')   # NOT lateral
        self.assertEqual(a['severity'], 'high')

    def test_cgnat_still_treated_as_internal(self):
        e = {'kind': 'conn', 'ts': 1000.0, 'src_ip': '10.9.9.9', 'src_port': 5000,
             'dst_ip': '100.101.102.103', 'dst_port': 4444, 'proto': 'tcp',
             'orig_bytes': 120, 'resp_bytes': 160, 'conn_state': 'SF'}
        f = {'window_seconds': 300, 'session_count': 8, 'iat_mean': 30.0, 'iat_cv': 0.0,
             'period_seconds': 30.0, 'destination': '100.101.102.103', 'destination_port_count': 1,
             'persistence_seconds': 210.0, 'outbound_bytes': 960, 'inbound_bytes': 1280,
             'outbound_inbound_ratio': 0.75, 'mean_outbound_bytes': 120.0,
             'mean_inbound_bytes': 160.0}
        a = rules.c2(e, f)
        self.assertEqual(a['subtype'], 'lateral_beacon')


class InboundRepliesAreNotLateral(unittest.TestCase):
    """Live-capture regression. Six `lateral_beacon` false positives appeared on the first
    F-09 build: dst was the LOCAL host on an ephemeral port (44088, 53054, 41764, 58702,
    38694) with PUBLIC sources (Akamai, GitHub, Facebook). Those are replies to our own
    outbound sessions, not beacons. The port range alone cannot be the test, because a real
    lateral implant uses a fixed port above 1024 as a matter of course - what separates the
    two cases is the source being off-net."""

    def _c2(self, src, dst, port):
        f = {'window_seconds': 300, 'session_count': 8, 'iat_mean': 30.0, 'iat_cv': 0.0,
             'period_seconds': 30.0, 'destination': dst, 'destination_port_count': 1,
             'persistence_seconds': 210.0, 'outbound_bytes': 960, 'inbound_bytes': 1280,
             'outbound_inbound_ratio': 0.75, 'mean_outbound_bytes': 120.0,
             'mean_inbound_bytes': 160.0}
        e = {'kind': 'conn', 'ts': 1000.0, 'src_ip': src, 'src_port': 443, 'dst_ip': dst,
             'dst_port': port, 'proto': 'tcp', 'orig_bytes': 150, 'resp_bytes': 200,
             'conn_state': 'SF'}
        return rules.c2(e, f)

    def test_observed_false_positives_are_now_silent(self):
        for src, dst, port in [('140.82.114.25', '192.168.0.102', 44088),
                               ('163.70.140.60', '192.168.0.102', 53054),
                               ('104.18.39.21', '192.168.0.102', 41764),
                               ('172.64.148.235', '192.168.0.102', 58702),
                               ('192.200.0.116', '192.168.0.102', 38694)]:
            self.assertIsNone(self._c2(src, dst, port),
                              f'reply from {src} to our own host on {port} is not lateral C2')

    def test_ephemeral_destination_from_public_source_is_never_lateral(self):
        for port in (44088, 53054, 41764, 58702, 38694, 60123):
            self.assertIsNone(self._c2('203.0.113.9', '10.0.0.5', port), port)

    def test_internal_source_on_a_fixed_implant_port_still_fires(self):
        """The other half of the same test: the fix must not become a blanket port-range skip,
        or genuine lateral C2 would be hidden again."""
        for port in (4444, 1337, 9001):
            self.assertEqual(self._c2('10.0.0.5', '10.0.0.99', port)['subtype'], 'lateral_beacon')

    def test_service_discovery_ports_are_internal_services(self):
        """WSD (5350/5351) is periodic-by-design on a LAN, the same family as mDNS 5353.
        Observed as a false positive against the local gateway."""
        for port in (5350, 5351, 5352, 5353, 5354, 5355):
            self.assertTrue(rules._internal_service_port(port), port)
        self.assertIsNone(self._c2('192.168.0.102', '192.168.0.1', 5351))


class EvalCoversTheNewFixture(unittest.TestCase):
    def test_both_fixtures_are_in_the_suite(self):
        from eval.run_suite import EXPECTED
        self.assertIsNone(EXPECTED['benign_internal'], 'must be scored as benign')
        self.assertEqual(EXPECTED['lateral_c2'], 'c2_beaconing')

    def test_fpr_aggregates_over_all_benign_scenarios(self):
        """Regression: the suite used to select only the FIRST benign scenario, so FPs in the
        others were invisible. Injected false positives must now show up."""
        from eval.run_suite import confusion_and_precision
        rows = [{'scenario': 'benign', 'ground_truth': 'benign', 'events': 30, 'alert_count': 0, 'predicted': {}},
                {'scenario': 'benign_internal', 'ground_truth': 'benign', 'events': 114, 'alert_count': 0, 'predicted': {}},
                {'scenario': 'ddos', 'ground_truth': 'ddos', 'events': 25, 'alert_count': 1, 'predicted': {'ddos': 1}}]
        self.assertEqual(confusion_and_precision(rows)['benign_alerts'], 0)
        rows[1]['alert_count'] = 7
        self.assertEqual(confusion_and_precision(rows)['benign_alerts'], 7)
        self.assertEqual(len(confusion_and_precision(rows)['benign_scenarios']), 2)


class C2WindowRobustness(unittest.TestCase):
    def test_out_of_order_events_do_not_corrupt_features(self):
        """The window is keyed on (src,dst) and evicted by time, so late/out-of-order events can
        leave timestamps unsorted. That previously produced NEGATIVE persistence_seconds and an
        exploding iat_cv, which silently disabled detection instead of raising an error."""
        from features.c2_beacon import C2Features
        f = C2Features()
        for ts in (1000.0, 1030.0, 1060.0, 1090.0, 1005.0, 1120.0):
            out = f.update({'src_ip': 'a', 'dst_ip': 'b', 'dst_port': 4444,
                            'orig_bytes': 120, 'resp_bytes': 160}, ts)
        self.assertGreaterEqual(out['persistence_seconds'], 0.0)
        self.assertGreaterEqual(out['iat_cv'], 0.0)


if __name__ == '__main__':
    unittest.main()
