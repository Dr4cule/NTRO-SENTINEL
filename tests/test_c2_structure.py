"""Tests for the structural C2 gate and the ASN reputation layer.

These encode the false-positive lesson from live capture (wlp0s20f3, 2026-09-29): a low-jitter
timing rule alone flagged browser keepalives, IMAP IDLE and push channels as C2. The gate now
requires direction + payload-size structure, and uses destination-network reputation to RANK
(not suppress). Each of those claims is asserted here.
"""
import unittest

from detectors import rules
from detectors.reputation import asn_of, describe, reputation


def feat(**over):
    """A passing-by-timing beacon feature vector (cv .01, 6 sessions, 180 s, 1 dst port)."""
    f = {'window_seconds': 300, 'session_count': 6, 'iat_mean': 30.0, 'iat_cv': 0.01,
         'period_seconds': 30.0, 'destination': '198.51.100.50', 'destination_port_count': 1,
         'persistence_seconds': 180.0, 'outbound_bytes': 900, 'inbound_bytes': 1200,
         'outbound_inbound_ratio': 0.75, 'mean_outbound_bytes': 150.0, 'mean_inbound_bytes': 200.0}
    f.update(over)
    return f


def ev(**over):
    e = {'kind': 'conn', 'src_ip': '10.9.9.9', 'src_port': 40000, 'dst_ip': '198.51.100.50',
         'dst_port': 443, 'proto': 'tcp', 'orig_bytes': 150, 'resp_bytes': 200, 'conn_state': 'SF'}
    e.update(over)
    return e


class BeaconStillDetected(unittest.TestCase):
    def test_unknown_host_beacon_still_fires_high(self):
        a = rules.c2(ev(), feat())
        self.assertIsNotNone(a)
        self.assertEqual(a['subtype'], 'periodic_beacon')
        self.assertEqual(a['severity'], 'high')
        self.assertEqual(a['confidence'], 0.8)

    def test_c2_mitigation_mapping_present(self):
        self.assertEqual(rules.c2(ev(), feat())['mitre_attack'], ['T1071.001'])

    def test_timing_still_gates(self):
        """Structure must never let a NON-beacon through."""
        self.assertIsNone(rules.c2(ev(), feat(session_count=2)))
        self.assertIsNone(rules.c2(ev(), feat(iat_cv=0.4)))
        self.assertIsNone(rules.c2(ev(), feat(persistence_seconds=30)))
        self.assertIsNone(rules.c2(ev(), feat(destination_port_count=5)))


class StructuralGates(unittest.TestCase):
    def test_response_to_ephemeral_port_is_not_a_beacon(self):
        """dst_port in the ephemeral range means the far end is the CLIENT -> this is a
        response returning, not a beaconing request. Was 354 of 626 real-world FPs."""
        self.assertIsNone(rules.c2(ev(dst_port=50160), feat()))
        self.assertIsNone(rules.c2(ev(dst_port=36648), feat()))

    def test_long_idle_port_overrides_ephemeral_range(self):
        """IMAP/push/VoIP sit above 1024 but are client-initiated, so they are not 'responses'."""
        for port in (5222, 51820, 3478):
            self.assertIsNotNone(rules.c2(ev(dst_port=port), feat(destination='198.51.100.50')), port)

    def test_https_port_is_never_treated_as_a_response(self):
        """443 is the primary malware C2 port. A connection to it is a client request, not a
        returning response -- treating it as ephemeral would have hidden essentially all C2.
        (8080/8443 are genuinely in the ephemeral range, so they ARE treated as responses.)"""
        self.assertIsNotNone(rules.c2(ev(dst_port=443), feat(destination='198.51.100.50')))
        for port in (8080, 8443):
            self.assertIsNone(rules.c2(ev(dst_port=port), feat(destination='198.51.100.50')), port)

    def test_large_outbound_is_content_not_heartbeat(self):
        self.assertIsNone(rules.c2(ev(), feat(mean_outbound_bytes=40_000,
                                              outbound_bytes=400_000)))

    def test_large_inbound_is_content(self):
        self.assertIsNone(rules.c2(ev(), feat(inbound_bytes=900_000, mean_inbound_bytes=90_000)))

    def test_boundary_size_is_inclusive(self):
        self.assertIsNotNone(rules.c2(ev(), feat(mean_outbound_bytes=rules._BROWSER_MIN_OUTBOUND)))


class ReputationLayer(unittest.TestCase):
    def test_known_providers_downgrade_never_suppress(self):
        for ip in ('140.82.113.26', '104.21.21.127', '172.217.24.170', '8.8.8.8'):
            a = rules.c2(ev(dst_ip=ip), feat(destination=ip))
            self.assertIsNotNone(a, ip)
            self.assertEqual(a['subtype'], 'periodic_session', ip)
            self.assertEqual(a['severity'], 'medium', ip)
            self.assertEqual(a['confidence'], 0.45, ip)

    def test_downgrade_reason_and_provenance_are_in_the_evidence(self):
        a = rules.c2(ev(dst_ip='104.21.21.27'), feat(destination='104.21.21.27'))
        ev_ = a['supporting_evidence']
        self.assertIn('downgrade_reason', ev_)
        self.assertEqual(ev_['asn'], 'AS13335')
        self.assertEqual(ev_['asn_name'], 'Cloudflare')
        self.assertEqual(ev_['reputation'], 'provider')

    def test_unknown_network_keeps_high_severity(self):
        a = rules.c2(ev(dst_ip='198.51.100.50', dst_port=443), feat())
        self.assertEqual(a['subtype'], 'periodic_beacon')
        self.assertEqual(a['severity'], 'high')
        self.assertEqual(a['supporting_evidence']['reputation'], 'unknown')

    def test_unknown_network_on_443_is_not_downgraded(self):
        """Regression guard: an HTTP/443 beacon to an unattributable host is the STRONGEST real
        case (443 is the primary malware C2 port), so a web port must never downgrade alone."""
        a = rules.c2(ev(dst_ip='198.51.100.50', dst_port=443), feat())
        self.assertEqual(a['subtype'], 'periodic_beacon')

    def test_testnet_never_classed_as_provider(self):
        for ip in ('198.51.100.50', '203.0.113.9', '192.0.2.1'):
            self.assertEqual(reputation(ip), 'unknown', ip)

    def test_long_idle_port_downgrades_even_on_unknown_net(self):
        """IMAP/SMTP/push have a permanent idle channel, so periodicity is expected regardless
        of who the far end is. These downgrade, but only to 'medium' — never suppressed."""
        for port in (993, 5222, 51820, 53):
            a = rules.c2(ev(dst_port=port), feat(destination='198.51.100.50'))
            self.assertEqual(a['subtype'], 'periodic_session', port)
            self.assertIn('idle', a['supporting_evidence']['downgrade_reason'])

    def test_noise_traffic_never_reaches_the_gate(self):
        for kw in ({'dst_ip': 'ff02::fb', 'dst_port': 5353},
                   {'dst_ip': '255.255.255.255', 'dst_port': 5678},
                   {'dst_ip': '172.168.3.255', 'dst_port': 57621},
                   {'dst_ip': '74.125.130.188', 'dst_port': 5228}):
            self.assertIsNone(rules.c2(ev(**kw), feat()), kw)


class ReputationModule(unittest.TestCase):
    def test_asn_lookups(self):
        self.assertEqual(asn_of('8.8.8.8'), 'AS15169')
        self.assertEqual(asn_of('1.1.1.1'), 'AS13335')
        self.assertEqual(asn_of('140.82.113.26'), 'AS36459')

    def test_fail_open_semantics(self):
        """Unknown must be the LOUD class, never 'benign'. There is no 'benign' return at all."""
        for ip in ('garbage', '', '203.0.113.9', 'fe80::1'):
            self.assertIn(reputation(ip), ('unknown', 'unavailable'), ip)
            self.assertNotEqual(reputation(ip), 'benign')

    def test_ipv6_is_unknown_not_an_error(self):
        self.assertIsNone(asn_of('2606:4700::1'))
        self.assertEqual(reputation('2606:4700::1'), 'unknown')

    def test_describe_never_raises(self):
        for ip in ('8.8.8.8', 'nope', '', '1.2.3.4.5'):
            d = describe(ip)
            self.assertIn('reputation', d)
            self.assertIn('asn', d)


class DdosMdnsSuppression(unittest.TestCase):
    def _f(self, **o):
        f = {'window_seconds': 5, 'packet_rate': 20, 'syn_count': 0, 'udp_count': 40,
             'unique_sources': 20, 'source_ip_entropy': 4.0, 'completion_ratio': 1.0,
             'dst_concentration': 'ff02::fb', 'inbound_bytes': 0, 'outbound_bytes': 0}
        f.update(o)
        return f

    def test_mdns_responders_are_not_reflection_amplifiers(self):
        """mDNS answers the whole subnet, so it trips udp>=20 + sources>=8. 41 real FPs."""
        for kw in ({'dst_ip': 'ff02::fb', 'dst_port': 5353},
                   {'dst_ip': '224.0.0.251', 'dst_port': 5353}):
            self.assertIsNone(rules.ddos(ev(**kw), self._f()), kw)

    def test_broadcast_not_a_flood(self):
        self.assertIsNone(rules.ddos(ev(dst_ip='255.255.255.255', dst_port=5678), self._f()))
        self.assertIsNone(rules.ddos(ev(dst_ip='172.168.3.255', dst_port=57621), self._f()))

    def test_real_reflection_still_detected(self):
        a = rules.ddos(ev(dst_ip='198.51.100.98', dst_port=53), self._f())
        self.assertIsNotNone(a)
        self.assertEqual(a['subtype'], 'udp_reflection_amplification')
        self.assertEqual(a['mitre_attack'], ['T1498'])

    def test_syn_flood_still_detected(self):
        # low source entropy (< 3.5) is what separates a plain syn_flood from a spoofed-source
        # flood; _f() defaults to 4.0, so it must be lowered explicitly here.
        a = rules.ddos(ev(dst_ip='198.51.100.99', dst_port=443),
                       self._f(syn_count=30, udp_count=0, unique_sources=1,
                               completion_ratio=0.1, source_ip_entropy=1.0))
        self.assertEqual(a['subtype'], 'syn_flood')

    def test_spoofed_source_flood_subtype_still_reachable(self):
        """source_ip_entropy >= 3.5 selects the spoofed-source subtype. My first fixture used
        entropy 4.0, which is why it came back spoofed rather than syn_flood."""
        a = rules.ddos(ev(dst_ip='198.51.100.99', dst_port=443),
                       self._f(syn_count=30, udp_count=0, unique_sources=1,
                               completion_ratio=0.1, source_ip_entropy=4.0))
        self.assertEqual(a['subtype'], 'spoof_like_source_flood')

    def test_high_completion_syn_burst_is_not_a_flood(self):
        """A load test that opens 30+ connections and COMPLETES them is not a SYN flood."""
        self.assertIsNone(rules.ddos(ev(dst_ip='198.51.100.99', dst_port=443),
                                     self._f(syn_count=30, udp_count=0, unique_sources=1,
                                             completion_ratio=1.0)))


class ReconFanout(unittest.TestCase):
    """The browser-vs-sweep discrimination. A blanket failure_ratio raise was tried and
    REJECTED because recorded nmap sweeps sit at 0.50-0.66 in a busy window, so raising the
    gate to 0.7 silently disabled real scan detection. Port diversity + provider spread do
    the work instead."""

    CDN = ['172.64.155.209', '104.21.21.127', '23.63.84.105', '13.211.115.13', '151.101.1.140',
           '104.18.43.204', '172.67.1.1', '104.16.1.1', '141.101.1.1', '23.55.1.1', '18.66.1.1',
           '104.20.1.1', '23.62.1.1', '18.164.1.1']

    def _run(self, hosts, ports, fail, dests):
        e = {'kind': 'early_event', 'ts': 1000, 'src_ip': '10.9.9.9', 'src_port': 1,
             'dst_ip': '198.51.100.1', 'dst_port': 22, 'proto': 'tcp', 'conn_state': 'S0'}
        f = {'window_seconds': 30, 'unique_dst_hosts': hosts, 'unique_dst_ports': ports,
             'scan_rate': 2.0, 'failure_ratio': fail, 'dst_hosts': dests}
        return rules.recon(e, f)

    def test_live_false_positive_is_downgraded(self):
        """34 CDN edge IPs across 9 ports at failure 0.51 was a `horizontal_scan/high` from a
        single page load. It must now rank below the equivalent non-provider fan-out."""
        a = self._run(34, 9, 0.51, self.CDN * 3)
        self.assertIsNotNone(a)
        self.assertEqual(a['subtype'], 'horizontal_scan')
        self.assertGreater(a['supporting_evidence']['provider_spread'], 0.5)
        self.assertIn('downgrade_reason', a['supporting_evidence'])
        # the provider fan-out must score strictly below a same-shape non-provider fan-out
        same = self._run(34, 9, 0.51, [f'10.5.0.{i}' for i in range(1, 35)])
        self.assertLess(a['confidence'], same['confidence'])

    def test_port_sweep_stays_high(self):
        a = self._run(29, 29, 0.58, [f'198.51.100.{i}' for i in range(1, 30)])
        self.assertEqual(a['subtype'], 'vertical_scan')
        self.assertIn(a['severity'], ('high', 'critical'))

    def test_nmap_style_sweep_at_the_half_failure_boundary_still_fires(self):
        """Regression guard: this is the case a failure_ratio>=0.7 gate would have broken."""
        a = self._run(24, 24, 0.50, [f'198.51.100.{i}' for i in range(1, 25)])
        self.assertEqual(a['subtype'], 'vertical_scan')
        self.assertIn(a['severity'], ('high', 'critical'))

    def test_confidence_scales_with_evidence(self):
        """Continuous scoring: more ports and more failures must never score LOWER."""
        scores = [self._run(p, p, .9, [f'198.51.100.{i}' for i in range(1, p + 1)])['confidence']
                  for p in (13, 20, 30, 45)]
        self.assertEqual(scores, sorted(scores))
        self.assertGreater(scores[-1], scores[0], 'a 45-port sweep must outrank a 13-port one')

    def test_alert_anchors_on_the_real_scan_target(self):
        """The trigger flow's dst_ip is whatever crossed the threshold — often a CDN edge IP.

        F12: the old behaviour REPLACED flow_id.dst_ip with the anchor host while keeping the
        trigger's ports, so the alert carried a five-tuple that never existed on the wire; an
        analyst matching it against a capture would find nothing. The anchor is still surfaced
        (that was the original goal -- do not send an analyst to a CDN edge IP), but as evidence
        alongside the REAL observed connection.
        """
        trigger = '151.101.65.91'          # Fastly edge, the flow that tripped the gate
        tgts = [{'dst_ip': f'198.51.100.{i}', 'failed': 3, 'attempts': 3, 'failure_ratio': 1.0}
                for i in (77, 78, 79)]
        tgts.append({'dst_ip': trigger, 'failed': 0, 'attempts': 2, 'failure_ratio': 0.0})
        e = {'kind': 'early_event', 'ts': 1000, 'src_ip': '10.9.9.9', 'src_port': 1,
             'dst_ip': trigger, 'dst_port': 443, 'proto': 'tcp', 'conn_state': 'S0'}
        f = {'window_seconds': 30, 'unique_dst_hosts': 4, 'unique_dst_ports': 30, 'scan_rate': 2.0,
             'failure_ratio': 0.6, 'dst_hosts': [t['dst_ip'] for t in tgts], 'scan_targets': tgts,
             'anchor_dst': '198.51.100.77'}
        a = rules.recon(e, f)
        # F12: the tuple must be one that actually occurred on the wire.
        self.assertEqual(a['flow_id']['dst_ip'], trigger)
        self.assertEqual(a['flow_id']['dst_port'], 443)
        self.assertEqual(a['flow_id']['src_port'], 1)
        # and the anchor is still available so nobody chases the CDN edge host
        self.assertEqual(a['supporting_evidence']['anchor_dst'], '198.51.100.77')
        self.assertTrue(a['supporting_evidence']['anchor_is_evidence_only'])
        self.assertEqual(a['supporting_evidence']['anchored_on'], 'highest per-host failure ratio')
        # the source is still the scanner, and dedup still keys on it
        self.assertEqual(a['flow_id']['src_ip'], '10.9.9.9')
        self.assertEqual(a['supporting_evidence']['aggregation_key'], 'src=10.9.9.9')

    def test_anchor_falls_back_when_no_target_data(self):
        """Older evidence without scan_targets must still produce a valid alert."""
        e = {'kind': 'early_event', 'ts': 1000, 'src_ip': '10.9.9.9', 'src_port': 1,
             'dst_ip': '198.51.100.5', 'dst_port': 22, 'proto': 'tcp', 'conn_state': 'S0'}
        f = {'window_seconds': 30, 'unique_dst_hosts': 20, 'unique_dst_ports': 25, 'scan_rate': 2.0,
             'failure_ratio': 0.9, 'dst_hosts': None, 'scan_targets': None, 'anchor_dst': None}
        a = rules.recon(e, f)
        self.assertIsNotNone(a)
        self.assertEqual(a['flow_id']['dst_ip'], '198.51.100.5')

    def test_real_host_enumeration_stays_high(self):
        a = self._run(30, 3, 0.90, [f'10.5.0.{i}' for i in range(1, 31)])
        self.assertEqual(a['subtype'], 'horizontal_scan')
        self.assertIn(a['severity'], ('high', 'critical'))

    def test_cross_provider_sweep_with_many_ports_still_fires(self):
        """Downgrade only applies to the few-port host-sweep branch; a port sweep is a port
        sweep regardless of where the targets live."""
        a = self._run(30, 26, 0.66, self.CDN[:14] + [f'198.51.100.{i}' for i in range(1, 17)])
        self.assertEqual(a['subtype'], 'vertical_scan')
        self.assertIn(a['severity'], ('high', 'critical'))

    def test_low_failure_fanout_is_suppressed(self):
        self.assertIsNone(self._run(34, 9, 0.10, self.CDN * 3))

    def test_narrow_fanout_never_alerts(self):
        self.assertIsNone(self._run(5, 4, 0.9, self.CDN[:5]))

    def test_absent_destination_list_cannot_downgrade(self):
        """A missing dst_hosts must not make the detector quieter: spread defaults to 0."""
        e = {'kind': 'early_event', 'ts': 1000, 'src_ip': '10.9.9.9', 'src_port': 1,
             'dst_ip': '198.51.100.1', 'dst_port': 22, 'proto': 'tcp', 'conn_state': 'S0'}
        f = {'window_seconds': 30, 'unique_dst_hosts': 30, 'unique_dst_ports': 3,
             'scan_rate': 2.0, 'failure_ratio': 0.9}
        a = rules.recon(e, f)
        self.assertIn(a['severity'], ('high', 'critical'))
        self.assertEqual(a['supporting_evidence']['provider_spread'], 0.0)

    def test_every_recon_alert_carries_an_aggregation_key(self):
        """The Pipeline dedups on (class, subtype, aggregation_key) and falls back to src|dst.
        A recon fan-out spans many dst_ips, so without an explicit key every flow is unique and
        dedup is defeated -- observed live as 12 alerts for a single nmap scan."""
        for ports, hosts, fail in ((29, 29, .58), (30, 3, .9)):
            a = self._run(hosts, ports, fail, [f'198.51.100.{i}' for i in range(1, hosts + 1)])
            self.assertEqual(a['supporting_evidence']['aggregation_key'], 'src=10.9.9.9')
        down = self._run(34, 9, 0.51, self.CDN * 3)
        self.assertEqual(down['supporting_evidence']['aggregation_key'], 'src=10.9.9.9')

    def test_one_scan_yields_one_alert_not_one_per_flow(self):
        from engine.stream_consumer import Pipeline
        p = Pipeline()
        out = []
        for i in range(50):
            out += p.process({'kind': 'early_event', 'ts': 1000 + i * 0.5, 'src_ip': '10.9.9.9',
                              'src_port': 1000 + i, 'dst_ip': f'198.51.100.{i % 30}',
                              'dst_port': 1 + i, 'proto': 'tcp', 'conn_state': 'S0'})
        self.assertEqual(len([a for a in out if a['threat_class'] == 'recon_scan']), 1)


if __name__ == '__main__':
    unittest.main()
