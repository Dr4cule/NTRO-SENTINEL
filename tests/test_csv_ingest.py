import unittest
from engine.stream_consumer import Pipeline
from ingest.csv_to_events import (
    analyze_aggregate, has_endpoints, read_conn_events)


class Tests(unittest.TestCase):
    def test_endpoint_csv_yields_conn_events(self):
        import tempfile, os
        body = ("Source IP,Source Port,Destination IP,Destination Port,Protocol,Timestamp,"
                "Total Length of Fwd Packets,Total Length of Bwd Packets,Flow Duration,"
                "SYN Flag Count,ACK Flag Count,FIN Flag Count,RST Flag Count\n"
                + "".join(
                    "10.0.0.9,40000,198.51.100.7,80,6,1720000000,60,40,1000000,1,1,1,0\n"
                    for _ in range(6)))
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as tf:
            tf.write(body)
            path = tf.name
        try:
            self.assertTrue(has_endpoints(['Source IP', 'Destination IP']))
            evs = list(read_conn_events(path))
            self.assertEqual(len(evs), 6)
            self.assertEqual(evs[0]['kind'], 'conn')
            self.assertEqual(evs[0]['src_ip'], '10.0.0.9')
            self.assertEqual(evs[0]['proto'], 'tcp')
            self.assertEqual(evs[0]['conn_state'], 'SF')
            pipe, alerts = Pipeline(), []
            for e in evs:
                alerts.extend(pipe.process(e))
            self.assertIsInstance(alerts, list)  # runs through detectors without crashing
        finally:
            os.unlink(path)

    def test_endpointless_csv_raises_then_analyzes(self):
        import tempfile, os
        body = ("Destination Port,Flow Duration,SYN Flag Count,Label\n"
                "80,1000000,0,BENIGN\n"
                "80,2000000,0,DDoS\n"
                "443,3000000,1,DDoS\n")
        with tempfile.NamedTemporaryFile('w', suffix='.csv', delete=False) as tf:
            tf.write(body)
            path = tf.name
        try:
            self.assertFalse(has_endpoints(['Destination Port', 'Label']))
            with self.assertRaises(ValueError):
                list(read_conn_events(path))
            info = analyze_aggregate(path)
            self.assertEqual(info['rows'], 3)
            self.assertEqual(info['label_census'], {'DDoS': 2, 'BENIGN': 1})
            self.assertEqual(info['syn_heavy_flows'], 1)
            self.assertTrue(any(p['port'] == '80' for p in info['top_destination_ports']))
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()
