import unittest,json
from pathlib import Path
from features.base import WindowState
from features.dga_dns import DNSFeatures, entropy
from features.tls_metadata import TLSFeatures
from engine.stream_consumer import Pipeline
from engine.contracts import alert
class Tests(unittest.TestCase):
 def test_eviction(self):
  s=WindowState(1,max_keys=2);s.add('a',0,1);s.add('a',2,2);self.assertEqual(list(s.data['a']),[(2,2)])
 def test_time_eviction_drops_stale_key(self):
  s=WindowState(10);s.add('k',0,'old');self.assertIn('k',s.data);s.add('k',11,'new')  # 11s > 10s window
  self.assertEqual([v for _,v in s.data['k']],['new'])  # stale entry evicted, only fresh remains
 def test_dns_entropy_benign_vs_dga(self):
  self.assertLess(entropy('www'),entropy('a9f3k2m8q1z7x5v2n0'))  # random label is higher entropy
  f=DNSFeatures().update({'src_ip':'h','query':'www.google.com'},1.0)
  self.assertLess(f['label_length'],18);self.assertLess(f['label_entropy'],3.3)  # benign won't trip detector
 def test_tls_benign_ratio_low(self):
  f=TLSFeatures().update({'src_ip':'h','orig_bytes':1400,'resp_bytes':9000,'tls':True},1.0)
  self.assertLessEqual(f['outbound_inbound_ratio'],8)  # balanced session won't trip encrypted detector
 def test_recon_alert(self):
  p=Pipeline(); out=[]
  for i in range(15): out += p.process({'kind':'early_event','ts':1000+i,'src_ip':'a','src_port':1,'dst_ip':'b','dst_port':i,'proto':'tcp','conn_state':'S0'})
  self.assertTrue(any(x['threat_class']=='recon_scan' for x in out))
 def test_six_required_detection_paths(self):
  expected={'ddos':'ddos','c2':'c2_beaconing','dns':'dga_dns_tunnel','encrypted':'encrypted_malware','recon':'recon_scan','exfil':'exfiltration'}
  for name,threat in expected.items():
   pipe=Pipeline();alerts=[]
   for line in Path('traffic-gen/scenarios/'+name+'.jsonl').read_text().splitlines():alerts.extend(pipe.process(json.loads(line)))
   self.assertTrue(any(x['threat_class']==threat for x in alerts),name)
 def test_ddos_subtypes_and_alert_contract(self):
  expected={'ddos':'syn_flood','ddos_udp_reflection':'udp_reflection_amplification','ddos_spoof':'spoof_like_source_flood'}
  for name,subtype in expected.items():
   pipe=Pipeline();alerts=[]
   for line in Path('traffic-gen/scenarios/'+name+'.jsonl').read_text().splitlines():alerts.extend(pipe.process(json.loads(line)))
   found=next(x for x in alerts if x['threat_class']=='ddos');self.assertEqual(found['subtype'],subtype);self.assertEqual(set(found),{'alert_id','timestamp','flow_id','threat_class','subtype','confidence','severity','supporting_evidence','mitre_attack','model_version'})
 def test_benign_scenario_raises_no_alerts(self):
  pipe=Pipeline();alerts=[]
  for line in Path('traffic-gen/scenarios/benign.jsonl').read_text().splitlines():
   if line.strip():alerts.extend(pipe.process(json.loads(line)))
  self.assertEqual(alerts,[],'benign traffic (incl. DNS/TLS negatives) must stay clean → FPR 0')
 def test_dedup_suppresses_repeat_within_window(self):
  pipe=Pipeline()
  ev=lambda t,port:{'kind':'early_event','ts':t,'src_ip':'s','src_port':1,'dst_ip':'d','dst_port':port,'proto':'tcp','conn_state':'S0'}
  first=[]
  for i in range(15): first+=pipe.process(ev(1000+i,i))  # 15 unique ports → recon fires
  again=pipe.process(ev(1020,99))  # same src key, <30s after emission
  self.assertTrue(any(x['threat_class']=='recon_scan' for x in first))
  self.assertFalse(any(x['threat_class']=='recon_scan' for x in again),'repeat within 30s must be deduped')
 def test_eval_confusion_clean_and_fpr_zero(self):
  from eval.run_suite import run, confusion_and_precision, EXPECTED
  cm=confusion_and_precision([run(x) for x in EXPECTED])
  self.assertEqual(cm['benign_false_positive_rate'],0.0)
  for c in cm['classes']: self.assertEqual(cm['alert_level_precision'][c],1.0,c)  # clean separation on corpus
 def test_loadtest_step_reports_envelope(self):
  from eval.loadtest import run_step, load_pool
  s=run_step(load_pool(['traffic-gen/scenarios/ddos.jsonl']),target_eps=500,duration=0.3)
  self.assertGreater(s['achieved_eps'],0);self.assertGreater(s['peak_rss_mb'],0)
  self.assertIsNotNone(s['latency_ms']['p95']);self.assertIn('stable',s)
if __name__=='__main__':
 unittest.main()
