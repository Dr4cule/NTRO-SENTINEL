#!/usr/bin/env python3
"""Controlled-scenario evaluation package.

This reports scenario-level detection coverage and benign alert count. It does not
turn alert counts into fabricated flow-level precision/recall/F1 metrics.
"""
from __future__ import annotations
import json
from collections import Counter
from pathlib import Path
from engine.stream_consumer import Pipeline

EXPECTED={
 'benign':None,'ddos':'ddos','ddos_udp_reflection':'ddos','ddos_spoof':'ddos',
 'c2':'c2_beaconing','dns':'dga_dns_tunnel','encrypted':'encrypted_malware',
 'recon':'recon_scan','exfil':'exfiltration'}
SUBTYPES={'ddos':'syn_flood','ddos_udp_reflection':'udp_reflection_amplification','ddos_spoof':'spoof_like_source_flood'}

def run(name):
 engine=Pipeline(); alerts=[]; path=Path('traffic-gen/scenarios')/(name+'.jsonl')
 lines=[l for l in path.read_text().splitlines() if l.strip()]
 for line in lines: alerts.extend(engine.process(json.loads(line)))
 expected=EXPECTED[name]; matched=[a for a in alerts if a['threat_class']==expected]
 expected_subtype=SUBTYPES.get(name); predicted=Counter(a['threat_class'] for a in alerts)
 return {'scenario':name,'ground_truth':expected or 'benign','events':len(lines),'alert_count':len(alerts),'matched_alert_count':len(matched),'detected':not alerts if expected is None else bool(matched),'expected_subtype':expected_subtype,'subtype_matched':any(a['subtype']==expected_subtype for a in matched) if expected_subtype else None,'unexpected_classes':sorted({a['threat_class'] for a in alerts if a['threat_class']!=expected}),'predicted':dict(predicted)}

def confusion_and_precision(rows):
 """Honest alert-level aggregation over the labeled controlled corpus. Scenarios are
 homogeneous, so every alert is a true positive iff its class == the scenario target.
 Not a flow-level recall/F1 claim (one aggregated alert can cover many flows)."""
 classes=[c for c in dict.fromkeys(EXPECTED.values()) if c]
 confusion={truth:{pred:0 for pred in classes} for truth in classes}; benign_pred=Counter()
 tp=Counter(); predicted_total=Counter()
 for r in rows:
  for pred,n in r['predicted'].items():
   predicted_total[pred]+=n
   if r['ground_truth']=='benign': benign_pred[pred]+=n
   else:
    confusion[r['ground_truth']][pred]=confusion[r['ground_truth']].get(pred,0)+n
    if pred==r['ground_truth']: tp[pred]+=n
 precision={c:round(tp[c]/predicted_total[c],3) if predicted_total[c] else None for c in classes}
 benign=next(r for r in rows if r['ground_truth']=='benign')
 return {'classes':classes,'confusion_truth_x_pred':confusion,'benign_predicted':dict(benign_pred),
   'benign_events':benign['events'],'benign_alerts':benign['alert_count'],
   'benign_false_positive_rate':round(benign['alert_count']/max(1,benign['events']),4),
   'alert_level_precision':precision,
   'note':'Alert-level precision on the controlled corpus (homogeneous scenarios). Flow-level recall/F1 is intentionally not claimed.'}

def main():
 rows=[run(x) for x in EXPECTED]; attack=[x for x in rows if x['ground_truth']!='benign']; benign=next(x for x in rows if x['ground_truth']=='benign')
 cm=confusion_and_precision(rows)
 out={'evaluation_type':'controlled scenario-level detection coverage','definition':'A scenario is detected when at least one alert has its known target threat class. This is not packet-level precision, recall, or F1.','scenario_results':rows,'confusion':cm,'summary':{'attack_scenarios':len(attack),'detected_attack_scenarios':sum(x['detected'] for x in attack),'benign_alert_count':benign['alert_count'],'benign_false_positive_rate':cm['benign_false_positive_rate'],'ddos_subtype_scenarios_matched':sum(bool(x['subtype_matched']) for x in rows if x['expected_subtype'])}}
 Path('eval/results.json').write_text(json.dumps(out,indent=2))
 lines=['# Controlled Scenario Evaluation','',out['definition'],'', '| Scenario | Target | Detected | Alerts | Subtype |','|---|---|---:|---:|---|']
 lines += [f"| {x['scenario']} | {x['ground_truth']} | {'yes' if x['detected'] else 'no'} | {x['alert_count']} | {'yes' if x['subtype_matched'] else ('—' if x['subtype_matched'] is None else 'no')} |" for x in rows]
 lines += ['',f"Attack scenarios detected: {out['summary']['detected_attack_scenarios']}/{out['summary']['attack_scenarios']}. Benign alerts: {out['summary']['benign_alert_count']} (FPR {cm['benign_false_positive_rate']}).",'']
 lines += ['## Confusion (scenario truth × predicted class)','',cm['note'],'','| Truth ＼ Pred | '+' | '.join(cm['classes'])+' |','|---|'+'---:|'*len(cm['classes'])]
 lines += ['| '+t+' | '+' | '.join(str(cm['confusion_truth_x_pred'][t][p]) for p in cm['classes'])+' |' for t in cm['classes']]
 lines += ['','## Alert-level precision (controlled corpus)','','| Class | Precision |','|---|---:|']
 lines += [f"| {c} | {cm['alert_level_precision'][c] if cm['alert_level_precision'][c] is not None else '—'} |" for c in cm['classes']]
 lines += ['', 'This result applies only to committed generated metadata scenarios. Use documented PCAP/lab labels and group-separated data for any public performance claims.']
 Path('eval/results.md').write_text('\n'.join(lines)+'\n'); print(json.dumps(out['summary'],indent=2))
if __name__=='__main__': main()
