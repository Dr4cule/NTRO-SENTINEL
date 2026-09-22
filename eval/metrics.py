"""Machine-readable scenario evaluation; never pre-populates reported results."""
from __future__ import annotations
import json
from pathlib import Path
EXPECTED={'ddos':'ddos','ddos_udp_reflection':'ddos','ddos_spoof':'ddos','c2':'c2_beaconing','dns':'dga_dns_tunnel','encrypted':'encrypted_malware','recon':'recon_scan','exfil':'exfiltration','benign':None}
def evaluate(scenario, alerts_path='artifacts/detector_alerts.jsonl'):
 expected=EXPECTED[scenario]; alerts=[json.loads(x) for x in Path(alerts_path).read_text().splitlines()] if Path(alerts_path).exists() else []
 positives=sum(a['threat_class']==expected for a in alerts) if expected else 0; fp=len(alerts)-positives
 result={'scenario':scenario,'ground_truth':expected or 'benign','alerts':len(alerts),'true_positive_alerts':positives,'false_positive_alerts':fp,'detected':bool(positives) if expected else not bool(fp),'note':'Alert-count evaluation for controlled scenario labels; not a packet-level F1 claim.'}
 Path('artifacts/evaluation.json').write_text(json.dumps(result,indent=2)); return result
if __name__=='__main__':
 import sys; print(json.dumps(evaluate(sys.argv[1]),indent=2))
