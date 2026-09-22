"""Small dependency-free guard for the PS-required alert contract."""
from engine.contracts import THREATS
REQUIRED={'alert_id':str,'timestamp':str,'flow_id':dict,'threat_class':str,'subtype':str,'confidence':(int,float),'severity':str,'supporting_evidence':dict,'mitre_attack':list,'model_version':str}
def validate_alert(record):
 missing=[name for name in REQUIRED if name not in record]
 wrong=[name for name,kind in REQUIRED.items() if name in record and not isinstance(record[name],kind)]
 flow={'src_ip','src_port','dst_ip','dst_port','proto'}
 if missing or wrong or set(record['flow_id'])!=flow: raise ValueError(f'Invalid alert contract: missing={missing}, wrong={wrong}')
 if record['threat_class'] not in THREATS or record['severity'] not in {'low','medium','high','critical'} or not 0<=record['confidence']<=1: raise ValueError('Invalid threat, severity, or score')
 return record
