"""Small dependency-free guard for the PS-required alert contract."""
from engine.contracts import THREATS
REQUIRED={'alert_id':str,'timestamp':str,'flow_id':dict,'threat_class':str,'subtype':str,'confidence':(int,float),'severity':str,'supporting_evidence':dict,'mitre_attack':list,'model_version':str}
_SEVERITIES={'low','medium','high','critical'}
def validate_alert(record):
 missing=[name for name in REQUIRED if name not in record]
 wrong=[name for name,kind in REQUIRED.items() if name in record and not isinstance(record[name],kind)]
 # bool is a subclass of int, so isinstance(True,(int,float)) passes the type gate above. A
 # boolean confidence is a contract violation (it silently lands in the 'low' severity band),
 # so reject bools explicitly before the range check.
 if 'confidence' in record and isinstance(record['confidence'],bool):
  raise ValueError('Invalid alert contract: confidence must be a number, not a bool')
 flow={'src_ip','src_port','dst_ip','dst_port','proto'}
 if missing or wrong or set(record['flow_id'])!=flow: raise ValueError(f'Invalid alert contract: missing={missing}, wrong={wrong}')
 confidence=record['confidence']
 if record['threat_class'] not in THREATS or record['severity'] not in _SEVERITIES or not isinstance(confidence,(int,float)) or isinstance(confidence,bool) or not 0<=confidence<=1:
  raise ValueError('Invalid threat, severity, or score')
 return record
