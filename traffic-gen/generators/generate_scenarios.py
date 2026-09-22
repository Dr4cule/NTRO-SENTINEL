#!/usr/bin/env python3
"""Creates safe metadata-only lab telemetry. It generates no attack packets."""
import json, pathlib, time
root=pathlib.Path(__file__).parents[1]/'scenarios'; root.mkdir(exist_ok=True)
base={'src_ip':'10.10.0.5','src_port':50000,'dst_ip':'198.51.100.10','dst_port':443,'proto':'tcp','orig_bytes':120,'resp_bytes':200,'conn_state':'SF'}
def write(name, events):
 with (root/(name+'.jsonl')).open('w') as f:
  for e in events:f.write(json.dumps(e)+'\n')
def event(**kw):
 x=base.copy();x.update(kw); return x
t=1000.0
# benign: normal conns + benign DNS (short, low-entropy names) + benign TLS (balanced bytes,
# no suspicious fingerprint) — real negatives so the DGA/DNS and encrypted detectors are exercised
# and their false-positive rate is measurable, not just assumed.
benign=[event(ts=t+i*3,kind='conn',src_ip='10.10.0.'+str(i%4+2),dst_ip='203.0.113.1') for i in range(10)]
benign+=[event(ts=t+30+i,kind='dns',src_ip='10.10.0.'+str(i%4+2),dst_ip='198.51.100.10',dst_port=53,proto='udp',query=q,orig_bytes=60,resp_bytes=120)
 for i,q in enumerate(['www.google.com','mail.example.org','cdn.microsoft.com'])]
benign+=[event(ts=t+40+i,kind='conn',src_ip='10.10.0.'+str(i%4+2),dst_ip='203.0.113.'+str(5+i),tls=True,tls_version='TLSv1.3',sni=s,ja3=j,orig_bytes=ob,resp_bytes=rb,duration=2.0)
 for i,(s,j,ob,rb) in enumerate([('www.wikipedia.org','e7d705a3286e19ea42f587b344ee6865',1400,9000),('updates.example.com','a0e9f5d64349fb13191bc781f81f42e1',2200,18000)])]
write('benign',benign)
write('ddos',[event(ts=t+i*.1,kind='early_event',src_ip='10.20.0.'+str(i%5+1),dst_ip='198.51.100.99',tcp_flags='S',conn_state='S0') for i in range(25)])
write('ddos_udp_reflection',[event(ts=t+i*.1,kind='early_event',src_ip='192.0.2.'+str(i),dst_ip='198.51.100.98',dst_port=53,proto='udp',orig_bytes=60,resp_bytes=4000) for i in range(25)])
write('ddos_spoof',[event(ts=t+i*.1,kind='early_event',src_ip='172.16.'+str(i//255)+'.'+str(i%255),dst_ip='198.51.100.97',tcp_flags='S',conn_state='S0') for i in range(25)])
write('c2',[event(ts=t+i*30,kind='conn',src_ip='10.30.0.5',dst_ip='198.51.100.88',tls=True,orig_bytes=100,resp_bytes=150) for i in range(5)])
write('dns',[event(ts=t+i,kind='dns',src_ip='10.40.0.5',query='a9f3k2m8q1z7x5v2n'+str(i)+'.example.net',dst_port=53,proto='udp') for i in range(5)])
write('encrypted',[event(ts=t,kind='conn',src_ip='10.50.0.5',tls=True,ja3='unknown-demo',sni='edge.example',orig_bytes=9000,resp_bytes=50,suspicious_fingerprint=True)])
write('recon',[event(ts=t+i,kind='early_event',src_ip='10.60.0.5',dst_ip='203.0.113.9',dst_port=1000+i,tcp_flags='S',conn_state='S0') for i in range(15)])
write('exfil',[event(ts=t+i,kind='conn',src_ip='10.70.0.5',dst_ip='198.51.100.200',orig_bytes=110000,resp_bytes=1000) for i in range(5)])
print('created',root)
