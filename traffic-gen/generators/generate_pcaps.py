#!/usr/bin/env python3
"""Build safe lab PCAPs containing only synthetic private/test-net metadata.

These are replay inputs for the isolated Docker lab. They do not target any real
host and must only be replayed through the lab namespace supplied by this project.
"""
from pathlib import Path
from scapy.all import DNS, DNSQR, Ether, IP, Raw, TCP, UDP, wrpcap
import hashlib

OUT=Path(__file__).parents[1]/'pcaps'; OUT.mkdir(exist_ok=True)
MAC_A='02:00:00:00:00:01'; MAC_B='02:00:00:00:00:02'
def eth(pkt): return Ether(src=MAC_A,dst=MAC_B)/pkt
def stamp(packets):
 for n,p in enumerate(packets): p.time=1_700_000_000+n*.002
 return packets
def save(name, packets):
 path=OUT/(name+'.pcap'); wrpcap(str(path),stamp(packets)); digest=hashlib.sha256(path.read_bytes()).hexdigest(); (OUT/(name+'.pcap.sha256')).write_text(f'{digest}  {path.name}\n'); print(path)

def main():
 syn=[eth(IP(src=f'10.20.0.{i%5+1}',dst='198.51.100.99')/TCP(sport=30000+i,dport=443,flags='S',seq=i)) for i in range(25)]
 udp=[eth(IP(src=f'192.0.2.{i+1}',dst='198.51.100.98')/UDP(sport=40000+i,dport=53)/Raw(b'x'*120)) for i in range(25)]
 dns=[eth(IP(src='10.40.0.5',dst='8.8.8.8')/UDP(sport=53000+i,dport=53)/DNS(rd=1,qd=DNSQR(qname=f'a9f3k2m8q1z7x5v2n{i}.example.net',qtype='TXT'))) for i in range(5)]
 recon=[eth(IP(src='10.60.0.5',dst='203.0.113.9')/TCP(sport=51000+i,dport=1000+i,flags='S',seq=i)) for i in range(15)]
 save('safe_syn_flood',syn); save('safe_udp_reflection',udp); save('safe_dns_tunnel',dns); save('safe_recon',recon); save('safe_mixed',syn+udp+dns+recon)
if __name__=='__main__': main()
