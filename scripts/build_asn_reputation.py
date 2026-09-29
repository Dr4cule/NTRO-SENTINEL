#!/usr/bin/env python3
"""Regenerate detectors/asn_reputation.json from the iptoasn.com BGP snapshot.

Run this ONLY when the curated ASN list changes. Inference never downloads anything: the
enclave must run air-gapped, so the committed JSON is the sole source of truth at runtime.

  python3 scripts/build_asn_reputation.py                 # reads /tmp/asn.tsv.gz
  curl -sSLo /tmp/asn.tsv.gz https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz
  python3 scripts/build_asn_reputation.py

The ASN list is HAND-CURATED in this file, not regex-mined from AS descriptions. An earlier
name-regex pass over the same dump pulled in IBM research networks, a shipping registry and an
unrelated telecom, which together would have "reputation-downgraded" nearly the whole internet.
Keep it small and verifiable.
"""
from __future__ import annotations
import gzip
import json
import sys
from pathlib import Path

DUMP = Path(sys.argv[1] if len(sys.argv) > 1 else '/tmp/asn.tsv.gz')
OUT = Path(__file__).resolve().parent.parent / 'detectors' / 'asn_reputation.json'

CURATED = {
    'AS13335': 'Cloudflare', 'AS54113': 'Fastly', 'AS4641': 'Fastly', 'AS55030': 'Fastly',
    'AS20940': 'Akamai', 'AS16625': 'Akamai', 'AS3257': 'Akamai', 'AS24940': 'Akamai',
    'AS15133': 'Edgio/Verizon CDN', 'AS20473': 'Varnish/Fastly',
    'AS15169': 'Google', 'AS3078': 'Google', 'AS396982': 'Google Cloud', 'AS394711': 'Google Cloud',
    'AS16509': 'Amazon AWS', 'AS14618': 'Amazon AWS', 'AS16510': 'Amazon AWS', 'AS8987': 'Amazon',
    'AS17493': 'Amazon', 'AS19047': 'Amazon', 'AS38895': 'Amazon',
    'AS8075': 'Microsoft Azure', 'AS8068': 'Microsoft', 'AS3598': 'Microsoft',
    'AS36459': 'GitHub', 'AS14061': 'DigitalOcean', 'AS63949': 'Linode/Akamai',
    'AS32934': 'Meta/Facebook', 'AS157359': 'Meta', 'AS20001': 'Twitter/X', 'AS26302': 'Twitter/X',
    'AS399358': 'Anthropic', 'AS135630': 'Anthropic', 'AS31898': 'Oracle',
    'AS12876': 'Scaleway', 'AS16276': 'OVH', 'AS16265': 'Leaseweb', 'AS60781': 'Leaseweb',
    'AS51167': 'Contabo', 'AS19807': 'Hetzner', 'AS207812': 'Hetzner',
    'AS202425': 'IP Volume hosting', 'AS11427': 'Slack', 'AS19165': 'Slack',
}

META = {
    'source': 'https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz — Public Domain Dedication (iptoasn.com)',
    'fetched_utc': '2026-09-29',
    'purpose': 'ASNs whose client-facing traffic is large and legitimately periodic (CDN, hyperscale '
               'cloud, SaaS/collab/push). Used ONLY to DOWNGRADE a c2_beaconing alert to '
               'periodic_session with a lower score. Never used to suppress, and never to clear an alert.',
    'rationale': 'Live capture (wlp0s20f3, 2026-09-29) showed ~90% of low-jitter periodicity alerts were '
                 'GitHub/Google/Cloudflare/Amazon/Facebook keepalives, IMAP IDLE and push channels. A '
                 'timing-only rule cannot separate those from malware phone-home, so the destination network '
                 'is used as a RANKING signal rather than a hard block. Hand-verified ASNs only — an earlier '
                 'name-regex pass over the BGP dump pulled in IBM research nets, a shipping registry and an '
                 'unrelated telecom, which would have downgraded nearly the whole internet.',
}


def main():
    present = set()
    with gzip.open(DUMP, 'rt') as f:
        for line in f:
            p = line.rstrip('\n').split('\t')
            if len(p) >= 3 and p[2] != '0':
                present.add('AS' + p[2])
    final = sorted({a for a in CURATED if a in present}, key=lambda x: int(x[2:]))
    missing = sorted(set(CURATED) - set(final))
    OUT.write_text(json.dumps({**META, 'asn_to_name': {a: CURATED[a] for a in final}, 'asns': final}, indent=1))
    print(f'wrote {OUT} with {len(final)} ASNs')
    if missing:
        print('not present in this dump (left out):', ', '.join(missing))


if __name__ == '__main__':
    main()
