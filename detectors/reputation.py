"""Offline IP -> ASN resolution + provider reputation.

WHY THIS EXISTS
---------------
A low-jitter periodicity rule cannot, on its own, tell malware phone-home apart from a Chrome
keepalive, an IMAP IDLE stream, or a push channel: all four produce "N sessions, tiny CV, one
port, sustained for minutes". Live capture on a real laptop (2026-09-29) made this concrete —
~90% of the resulting alerts were GitHub / Google / Cloudflare / Amazon / Facebook traffic.

The fix is NOT a looser threshold. It is a second, independent signal: who the destination
network is. `reputation()` returns a coarse class, and the caller uses it to RANK an alert, never
to hide one.

DESIGN CONSTRAINTS
------------------
* **Air-gapped.** No network access at runtime. Ranges are embedded in this file and refreshed by
  `scripts/build_asn_reputation.py`, not fetched.
* **Binary search** over ~150 sorted u32 ranges: O(log n), no dependency, no per-IP dict.
* **Fail open.** An unknown or unresolvable IP returns None -> the caller treats it as UNKNOWN,
  which is the *most* suspicious class, not the least. A missing database must never make the
  detector quieter.
"""
from __future__ import annotations
import ipaddress
import json
import os
from bisect import bisect_right
from pathlib import Path

_RANGES: list[tuple[int, int, str]] = []
_NAMES: dict[str, str] = {}
_STATUS: str = 'unloaded'


def _u32(ip: str) -> int | None:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version != 4:
        return None
    return int(a)


def _load() -> None:
    """Embed the curated prefix->ASN ranges at import. Idempotent."""
    global _STATUS, _NAMES
    if _RANGES:
        return
    src = os.getenv('ASN_TABLE', str(Path(__file__).with_name('asn_prefixes.json')))
    try:
        raw = json.loads(Path(src).read_text())
        names = raw.get('asn_to_name', {})
        ranges = sorted((int(s), int(e), a) for s, e, a in raw.get('prefixes', []))
        _NAMES = names
        _RANGES[:] = ranges          # in-place: keeps the module-level list identity
        _STATUS = 'loaded'
    except Exception:
        _RANGES[:] = []
        _NAMES = {}
        _STATUS = 'unavailable'   # fail OPEN: unknown == most suspicious


def asn_of(ip: str) -> str | None:
    """Autonomous System number for an IPv4 address, or None (unknown/unavailable)."""
    v = _u32(ip)
    if v is None:
        return None
    if not _RANGES:
        _load()
    if not _RANGES:
        return None
    lo, hi = 0, len(_RANGES) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        start, end, asn = _RANGES[mid]
        if v < start:
            hi = mid - 1
        elif v > end:
            lo = mid + 1
        else:
            return asn
    return None


# ASNs whose client-facing traffic is large and legitimately periodic. Kept as an explicit set
# (mirrored in asn_reputation.json) so the policy is auditable in one place.
_PERIODIC_PROVIDERS = {
    'AS13335', 'AS54113', 'AS4641', 'AS55030',            # Cloudflare, Fastly
    'AS20940', 'AS16625', 'AS3257', 'AS24940',            # Akamai
    'AS15133', 'AS20473',                                # Edgio, Varnish
    'AS15169', 'AS3078', 'AS396982', 'AS394711',          # Google, Google Cloud
    'AS16509', 'AS14618', 'AS16510', 'AS8987',            # Amazon AWS
    'AS17493', 'AS19047', 'AS38895',
    'AS8075', 'AS8068', 'AS3598',                        # Microsoft
    'AS36459',                                            # GitHub
    'AS32934', 'AS157359', 'AS20001', 'AS26302',         # Meta, Twitter
    'AS399358', 'AS135630', 'AS31898',                    # Anthropic, Oracle
    'AS14061', 'AS63949', 'AS12876', 'AS16276',           # DigitalOcean, Linode, Scaleway, OVH
    'AS16265', 'AS60781', 'AS51167', 'AS19807', 'AS207812',
    'AS202425', 'AS11427', 'AS19165',
}


def provider_name(asn: str | None) -> str | None:
    return _NAMES.get(asn) if asn else None


def reputation(ip: str) -> str:
    """One of 'provider' (known periodic-infrastructure), 'unknown', 'unavailable'.

    'unknown' is the default and the LOUD class: an address we cannot attribute is a weaker
    lead, not a safer one. This function never returns 'benign' and never silences a detector.
    """
    asn = asn_of(ip)
    if asn is None:
        return 'unavailable' if _STATUS != 'loaded' else 'unknown'
    return 'provider' if asn in _PERIODIC_PROVIDERS else 'unknown'


def describe(ip: str) -> dict:
    """Provenance for the alert's supporting_evidence — an analyst can always audit the call."""
    asn = asn_of(ip)
    return {'asn': asn, 'asn_name': provider_name(asn), 'reputation': reputation(ip)}


if __name__ == '__main__':
    _load()
    print('table status:', _STATUS, '| ranges:', len(_RANGES))
    for ip in ('140.82.113.26', '104.21.21.127', '8.8.8.8', '172.217.24.170', '1.1.1.1'):
        print(f'  {ip:16} {describe(ip)}')
    print('  203.0.113.9    ', describe('203.0.113.9'), '<- TEST-NET must be unknown, never provider')
    print('  not-an-ip      ', describe('garbage'))
