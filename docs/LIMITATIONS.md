# Limitations

- The namespace setup demonstrates software isolation, not a certified physical diode.
- Generated scenarios are metadata-only acceptance inputs, not substitutes for public-PCAP validation.
- **The starter DGA classifier is weak, and the number is known.** On the disjoint holdout it scores precision 0.32 / recall 1.00 / F1 0.48 (the previously reported 1.00 came from a vocabulary leak between train and evaluation and is not valid). It has learned token *length*, not entropy. The lexical gate in `detectors/rules.py` is the real detector; the model is optional second-opinion enrichment. The committed `dga_holdout_evaluation.json` is stale and must not be quoted — see `models/model_cards/README.md`.
- **C2 and exfiltration rank by destination ASN.** A beacon or a large upload to Cloudflare/Google/GitHub/Amazon is downgraded to `medium` with the provider name recorded in the evidence, because timing and volume cannot separate those from malware. This is a ranking, never a suppression — but it does mean a genuine implant fronted by a CDN IP ranks below an unknown host, and an analyst must read the `asn`/`downgrade_reason` fields rather than the severity alone.
- `encrypted_malware` is strongest on the Zeek path, where JA3/JA4 exists. On the scapy/live path there is no fingerprint, so a metadata-only heuristic (upload asymmetry + low host diversity + unattributable destination) is used and scored *below* a real fingerprint match. It is a weaker signal and labelled as such in `model_version`.
- ~~The C2 rule skips RFC1918 and CGNAT destinations, so lateral C2 is not detected.~~ **Closed
  2026-09-29 (§20.2).** Internal destinations are now judged on the same structural gates, gated
  on a destination-port allowlist of LAN services. Residual limits: a beacon to an internal host on
  a port that legitimately runs a service (443, 8080, 8443) is **not** flagged, because internal web
  traffic is indistinguishable from internal C2 on port alone; and the allowlist is static, so an
  environment running an unusual service on 1337/4444/9001 would see false positives.
- Only the DGA starter classifier is trained; it uses generated lab labels and carries no external-performance claim.
- Redis Streams and SQLite are implemented; PostgreSQL is not bundled because SQLite is the explicitly supported reduced local demo store.
- Zeek live ingestion and tcpreplay are implemented as host-prerequisite scripts but cannot be asserted as validated until a permitted PCAP and host tools are supplied.
- `docker-compose.yml` bind-mounts `./artifacts` read-write because that path **is** the alert store; `:ro` would break ingestion. The hardening that is available on a write mount (`:nosuid,nodev,noexec`) is applied instead.
- Read endpoints (`/api/alerts`, the dashboard, `/health`, `/ws/alerts`) are unauthenticated by design, since this is a read-only analyst enclave. Only the write endpoints are token-gated.
- `scripts/preview_server.py` is a stdlib-only development viewer: single-threaded (it can wedge under concurrent browser fetches) and unauthenticated. Production serving is FastAPI in Docker.
- TLS/QUIC payloads are never decrypted or stored.
