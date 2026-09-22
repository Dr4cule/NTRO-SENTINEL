# Limitations

- The namespace setup demonstrates software isolation, not a certified physical diode.
- Generated scenarios are metadata-only acceptance inputs, not substitutes for public-PCAP validation.
- Only the DGA starter classifier is trained; it uses generated lab labels and carries no external-performance claim.
- Redis Streams and SQLite are implemented; PostgreSQL is not bundled because SQLite is the explicitly supported reduced local demo store.
- Zeek live ingestion and tcpreplay are implemented as host-prerequisite scripts but cannot be asserted as validated until a permitted PCAP and host tools are supplied.
- TLS/QUIC payloads are never decrypted or stored.
