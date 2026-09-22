# Enclave hardening

Implemented controls:

- Capture and replay namespaces are distinct; the monitor interface has no L3 address/default route.
- IPv6 is disabled in the capture namespace and its output firewall policy is DROP.
- The capture process is not a Docker analytics service; analytics reads only Zeek-derived metadata.
- API and worker containers run as non-root, with dropped Linux capabilities, read-only roots, explicit tmpfs, memory/CPU limits and a single exposed API port.
- Redis has no published host port. SQLite alerts form an application-append-only SHA-256 hash chain; `/api/evidence/verify` checks it.

`verify_one_way.sh` is a mandatory demo artifact. This does not claim immutable storage, certified isolation, or equivalence to a physical diode; production deployment needs a hardware boundary, hardened host, managed secrets, signed images, access control, backups and independent audit.
