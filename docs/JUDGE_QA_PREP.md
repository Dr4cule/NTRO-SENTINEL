# Judge Q&A

**Production network?** No private or production traffic is used. The demonstration uses a disposable, container-local one-way lab with checksummed safe generated PCAPs, live Zeek capture and paced tcpreplay, plus controlled metadata scenarios where appropriate.

**One-way proof?** The capture namespace monitor interface has no L3 identity/default route, IPv6 disabled, and an output-DROP nftables policy. The capture evidence contains interface RX/TX counters, routes, firewall, sockets and a blocked-egress probe. This is a software simulation, not represented as a physical diode.

**Why not Zeek alone?** Zeek supplies passive metadata; bounded feature state, detectors, correlation, alert evidence, and streaming metrics are the added layer.

**TLS decryption?** Never. Only observable metadata is normalized.

**How can we reproduce this now?** Run `make judge-demo`, open `http://localhost:8000`, then inspect the timestamped `artifacts/zeek-live-*` and `artifacts/evidence-bundle-*` outputs. `make capture-proof` runs only the live Zeek/tcpreplay portion.

**Are all confidence values probabilities?** No. Rule/anomaly confidences are normalized detector scores. A confidence is presented as a probability only after model calibration and validation, which this prototype does not claim.
