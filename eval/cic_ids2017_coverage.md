# CIC-IDS2017 — Dataset Coverage / Fit Check

This release carries CICFlowMeter statistical features only; the IP/port/DNS/TLS/timestamp metadata every Sentinel detector groups on is absent, so no detector can be exercised on it. Use the CIC-IDS2017 PCAPs replayed through Zeek (build-guide Tier A) to validate the detectors on this dataset.

Files: 8 · Flows: 2,313,810 · Feature columns: 78 · Metadata columns present: ['orig_bytes', 'proto', 'resp_bytes']

## Label census (real labels in the files)

| CIC-IDS2017 label | flows | nearest Sentinel class |
|---|---:|---|
| Benign | 1,977,318 | — |
| DoS Hulk | 172,846 | ddos |
| DDoS | 128,014 | ddos |
| DoS GoldenEye | 10,286 | ddos |
| FTP-Patator | 5,931 | recon_scan |
| DoS slowloris | 5,385 | ddos |
| DoS Slowhttptest | 5,228 | ddos |
| SSH-Patator | 3,219 | recon_scan |
| PortScan | 1,956 | recon_scan |
| Web Attack � Brute Force | 1,470 | — |
| Bot | 1,437 | c2_beaconing |
| Web Attack � XSS | 652 | — |
| Infiltration | 36 | exfiltration |
| Web Attack � Sql Injection | 21 | — |
| Heartbleed | 11 | encrypted_malware |

## Detector coverage (can each detector run on this release?)

| Sentinel detector | requires | missing here | can run |
|---|---|---|:--:|
| ddos | src_ip, dst_ip, proto, tcp_flags/conn_state | src_ip, dst_ip, tcp_flags/conn_state | NO |
| c2_beaconing | src_ip, dst_ip, timestamp | src_ip, dst_ip, timestamp | NO |
| dga_dns_tunnel | dns_query | dns_query | NO |
| encrypted_malware | tls_ja3/sni, src_ip, orig_bytes, resp_bytes | tls_ja3/sni, src_ip | NO |
| recon_scan | src_ip, dst_port | src_ip, dst_port | NO |
| exfiltration | src_ip, dst_ip, orig_bytes | src_ip, dst_ip | NO |

Detectors runnable on this artifact: **none**.

Coverage/fit check only. No precision/recall/F1 is computed or claimed here.

