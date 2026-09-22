# Controlled Scenario Evaluation

A scenario is detected when at least one alert has its known target threat class. This is not packet-level precision, recall, or F1.

| Scenario | Target | Detected | Alerts | Subtype |
|---|---|---:|---:|---|
| benign | benign | yes | 0 | — |
| ddos | ddos | yes | 1 | yes |
| ddos_udp_reflection | ddos | yes | 1 | yes |
| ddos_spoof | ddos | yes | 1 | yes |
| c2 | c2_beaconing | yes | 2 | — |
| dns | dga_dns_tunnel | yes | 2 | — |
| encrypted | encrypted_malware | yes | 1 | — |
| recon | recon_scan | yes | 1 | — |
| exfil | exfiltration | yes | 1 | — |

Attack scenarios detected: 8/8. Benign alerts: 0 (FPR 0.0).

## Confusion (scenario truth × predicted class)

Alert-level precision on the controlled corpus (homogeneous scenarios). Flow-level recall/F1 is intentionally not claimed.

| Truth ＼ Pred | ddos | c2_beaconing | dga_dns_tunnel | encrypted_malware | recon_scan | exfiltration |
|---|---:|---:|---:|---:|---:|---:|
| ddos | 3 | 0 | 0 | 0 | 0 | 0 |
| c2_beaconing | 0 | 2 | 0 | 0 | 0 | 0 |
| dga_dns_tunnel | 0 | 0 | 2 | 0 | 0 | 0 |
| encrypted_malware | 0 | 0 | 0 | 1 | 0 | 0 |
| recon_scan | 0 | 0 | 0 | 0 | 1 | 0 |
| exfiltration | 0 | 0 | 0 | 0 | 0 | 1 |

## Alert-level precision (controlled corpus)

| Class | Precision |
|---|---:|
| ddos | 1.0 |
| c2_beaconing | 1.0 |
| dga_dns_tunnel | 1.0 |
| encrypted_malware | 1.0 |
| recon_scan | 1.0 |
| exfiltration | 1.0 |

This result applies only to committed generated metadata scenarios. Use documented PCAP/lab labels and group-separated data for any public performance claims.
