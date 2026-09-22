#!/usr/bin/env bash
set -euo pipefail

# Complete Mode A/B proof: generated safe PCAP -> paced tcpreplay -> live Zeek
# interface -> incremental tailer -> Redis Streams -> detector worker -> alert store.
./scripts/run_live_capture_proof.sh
latest=$(find artifacts -maxdepth 1 -type d -name 'zeek-live-*' | sort | tail -1)
test -n "$latest" && test -f "$latest/early.log" || { echo 'Missing live Zeek telemetry.' >&2; exit 1; }
docker compose down -v --remove-orphans >/dev/null 2>&1 || true
rm -f artifacts/sentinel.db artifacts/sentinel.db-shm artifacts/sentinel.db-wal
docker compose up --build -d redis api worker
./scripts/demo_preflight.sh
for log in early conn dns; do
  test -f "$latest/$log.log" || continue
  docker compose run --rm worker python -m ingest.tailer /data/"$(basename "$latest")"/"$log".log --once --redis-url redis://redis:6379/0
done
sleep 2
summary=$(curl --fail --silent http://localhost:8000/api/dashboard/summary)
echo "$summary" > "$latest/pipeline-summary.json"
for threat in ddos dga_dns_tunnel recon_scan; do
  alerts=$(curl --fail --silent "http://localhost:8000/api/alerts?threat_class=$threat&limit=50")
  echo "$alerts" > "$latest/$threat-alerts.json"
  test "$alerts" != '[]' || { echo "FAIL: live Zeek telemetry produced no $threat alert." >&2; exit 1; }
done
./scripts/export_evidence_bundle.sh
printf 'END_TO_END_CAPTURE_PASS evidence=%s\n' "$latest" | tee "$latest/end-to-end-result.txt"
