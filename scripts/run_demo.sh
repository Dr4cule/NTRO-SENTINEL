#!/usr/bin/env bash
set -euo pipefail
command -v docker >/dev/null || { echo 'Docker is required for the full live dashboard demo. Use scripts/run_replay.sh for local fallback.' >&2; exit 2; }
python3 traffic-gen/generators/generate_scenarios.py
docker compose down -v --remove-orphans >/dev/null 2>&1 || true
rm -f artifacts/sentinel.db artifacts/sentinel.db-shm artifacts/sentinel.db-wal
docker compose up --build -d redis api worker
./scripts/demo_preflight.sh
echo 'Dashboard is live at http://localhost:8000'
warmup=${DEMO_WARMUP_SECONDS:-4}
echo "Opening story replay in ${warmup} seconds: DDoS → C2 → DNS/DGA → encrypted anomaly → recon → exfiltration."
sleep "$warmup"
pace=${DEMO_PACE:-0.18}
for s in ddos ddos_udp_reflection ddos_spoof c2 dns encrypted recon exfil; do
  echo "== replaying $s =="
  docker compose run --rm worker python -m eval.replay_eval "traffic-gen/scenarios/$s.jsonl" --pace "$pace" --redis-url redis://redis:6379/0
done
sleep 2
./scripts/export_evidence_bundle.sh
echo 'Dashboard: http://localhost:8000  |  API health: http://localhost:8000/health'
echo 'Evidence integrity: http://localhost:8000/api/evidence/verify'
echo 'For physical-boundary simulation: sudo ./scripts/setup_lab.sh && sudo ./scripts/verify_one_way.sh'
