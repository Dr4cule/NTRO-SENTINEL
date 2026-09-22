#!/usr/bin/env bash
set -euo pipefail

# Best presentation path. First proves real live Zeek capture for DDoS/DNS/recon,
# then adds controlled metadata scenarios for C2, encrypted-session and exfiltration
# so the same SOC dashboard shows all six required classes.
echo 'Phase 1/2 — live passive capture proof (safe generated PCAP, Zeek -i, Redis worker)'
./scripts/run_end_to_end_capture_proof.sh
echo 'Dashboard is available at http://localhost:8000 — open it now.'
sleep "${JUDGE_WARMUP_SECONDS:-5}"
for scenario in c2 encrypted exfil; do
  echo "Phase 2/2 — controlled streaming scenario: $scenario"
  docker compose run --rm worker python -m eval.replay_eval "traffic-gen/scenarios/$scenario.jsonl" --pace "${JUDGE_PACE:-.20}" --redis-url redis://redis:6379/0
done
sleep 2
./scripts/export_evidence_bundle.sh
curl --fail --silent http://localhost:8000/api/dashboard/summary | tee artifacts/judge-demo-summary.json
echo 'JUDGE_DEMO_PASS — inspect six-class dashboard and latest evidence bundle.'
