#!/usr/bin/env bash
set -euo pipefail

command -v curl >/dev/null || { echo 'curl is required.' >&2; exit 2; }
stamp=$(date -u +%Y%m%dT%H%M%SZ)
bundle="artifacts/evidence-bundle-$stamp"
mkdir -p "$bundle"
curl --fail --silent http://localhost:8000/health -o "$bundle/health.json"
curl --fail --silent http://localhost:8000/api/dashboard/summary -o "$bundle/dashboard-summary.json"
curl --fail --silent http://localhost:8000/api/evidence/verify -o "$bundle/evidence-chain.json"
curl --fail --silent 'http://localhost:8000/api/alerts?limit=1000' -o "$bundle/alerts.json"
docker compose ps --format json > "$bundle/services.json"
for source in artifacts/metrics.json artifacts/loadtest.json eval/results.json eval/results.md models/artifacts/training_manifest.json; do
  test -f "$source" && cp "$source" "$bundle/"
done
sha256sum "$bundle"/* > "$bundle/SHA256SUMS"
echo "Evidence bundle written to $bundle"
