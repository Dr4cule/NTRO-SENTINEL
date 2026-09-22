#!/usr/bin/env bash
set -euo pipefail

command -v docker >/dev/null || { echo 'FAIL: Docker is not installed.' >&2; exit 2; }
command -v curl >/dev/null || { echo 'FAIL: curl is required for health checks.' >&2; exit 2; }
docker compose config >/dev/null
echo 'PASS: Docker Compose configuration is valid.'

for _ in $(seq 1 30); do
  if curl --fail --silent http://localhost:8000/health >/dev/null; then
    echo 'PASS: Sentinel API is healthy.'
    exit 0
  fi
  sleep 1
done
echo 'FAIL: Sentinel API did not become healthy within 30 seconds.' >&2
docker compose logs --tail=80 api worker redis >&2 || true
exit 1
