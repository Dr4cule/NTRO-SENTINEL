#!/usr/bin/env bash
set -euo pipefail

command -v docker >/dev/null || { echo 'Docker is required.' >&2; exit 2; }
python3 traffic-gen/generators/generate_pcaps.py
docker build -f tap/Dockerfile -t ntro-zeek-lab:9.0.0 .
docker run --rm --privileged -v "$PWD:/workspace" -w /workspace ntro-zeek-lab:9.0.0 ./scripts/run_container_live_lab.sh
echo "Live-capture evidence: $(find artifacts -maxdepth 1 -type d -name 'zeek-live-*' | sort | tail -1)/"
