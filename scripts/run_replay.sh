#!/usr/bin/env bash
set -euo pipefail
scenario=${1:?usage: $0 traffic-gen/scenarios/<scenario>.jsonl [pace seconds]}
pace=${2:-0.05}
PYTHONPATH=. python3 -m eval.replay_eval "$scenario" --pace "$pace"
