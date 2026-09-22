#!/usr/bin/env bash
set -euo pipefail
python3 traffic-gen/generators/generate_scenarios.py
PYTHONPATH=. python3 -m eval.run_suite
echo 'Wrote eval/results.json and eval/results.md'
