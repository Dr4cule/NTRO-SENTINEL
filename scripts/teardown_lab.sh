#!/usr/bin/env bash
set -euo pipefail
ip netns del ntro-capture 2>/dev/null || true
ip netns del ntro-replay 2>/dev/null || true
