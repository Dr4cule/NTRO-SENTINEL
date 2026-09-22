#!/usr/bin/env bash
set -euo pipefail
interface=${1:-ntro-mon0}; namespace=${CAPTURE_NAMESPACE:-ntro-capture}; root=$(cd "$(dirname "$0")/.." && pwd)
command -v zeek >/dev/null || { echo 'Zeek is required; install a pinned Zeek release first.' >&2; exit 2; }
ip netns list | grep -q "^$namespace" || { echo "Missing capture namespace $namespace; run sudo scripts/setup_lab.sh" >&2; exit 2; }
mkdir -p artifacts/zeek
cd artifacts/zeek
exec ip netns exec "$namespace" zeek -i "$interface" "$root/ingest/zeek/sentinel.zeek"
