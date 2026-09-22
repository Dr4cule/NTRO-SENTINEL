#!/usr/bin/env bash
set -euo pipefail
pcap=${1:?usage: $0 <pcap> [mbps]}; mbps=${2:-10}; iface=${REPLAY_INTERFACE:-ntro-feed0}
command -v tcpreplay >/dev/null || { echo 'tcpreplay is required for live PCAP proof.' >&2; exit 2; }
test -f "$pcap" || { echo "PCAP missing: $pcap" >&2; exit 2; }
if [ -f "${pcap}.sha256" ]; then (cd "$(dirname "$pcap")" && sha256sum -c "$(basename "$pcap").sha256"); fi
exec ip netns exec ntro-replay tcpreplay --intf1="$iface" --mbps="$mbps" "$pcap"
