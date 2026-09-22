#!/usr/bin/env bash
set -euo pipefail
NS=ntro-capture; MON=ntro-mon0
ip netns list | grep -q "^$NS" || { echo "missing namespace; run sudo scripts/setup_lab.sh"; exit 1; }
ip netns exec "$NS" ip addr show "$MON"; ip netns exec "$NS" ip route; ip netns exec "$NS" ip -6 addr; ip netns exec "$NS" ip -6 route
if command -v nft >/dev/null; then ip netns exec "$NS" nft list ruleset; elif command -v iptables >/dev/null; then ip netns exec "$NS" iptables -S; fi
ip netns exec "$NS" ss -tpn
if ip netns exec "$NS" ping -c1 -W1 198.51.100.1; then echo 'FAIL: egress unexpectedly succeeded'; exit 1; else echo 'PASS: controlled egress is blocked'; fi
