#!/usr/bin/env bash
set -euo pipefail
# Software isolation demonstration only; never represents hardware-diode assurance.
CAP=ntro-capture; SRC=ntro-replay; MON=ntro-mon0; FEED=ntro-feed0
ip netns del "$CAP" 2>/dev/null || true; ip netns del "$SRC" 2>/dev/null || true
ip netns add "$CAP"; ip netns add "$SRC"
ip link add "$MON" type veth peer name "$FEED"
ip link set "$MON" netns "$CAP"; ip link set "$FEED" netns "$SRC"
ip -n "$CAP" link set lo up; ip -n "$CAP" link set "$MON" up promisc on
ip -n "$SRC" link set lo up; ip -n "$SRC" link set "$FEED" up
ip netns exec "$CAP" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
if command -v nft >/dev/null; then
 ip netns exec "$CAP" nft add table inet sentinel 2>/dev/null || true
 ip netns exec "$CAP" nft 'add chain inet sentinel output { type filter hook output priority 0; policy drop; }' 2>/dev/null || true
elif command -v iptables >/dev/null; then ip netns exec "$CAP" iptables -P OUTPUT DROP
else echo 'nftables or iptables is required for the capture-boundary proof' >&2; exit 2; fi
echo "capture namespace $CAP ready: $MON has no L3 address/route; $SRC can only feed replay frames"
