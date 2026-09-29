#!/usr/bin/env bash
# Persistent two-party test segment for the live sensor.
#
# The box's own traffic alone cannot exercise every detector: exfiltration needs a peer that
# actually completes the handshake and reads the upload (a closed port RSTs, and traffic to a
# local address loops via `lo` where the NIC sniffer never sees it).
#
# So stand up a veth pair with the PEER END IN A NETWORK NAMESPACE:
#   veth-mon  10.99.0.1  stays on the host -- the SENSOR watches this, promiscuous
#   veth-sink 10.99.0.2  lives in netns ntro-peer -- runs tools/sink.py
#
# The namespace is the essential part. With both ends on one host the kernel resolves
# 10.99.0.2 as a LOCAL address and routes via `lo`, so the frames never cross veth-mon and the
# sniffer legitimately sees nothing. Idempotent: safe to re-run on every boot.
set -euo pipefail
MON=veth-mon; SINK=veth-sink; NS=ntro-peer

ip netns del "$NS" 2>/dev/null || true
ip link del "$MON" 2>/dev/null || true
ip netns add "$NS"
ip link add "$MON" type veth peer name "$SINK"
ip link set "$SINK" netns "$NS"

# host end: the monitored side
ip addr replace 10.99.0.1/24 dev "$MON"
ip link set "$MON" up promisc on

# peer end: a genuinely separate network stack
ip -n "$NS" addr replace 10.99.0.2/24 dev "$SINK"
# a SECOND peer address: detectors window on src|dst, so exfil and C2 must not share a
# conversation. One megabyte of upload into the same src|dst bucket makes the C2 size gate
# correctly refuse to call that channel a heartbeat -- which is right, and is why the demo
# needs distinct peers rather than distinct ports.
ip -n "$NS" addr replace 10.99.0.3/24 dev "$SINK"
ip -n "$NS" link set "$SINK" up
ip -n "$NS" link set lo up
ip -n "$NS" route replace default via 10.99.0.1 2>/dev/null || true

# prove the frames really traverse the monitored wire before anything relies on it
if ip route get 10.99.0.2 | grep -q 'dev lo'; then
  echo "FATAL: 10.99.0.2 still resolves via lo -- traffic would bypass the sensor" >&2
  exit 1
fi
echo "test segment ready: $MON=10.99.0.1 (host, monitored/promisc)  $SINK=10.99.0.2 (netns $NS)"
ip route get 10.99.0.2
