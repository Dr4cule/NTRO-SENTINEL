#!/usr/bin/env bash
set -euo pipefail

# Runs INSIDE the privileged ntro-zeek-lab container. All network namespaces are
# container-local; this does not change the host's production network stack.
root=/workspace; capture=ntro-capture; replay=ntro-replay; monitor=ntro-mon0; feed=ntro-feed0
cleanup() { ip netns del "$capture" 2>/dev/null || true; ip netns del "$replay" 2>/dev/null || true; }
trap cleanup EXIT
cleanup
ip netns add "$capture"; ip netns add "$replay"
ip link add "$monitor" type veth peer name "$feed"
ip link set "$monitor" netns "$capture"; ip link set "$feed" netns "$replay"
ip -n "$capture" link set lo up; ip -n "$capture" link set "$monitor" up promisc on
ip -n "$replay" link set lo up; ip -n "$replay" link set "$feed" up
ip netns exec "$capture" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
ip netns exec "$capture" nft add table inet sentinel
ip netns exec "$capture" nft 'add chain inet sentinel output { type filter hook output priority 0; policy drop; }'

out="$root/artifacts/zeek-live-$(date -u +%Y%m%dT%H%M%SZ)"; mkdir -p "$out"
{ date -u --iso-8601=seconds; zeek --version; tcpreplay --version | head -1; uname -a; } >"$out/environment.txt"
(
 cd "$out"
 exec ip netns exec "$capture" zeek -i "$monitor" "$root/ingest/zeek/sentinel.zeek"
) >"$out/zeek.stdout" 2>"$out/zeek.stderr" &
zeek_pid=$!
for _ in $(seq 1 20); do test -f "$out/early.log" && break; sleep .25; done
test -f "$out/early.log" || { echo 'Zeek did not create early.log'; cat "$out/zeek.stderr"; exit 1; }

pcap="$root/traffic-gen/pcaps/safe_mixed.pcap"
(cd "$(dirname "$pcap")" && sha256sum -c "$(basename "$pcap").sha256")
ip netns exec "$replay" tcpreplay --intf1="$feed" --pps=200 "$pcap" >"$out/replay.stdout" 2>"$out/replay.stderr"
sleep 2
kill "$zeek_pid" 2>/dev/null || true; wait "$zeek_pid" 2>/dev/null || true
records=$(wc -l < "$out/early.log")
test "$records" -gt 0 || { echo 'FAIL: no early telemetry arrived during live replay'; exit 1; }
ip netns exec "$capture" ip addr show "$monitor" >"$out/capture-ip-addr.txt"
ip netns exec "$capture" ip -s link show "$monitor" >"$out/capture-interface-stats.txt"
ip netns exec "$capture" ip route >"$out/capture-ip-route.txt"
ip netns exec "$capture" ip -6 route >"$out/capture-ip6-route.txt"
ip netns exec "$capture" nft list ruleset >"$out/capture-firewall.txt"
ip netns exec "$capture" ss -tpn >"$out/capture-sockets.txt"
if ip netns exec "$capture" ping -c1 -W1 198.51.100.1 >"$out/egress-test.txt" 2>&1; then echo 'FAIL: capture egress unexpectedly succeeded'; exit 1; else echo 'PASS: capture egress blocked' >>"$out/egress-test.txt"; fi
chmod -R a+rwX "$out"
printf 'LIVE_ZEEK_REPLAY_PASS early_records=%s\n' "$records" | tee "$out/result.txt"
