#!/usr/bin/env bash
# Rough UDP throughput through hydra in netns, with and without flowtable.
# veth numbers are CPU-bound and only useful as a relative comparison.
set -euo pipefail
BIN="${HYDRA_BIN:-$(cd "$(dirname "$0")/.." && pwd)/target/release/hydra}"
S=$$; H=bh-$S C=bc-$S E=be-$S; W=$(mktemp -d)
trap 'for n in $H $C $E; do ip netns del $n 2>/dev/null||true; done; rm -rf $W' EXIT
for n in $H $C $E; do ip netns add $n; ip -n $n link set lo up; done
ip link add hc0 netns $H type veth peer name ch0 netns $C
ip link add he0 netns $H type veth peer name eh0 netns $E
ip -n $H addr add 203.0.113.1/24 dev hc0; ip -n $C addr add 203.0.113.2/24 dev ch0
ip -n $H addr add 198.51.100.1/24 dev he0; ip -n $E addr add 198.51.100.10/24 dev eh0
for l in "$H hc0" "$H he0" "$C ch0" "$E eh0"; do set -- $l; ip -n $1 link set $2 up; done
ip -n $C route add default via 203.0.113.1; ip -n $E route add default via 198.51.100.1
ip netns exec $H sysctl -qw net.ipv4.ip_forward=1
ip netns exec $E iperf3 -s -D -p 443 >/dev/null
# iperf3 needs a TCP control channel; hydra only forwards UDP, so DNAT TCP here for the benchmark.
ip netns exec $H nft -f - <<'NFT'
table ip benchctl {
  chain pre {
    type nat hook prerouting priority -110;
    ip daddr 203.0.113.1 tcp dport 443 dnat to 198.51.100.10
  }
  chain post {
    type nat hook postrouting priority 110;
    ip daddr 198.51.100.10 tcp dport 443 masquerade
  }
}
NFT
sleep 0.5
run() {
  ip netns exec $H "$BIN" up --listen 203.0.113.1 --exit-ip 198.51.100.10 --exit-hostname lab \
    --write $W/h.json --skip-sysctl "$@" >/dev/null 2>&1
  ip netns exec $C iperf3 -c 203.0.113.1 -p 443 -u -b 0 -l 1400 -t 5 -J > $W/r.json
  python3 -c "import json;e=json.load(open('$W/r.json'))['end'].get('sum') or json.load(open('$W/r.json'))['end']['sum_received'];print(f\"{e['bits_per_second']/1e9:.2f} Gbit/s at receiver, loss {e['lost_percent']:.1f}%\")"
}
echo "normal path:   $(run --no-flowtable)"
echo "flowtable:     $(run)"
