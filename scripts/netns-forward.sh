#!/usr/bin/env bash
# Prove hydra forwarding, flowtable fast path, 1:1 NAT bind, several entries
# on several IPs, datacenters spread and followed through DNS, ranges routed to
# the server or on its link, and doctor/tune in network namespaces. Needs root,
# nft, iproute2, python3, conntrack.
#
#   client 203.0.113.2 --> hydra (203.0.113.1 local, or public 192.0.2.50
#   via 1:1 NAT onto 203.0.113.1) --> a datacenter's server 198.51.100.10:51820
#   T11-T13 add 203.0.113.3 (public 192.0.2.51) on hydra and 198.51.100.20 on
#   the exit side. hydra's namespace gets its own /etc/hosts (ip netns exec
#   mounts /etc/netns/<ns>/hosts), standing in for the datacenters' DNS, and
#   Windscribe's locations (WebsiteStatus) with those datacenters, served inside it.
#   T17-T18 make the client side the provider's router: it routes
#   45.33.30.0/24 to hydra, and has 45.33.31.0/28 on the link, where it asks
#   (ARP) for each address.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${HYDRA_BIN:-${ROOT}/target/release/hydra}"
[[ -x "$BIN" ]] || { echo "missing $BIN; run cargo build --release first" >&2; exit 1; }

S="$$"
H="hydra-$S" C="client-$S" E="exit-$S"
WORK="$(mktemp -d)"
WWW= WWW2=
cleanup() {
  for pid in $WWW $WWW2; do kill "$pid" 2>/dev/null; done
  for n in "$H" "$C" "$E"; do ip netns del "$n" 2>/dev/null || true; done
  rm -rf "$WORK" "/etc/netns/$H"
}
trap cleanup EXIT

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; exit 1; }

for n in "$H" "$C" "$E"; do ip netns add "$n"; ip -n "$n" link set lo up; done
mkdir -p "/etc/netns/$H"
echo "127.0.0.1 localhost" >"/etc/netns/$H/hosts"
# Names not in that file fail at once instead of waiting on the host's DNS.
echo "nameserver 127.0.0.1" >"/etc/netns/$H/resolv.conf"
mkdir -p "$WORK/www"
# Windscribe's locations as hydra reads them (WebsiteStatus): in location Lab,
# one datacenter per name dns() gave. A name is <iata>-<id>-wg.example.com, as
# hydra builds it from the datacenter's IATA code and id.
LIST=http://127.0.0.1:8080/WebsiteStatus
dns() { # name [ip...]: what a datacenter's WireGuard hostname resolves to in hydra's namespace
  local name="$1"; shift
  sed -i "/ $name\$/d" "/etc/netns/$H/hosts"
  for ip in "$@"; do echo "$ip $name" >>"/etc/netns/$H/hosts"; done
  python3 - "/etc/netns/$H/hosts" "$WORK/www/WebsiteStatus" <<'PY'
import json, re, sys
hosts, out = sys.argv[1:]
names = []
for line in open(hosts):
    ip, name = line.split()
    if name != "localhost" and name not in names:
        names.append(name)
pops = []
for n in names:
    m = re.fullmatch(r"([a-z0-9]+)-(\d+)-wg\.example\.com", n)
    pops.append({"status": 1, "datacenter_id": int(m[2]), "iata_code": m[1].upper(), "name": "Lab", "usage": 0})
json.dump({"data": {"locations": {"1": {"name": "Lab", "pops": pops}}}}, open(out, "w"))
PY
}
dc_id() { local n="${1%-wg.example.com}"; echo "${n##*-}"; } # the id in a datacenter's name
dns lab-1-wg.example.com 198.51.100.10
ip netns exec "$H" python3 -m http.server 8080 --bind 127.0.0.1 --directory "$WORK/www" >/dev/null 2>&1 &
WWW=$!
for _ in $(seq 100); do
  ip netns exec "$H" python3 -c 'import socket; socket.create_connection(("127.0.0.1", 8080), 0.2)' 2>/dev/null && break
  sleep 0.1
done
ip link add hc0 netns "$H" type veth peer name ch0 netns "$C"
ip link add he0 netns "$H" type veth peer name eh0 netns "$E"
ip -n "$H" addr add 203.0.113.1/24 dev hc0
ip -n "$C" addr add 203.0.113.2/24 dev ch0
ip -n "$H" addr add 198.51.100.1/24 dev he0
ip -n "$E" addr add 198.51.100.10/24 dev eh0
for l in "$H hc0" "$H he0" "$C ch0" "$E eh0"; do set -- $l; ip -n "$1" link set "$2" up; done
ip -n "$C" route add default via 203.0.113.1
ip -n "$E" route add default via 198.51.100.1
# hydra's default route points at the client side, so auto-detection sees 203.0.113.1.
ip -n "$H" route add default via 203.0.113.2

# UDP echo on the exit: replies "pong" and records the source it saw.
cat >"$WORK/echo.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[3] if len(sys.argv) > 3 else "0.0.0.0", int(sys.argv[4]) if len(sys.argv) > 4 else 51820))
s.settimeout(5)
seen = set()
for _ in range(int(sys.argv[2])):
    try:
        data, addr = s.recvfrom(4096)
    except socket.timeout:
        break
    seen.add(addr[0])
    s.sendto(b"pong", addr)
open(sys.argv[1], "w").write(",".join(sorted(seen)))
PY
cat >"$WORK/client.py" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
ok = 0
for i in range(int(sys.argv[2])):
    s.sendto(b"ping", (sys.argv[1], 443))
    try:
        if s.recvfrom(4096)[0] == b"pong":
            ok += 1
    except socket.timeout:
        pass
print(ok)
PY

roundtrip() { # target count -> "ok_count seen_sources"
  roundtrip_via "$1" 0.0.0.0 "$2"
}

roundtrip_via() { # target exit_ip count [exit_port] -> "ok_count seen_sources"; the exit answers on exit_ip only
  local target="$1" exit_ip="$2" n="$3" port="${4:-51820}"
  ip netns exec "$E" python3 "$WORK/echo.py" "$WORK/seen" "$n" "$exit_ip" "$port" &
  local pid=$!
  sleep 0.3
  local ok
  ok="$(ip netns exec "$C" python3 "$WORK/client.py" "$target" "$n")"
  wait "$pid"
  echo "$ok $(cat "$WORK/seen")"
  rm -f "$WORK/seen"
}

ST="$WORK/entries.json"
hydra() { ip netns exec "$H" "$BIN" "$@"; }
up() { hydra up --state "$ST" --write "$WORK/hydra.json" --datacenter lab-1-wg.example.com \
  --status-url "$LIST" --wg-zone example.com --label Lab --exit-port 51820 "$@"; }

echo "=== T1 doctor before up flags forwarding off"
ip netns exec "$H" sysctl -qw net.ipv4.ip_forward=0
set +e; ip netns exec "$H" "$BIN" doctor >"$WORK/d1" 2>&1; rc=$?; set -e
cat "$WORK/d1"
[[ $rc -eq 2 ]] && grep -q "FAIL.*forwarding is off" "$WORK/d1" && pass "T1 doctor exit 2 on forwarding off" || fail "T1 rc=$rc"

echo "=== T2 up with explicit listen, flowtable on"
up --listen 203.0.113.1 2>&1
ip netns exec "$H" nft list table inet hydra >"$WORK/t2"
grep -q "flowtable ft" "$WORK/t2" && pass "T2 flowtable present" || echo "INFO T2 kernel has no flowtable; fallback used"
read -r ok seen <<<"$(roundtrip 203.0.113.1 20)"
[[ "$ok" == 20 && "$seen" == 203.0.113.1 ]] && pass "T2 20/20 pongs, exit saw $seen" || fail "T2 ok=$ok seen=$seen"
ip netns exec "$H" nft list flowtable inet hydra ft >/dev/null 2>&1 && \
  ip netns exec "$H" conntrack -L 2>/dev/null | grep -q OFFLOAD && pass "T2 flow offloaded" || true

echo "=== T3 up is idempotent"
up --listen 203.0.113.1 >/dev/null 2>&1
[[ "$(ip netns exec "$H" nft list tables | grep -c 'inet hydra')" == 1 ]] && pass "T3 single table after rerun" || fail T3
read -r ok seen <<<"$(roundtrip 203.0.113.1 5)"
[[ "$ok" == 5 ]] && pass "T3 still forwarding" || fail "T3 ok=$ok"

echo "=== T4 auto-detect refuses a non-public default source"
set +e; up --no-flowtable >"$WORK/t4" 2>&1; rc=$?; set -e
cat "$WORK/t4"
[[ $rc -ne 0 ]] && grep -q "not a public address" "$WORK/t4" && pass "T4 refused to advertise 203.0.113.1" || fail "T4 rc=$rc"

echo "=== T5 1:1 NAT: public 192.0.2.50 is not local; traffic arrives as 203.0.113.1"
# Simulate the provider NAT on the client side: client sends to 192.0.2.50,
# a DNAT in the client namespace rewrites it to 203.0.113.1 (like a cloud edge).
ip netns exec "$C" nft -f - <<'NFT'
table ip edge {
  chain out {
    type nat hook output priority -100;
    ip daddr 192.0.2.50 dnat to 203.0.113.1
  }
}
NFT
up --listen 192.0.2.50 2>&1 | grep -E "not local|forwarding"
grep -q '"entry_ip": "192.0.2.50"' "$WORK/hydra.json" && pass "T5 profile advertises public 192.0.2.50" || fail "T5 profile"
ip netns exec "$H" nft list table inet hydra | grep -q "ip daddr 203.0.113.1 udp dport 443" && pass "T5 rules bind local 203.0.113.1" || fail "T5 rules"
read -r ok seen <<<"$(roundtrip 192.0.2.50 5)"
[[ "$ok" == 5 ]] && pass "T5 5/5 via NAT" || fail "T5 ok=$ok"

echo "=== T6 doctor after up"
ip netns exec "$H" "$BIN" doctor --from "$WORK/hydra.json" | tee "$WORK/d6"
grep -q "ok.*table inet hydra is loaded" "$WORK/d6" && pass "T6 table seen with flow counter" || fail T6

echo "=== T7 foreign forward drop chain is reported"
ip netns exec "$H" nft -f - <<'NFT'
table ip filter {
  chain FORWARD {
    type filter hook forward priority 0; policy drop;
  }
}
NFT
set +e; ip netns exec "$H" "$BIN" doctor --from "$WORK/hydra.json" >"$WORK/d7"; rc=$?; set -e
grep "forward" "$WORK/d7"
[[ $rc -eq 2 ]] && grep -q "ip filter FORWARD" "$WORK/d7" && pass "T7 drop chain flagged" || fail "T7 rc=$rc"
read -r ok seen <<<"$(roundtrip 192.0.2.50 1)"
[[ "$ok" == 0 ]] && pass "T7 confirmed: drop chain really blocks forwarding" || echo "INFO T7 ok=$ok"
ip netns exec "$H" nft delete table ip filter

echo "=== T8 tune plan, apply, persist, rerun"
ip netns exec "$H" sysctl -qw net.core.netdev_max_backlog=1000 2>/dev/null || true
ip netns exec "$H" "$BIN" tune --from "$WORK/hydra.json" | tee "$WORK/t8"
ip netns exec "$H" "$BIN" tune --from "$WORK/hydra.json" --apply | tee "$WORK/t8a"
grep -q "^applied" "$WORK/t8a" || echo "INFO T8 nothing applied (values already tuned or read-only in netns)"
grep -q "^error" "$WORK/t8a" && echo "INFO T8 some sysctls are host-global and read-only in a netns" || true
ip netns exec "$H" "$BIN" tune --from "$WORK/hydra.json" | tee "$WORK/t8b"

echo "=== T10 one profile, two fronts on one IP"
dns lab-2-wg.example.com 198.51.100.10
python3 - "$WORK/hydra.json" "$WORK/multi.json" "$(dc_id lab-2-wg.example.com)" <<'PY2'
import json, sys
p = json.load(open(sys.argv[1]))
f = dict(p["fronts"][0]); f["entry_port"] = 8443
f["datacenter"] = "lab-2-wg.example.com"; f["datacenter_id"] = int(sys.argv[3])
p["fronts"].append(f)
json.dump(p, open(sys.argv[2], "w"))
PY2
hydra up --state "$ST" --from "$WORK/multi.json" --write "$WORK/multi.json" 2>&1 | tail -1
[[ "$(ip netns exec "$H" nft list chain inet hydra prerouting | grep -c dnat)" == 2 ]] && pass "T10 two DNAT rules" || fail T10
ip netns exec "$H" "$BIN" status --from "$WORK/multi.json"

echo "=== T11 two IPs to two datacenters, one datacenter per profile"
ip -n "$H" addr add 203.0.113.3/24 dev hc0
ip -n "$E" addr add 198.51.100.20/24 dev eh0
hydra down --forget --state "$ST"
dcname() { echo "dc-${1##*.}-wg.example.com"; } # a one-server datacenter, its id the server's last octet
dns "$(dcname 198.51.100.10)" 198.51.100.10
dns "$(dcname 198.51.100.20)" 198.51.100.20
entry() { # listen server write [more up flags]: an entry to the server's one-server datacenter
  local listen="$1" server="$2" write="$3"; shift 3
  hydra up --state "$ST" --listen "$listen" --datacenter "$(dcname "$server")" --status-url "$LIST" --wg-zone example.com --label Lab \
    --exit-port 51820 --write "$write" "$@" 2>&1 | grep -E "^(replaced|forwarding|this host)"
}
entry 203.0.113.1 198.51.100.10 "$WORK/a.json"
entry 203.0.113.3 198.51.100.20 "$WORK/b.json"
[[ "$(ip netns exec "$H" nft list chain inet hydra prerouting | grep -c dnat)" == 2 ]] && pass "T11 two DNAT rules" || fail "T11 rules"
python3 - "$WORK/a.json" "$WORK/b.json" <<'PY3'
import json, sys
for path, dc, dc_id in zip(sys.argv[1:3], ["dc-10-wg.example.com", "dc-20-wg.example.com"], [10, 20]):
    fronts = json.load(open(path))["fronts"]
    assert len(fronts) == 1 and fronts[0]["datacenter"] == dc, (path, fronts)
    assert fronts[0]["datacenter_id"] == dc_id, (path, fronts)
    assert "exit_ip" not in fronts[0] and "exit_hostname" not in fronts[0], fronts
PY3
pass "T11 each profile names one datacenter by its hostname and the list's id, and no server"
read -r ok seen <<<"$(roundtrip_via 203.0.113.1 198.51.100.10 5)"
[[ "$ok" == 5 && "$seen" == 203.0.113.1 ]] && pass "T11 203.0.113.1 reaches 198.51.100.10, which sees $seen" || fail "T11 a ok=$ok seen=$seen"
read -r ok seen <<<"$(roundtrip_via 203.0.113.3 198.51.100.20 5)"
[[ "$ok" == 5 && "$seen" == 203.0.113.3 ]] && pass "T11 203.0.113.3 reaches 198.51.100.20, which sees $seen" || fail "T11 b ok=$ok seen=$seen"

echo "=== T11b two entries to one server each leave from their own address"
entry 203.0.113.3 198.51.100.10 "$WORK/b.json"
read -r ok seen <<<"$(roundtrip_via 203.0.113.3 198.51.100.10 5)"
[[ "$ok" == 5 && "$seen" == 203.0.113.3 ]] && pass "T11b via 203.0.113.3, the server sees $seen" || fail "T11b b ok=$ok seen=$seen"
read -r ok seen <<<"$(roundtrip_via 203.0.113.1 198.51.100.10 5)"
[[ "$ok" == 5 && "$seen" == 203.0.113.1 ]] && pass "T11b via 203.0.113.1, the server sees $seen" || fail "T11b a ok=$ok seen=$seen"

echo "=== T12 export all entries or one, remove one, stop, apply"
hydra export --state "$ST" | python3 -c 'import json, sys; p = json.load(sys.stdin); assert sorted(f["entry_ip"] for f in p["fronts"]) == ["203.0.113.1", "203.0.113.3"] and "all" not in p, p' \
  && pass "T12 export prints one profile for both entries" || fail "T12 export"
hydra export --state "$ST" --entry 203.0.113.3:443 | python3 -c 'import json, sys; f = json.load(sys.stdin)["fronts"]; assert len(f) == 1 and f[0]["entry_ip"] == "203.0.113.3", f' \
  && pass "T12 export --entry prints one front" || fail "T12 export --entry"
hydra down --state "$ST" --entry 203.0.113.1:443
read -r ok _ <<<"$(roundtrip_via 203.0.113.1 198.51.100.10 2)"
[[ "$ok" == 0 ]] && pass "T12 the removed entry no longer forwards" || fail "T12 removed ok=$ok"
read -r ok _ <<<"$(roundtrip_via 203.0.113.3 198.51.100.10 3)"
[[ "$ok" == 3 ]] && pass "T12 the other entry still forwards" || fail "T12 other ok=$ok"
hydra down --state "$ST"
read -r ok _ <<<"$(roundtrip_via 203.0.113.3 198.51.100.10 1)"
[[ "$ok" == 0 ]] && pass "T12 down stops forwarding" || fail "T12 down ok=$ok"
hydra apply --state "$ST"
read -r ok _ <<<"$(roundtrip_via 203.0.113.3 198.51.100.10 3)"
[[ "$ok" == 3 ]] && pass "T12 apply forwards the saved entry again" || fail "T12 apply ok=$ok"

echo "=== T13 1:1 NAT with two public IPs, each with its own --bind"
ip netns exec "$C" nft add rule ip edge out ip daddr 192.0.2.51 dnat to 203.0.113.3
entry 192.0.2.50 198.51.100.10 "$WORK/c.json" --bind 203.0.113.1
entry 192.0.2.51 198.51.100.20 "$WORK/d.json" --bind 203.0.113.3
grep -q '"entry_ip": "192.0.2.51"' "$WORK/d.json" && pass "T13 profile advertises public 192.0.2.51" || fail "T13 profile"
read -r ok seen <<<"$(roundtrip_via 192.0.2.50 198.51.100.10 5)"
[[ "$ok" == 5 && "$seen" == 203.0.113.1 ]] && pass "T13 192.0.2.50 reaches 198.51.100.10 from $seen" || fail "T13 a ok=$ok seen=$seen"
read -r ok seen <<<"$(roundtrip_via 192.0.2.51 198.51.100.20 5)"
[[ "$ok" == 5 && "$seen" == 203.0.113.3 ]] && pass "T13 192.0.2.51 reaches 198.51.100.20 from $seen" || fail "T13 b ok=$ok seen=$seen"
hydra status --state "$ST"

# drive.py: runs a command in a pseudo-terminal and answers it. Each step waits
# for a piece of screen text, then types keys. Writes transcript.txt (no escape
# codes) and transcript.raw in the working directory; exits with the command's code.
cat >"$WORK/drive.py" <<'PY'
import fcntl, json, os, pty, re, select, struct, sys, termios, time
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-_]|\r")
cwd, steps, cmd = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3:]
pid, fd = pty.fork()
if pid == 0:
    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 160, 0, 0))
    os.chdir(cwd)
    os.environ["TERM"] = "xterm-256color"
    os.execvp(cmd[0], cmd)
raw, pos = b"", 0
def screen():
    return ANSI.sub("", raw.decode("utf-8", "replace"))
def read(timeout):
    global raw
    if not select.select([fd], [], [], timeout)[0]:
        return False
    try:
        chunk = os.read(fd, 65536)
    except OSError:
        return None
    raw += chunk
    return True if chunk else None
for want, keys in steps:
    end = time.time() + 20
    while want not in screen()[pos:]:
        if end <= time.time() or read(end - time.time()) is None:
            sys.exit("never saw %r; the screen ended with:\n%s" % (want, screen()[-3000:]))
    pos = screen().index(want, pos) + len(want)
    time.sleep(0.2)
    os.write(fd, keys.encode())
while read(10) is not None:
    pass
status = os.waitpid(pid, 0)[1]
open(os.path.join(cwd, "transcript.txt"), "w").write(screen())
open(os.path.join(cwd, "transcript.raw"), "wb").write(raw)
sys.exit(os.waitstatus_to_exitcode(status))
PY

# On a host that runs systemd, setup offers to install hydra's units after
# mapping; the lab says no.
BOOT_STEP=
[[ -d /run/systemd/system ]] && BOOT_STEP='["(recommended)", "n"],'

echo "=== T14 hydra setup in a terminal: two addresses to two servers"
mkdir -p "$WORK/t14"
cat >"$WORK/www/setup.json" <<'JSON'
{"data":{"locations":{"1":{"name":"Lab","pops":[
  {"status":1,"datacenter_id":21,"iata_code":"LAB","name":"Lab City - Bench","usage":2},
  {"status":1,"datacenter_id":22,"iata_code":"LAB","name":"Lab City - Pier","usage":9}]}}}}
JSON
dns lab-21-wg.example.com 198.51.100.20
dns lab-22-wg.example.com 198.51.100.10
# The mapping screen lists 203.0.113.1, 203.0.113.3, 198.51.100.1, "a public IP
# this server doesn't show", then Done. The cursor starts on the public-IP
# option (none is public), and on Done once something is mapped; Down wraps.
# The location menu starts on Lab, the only location; its two datacenters are
# listed least loaded first: Bench, then Pier. Keys: \u001b[B is Down, \r Enter.
steps='[
  ["Map which address to a Windscribe location?", "\u001b[B\u001b[B\r"],
  ["Use it anyway?", "y"],
  ["Which UDP port?", "\r"],
  ["Which Windscribe location?", "\r"],
  ["Which datacenter in Lab?", "\r"],
  ["Write the profile to", "\r"],
  ["Start forwarding?", "\r"],
  ["Map which address to a Windscribe location?", "\u001b[B\u001b[B\r"],
  ["Use it anyway?", "y"],
  ["Which UDP port?", "\r"],
  ["Which Windscribe location?", "\r"],
  ["Which datacenter in Lab?", "\u001b[B\r"],
  ["Write the profile to", "lab-1.json\r"],
  ["Start forwarding?", "\r"],
  ["Map which address to a Windscribe location?", "\r"],
  '"$BOOT_STEP"'
  ["What next?", "q"]
]'
SETUP_ST="$WORK/setup-entries.json"
python3 "$WORK/drive.py" "$WORK/t14" "$steps" ip netns exec "$H" "$BIN" setup --state "$SETUP_ST" \
  --status-url http://127.0.0.1:8080/setup.json --wg-zone example.com && pass "T14 setup ran to the end in a terminal" \
  || { cat "$WORK/t14/transcript.txt" 2>/dev/null; fail "T14 setup"; }
grep -q "Done." "$WORK/t14/transcript.txt" && pass "T14 setup said Done" || fail "T14 no Done"
grep -q "Lab City · lowest load 2%" "$WORK/t14/transcript.txt" \
  && pass "T14 the location menu listed Lab with its city and load" || fail "T14 location menu"
grep -q "203.0.113.1      hc0      not public · :443 → Lab City · Bench" "$WORK/t14/transcript.txt" \
  && pass "T14 the mapping screen showed 203.0.113.1 mapped" || fail "T14 mapping screen"
python3 - "$SETUP_ST" "$WORK/t14/lab-city.json" "$WORK/t14/lab-1.json" <<'PY3'
import json, sys
st = json.load(open(sys.argv[1]))
got = [(e["profile"]["fronts"][0]["entry_ip"], e["profile"]["fronts"][0]["datacenter"]) for e in st["entries"]]
assert got == [("203.0.113.1", "lab-21-wg.example.com"), ("203.0.113.3", "lab-22-wg.example.com")], got
for path, dc, dc_id in zip(sys.argv[2:], ["lab-21-wg.example.com", "lab-22-wg.example.com"], [21, 22]):
    fronts = json.load(open(path))["fronts"]
    assert len(fronts) == 1 and fronts[0]["datacenter"] == dc, (path, fronts)
    assert fronts[0]["datacenter_id"] == dc_id, (path, fronts)
PY3
pass "T14 two entries saved; each profile names one datacenter"
grep -q "lab-[12].example" "$WORK/t14/transcript.txt" && fail "T14 a server name was shown" || pass "T14 no server names on screen"
read -r ok seen <<<"$(roundtrip_via 203.0.113.1 198.51.100.20 5 443)"
[[ "$ok" == 5 && "$seen" == 203.0.113.1 ]] && pass "T14 203.0.113.1 reaches Bench's server from $seen" || fail "T14 a ok=$ok seen=$seen"
read -r ok seen <<<"$(roundtrip_via 203.0.113.3 198.51.100.10 5 443)"
[[ "$ok" == 5 && "$seen" == 203.0.113.3 ]] && pass "T14 203.0.113.3 reaches Pier's server from $seen" || fail "T14 b ok=$ok seen=$seen"
hydra status --state "$SETUP_ST"

echo "=== T15 hydra on its own in a terminal starts setup; Ctrl-C leaves it"
mkdir -p "$WORK/t15"
set +e
python3 "$WORK/drive.py" "$WORK/t15" '[["Map which address to a Windscribe location?", "\u0003"]]' ip netns exec "$H" "$BIN"
rc=$?
set -e
[[ $rc -eq 1 ]] && grep -q "setup stopped (Ctrl-C)" "$WORK/t15/transcript.txt" && pass "T15 Ctrl-C stops setup (exit 1)" \
  || { cat "$WORK/t15/transcript.txt"; fail "T15 rc=$rc"; }
[[ ! -e /etc/hydra/entries.json ]] && pass "T15 nothing saved" || fail "T15 entries saved"
python3 -c 'import sys; r = open(sys.argv[1], "rb").read(); assert r.rfind(b"\x1b[?25h") > r.rfind(b"\x1b[?25l"), "cursor left hidden"' \
  "$WORK/t15/transcript.raw" && pass "T15 the cursor is visible again" || fail "T15 cursor"

echo "=== T16 an entry spreads over its datacenter's servers and follows them"
hydra down --forget --state "$ST"
dns ha-7-wg.example.com 198.51.100.10 198.51.100.20
hydra up --state "$ST" --listen 203.0.113.3 --datacenter ha-7-wg.example.com --status-url "$LIST" --wg-zone example.com --label HA \
  --exit-port 51820 --write "$WORK/ha.json" 2>&1 | grep -E "^forwarding"
ip netns exec "$H" nft list chain inet hydra prerouting | grep -q "jhash ip saddr . udp sport mod 2" \
  && pass "T16 one entry, two servers" || fail "T16 rules"
# New clients (new source ports) land on both servers.
ECHOS=()
for ip in 198.51.100.10 198.51.100.20; do
  ip netns exec "$E" python3 "$WORK/echo.py" "$WORK/seen-$ip" 40 "$ip" 51820 &
  ECHOS+=($!)
done
sleep 0.3
for _ in $(seq 16); do ip netns exec "$C" python3 "$WORK/client.py" 203.0.113.3 1 >/dev/null; done
wait "${ECHOS[@]}"
[[ -s "$WORK/seen-198.51.100.10" && -s "$WORK/seen-198.51.100.20" ]] \
  && pass "T16 16 new clients reached both servers" || fail "T16 spread: $(ls -s "$WORK"/seen-*)"
rm -f "$WORK"/seen-*

# One client keeps its source port while a server leaves DNS: its next packets
# reach the other server, with no reconnect. Both servers stay up, so only
# hydra clearing the old connection can move it.
cat >"$WORK/echo_id.py" <<'PY'
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 51820)); s.settimeout(0.5)
end = time.time() + float(sys.argv[2])
while time.time() < end:
    try:
        data, addr = s.recvfrom(64)
    except socket.timeout:
        continue
    s.sendto(sys.argv[1].encode(), addr)
PY
cat >"$WORK/steady.py" <<'PY'
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(0.3)
seen = []
end = time.time() + float(sys.argv[2])
while time.time() < end:
    s.sendto(b"ping", (sys.argv[1], 443))
    try:
        seen.append(s.recvfrom(64)[0].decode())
    except socket.timeout:
        seen.append("-")
    time.sleep(0.2)
open(sys.argv[3], "w").write(" ".join(seen))
PY
dns ha-7-wg.example.com 198.51.100.20
hydra apply --refresh --state "$ST" 2>&1 | tail -1
ECHOS=()
for ip in 198.51.100.10 198.51.100.20; do ip netns exec "$E" python3 "$WORK/echo_id.py" "$ip" 9 & ECHOS+=($!); done
sleep 0.3
ip netns exec "$C" python3 "$WORK/steady.py" 203.0.113.3 8 "$WORK/steady" &
STEADY=$!
sleep 3
dns ha-7-wg.example.com 198.51.100.10
hydra apply --refresh --state "$ST" 2>&1 | tail -1
wait "$STEADY" "${ECHOS[@]}"
echo "INFO T16 replies, in order: $(cat "$WORK/steady")"
python3 - "$WORK/steady" <<'PY3'
import sys
seen = open(sys.argv[1]).read().split()
first = next(r for r in seen if r != "-")
last = [r for r in seen if r != "-"][-1]
assert first == "198.51.100.20" and last == "198.51.100.10", seen
assert seen.count("-") <= 2, seen
PY3
pass "T16 a connected client moved to the server left, without reconnecting"

hydra down --state "$ST" >/dev/null 2>&1
dns ha-7-wg.example.com
out="$(hydra apply --state "$ST" 2>&1)"
grep -q "keeping the addresses it had" <<<"$out" && pass "T16 DNS failing keeps the servers known" \
  || { echo "$out"; fail "T16 DNS failure"; }
hydra down --state "$ST" >/dev/null 2>&1
dns ha-7-wg.example.com 198.51.100.20
hydra apply --refresh --state "$ST" >/dev/null 2>&1
ip netns exec "$H" nft list tables | grep -q "inet hydra" && fail "T16 refresh started forwarding" \
  || pass "T16 refresh leaves stopped forwarding stopped"
grep -q '"198.51.100.20"' "$ST" && pass "T16 ...and remembers the new servers" || fail "T16 state"

echo "=== T9 down removes the table"
hydra down --state "$ST"
ip netns exec "$H" nft list tables | grep -q "inet hydra" && fail T9 || pass "T9 table removed"
hydra down --state "$ST" && pass "T9 down is idempotent"

echo "=== T17 ranges: a routed one works as it is, an on-link one once hydra holds the address"
ip -n "$H" addr add 45.33.30.1/24 dev hc0
ip -n "$H" addr add 45.33.31.1/28 dev hc0
ip -n "$C" route add 45.33.30.0/24 via 203.0.113.1
ip -n "$C" addr add 45.33.31.14/28 dev ch0
# A host on the far side of the router that answers TCP, as the one
# Windscribe's locations come from does.
ip netns exec "$C" python3 -m http.server 8081 --bind 203.0.113.2 --directory "$WORK/www" >/dev/null 2>&1 &
WWW2=$!
for _ in $(seq 100); do
  ip netns exec "$H" python3 -c 'import socket; socket.create_connection(("203.0.113.2", 8081), 0.2)' 2>/dev/null && break
  sleep 0.1
done
FAR=http://203.0.113.2:8081/WebsiteStatus
ST2="$WORK/range-entries.json"
hydra check-range 45.33.30.0/24 --status-url "$FAR" --state "$ST2" | tee "$WORK/t17"
grep -q "45.33.30.0/24: routed to this server" "$WORK/t17" && pass "T17 check-range: the /24 is routed here" || fail "T17 routed"
hydra check-range 45.33.31.0/28 --status-url "$FAR" --state "$ST2" | tee "$WORK/t17"
grep -q "45.33.31.0/28: not routed to this server" "$WORK/t17" && pass "T17 check-range: the /28 is on the link" || fail "T17 on-link"
ip netns exec "$H" nft list tables | grep -q hydra_probe && fail "T17 the check left its table" || pass "T17 the check cleans up"

dns lab-31-wg.example.com 198.51.100.10
ranged() { hydra up --state "$ST2" --datacenter lab-31-wg.example.com --status-url "$LIST" --wg-zone example.com --label Lab \
  --exit-port 51820 --write "$WORK/r.json" "$@" 2>&1 | grep -E "^(forwarding|replaced)|range"; }
ranged --listen 45.33.30.5
read -r ok seen <<<"$(roundtrip_via 45.33.30.5 198.51.100.10 5)"
[[ "$ok" == 5 && "$seen" == 45.33.30.5 ]] && pass "T17 routed 45.33.30.5 forwards, the server sees $seen" || fail "T17 routed ok=$ok seen=$seen"
ip -n "$H" -4 addr show | grep -q "45.33.30.5" && fail "T17 hydra added a routed address" || pass "T17 ...without hydra adding it"
ranged --listen 45.33.31.5
read -r ok _ <<<"$(roundtrip_via 45.33.31.5 198.51.100.10 2)"
[[ "$ok" == 0 ]] && pass "T17 on-link 45.33.31.5 doesn't reach hydra on its own" || fail "T17 on-link without the address ok=$ok"
ranged --listen 45.33.31.5 --add-address
ip -n "$H" -4 addr show dev hc0 | grep -q "inet 45.33.31.5/32" && pass "T17 --add-address holds 45.33.31.5/32 on hc0" || fail "T17 not held"
ip -n "$C" neigh flush dev ch0
read -r ok seen <<<"$(roundtrip_via 45.33.31.5 198.51.100.10 5)"
[[ "$ok" == 5 && "$seen" == 45.33.31.5 ]] && pass "T17 ...and it forwards, the server sees $seen" || fail "T17 held ok=$ok seen=$seen"
hydra down --state "$ST2"
ip -n "$H" -4 addr show | grep -q "45.33.31.5/32" && fail "T17 down kept the address" || pass "T17 down lets the address go"
hydra apply --state "$ST2" --skip-sysctl
ip -n "$H" -4 addr show dev hc0 | grep -q "inet 45.33.31.5/32" && pass "T17 apply (at boot) holds it again" || fail "T17 apply"
hydra down --state "$ST2" --entry 45.33.31.5:443
ip -n "$H" -4 addr show | grep -q "45.33.31.5/32" && fail "T17 the removed entry kept its address" || pass "T17 removing the entry lets the address go"
hydra down --state "$ST2" --forget

echo "=== T18 hydra setup maps every location to a routed range"
mkdir -p "$WORK/t18"
cat >"$WORK/www/range.json" <<'JSON'
{"data":{"locations":{"1":{"name":"Lab","pops":[
  {"status":1,"datacenter_id":41,"iata_code":"LAB","name":"Lab City - Bench","usage":2},
  {"status":1,"datacenter_id":42,"iata_code":"LAB","name":"Lab City - Pier","usage":5},
  {"status":1,"datacenter_id":43,"iata_code":"LAB","name":"Lab City - Dock","usage":9}]}}}}
JSON
for id in 41 42 43; do dns "lab-$id-wg.example.com" 198.51.100.10; done
# hydra's two public addresses aren't enough for three locations; the /24 is.
steps='[
  ["Map all 3 locations to addresses in 45.33.30.0/24?", "y"],
  ["Is all of 45.33.30.0/24 assigned to this server by your provider?", "y"],
  ["Write the profile to", "\r"],
  '"$BOOT_STEP"'
  ["What next?", "q"]
]'
python3 "$WORK/drive.py" "$WORK/t18" "$steps" ip netns exec "$H" "$BIN" setup --state "$WORK/t18-entries.json" \
  --status-url http://203.0.113.2:8081/range.json --wg-zone example.com && pass "T18 setup ran to the end" \
  || { cat "$WORK/t18/transcript.txt" 2>/dev/null; fail "T18 setup"; }
grep -q "45.33.30.0/24 is routed to this server" "$WORK/t18/transcript.txt" && pass "T18 setup checked the range: routed" \
  || { cat "$WORK/t18/transcript.txt"; fail "T18 check"; }
python3 - "$WORK/t18-entries.json" "$WORK/t18/hydra.json" <<'PY3'
import json, sys
st = json.load(open(sys.argv[1]))
ips = sorted(e["profile"]["fronts"][0]["entry_ip"] for e in st["entries"])
assert ips == ["45.33.30.2", "45.33.30.3", "45.33.30.4"], ips
assert not any("claim" in e for e in st["entries"]), st["entries"]
assert st["ranges"] == [{"cidr": "45.33.30.0/24", "iface": "hc0", "claim": False}], st["ranges"]
assert json.load(open(sys.argv[2]))["all"] is True
PY3
pass "T18 three entries on 45.33.30.2-4, none held; one profile for every location"
read -r ok seen <<<"$(roundtrip_via 45.33.30.4 198.51.100.10 5 443)"
[[ "$ok" == 5 && "$seen" == 45.33.30.4 ]] && pass "T18 45.33.30.4 forwards, the server sees $seen" || fail "T18 ok=$ok seen=$seen"
hydra down --state "$WORK/t18-entries.json" --forget

echo "ALL PASS"
