#!/usr/bin/env bash
# Enroll a host as an exit for sites that refuse the cloud exit.
#
#   ./deploy/add-exit.sh --id hestia --host hestia
#
# The host keeps the private key; this script reads or creates it there, writes
# the host's WireGuard interface, adds the peer to Aegis and upserts the exit
# registry. Idempotent.
#
# Environment:
#   AEGIS_HOST     ssh host of the exit server      (default aegis)
#   EXIT_ENDPOINT  Aegis WireGuard endpoint         (default 152.69.174.7:7105)
#   AEGIS_DEV      Aegis tunnel interface           (default wg0)
#   REGISTRY       registry path on Aegis           (default /var/lib/bypass/exits.json)

set -euo pipefail
umask 077

AEGIS_HOST="${AEGIS_HOST:-aegis}"
AEGIS_DEV="${AEGIS_DEV:-wg0}"
EXIT_ENDPOINT="${EXIT_ENDPOINT:-152.69.174.7:7105}"
REGISTRY="${REGISTRY:-/var/lib/bypass/exits.json}"

note() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10)

id=""
host_ssh=""
label=""
priority=100
max_prefixes=200
network=""

while [ $# -gt 0 ]; do
    case "$1" in
        --id)           id="$2"; shift 2 ;;
        --host)         host_ssh="$2"; shift 2 ;;
        --label)        label="$2"; shift 2 ;;
        --priority)     priority="$2"; shift 2 ;;
        --max-prefixes) max_prefixes="$2"; shift 2 ;;
        --network)      network="$2"; shift 2 ;;
        -h|--help)      sed -n '2,20p' "$0"; exit 0 ;;
        *)              die "unknown argument: $1" ;;
    esac
done

[ -n "$id" ] && [ -n "$host_ssh" ] || die "usage: $0 --id <name> --host <ssh host> [--priority N] [--max-prefixes N] [--network <feed id>]"
[[ "$id" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "id must be lowercase letters, digits and hyphens"
[ -n "$label" ] || label="$id"

ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n true" >/dev/null 2>&1 \
    || die "cannot ssh to $AEGIS_HOST with passwordless sudo"
ssh "${ssh_opts[@]}" "$host_ssh" "sudo -n true" >/dev/null 2>&1 \
    || die "cannot ssh to $host_ssh with passwordless sudo"

note "== $host_ssh: key and interface"
ssh "${ssh_opts[@]}" "$host_ssh" 'command -v wg >/dev/null 2>&1 || sudo -n apt-get install -y -qq wireguard-tools >/dev/null'
ssh "${ssh_opts[@]}" "$host_ssh" \
    'sudo -n sh -c "umask 077; test -s /etc/wireguard/wgexit.key || wg genkey > /etc/wireguard/wgexit.key; chmod 600 /etc/wireguard/wgexit.key"'
pub=$(ssh "${ssh_opts[@]}" "$host_ssh" 'sudo -n sh -c "wg pubkey < /etc/wireguard/wgexit.key"')
[ -n "$pub" ] || die "could not read the exit public key"
aegis_pub=$(ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n wg show $AEGIS_DEV public-key")
[ -n "$aegis_pub" ] || die "could not read the Aegis public key"
uplink=$(ssh "${ssh_opts[@]}" "$host_ssh" "ip route show default | awk '/^default/{print \$5; exit}'")
[ -n "$uplink" ] || die "could not find the uplink interface on $host_ssh"

note "== registry"
index=$(ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n python3 - '$REGISTRY' '$id' '$label' '$pub' '$priority' '$max_prefixes' '$network' '$host_ssh'" <<'PY'
import json, os, sys
path, ident, label, pub, priority, maxp, network, host = sys.argv[1:9]
reg = {"version": 1, "exits": []}
if os.path.exists(path):
    try:
        reg = json.load(open(path))
    except Exception:
        reg = {"version": 1, "exits": []}
exits = reg.setdefault("exits", [])
entry = next((e for e in exits if e.get("id") == ident), None)
if entry is None:
    entry = {"id": ident}
    exits.append(entry)
entry.update({
    "id": ident,
    "label": label,
    "pubkey": pub,
    "enabled": True,
    "priority": int(priority),
    "max_prefixes": int(maxp),
    "host": host,
})
if network:
    entry["network"] = network
elif "network" in entry:
    entry.pop("network")
# Index for the host's tunnel address, stable for the life of the entry.
ids = [e["id"] for e in exits]
index = ids.index(ident) + 2
entry["address"] = "10.99.0.%d" % index
reg["version"] = 1
os.makedirs(os.path.dirname(path), exist_ok=True)
tmp = path + ".tmp"
open(tmp, "w").write(json.dumps(reg, indent=2, sort_keys=True) + "\n")
os.chmod(tmp, 0o644)
os.replace(tmp, path)
print(index)
PY
)
[ -n "$index" ] || die "could not write the registry"
# The web admin may toggle an exit, so the service user owns the file.
ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n chown bypass:bypass '$REGISTRY' 2>/dev/null || true"
note "registered $id (host address 10.99.0.$index)"

note "== $host_ssh: exit interface"
set +e
ssh "${ssh_opts[@]}" "$host_ssh" 'sudo -n bash -s' -- "$aegis_pub" "$EXIT_ENDPOINT" "$uplink" "$index" <<'SH'
set -euo pipefail
pub=$1; endpoint=$2; uplink=$3; index=$4
tmp=/etc/wireguard/wgexit.conf.new
{
    printf '%s\n' '[Interface]'
    printf 'PrivateKey = '; cat /etc/wireguard/wgexit.key
    printf '%s\n' \
        "Address = 10.99.0.$index/32" \
        'MTU = 1420' \
        'PostUp = sysctl -qw net.ipv4.ip_forward=1; ip route replace 10.88.0.0/24 dev %i' \
        "PostUp = iptables -C FORWARD -i %i -o $uplink -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i %i -o $uplink -j ACCEPT" \
        "PostUp = iptables -C FORWARD -i $uplink -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i $uplink -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT" \
        'PostUp = iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu' \
        "PostUp = iptables -t nat -C POSTROUTING -s 10.88.0.0/24 -o $uplink -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.88.0.0/24 -o $uplink -j MASQUERADE" \
        'PostDown = ip route del 10.88.0.0/24 dev %i 2>/dev/null || true' \
        "PostDown = iptables -D FORWARD -i %i -o $uplink -j ACCEPT 2>/dev/null || true" \
        "PostDown = iptables -D FORWARD -i $uplink -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true" \
        'PostDown = iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || true' \
        "PostDown = iptables -t nat -D POSTROUTING -s 10.88.0.0/24 -o $uplink -j MASQUERADE 2>/dev/null || true" \
        '' \
        '[Peer]'
    printf 'PublicKey = %s\n' "$pub"
    printf 'Endpoint = %s\n' "$endpoint"
    printf '%s\n' 'AllowedIPs = 10.88.0.0/24' 'PersistentKeepalive = 25'
} > "$tmp"
chmod 600 "$tmp"
if [ -f /etc/wireguard/wgexit.conf ] && cmp -s "$tmp" /etc/wireguard/wgexit.conf; then
    rm -f "$tmp"
    echo "wgexit.conf unchanged"
    exit 3
fi
mv "$tmp" /etc/wireguard/wgexit.conf
echo "wgexit.conf written"
SH
status=$?
set -e
case "$status" in
    0|3) ;;
    *) die "could not write the exit interface on $host_ssh" ;;
esac
ssh "${ssh_opts[@]}" "$host_ssh" 'sudo -n systemctl enable wg-quick@wgexit >/dev/null 2>&1 || true'
if [ "$status" = 0 ] || ! ssh "${ssh_opts[@]}" "$host_ssh" 'systemctl is-active --quiet wg-quick@wgexit'; then
    ssh "${ssh_opts[@]}" "$host_ssh" 'sudo -n systemctl restart wg-quick@wgexit'
fi

note "== $AEGIS_HOST: peer"
present=$(ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n wg show $AEGIS_DEV peers | grep -F '$pub' || true")
ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n python3 - '/etc/wireguard/$AEGIS_DEV.conf' '$pub' '$id' '$host_ssh'" <<'PY'
import shutil, sys, time
path, pub, ident, host = sys.argv[1:5]
s = open(path).read()
if pub in s:
    print('peer already in the config')
    raise SystemExit
block = f'''
# exit: {ident} ({host}). Routes are assigned by egress-exit; Table = off keeps
# this peer's 0.0.0.0/0 mapping from installing a default route.
[Peer]
PublicKey = {pub}
AllowedIPs = 0.0.0.0/0
'''
shutil.copy2(path, f'{path}.bak-{time.strftime("%Y%m%d-%H%M%S")}')
open(path, 'a').write(block)
print('peer appended to the config')
PY
if [ -z "$present" ]; then
    ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n wg set $AEGIS_DEV peer '$pub' allowed-ips ''"
fi

note "== verify"
for _ in $(seq 1 20); do
    handshake=$(ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n wg show $AEGIS_DEV latest-handshakes | awk -v p='$pub' '\$1==p{print \$2}'")
    [ -n "$handshake" ] && [ "$handshake" != "0" ] && break
    sleep 1
done
[ -n "${handshake:-}" ] && [ "$handshake" != "0" ] || die "the exit has no handshake; check wg-quick@wgexit on $host_ssh"
note "handshake: $handshake"
note "exit $id is enrolled. The learner assigns prefixes on its next cycle."
