#!/usr/bin/env bash
# Install the residential exit used for sites that refuse the cloud exit.
#
#   hestia (home) --WireGuard--> Aegis wg0 --policy routes--> learned prefixes
#
# Run from the egress repo root. Idempotent: a second run reports no changes.
#
#   ./deploy/install-exit.sh
#
# Environment:
#   AEGIS_HOST     ssh host of the exit server        (default aegis)
#   HESTIA_HOST    ssh host of the residential exit   (default hestia)
#   EXIT_ENDPOINT  Aegis WireGuard endpoint           (default 152.69.174.7:7105)
#   AEGIS_DEV      Aegis tunnel interface             (default wg0)
#   CLOUD_DEV      Aegis cloud-facing interface       (default ens3)
#
# The hestia private key is generated on hestia and never leaves it. Nothing
# here restarts wg0: the peer is applied live with `wg set`, and the config
# change (Table = off) only matters on the server's next restart.

set -euo pipefail
umask 077

AEGIS_HOST="${AEGIS_HOST:-aegis}"
HESTIA_HOST="${HESTIA_HOST:-hestia}"
EXIT_ENDPOINT="${EXIT_ENDPOINT:-152.69.174.7:7105}"
AEGIS_DEV="${AEGIS_DEV:-wg0}"
CLOUD_DEV="${CLOUD_DEV:-ens3}"

note() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
changed=0

[ -f go.mod ] && [ -d internal/exitroute ] || die "run this from the egress repo root"
command -v go >/dev/null 2>&1 || die "go is required"
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10)

for host in "$AEGIS_HOST" "$HESTIA_HOST"; do
    ssh "${ssh_opts[@]}" "$host" "sudo -n true" >/dev/null 2>&1 \
        || die "cannot ssh to $host with passwordless sudo"
done

note "== hestia key and Aegis identity"
ssh "${ssh_opts[@]}" "$HESTIA_HOST" 'command -v wg >/dev/null 2>&1 || sudo -n apt-get install -y -qq wireguard-tools >/dev/null' \
    || die "could not install wireguard-tools on $HESTIA_HOST"
ssh "${ssh_opts[@]}" "$HESTIA_HOST" \
    'sudo -n sh -c "umask 077; test -s /etc/wireguard/wgexit.key || wg genkey > /etc/wireguard/wgexit.key; chmod 600 /etc/wireguard/wgexit.key"' \
    || die "could not prepare the hestia key"
hestia_pub=$(ssh "${ssh_opts[@]}" "$HESTIA_HOST" 'sudo -n sh -c "wg pubkey < /etc/wireguard/wgexit.key"')
aegis_pub=$(ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n wg show $AEGIS_DEV public-key")
[ -n "$hestia_pub" ] || die "could not read the hestia public key"
[ -n "$aegis_pub" ] || die "could not read the Aegis public key"
uplink=$(ssh "${ssh_opts[@]}" "$HESTIA_HOST" "ip route show default | awk '/^default/{print \$5; exit}'")
[ -n "$uplink" ] || die "could not find hestia's uplink interface"
note "hestia $hestia_pub via $uplink -> $EXIT_ENDPOINT ($AEGIS_DEV)"

note "== learner binary and unit"
mkdir -p dist
GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags '-s -w' -o dist/egress-exit ./cmd/egress-exit
want_sum=$(sha256sum dist/egress-exit | awk '{print $1}')
have_sum=$(ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sha256sum /usr/local/bin/egress-exit 2>/dev/null | awk '{print \$1}' || true")
if [ "$want_sum" != "$have_sum" ]; then
    ssh "${ssh_opts[@]}" "$AEGIS_HOST" 'sudo -n install -o root -g root -m 0755 /dev/stdin /usr/local/bin/egress-exit' < dist/egress-exit
    note "installed egress-exit $want_sum"
    changed=1
else
    note "egress-exit is up to date"
fi

unit_changed=0
if ! ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n cmp -s /dev/stdin /etc/systemd/system/egress-exit.service" < deploy/egress-exit.service; then
    ssh "${ssh_opts[@]}" "$AEGIS_HOST" 'sudo -n install -D -m 0644 /dev/stdin /etc/systemd/system/egress-exit.service' < deploy/egress-exit.service
    unit_changed=1
    changed=1
    note "updated egress-exit.service"
fi
ssh "${ssh_opts[@]}" "$AEGIS_HOST" 'sudo -n install -d -m 0755 /etc/egress-exit && if [ ! -f /etc/egress-exit/domains ]; then printf "# Extra candidates for the residential exit learner, one domain per line.\n# The shared block table is the main source; this file is for names the\n# fleet has not reported yet.\n" | sudo -n tee /etc/egress-exit/domains >/dev/null; fi'
ssh "${ssh_opts[@]}" "$AEGIS_HOST" 'sudo -n systemctl daemon-reload && sudo -n systemctl enable egress-exit >/dev/null'
if [ "$unit_changed" = 1 ] || ! ssh "${ssh_opts[@]}" "$AEGIS_HOST" 'systemctl is-active --quiet egress-exit'; then
    ssh "${ssh_opts[@]}" "$AEGIS_HOST" 'sudo -n systemctl restart egress-exit'
fi

note "== Aegis $AEGIS_DEV: peer, table and restore route"
before=$(ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n sha256sum /etc/wireguard/$AEGIS_DEV.conf | awk '{print \$1}'")
ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n python3 - '$hestia_pub' '$AEGIS_DEV'" <<'PY'
import shutil, sys, time
pub, dev = sys.argv[1], sys.argv[2]
path = f'/etc/wireguard/{dev}.conf'
s = open(path).read()
out = s
if 'Table = off' not in out:
    if '\nListenPort = ' in out:
        out = out.replace('\nListenPort = ', '\nTable = off\nListenPort = ', 1)
    else:
        out = '[Interface]\nTable = off\n' + out.split('[Interface]\n', 1)[-1]
if f'ip route replace 10.88.0.0/24 dev {dev}' not in out:
    out = out.replace('PostUp = sysctl -w net.ipv4.ip_forward=1;',
                      f'PostUp = sysctl -w net.ipv4.ip_forward=1; ip route replace 10.88.0.0/24 dev {dev};', 1)
if pub not in out:
    out = out.rstrip('\n') + f'''

# residential exit: hestia. Aegis routes only the prefixes the cloud exit gets
# rejected on here; hestia NATs them out its home link. Learned by egress-exit.
[Peer]
PublicKey = {pub}
AllowedIPs = 0.0.0.0/0
'''
if out == s:
    print(f'{dev}.conf unchanged')
else:
    shutil.copy2(path, f'{path}.bak-{time.strftime("%Y%m%d-%H%M%S")}')
    open(path, 'w').write(out)
    print(f'{dev}.conf updated')
PY
after=$(ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n sha256sum /etc/wireguard/$AEGIS_DEV.conf | awk '{print \$1}'")
conf_changed=0
if [ "$before" != "$after" ]; then
    conf_changed=1
    changed=1
fi
ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n wg set $AEGIS_DEV peer '$hestia_pub' allowed-ips 0.0.0.0/0"

note "== hestia: exit interface"
set +e
ssh "${ssh_opts[@]}" "$HESTIA_HOST" 'sudo -n bash -s' -- "$aegis_pub" "$EXIT_ENDPOINT" "$uplink" <<'SH'
set -euo pipefail
pub=$1; endpoint=$2; uplink=$3
tmp=/etc/wireguard/wgexit.conf.new
{
    printf '%s\n' '[Interface]'
    printf 'PrivateKey = '; cat /etc/wireguard/wgexit.key
    printf '%s\n' \
        'Address = 10.99.0.2/32' \
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
hestia_status=$?
set -e
case "$hestia_status" in
    0) hestia_changed=1; changed=1 ;;
    3) hestia_changed=0 ;;
    *) die "could not write hestia's exit config" ;;
esac
ssh "${ssh_opts[@]}" "$HESTIA_HOST" 'sudo -n systemctl enable wg-quick@wgexit >/dev/null 2>&1 || true'
if [ "$hestia_changed" = 1 ] || ! ssh "${ssh_opts[@]}" "$HESTIA_HOST" 'systemctl is-active --quiet wg-quick@wgexit'; then
    ssh "${ssh_opts[@]}" "$HESTIA_HOST" 'sudo -n systemctl restart wg-quick@wgexit'
fi

note "== verify"
handshake=$(ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n wg show $AEGIS_DEV latest-handshakes | awk -v p='$hestia_pub' '\$1==p{print \$2}'")
[ -n "$handshake" ] || die "the hestia peer has no handshake yet; check wgexit on $HESTIA_HOST"
note "hestia handshake: $handshake"
routed=$(ssh "${ssh_opts[@]}" "$AEGIS_HOST" "ip route show dev $AEGIS_DEV | grep -v '10.88.0.0/24' | grep -c . || true")
note "learned prefixes currently routed: $routed"
ssh "${ssh_opts[@]}" "$AEGIS_HOST" 'systemctl is-active --quiet egress-exit' || die "egress-exit is not running"

if [ "$conf_changed" = 1 ]; then
    note ""
    note "wg0.conf changed. The peer is live now; Table = off and the restore"
    note "route take effect on the next wg0 restart. Table = off is what keeps"
    note "the residential peer from installing a default route."
fi
if [ "$changed" = 0 ] && [ "$conf_changed" = 0 ] && [ "$hestia_changed" = 0 ]; then
    note "no changes"
fi
