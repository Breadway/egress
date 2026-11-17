#!/usr/bin/env bash
# Install the exit router on Aegis.
#
# The router decides which destination prefixes leave through which enrolled
# exit. Enroll exits separately:
#
#   ./deploy/install-exit.sh
#   ./deploy/add-exit.sh --id hestia --host hestia
#
# Idempotent. Environment: AEGIS_HOST (default aegis), AEGIS_DEV (default wg0).

set -euo pipefail
umask 077

AEGIS_HOST="${AEGIS_HOST:-aegis}"
AEGIS_DEV="${AEGIS_DEV:-wg0}"
REGISTRY="${REGISTRY:-/var/lib/bypass/exits.json}"

note() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10)

[ -f go.mod ] && [ -d internal/exitroute ] || die "run this from the egress repo root"
command -v go >/dev/null 2>&1 || die "go is required"
ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n true" >/dev/null 2>&1 \
    || die "cannot ssh to $AEGIS_HOST with passwordless sudo"

note "== learner binary and unit"
mkdir -p dist
GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags '-s -w' -o dist/egress-exit ./cmd/egress-exit
want_sum=$(sha256sum dist/egress-exit | awk '{print $1}')
have_sum=$(ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sha256sum /usr/local/bin/egress-exit 2>/dev/null | awk '{print \$1}' || true")
changed=0
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
ssh "${ssh_opts[@]}" "$AEGIS_HOST" 'sudo -n install -d -m 0755 /etc/egress-exit /var/lib/egress-exit'
ssh "${ssh_opts[@]}" "$AEGIS_HOST" 'if [ ! -f /etc/egress-exit/domains ]; then printf "# Extra candidates for the exit router, one domain per line.\n# The shared block table is the main source; this file is for names the\n# fleet has not reported yet.\n" | sudo -n tee /etc/egress-exit/domains >/dev/null; fi'
ssh "${ssh_opts[@]}" "$AEGIS_HOST" 'sudo -n systemctl daemon-reload && sudo -n systemctl enable egress-exit >/dev/null'

note "== $AEGIS_DEV: table and restore route"
before=$(ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n sha256sum /etc/wireguard/$AEGIS_DEV.conf | awk '{print \$1}'")
ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n python3 - '$AEGIS_DEV'" <<'PY'
import sys
dev = sys.argv[1]
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
if out == s:
    print(f'{dev}.conf unchanged')
else:
    import shutil, time
    shutil.copy2(path, f'{path}.bak-{time.strftime("%Y%m%d-%H%M%S")}')
    open(path, 'w').write(out)
    print(f'{dev}.conf updated')
PY
after=$(ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n sha256sum /etc/wireguard/$AEGIS_DEV.conf | awk '{print \$1}'")

# The previous single-exit version used fwmark 0x45 with a default route in
# table 811. Nothing marks that traffic any more.
ssh "${ssh_opts[@]}" "$AEGIS_HOST" 'sudo -n ip rule del fwmark 0x45/0xff 2>/dev/null || true; sudo -n ip route flush table 811 2>/dev/null || true'

if [ "$changed" = 1 ] || [ "$unit_changed" = 1 ] || ! ssh "${ssh_opts[@]}" "$AEGIS_HOST" 'systemctl is-active --quiet egress-exit'; then
    ssh "${ssh_opts[@]}" "$AEGIS_HOST" 'sudo -n systemctl restart egress-exit'
fi

note "== verify"
exits=$(ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n python3 -c \"import json;d=json.load(open('$REGISTRY'));print(len(d.get('exits',[])))\" 2>/dev/null || echo 0")
if [ "$exits" = 0 ]; then
    note "no exits enrolled yet: enroll one with ./deploy/add-exit.sh --id hestia --host hestia"
    note "until then every blocked name is unserved and the cloud exit is used."
else
    ssh "${ssh_opts[@]}" "$AEGIS_HOST" 'sudo -n python3 -c "import json;d=json.load(open(\"/var/lib/egress-exit/status.json\"));print(\"exits:\", [(e[\"id\"], e[\"healthy\"], e[\"prefixes\"]) for e in d[\"exits\"]]);print(\"unserved:\", d[\"unserved\"])"' 2>/dev/null || true
fi
ssh "${ssh_opts[@]}" "$AEGIS_HOST" 'systemctl is-active --quiet egress-exit' || die "egress-exit is not running"

if [ "$before" != "$after" ]; then
    note ""
    note "$AEGIS_DEV.conf changed. Table = off and the restore route take effect"
    note "on the next restart; Table = off is what keeps an exit peer's"
    note "0.0.0.0/0 mapping from installing a default route."
fi
if [ "$changed" = 0 ] && [ "$unit_changed" = 0 ] && [ "$before" = "$after" ]; then
    note "no changes"
fi
