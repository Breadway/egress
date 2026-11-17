#!/usr/bin/env bash
# Remove an enrolled exit.
#
#   ./deploy/remove-exit.sh --id hestia
#
# Removes the registry entry, the live peer and its wg0.conf block, and stops
# the exit interface on the host when the registry recorded one. Add
# --keep-host to leave the host's interface in place.
#
# Environment: AEGIS_HOST, AEGIS_DEV (default wg0), REGISTRY.

set -euo pipefail
umask 077

AEGIS_HOST="${AEGIS_HOST:-aegis}"
AEGIS_DEV="${AEGIS_DEV:-wg0}"
REGISTRY="${REGISTRY:-/var/lib/bypass/exits.json}"

note() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10)

id=""
keep_host=0
while [ $# -gt 0 ]; do
    case "$1" in
        --id)        id="$2"; shift 2 ;;
        --keep-host) keep_host=1; shift ;;
        -h|--help)   sed -n '2,12p' "$0"; exit 0 ;;
        *)           die "unknown argument: $1" ;;
    esac
done
[ -n "$id" ] || die "usage: $0 --id <name> [--keep-host]"

info=$(ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n python3 - '$REGISTRY' '$id'" <<'PY'
import json, os, sys
path, ident = sys.argv[1], sys.argv[2]
reg = {"version": 1, "exits": []}
if os.path.exists(path):
    reg = json.load(open(path))
exits = reg.get("exits", [])
entry = next((e for e in exits if e.get("id") == ident), None)
if entry is None:
    print("missing")
    raise SystemExit(1)
reg["exits"] = [e for e in exits if e.get("id") != ident]
tmp = path + ".tmp"
open(tmp, "w").write(json.dumps(reg, indent=2, sort_keys=True) + "\n")
os.chmod(tmp, 0o644)
os.replace(tmp, path)
print(entry.get("pubkey", ""), entry.get("host", ""))
PY
) || die "no exit named $id in the registry"
ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n chown bypass:bypass '$REGISTRY' 2>/dev/null || true"
pub=${info%% *}
host=${info#* }
[ -n "$pub" ] || die "registry entry for $id has no pubkey"

note "== $AEGIS_HOST: peer and config"
ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n wg set $AEGIS_DEV peer '$pub' remove 2>/dev/null || true"
ssh "${ssh_opts[@]}" "$AEGIS_HOST" "sudo -n python3 - '/etc/wireguard/$AEGIS_DEV.conf' '$pub' '$id'" <<'PY'
import shutil, sys, time
path, pub, ident = sys.argv[1:4]
lines = open(path).read().splitlines()
blocks, cur = [], []
for line in lines:
    if line.strip().startswith('[Peer]'):
        blocks.append(cur)
        cur = [line]
    else:
        cur.append(line)
blocks.append(cur)
out = []
removed = False
for index, block in enumerate(blocks):
    if index > 0 and any(l.strip() == f'PublicKey = {pub}' for l in block):
        while out and out[-1].startswith(f'# exit: {ident}'):
            out.pop()
        removed = True
        continue
    out.extend(block)
if not removed:
    print('peer block not found in the config')
    raise SystemExit
shutil.copy2(path, f'{path}.bak-{time.strftime("%Y%m%d-%H%M%S")}')
open(path, 'w').write('\n'.join(out).rstrip('\n') + '\n')
print('peer block removed from the config')
PY

if [ "$keep_host" = 0 ] && [ -n "$host" ]; then
    note "== $host: stopping wgexit"
    ssh "${ssh_opts[@]}" "$host" 'sudo -n systemctl disable --now wg-quick@wgexit >/dev/null 2>&1 || true'
fi

note "exit $id removed. The learner releases its prefixes on the next cycle."
