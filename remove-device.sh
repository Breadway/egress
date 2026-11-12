#!/usr/bin/env bash
# Remove a device provisioned by new-device.sh, using the local peer registry.

set -euo pipefail
umask 077

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: ./remove-device.sh --name <label> [options]
       ./remove-device.sh --list

  --name <label>  Remove this registered peer from Aegis and delete its local
                  key and built binary.
  --list          List peers known to the local registry.
  --keep-files    Keep the local private-key and binary files after removing
                  the peer. Useful for an emergency rollback.
  -h, --help

The registry is ~/.keys/egress-peers.tsv. It is created by new-device.sh.
Override the Aegis SSH target with AEGIS_HOST, if necessary.
EOF
}

registry="$HOME/.keys/egress-peers.tsv"
name=""
list=0
keep_files=0

while [ $# -gt 0 ]; do
    case "$1" in
        --name)       name="$2"; shift 2 ;;
        --list)       list=1; shift ;;
        --keep-files) keep_files=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            die "unknown option: $1" ;;
    esac
done

if [ "$list" -eq 1 ]; then
    [ -z "$name" ] || die "--list cannot be combined with --name"
    if [ ! -f "$registry" ]; then
        printf '%-20s %-15s %-46s %s\n' "LABEL" "TUNNEL IP" "PUBLIC KEY" "CREATED"
        exit 0
    fi
    awk -F'\t' '
        BEGIN { printf "%-20s %-15s %-46s %s\n", "LABEL", "TUNNEL IP", "PUBLIC KEY", "CREATED" }
        /^#/ { next }
        NF >= 8 { printf "%-20s %-15s %-46s %s\n", $1, $2, $3, $7 }
    ' "$registry"
    exit 0
fi

[ -n "$name" ] || die "supply --name <label>, or use --list"
[ -f "$registry" ] || die "no registry at $registry; no peer will be changed"
command -v ssh >/dev/null 2>&1 || die "ssh is not on PATH"

matches=$(awk -F'\t' -v l="$name" '$1 == l { count++; row = $0 } END { if (count == 1) print row; else exit(count ? 2 : 1) }' "$registry") \
    || {
        status=$?
        if [ "$status" -eq 2 ]; then
            die "registry has more than one peer labelled '$name'; repair $registry before removing anything"
        fi
        die "no peer labelled '$name' in $registry"
    }

IFS=$'\t' read -r label ip pub key_path binary registered_host created comment <<< "$matches"
[ -n "$comment" ] || die "registry entry for '$name' is incomplete; refusing to guess"

aegis_host="${AEGIS_HOST:-$registered_host}"
[ -n "$aegis_host" ] || aegis_host="aegis"
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10)

ssh "${ssh_opts[@]}" "$aegis_host" true >/dev/null 2>&1 \
    || die "cannot ssh to $aegis_host"
ssh "${ssh_opts[@]}" "$aegis_host" "sudo -n true" >/dev/null 2>&1 \
    || die "$aegis_host needs passwordless sudo"

stamp=$(date +%Y%m%d-%H%M%S)
printf 'removing %s (%s, %s) from %s\n' "$label" "$ip" "$pub" "$aegis_host"

# Take the backup first. Aegis config is changed only after this succeeds.
ssh "${ssh_opts[@]}" "$aegis_host" \
    "sudo -n cp -a /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.bak.$stamp" \
    || die "could not back up wg0.conf on $aegis_host; nothing was changed"

# new-device.sh owns the exact four-line block below. Match the complete comment
# line, not a partial public key, so manually-managed peers are never touched.
ssh "${ssh_opts[@]}" "$aegis_host" \
    "sudo -n awk -v marker='# $comment' '\$0 == marker { skip = 4; next } skip > 0 { skip--; next } { print }' /etc/wireguard/wg0.conf | sudo -n tee /etc/wireguard/wg0.conf.new >/dev/null && sudo -n mv /etc/wireguard/wg0.conf.new /etc/wireguard/wg0.conf" \
    || die "could not remove the registered peer block from wg0.conf; live peer left intact"

if ssh "${ssh_opts[@]}" "$aegis_host" "sudo -n grep -qF '$pub' /etc/wireguard/wg0.conf"; then
    die "the registered peer block was not found exactly; restored nothing and left the live peer intact. Backup: /etc/wireguard/wg0.conf.bak.$stamp"
fi

ssh "${ssh_opts[@]}" "$aegis_host" "sudo -n wg set wg0 peer '$pub' remove" \
    || die "config was updated but the live peer could not be removed; restore /etc/wireguard/wg0.conf.bak.$stamp if needed"

tmp=$(mktemp "${registry}.XXXXXX")
trap 'rm -f "$tmp"' EXIT
awk -F'\t' -v l="$label" -v p="$pub" 'BEGIN { OFS="\t" } /^#/ { print; next } !($1 == l && $3 == p) { print }' "$registry" > "$tmp"
chmod 0600 "$tmp"
mv "$tmp" "$registry"
trap - EXIT

relay_cred_path="$HOME/.keys/egress-socks-${label}-${ip}.cred"
if [ -r "$relay_cred_path" ]; then
    relay_user=$(cut -d: -f1 "$relay_cred_path")
    ssh "${ssh_opts[@]}" "$aegis_host"         "sudo -n sed -i '/^${relay_user}:/d' /etc/egress-socks/auth && sudo -n chown bypass:egress-socks /etc/egress-socks/auth && sudo -n chmod 0640 /etc/egress-socks/auth && sudo -n systemctl reload-or-restart egress-socks"         && printf 'relay user %s removed from %s\n' "$relay_user" "$aegis_host"         || printf 'warning: could not remove relay user %s; edit /etc/egress-socks/auth on %s\n' "$relay_user" "$aegis_host" >&2
fi

if [ "$keep_files" -eq 0 ]; then
    # $binary may hold several space-separated paths (see new-device.sh
    # --os both). None of our paths contain spaces.
    # shellcheck disable=SC2086
    for path in "$key_path" "$relay_cred_path" $binary; do
        if [ -n "$path" ] && [ -e "$path" ]; then
            rm -f -- "$path"
            printf 'deleted %s\n' "$path"
        fi
    done
fi

cat <<EOF

Removed '$label'.
  Aegis peer:     removed from wg0 and /etc/wireguard/wg0.conf
  Registry:       $registry
  Aegis backup:   /etc/wireguard/wg0.conf.bak.$stamp
EOF

if [ "$keep_files" -eq 1 ]; then
    printf '  Local key/binary: kept (--keep-files)\n'
else
    printf '  Local key/binary: deleted when present\n'
fi
