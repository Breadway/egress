#!/usr/bin/env bash
# Provision one new device in a single run:
#
#   1. asks Aegis which tunnel addresses are already in use
#   2. picks the lowest free /32
#   3. generates a WireGuard key and saves the private half locally
#   4. records the device in ~/.keys/egress-peers.tsv
#   5. enrolls the public key on Aegis and makes it live
#   6. builds a Windows binary with the key and address compiled in
#
# The private key is never printed. The only file you hand over is the binary.
# Use remove-device.sh to undo one by label.

set -euo pipefail
umask 077

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

usage() {
    cat <<'EOF'
Usage: ./new-device.sh [options]

  --name <label>   Label for the device (used in the Aegis comment, key path
                   and binary name). Default: device
  --ip <addr>      Use this tunnel address instead of picking a free one.
  --os <target>    windows (default), linux, darwin, or both (windows+linux).
  --arch <goarch>  amd64 or arm64 (default: arm64 for darwin, amd64 otherwise).
  --debug-build    Pass --debug-build to build.sh so the binary logs by default.
  --split          Build a device that installs split mode by default.
  --version <v>    Release version to embed (default 0.3.2, env EGRESS_VERSION).
  --update-key <k> Update public key (default ~/.keys/egress-update-public.key).
  --socks-auth <f> Relay credentials file (default ~/.keys/egress-socks-auth).
  --dry-run        Check Aegis and print the address that would be used, then stop.
  -h, --help

Requires: ssh access to a host that can read and change wg0 (default: aegis),
passwordless sudo there, wg, and go. Override the host with AEGIS_HOST.

Environment:
  AEGIS_HOST   SSH host or user@host for Aegis (default: aegis)
  EGRESS_VERSION  Release version for the build (default 0.3.2)
EOF
}

label="device"
request_ip=""
target_os="windows"
target_arch=""
dry_run=0
debug_build=0
split=0
version="${EGRESS_VERSION:-0.3.2}"
update_key=""
socks_auth="$HOME/.keys/egress-socks-auth"
aegis_host="${AEGIS_HOST:-aegis}"
registry="$HOME/.keys/egress-peers.tsv"

while [ $# -gt 0 ]; do
    case "$1" in
        --name)    label="$2"; shift 2 ;;
        --ip)      request_ip="$2"; shift 2 ;;
        --os)      target_os="$2"; shift 2 ;;
        --arch)    target_arch="$2"; shift 2 ;;
        --dry-run) dry_run=1; shift ;;
        --debug-build) debug_build=1; shift ;;
        --split) split=1; shift ;;
        --version) version="$2"; shift 2 ;;
        --update-key) update_key="$2"; shift 2 ;;
        --socks-auth) socks_auth="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *)         die "unknown option: $1" ;;
    esac
done

case "$target_os" in
    windows|linux|darwin|both) ;;
    *) die "--os must be windows, linux, darwin, or both" ;;
esac
case "$target_arch" in
    ""|amd64|arm64) ;;
    *) die "--arch must be amd64 or arm64" ;;
esac
if [ -z "$target_arch" ]; then
    if [ "$target_os" = "darwin" ]; then
        target_arch="arm64"
    else
        target_arch="amd64"
    fi
fi

cd "$(dirname "$0")"

label=$(printf '%s' "$label" | tr -cd 'A-Za-z0-9._ -' | cut -c1-60)
[ -n "$label" ] || label="device"
safe_label=$(printf '%s' "$label" | tr -cs 'A-Za-z0-9._-' '-')

registry_has_label() {
    [ -f "$registry" ] || return 1
    awk -F'\t' -v l="$1" '
        /^#/ { next }
        $1 == l { found = 1; exit }
        END { exit(found ? 0 : 1) }
    ' "$registry"
}

registry_init() {
    if [ -f "$registry" ]; then
        return 0
    fi
    printf '# label\tip\tpublic_key\tprivate_key\tbinaries\taegis_host\tcreated\tcomment\n' > "$registry" || return 1
    chmod 0600 "$registry" || return 1
}

# The provisional row is written right after enrollment; the binaries are
# filled in after the builds.

if registry_has_label "$label"; then
    die "label '$label' is already registered; use another --name or run ./remove-device.sh --name '$label'"
fi

# Serialize against concurrent runs before the used-address scan: the scan
# and the peer append below must be atomic, or two runs can enroll the same
# /32 for different keys. mkdir is atomic; the trap releases on any exit,
# including dry runs.
lockdir="${registry}.lock"
mkdir -p "$(dirname "$lockdir")" || die "cannot create $HOME/.keys"
if ! mkdir "$lockdir" 2>/dev/null; then
    die "another provisioning run is in progress ($lockdir exists)"
fi
trap 'rmdir "$lockdir" 2>/dev/null' EXIT

command -v ssh >/dev/null 2>&1 || die "ssh is not on PATH"
command -v wg  >/dev/null 2>&1 || die "wg is not on PATH; install wireguard-tools"
command -v go  >/dev/null 2>&1 || die "go is not on PATH"

ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10)

note "checking $aegis_host"
ssh "${ssh_opts[@]}" "$aegis_host" true >/dev/null 2>&1 \
    || die "cannot ssh to $aegis_host; set AEGIS_HOST or fix ~/.ssh/config"
ssh "${ssh_opts[@]}" "$aegis_host" "sudo -n true" >/dev/null 2>&1 \
    || die "$aegis_host needs passwordless sudo for this to work"

addr=$(ssh "${ssh_opts[@]}" "$aegis_host" "sudo -n ip -4 -o addr show wg0" \
    | awk '{print $4}' | head -n1)
[ -n "$addr" ] || die "wg0 has no IPv4 address on $aegis_host"
base=$(printf '%s' "$addr" | cut -d/ -f1 | awk -F. '{print $1"."$2"."$3}')

used=$(
    {
        ssh "${ssh_opts[@]}" "$aegis_host" "sudo -n wg show wg0 allowed-ips" 2>/dev/null || true
        ssh "${ssh_opts[@]}" "$aegis_host" "sudo -n grep -oE '$base\.[0-9]{1,3}' /etc/wireguard/wg0.conf" 2>/dev/null || true
        if [ -f "$registry" ]; then
            awk -F'\t' '/^#/ { next } { print $2 }' "$registry"
        fi
        printf '%s\n' "$base.1"
    } | grep -oE "$base\.[0-9]{1,3}" | awk -F. '{print $4}' | sort -n | uniq
)

if [ -n "$request_ip" ]; then
    [[ "$request_ip" =~ ^${base//./\\.}\.([0-9]{1,3})$ ]] \
        || die "--ip $request_ip is not in $base.0/24"
    octet=$((10#${BASH_REMATCH[1]}))
    if [ "$octet" -eq 254 ]; then
        die "--ip $request_ip is reserved for the Microsoft relay (dnscloak); pick another address"
    fi
    [ "$octet" -ge 2 ] && [ "$octet" -le 253 ] \
        || die "--ip $request_ip is the network, the server, or the broadcast address"
    ip="$base.$octet"
    if printf '%s\n' "$used" | grep -qx "$octet"; then
        die "--ip $ip is already used on $aegis_host"
    fi
else
    ip=""
    # Octets 1 (server) and 254 (Microsoft relay) are never allocated.
    for n in $(seq 2 253); do
        if ! printf '%s\n' "$used" | grep -qx "$n"; then
            ip="$base.$n"
            break
        fi
    done
    [ -n "$ip" ] || die "no free address left in $base.0/24"
fi

note "tunnel address: $ip/32 (free on $aegis_host)"

if [ "$dry_run" -eq 1 ]; then
    note "dry run; no key was generated and nothing was changed"
    exit 0
fi

key=$(wg genkey)
pub=$(printf '%s' "$key" | wg pubkey)
[ "${#key}" -eq 44 ] || die "wg genkey produced an unexpected key"
[ "${#pub}" -eq 44 ] || die "wg pubkey produced an unexpected key"

mkdir -p "$HOME/.keys"
key_path="$HOME/.keys/egress-${safe_label}-${ip}.key"
relay_cred_path="$HOME/.keys/egress-socks-${safe_label}-${ip}.cred"
[ ! -e "$key_path" ] || die "refusing to overwrite $key_path; delete it first if you mean a new key"
printf '%s\n' "$key" > "$key_path"
unset key
chmod 0600 "$key_path"

note "public key:     $pub"
note "private key:    $key_path (0600)"

stamp=$(date +%Y%m%d-%H%M%S)
comment="egress device ${label} (${ip}), added ${stamp}"
out="dist/egress-${safe_label}-${ip}.exe"
created=$(date '+%Y-%m-%d %H:%M:%S')

note "enrolling on $aegis_host"
ssh "${ssh_opts[@]}" "$aegis_host" \
    "sudo -n cp -a /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.bak.$stamp" \
    || die "could not back up wg0.conf on $aegis_host; nothing was changed"

block=$(printf '\n# %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\n' \
    "$comment" "$pub" "$ip")
printf '%s\n' "$block" \
    | ssh "${ssh_opts[@]}" "$aegis_host" 'sudo -n tee -a /etc/wireguard/wg0.conf >/dev/null' \
    || die "could not append the peer to wg0.conf on $aegis_host"

ssh "${ssh_opts[@]}" "$aegis_host" "sudo -n wg set wg0 peer '$pub' allowed-ips '$ip/32'" \
    || die "peer is in wg0.conf but wg set failed; apply it manually on $aegis_host"
ssh "${ssh_opts[@]}" "$aegis_host" "sudo -n grep -qF '$pub' /etc/wireguard/wg0.conf" \
    || die "peer was applied but is not in wg0.conf; add it manually before rebooting $aegis_host"

note "enrolled and live"

# Record the peer immediately, before the build: if the build fails or the
# process dies here, the device keeps a live peer with no registry row and
# remove-device cannot undo it. The row carries no binaries yet, so publish
# refuses it until the build fills them in below.
registry_add_pending() {
    registry_init || return 1
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$label" "$ip" "$pub" "$key_path" "" "$aegis_host" "$created" "$comment" \
        >> "$registry" || return 1
}

registry_add_pending || die "peer is live but the registry is unwritable; remove it on $aegis_host manually"

provision_relay_credentials

# Fill in the built binaries on the provisional row. A second process adding
# the same label would have died at the top guard, so label+pub match at
# most this row.
registry_update_binaries() {
    local tmp
    tmp=$(mktemp "${registry}.XXXXXX") || return 1
    awk -F'\t' -v l="$label" -v p="$pub" -v b="$binaries_abs" 'BEGIN { OFS="\t" } /^#/ { print; next } $1 == l && $3 == p { $5 = b } { print }' \
        "$registry" > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod 0600 "$tmp" || { rm -f "$tmp"; return 1; }
    mv "$tmp" "$registry" || { rm -f "$tmp"; return 1; }
}

# provision_relay_credentials creates a user:password pair for this device and
# appends it to the relay's auth file. Credentials are per device so revoking
# one device stops its relay access without touching anyone else's.
provision_relay_credentials() {
    local user pass
    user="dev-${ip}-$(openssl rand -hex 4)"
    pass=$(openssl rand -base64 18 | tr '+/' '-_' | tr -d '=')
    printf '%s:%s\n' "$user" "$pass" | ssh "${ssh_opts[@]}" "$aegis_host"         "sudo -n tee -a /etc/egress-socks/auth >/dev/null && sudo -n systemctl reload-or-restart egress-socks"         || die "could not add relay credentials on $aegis_host"
    printf '%s\n' "$user:$pass" > "$relay_cred_path"
    chmod 0600 "$relay_cred_path"
    note "relay user $user added on $aegis_host"
}

build_one() {
    # $1 = goos, $2 = goarch, $3 = out path
    if [ -z "$update_key" ] && [ -r "$HOME/.keys/egress-update-public.key" ]; then
        update_key=$(tr -d ' \t\r\n' < "$HOME/.keys/egress-update-public.key")
    fi
    local socks_user socks_pass
    IFS=: read -r socks_user socks_pass < "$relay_cred_path" || die "could not read $relay_cred_path"
    args=(--key-file "$key_path" --ip "$ip" --os "$1" --arch "$2" --out "$3" --quiet
          --socks-user "$socks_user" --socks-pass "$socks_pass"
          --version "$version")
    [ "$debug_build" -eq 1 ] && args+=(--debug-build)
    [ -n "$update_key" ] && args+=(--update-key "$update_key")
    if ! ./build.sh "${args[@]}"; then
        cat >&2 <<EOF

build failed, but the peer is already live on $aegis_host and recorded in
$registry, and the key is saved at
  $key_path
To undo the enrollment before retrying:
  ./remove-device.sh --name '$label'
Then rerun this script.
EOF
        return 1
    fi
    [ -f "$3" ] || { printf 'error: build did not produce %s\n' "$3" >&2; return 1; }
}

outs=""
case "$target_os" in
    windows)
        out="dist/egress-${safe_label}-${ip}.exe"
        build_one windows "$target_arch" "$out" || exit 1
        outs="$out"
        ;;
    linux)
        out="dist/egress-${safe_label}-${ip}"
        build_one linux "$target_arch" "$out" || exit 1
        outs="$out"
        ;;
    darwin)
        out="dist/egress-${safe_label}-${ip}-darwin-${target_arch}"
        build_one darwin "$target_arch" "$out" || exit 1
        outs="$out"
        ;;
    both)
        out_win="dist/egress-${safe_label}-${ip}.exe"
        out_linux="dist/egress-${safe_label}-${ip}-linux"
        build_one windows "$target_arch" "$out_win" || exit 1
        build_one linux "$target_arch" "$out_linux" || exit 1
        outs="$out_win $out_linux"
        ;;
esac

binaries_abs=""
for o in $outs; do
    binaries_abs="$binaries_abs $PWD/$o"
done
binaries_abs=${binaries_abs# }

registry_update_binaries || die "binaries built, but could not update $registry; peer remains enrolled"
note "registered as '$label' in $registry"

report_bins=""
for o in $outs; do
    sha_one=$(sha256sum "$o" | awk '{print $1}')
    report_bins="$report_bins
  binary:        $PWD/$o
  sha256:        $sha_one"
done

cat <<EOF

Done.

  device:        $label
  tunnel ip:     $ip/32
  public key:    $pub
  private key:   $key_path (0600, keep this)$report_bins
  aegis backup:  /etc/wireguard/wg0.conf.bak.$stamp
  registry:      $registry

Hand only the built binaries to $label. Each is a credential, so send them
over a channel you trust, not email.
EOF

win_help() {
    local exe="$1"
    cat <<EOF
On Windows, in an elevated PowerShell, run the file from anywhere:

  .\\$(basename "$exe") install --debug

install copies itself to C:\\ProgramData\\egress\\egress.exe.
Afterwards:

  C:\\ProgramData\\egress\\egress.exe diagnose
  Get-Content C:\\ProgramData\\egress\\egress.log -Tail 120
EOF
}

linux_help() {
    local bin="$1"
    cat <<EOF
On Linux, as root:

  sudo ./$(basename "$bin") install

Confirm with: sudo ./$(basename "$bin") verify
EOF
}

mac_help() {
    local bin="$1"
    cat <<EOF
On macOS, as root (requires Homebrew wireguard-tools, see below):

  sudo ./$(basename "$bin") install

Confirm with: sudo ./$(basename "$bin") verify
EOF
}

case "$target_os" in
    windows) win_help "$(printf '%s' "$outs" | awk '{print $1}')" ;;
    linux)   linux_help "$(printf '%s' "$outs" | awk '{print $1}')" ;;
    darwin)  mac_help "$(printf '%s' "$outs" | awk '{print $1}')" ;;
    both)
        win_help "$out_win"
        echo
        linux_help "$out_linux"
        ;;
esac

cat <<EOF
To revoke this device later, run:

  ./remove-device.sh --name '$label'

To let the owner download the installer themselves with a username and
password instead of sending the file, run:

  ./publish-device.sh --name '$label'
EOF
