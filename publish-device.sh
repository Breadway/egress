#!/usr/bin/env bash
# Publish an enrolled device's installer to bypass.breadway.dev.
#
# Takes the Windows or Linux binary recorded in the local peer registry,
# uploads it to Aegis, and registers a username + password that downloads
# exactly that file.
# The password is generated unless --password is given. Hand the printed URL,
# username and password to the device owner over a channel you trust.
#
# Nothing here touches WireGuard: the peer must already be enrolled with
# new-device.sh (or any other way).

set -euo pipefail
umask 077

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

usage() {
    cat <<'EOF'
Usage: ./publish-device.sh --name <label> [options]

  --name <label>   Registry label from new-device.sh (required).
  --user <name>    Download username (default: lowercased label).
  --password <pw>  Use this password (at least 12 characters). Default: generate one.
  --application <id>
                   Link this enrollment application (16 hex chars from its
                   status link) to the new login and mark it reviewed, so the
                   applicant can set their own password right away.
  --os <target>    windows (default), linux, or darwin. Selects which recorded
                   binary to publish when several exist.
  --arch <goarch>  amd64 or arm64 (default: arm64 for darwin, amd64 otherwise).
                   Selects the recorded binary together with --os.
  --dry-run        Show what would be published without changing anything.
  -h, --help

Requires: the device in ~/.keys/egress-peers.tsv with a built binary for
the selected OS, ssh access to Aegis with passwordless sudo, and a running
bypass-server there. Override the host with AEGIS_HOST.
EOF
}

label=""
user=""
password=""
appid=""
os_target="windows"
arch_target=""
dry_run=0
aegis_host="${AEGIS_HOST:-aegis}"
registry="$HOME/.keys/egress-peers.tsv"

while [ $# -gt 0 ]; do
    case "$1" in
        --name)     label="$2"; shift 2 ;;
        --user)     user="$2"; shift 2 ;;
        --password) password="$2"; shift 2 ;;
        --application) appid="$2"; shift 2 ;;
        --os)       os_target="$2"; shift 2 ;;
        --arch)     arch_target="$2"; shift 2 ;;
        --dry-run)  dry_run=1; shift ;;
        -h|--help)  usage; exit 0 ;;
        *)          die "unknown option: $1" ;;
    esac
done

[ -n "$label" ] || die "supply --name <label>, or use ./remove-device.sh --list"
if [ -n "$appid" ] && [[ ! "$appid" =~ ^[0-9a-f]{16}$ ]]; then
    die "--application must be the 16 hex characters from the applicant's status link"
fi
case "$os_target" in
    windows|linux|darwin) ;;
    *) die "--os must be windows, linux, or darwin" ;;
esac
case "$arch_target" in
    ""|amd64|arm64) ;;
    *) die "--arch must be amd64 or arm64" ;;
esac
if [ -z "$arch_target" ]; then
    if [ "$os_target" = "darwin" ]; then
        arch_target="arm64"
    else
        arch_target="amd64"
    fi
fi
[ -f "$registry" ] || die "no registry at $registry"

matches=$(awk -F'\t' -v l="$label" '$1 == l { count++; row = $0 } END { if (count == 1) print row; else exit(count ? 2 : 1) }' "$registry") \
    || {
        status=$?
        if [ "$status" -eq 2 ]; then
            die "registry has more than one peer labelled '$label'"
        fi
        die "no peer labelled '$label' in $registry"
    }

IFS=$'\t' read -r rlabel rip pub key_path binaries _ _ _ <<< "$matches"
[ "$rlabel" = "$label" ] || die "registry entry for '$label' is incomplete"

# The registry may list several binaries (--os both); pick the selected OS and
# arch. Darwin files carry -darwin-<arch> in the name.
binary=""
for b in $binaries; do
    case "$os_target:$b" in
        windows:*.exe) binary="$b"; break ;;
        linux:*.exe|linux:*darwin-*) ;;
        linux:*) binary="$b"; break ;;
        darwin:*darwin-"$arch_target") binary="$b"; break ;;
    esac
done
[ -n "$binary" ] || die "no $os_target/$arch_target binary recorded for '$label'"
[ -f "$binary" ] || die "recorded binary is missing: $binary"

if [ -z "$user" ]; then
    user=$(printf '%s' "$label" | tr '[:upper:]' '[:lower:]' | tr -cs 'a-z0-9._-' '-')
fi
[[ "$user" =~ ^[a-z0-9][a-z0-9._-]{0,31}$ ]] \
    || die "username '$user' is invalid; use 1-32 chars of a-z 0-9 . _ -"

if [ -z "$password" ]; then
    while :; do
        password=$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)
        [ "${#password}" -ge 20 ] && break
    done
fi
[ "${#password}" -ge 12 ] || die "password must be at least 12 characters"

if [ "$os_target" = "linux" ]; then
    remote_file="$user"
elif [ "$os_target" = "darwin" ]; then
    remote_file="$user-darwin-$arch_target"
else
    remote_file="$user.exe"
fi

note "device:   $label ($rip)"
note "binary:   $binary"
note "username: $user"

if [ "$dry_run" -eq 1 ]; then
    note "dry run; nothing was uploaded or registered"
    exit 0
fi

command -v ssh >/dev/null 2>&1 || die "ssh is not on PATH"
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10)

ssh "${ssh_opts[@]}" "$aegis_host" true >/dev/null 2>&1 \
    || die "cannot ssh to $aegis_host"
ssh "${ssh_opts[@]}" "$aegis_host" "sudo -n true" >/dev/null 2>&1 \
    || die "$aegis_host needs passwordless sudo"

token=$(ssh "${ssh_opts[@]}" "$aegis_host" "sudo -n cat /etc/bypass/admin-token") \
    || die "could not read the bypass admin token on $aegis_host"
[ -n "$token" ] || die "bypass-server is not set up on $aegis_host (no admin token)"
# The token ends up inside a curl --config stream, where quotes and
# backslashes would need escaping. Admin tokens are hex; refuse anything
# else rather than guessing at escaping.
[[ "$token" =~ ^[A-Za-z0-9_./-]+$ ]] \
    || die "admin token has unexpected characters; refusing to send it"
# A newline would break the heredoc transport below. Passwords do not need
# newlines; refuse rather than corrupting the request.
case "$password" in
    *$'\n'*|*BYPASS_PW_EOF*) die "password contains a newline or the reserved delimiter; pick another" ;;
esac

# Upload the installer with no staging file: scp to a predictable /tmp name
# would leave a credential-bearing binary world-readable, and pre-creatable
# as a symlink. Piping straight into install sets owner and mode at once.
ssh "${ssh_opts[@]}" "$aegis_host" \
    "sudo -n install -o bypass -g bypass -m 0600 /dev/stdin /var/lib/bypass/binaries/$remote_file" \
    < "$binary" >/dev/null \
    || die "upload failed"

# api_post runs a curl against the local bypass-server without ever putting
# the bearer token or the password in any process argv (local ssh, remote
# bash, or remote curl): both travel in the script body on ssh stdin, and
# curl reads them from a --config stream and a protected file. Extra curl
# arguments must be public fields only (username, label, binary, peer...).
api_post() {
    local endpoint=$1; shift
    local extra
    extra=$(printf '%q ' "$@")
    ssh "${ssh_opts[@]}" "$aegis_host" "sudo -n bash -s" <<EOF
pwfile=\$(mktemp /tmp/bypass-pw-XXXXXX)
chmod 600 "\$pwfile"
trap 'rm -f "\$pwfile"' EXIT
cat > "\$pwfile" <<'BYPASS_PW_EOF'
$password
BYPASS_PW_EOF
{
printf '%s\n' "header = \\"Authorization: Bearer $token\\""
} | curl -s -w '\n%{http_code}' --config - -X POST $extra --data-urlencode "password@\$pwfile" http://127.0.0.1:7220/admin/api/$endpoint
EOF
}

reply=$(api_post users \
    --data-urlencode "username=$user" \
    --data-urlencode "label=$label" \
    --data-urlencode "binary=$remote_file" \
    --data-urlencode "os=$os_target" \
    --data-urlencode "arch=$arch_target" \
    --data-urlencode "peer=$pub") \
    || die "could not reach bypass-server on $aegis_host"
code=$(printf '%s' "$reply" | tail -n1)
if [ "$code" = "409" ]; then
    # A retried provisioning run finds the login it created last time. Reuse
    # it: the peer and label are the same, and the link step still has to run.
    note "login $user already exists; reusing it"
elif [ "$code" != "201" ]; then
    die "registration failed (HTTP $code): $(printf '%s' "$reply" | head -n1)"
fi

if [ -n "$appid" ]; then
    link_reply=$(api_post link \
        --data-urlencode "id=$appid" \
        --data-urlencode "username=$user") \
        || die "registered, but could not reach bypass-server to link the application"
    link_code=$(printf '%s' "$link_reply" | tail -n1)
    [ "$link_code" = "200" ] || die "registered, but linking the application failed (HTTP $link_code): $(printf '%s' "$link_reply" | head -n1)"
    note "linked to application $appid"
fi

cat <<EOF

Published.

  url:      https://bypass.breadway.dev/download
  username: $user
  password: $password
  os:       $os_target

Send all three to $label over a channel you trust. The password is shown here
once; a recoverable copy stays on the server so the status page and admin UI
can display it.
To revoke everything from the admin UI: Revoke removes the login, installer,
and WireGuard peer. From here: ./remove-device.sh --name '$label' removes the
peer and local files but leaves the download login, so revoke that too.
EOF
