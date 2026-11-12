#!/usr/bin/env bash
# Build egress with a WireGuard private key and tunnel address compiled in,
# so the result can be handed to someone as a single file.
#
# The key is embedded with the Go linker (-X), not written to a source file, so
# it never lands in the repository. It does end up in the binary and in the Go
# build cache. See the warning printed at the end.

set -euo pipefail

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

check_sha() {
    file=$1
    want=$2
    if command -v sha256sum >/dev/null 2>&1; then
        got=$(sha256sum "$file" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        got=$(shasum -a 256 "$file" | awk '{print $1}')
    else
        die "need sha256sum or shasum to verify embedded Windows assets"
    fi
    [ "$got" = "$want" ] || die "$file checksum mismatch: got $got, want $want"
}

usage() {
    cat <<'EOF'
Usage: ./build.sh [options]

  --key <base64>       Embed this private key (44 chars, ends with '=')
  --key-file <path>    Read the private key from a file (preferred: keeps it
                       out of shell history and out of `ps`)
  --generate           Generate a new key, print it, and embed it
  --ip <addr>          Tunnel address for this device (default 10.88.0.4)
  --os <goos>          linux or windows (default: host OS)
  --arch <goarch>      amd64 or arm64 (default: amd64)
  --out <path>         Output path (default: dist/egress-<os>-<arch>[.exe])
  --version <semver>   Release version, for example 0.3.0 (default 0.0.0)
  --save-key <path>    Also write the private key to this file, mode 0600
  --no-key             Build without an embedded device key (generic update
                       artifact; reuse an existing config with install
                       --keep-config)
  --update-key <b64>   Embed the Ed25519 update public key (44 chars)
  --socks-user <name>  Embed the SOCKS relay username (split mode)
  --socks-pass <pass>  Embed the SOCKS relay password (split mode)
  --default-split      Install split mode unless --no-split is passed
  --quiet              Do not print the private key, next steps or warnings
  --debug-build        Bake in debug mode: the binary behaves as if --debug
                       were passed to every command. For diagnosing other
                       people's machines; there is no opt-out flag.
  -h, --help

The public key is printed before the build. Add it to Aegis as a peer with the
same address as --ip, or the tunnel will not handshake.

A built binary is a credential: anyone who has it can recover the private key.
Do not publish it, email it on a channel you do not trust, or commit it.
EOF
}

key=""
key_file=""
generate=0
ip="10.88.0.4"
goos=""
goarch="amd64"
out=""
version="0.0.0"
save_key=""
quiet=0
no_key=0
update_key=""
socks_user=""
socks_pass=""
default_split=0
debug_build=0

while [ $# -gt 0 ]; do
    case "$1" in
        --key)        key="$2"; shift 2 ;;
        --key-file)   key_file="$2"; shift 2 ;;
        --generate)   generate=1; shift ;;
        --ip)         ip="$2"; shift 2 ;;
        --os)         goos="$2"; shift 2 ;;
        --arch)       goarch="$2"; shift 2 ;;
        --out)        out="$2"; shift 2 ;;
        --version)    version="$2"; shift 2 ;;
        --save-key)   save_key="$2"; shift 2 ;;
        --no-key)     no_key=1; shift ;;
        --update-key) update_key="$2"; shift 2 ;;
        --socks-user) socks_user="$2"; shift 2 ;;
        --socks-pass) socks_pass="$2"; shift 2 ;;
        --default-split) default_split=1; shift ;;
        --quiet)      quiet=1; shift ;;
        --debug-build) debug_build=1; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            die "unknown option: $1" ;;
    esac
done

command -v go >/dev/null 2>&1 || die "go is not on PATH"

host_os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$host_os" in
    linux)  host_os=linux ;;
    darwin) host_os=darwin ;;
    msys*|mingw*|cygwin*) host_os=windows ;;
esac
[ -n "$goos" ] || goos="$host_os"

# Delivery builds embed the fallback client (and the WireGuard installer on
# Windows) so the target never needs GitHub or winget.
if [ "$goos" = "windows" ]; then
    [ -f internal/assets/assets/wstunnel-windows-amd64.exe ] \
        || die "missing internal/assets/assets/wstunnel-windows-amd64.exe; Windows builds embed it"
    [ -f internal/assets/assets/wireguard-amd64-1.1.1.msi ] \
        || die "missing internal/assets/assets/wireguard-amd64-1.1.1.msi; Windows builds embed it"
    check_sha internal/assets/assets/wstunnel-windows-amd64.exe \
        c7b5b53c1476995310fe10b2f3f6d19006e5a5948984d8d25682b47e8ecb8f73
    check_sha internal/assets/assets/wireguard-amd64-1.1.1.msi \
        7bfed60ad61b785c914b38b61555a975488e1d3ec472dbfb2fcdf498fca75242
fi
if [ "$goos" = "linux" ]; then
    [ -f internal/assets/assets/wstunnel-linux-amd64 ] \
        || die "missing internal/assets/assets/wstunnel-linux-amd64; Linux delivery builds embed it (copy from /usr/local/bin/wstunnel)"
    check_sha internal/assets/assets/wstunnel-linux-amd64 \
        62b26d0ee0f2211cef15fa1b85173fe687bc6698121842bf324359b412afc151
fi
if [ "$goos" = "darwin" ]; then
    [ -f "internal/assets/assets/wstunnel-darwin-$goarch" ] \
        || die "missing internal/assets/assets/wstunnel-darwin-$goarch; Darwin delivery builds embed it"
    case "$goarch" in
        amd64)
            check_sha internal/assets/assets/wstunnel-darwin-amd64 \
                72349e8eda9b80762e809b51dbe3c81aea8094b57da6ab6bb97274f048be4adb
            ;;
        arm64)
            check_sha internal/assets/assets/wstunnel-darwin-arm64 \
                3c814a9b16481b6b17b9ea02b679b8b21454788da6c61366c4d26fca823c9feb
            ;;
        *) die "unsupported arch for darwin: $goarch" ;;
    esac
fi

# --- key ---------------------------------------------------------------

if [ "$generate" -eq 1 ]; then
    if command -v wg >/dev/null 2>&1; then
        key=$(wg genkey)
    else
        key=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
    fi
elif [ -n "$key_file" ]; then
    [ -r "$key_file" ] || die "cannot read $key_file"
    key=$(tr -d ' \t\r\n' < "$key_file")
fi

if [ "$no_key" -eq 0 ]; then
    [ -n "$key" ] || die "no key given; use --key, --key-file or --generate (or --no-key for a generic build)"
    case "$key" in
        *[!A-Za-z0-9+/=]*) die "key contains characters outside the base64 alphabet" ;;
    esac
    [ "${#key}" -eq 44 ] || die "key must be 44 characters, got ${#key}"
    [ "${key: -1}" = "=" ] || die "key must end with '='"
    decoded=$(printf '%s' "$key" | base64 -d 2>/dev/null | wc -c)
    [ "$decoded" -eq 32 ] || die "key does not decode to 32 bytes"
fi

if [ -n "$update_key" ]; then
    case "$update_key" in
        *[!A-Za-z0-9+/=]*) die "update key contains characters outside the base64 alphabet" ;;
    esac
    [ "${#update_key}" -eq 44 ] || die "update key must be 44 characters, got ${#update_key}"
fi

case "$ip" in
    *[!0-9.]*) die "--ip must be a dotted IPv4 address" ;;
esac
[ "$(printf '%s' "$ip" | awk -F. 'NF==4 && $1<256 && $2<256 && $3<256 && $4<256 {print "ok"}')" = ok ] \
    || die "--ip is not a valid IPv4 address: $ip"

if [ -z "$key" ]; then
    pubkey="(no embedded key; generic update artifact)"
elif command -v wg >/dev/null 2>&1; then
    pubkey=$(printf '%s' "$key" | wg pubkey)
else
    pubkey="(unknown on this host; run the built binary with 'egress pubkey')"
fi

# --- build -------------------------------------------------------------

if [ -z "$out" ]; then
    out="dist/egress-${goos}-${goarch}"
    case "$goos" in
        windows) out="${out}.exe" ;;
    esac
fi
mkdir -p "$(dirname "$out")"

if [ "$quiet" -eq 1 ]; then
    if [ -n "$save_key" ]; then
        printf '\nprivate key: saved to %s\n' "$save_key"
    else
        printf '\nprivate key: not printed\n'
    fi
else
    printf '\nprivate key: %s\n' "$key"
fi
printf 'public key:  %s\n' "$pubkey"
printf 'tunnel ip:   %s/32\n' "$ip"
printf 'building:    %s/%s -> %s\n\n' "$goos" "$goarch" "$out"

debug_ldflag=""
if [ "$debug_build" -eq 1 ]; then
    debug_ldflag=" -X egress/internal/egress.defaultDebug=true"
fi
update_ldflag=""
if [ -n "$update_key" ]; then
    update_ldflag=" -X egress/internal/update.PublicKey=$update_key"
fi
socks_ldflag=""
if [ -n "$socks_user" ] && [ -n "$socks_pass" ]; then
    socks_ldflag=" -X egress/internal/egress.embeddedSocksUser=$socks_user -X egress/internal/egress.embeddedSocksPass=$socks_pass"
fi
split_ldflag=""
if [ "$default_split" -eq 1 ]; then
    split_ldflag=" -X egress/internal/egress.embeddedDefaultSplit=true"
fi

GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -tags delivery -trimpath -buildvcs=false \
    -ldflags "-s -w -X egress/internal/egress.embeddedKey=$key -X egress/internal/egress.embeddedClientIP=$ip -X egress/internal/egress.buildVersion=$version${debug_ldflag}${update_ldflag}${socks_ldflag}${split_ldflag}" \
    -o "$out" .

case "$goos" in
    windows) ;;
    *) chmod 0755 "$out" ;;
esac

# The key is embedded as a plain string, so it must be present in the binary.
# If this fails, the linker contract in DESIGN.md was not met.
if command -v grep >/dev/null 2>&1; then
    grep -aqF -- "$key" "$out" \
        || die "the key is not in the output binary; check the -X variable names"
fi

if [ -n "$save_key" ]; then
    umask 077
    printf '%s\n' "$key" > "$save_key"
    chmod 0600 "$save_key"
    printf 'saved key:   %s\n' "$save_key"
fi

if [ "$quiet" -eq 0 ]; then
    cat <<'EOF'

Next steps
  1. Add the public key above to Aegis, with the tunnel address from --ip:
       wg set wg0 peer <public key> allowed-ips <ip>/32
     then add it to /etc/wireguard/wg0.conf so it survives a restart.
  2. Copy only the binary to the target machine and run it as root/Administrator.
  3. Confirm the exit with:  egress verify

Warning
  The private key is recoverable from the binary with `strings`. Treat the file
  as a credential. If it leaks, remove that peer on Aegis and rebuild.
  Also note the key is in the Go build cache and, if you used --key, in shell
  history and in `ps` output while the build ran. Prefer --key-file.
EOF
fi
