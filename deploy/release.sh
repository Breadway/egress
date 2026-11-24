#!/usr/bin/env bash
# One command for a release: build the generic targets, assert their embedded
# values, sign and publish the manifests, optionally build and upload a device
# binary, and print every checksum.
#
#   ./deploy/release.sh --version 0.5.0
#   ./deploy/release.sh --version 0.5.0 --device ethan --ip 10.88.0.3 \
#       --key ~/.keys/egress-ethan-10.88.0.3.key \
#       --socks-user dev-10.88.0.3-ethan --socks-pass '...'
#
# Generic builds embed no relay credentials: the device's auth file, written at
# install and preserved across updates, is the credential. That keeps a shared
# secret out of every download.
#
# Rollback: keep the previous dist binary, then republish it at its own version
# with --force:
#   ./deploy/publish-update.sh --binary dist/egress-windows-amd64-<old>.exe \
#       --os windows --arch amd64 --version <old> --force
set -euo pipefail

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '%s\n' "$*"; }

version=""
device=""
ip=""
key=""
socks_user=""
socks_pass=""

while [ $# -gt 0 ]; do
    case "$1" in
        --version)      version="$2"; shift 2 ;;
        --device)       device="$2"; shift 2 ;;
        --ip)           ip="$2"; shift 2 ;;
        --key)          key="$2"; shift 2 ;;
        --socks-user)   socks_user="$2"; shift 2 ;;
        --socks-pass)   socks_pass="$2"; shift 2 ;;
        -h|--help)      sed -n '2,22p' "$0"; exit 0 ;;
        *) die "unknown option: $1" ;;
    esac
done

[ -n "$version" ] || die "--version is required"
update_key=$(tr -d ' \t\r\n' < "$HOME/.keys/egress-update-public.key") \
    || die "missing ~/.keys/egress-update-public.key"

# Windows Authenticode. Signing has to happen before publish-update.sh: the
# update manifest holds the SHA-256 of the exact file we ship, so signing after
# publishing would make every device reject the release. Skipped unless a
# certificate is configured, so an unsigned build still works.
sign_windows() {
    local path="$1"
    [ -n "${EGRESS_SIGN_PFX:-}" ] || return 0
    command -v osslsigncode >/dev/null 2>&1 \
        || die "EGRESS_SIGN_PFX is set but osslsigncode is not installed"
    [ -n "${EGRESS_SIGN_PFX_PASS:-}" ] \
        || die "EGRESS_SIGN_PFX_PASS is required with EGRESS_SIGN_PFX"
    note "signing $(basename "$path")"
    osslsigncode sign \
        -pkcs12 "$EGRESS_SIGN_PFX" -pass "$EGRESS_SIGN_PFX_PASS" \
        -h sha256 -n "egress" -i "${EGRESS_SIGN_URL:-https://bypass.breadway.dev}" \
        -ts "${EGRESS_SIGN_TSA:-http://timestamp.digicert.com}" \
        -in "$path" -out "$path.signed" \
        || die "signing $(basename "$path") failed"
    osslsigncode verify -in "$path.signed" >/dev/null 2>&1 \
        || die "signature on $(basename "$path") did not verify"
    mv "$path.signed" "$path"
}

note "building generic targets for $version"
./build.sh --no-key --os windows --version "$version" --update-key "$update_key" \
    --out "dist/egress-windows-amd64-$version.exe" --quiet
./build.sh --no-key --os linux --version "$version" --update-key "$update_key" \
    --out "dist/egress-linux-amd64-$version" --quiet

sign_windows "dist/egress-windows-amd64-$version.exe"

note "publishing manifests"
./deploy/publish-update.sh --binary "dist/egress-windows-amd64-$version.exe" \
    --os windows --arch amd64 --version "$version" --notes "release $version"
./deploy/publish-update.sh --binary "dist/egress-linux-amd64-$version" \
    --os linux --arch amd64 --version "$version" --notes "release $version"

# Approved applications download a shared generic Windows installer. It was
# left at whatever file was newest in the bypass binaries directory, which is
# how a new device still got 0.4.82 after 0.5.x was current. Keep that file
# current with every release.
aegis_host="${AEGIS_HOST:-aegis}"
note "updating the approved-request Windows installer"
scp -q "dist/egress-windows-amd64-$version.exe" \
    "${aegis_host}:/tmp/egress-windows-amd64-$version.exe"
ssh "$aegis_host" "sudo -n install -o bypass -g bypass -m 0600 \
    /tmp/egress-windows-amd64-$version.exe \
    /var/lib/bypass/binaries/egress-windows-amd64-$version.exe && \
    rm -f /tmp/egress-windows-amd64-$version.exe"

if [ -n "$device" ]; then
    [ -n "$ip" ] && [ -n "$key" ] && [ -n "$socks_user" ] && [ -n "$socks_pass" ] \
        || die "--device needs --ip, --key, --socks-user and --socks-pass"
    out="dist/egress-$device-$ip.exe"
    note "building device binary for $device"
    ./build.sh --key-file "$key" --ip "$ip" --os windows --version "$version" \
        --update-key "$update_key" --socks-user "$socks_user" --socks-pass "$socks_pass" \
        --debug-build --out "$out" --quiet
    sign_windows "$out"
    scp -q "$out" "aegis:/tmp/$(basename "$out")"
    ssh aegis "sudo -n install -o bypass -g bypass -m 0600 /tmp/$(basename "$out") /var/lib/bypass/binaries/$(basename "$out")"
    note "uploaded $(basename "$out"); point the login at it in the admin UI"
fi

note ""
note "checksums"
( cd dist && sha256sum "egress-windows-amd64-$version.exe" "egress-linux-amd64-$version" 2>/dev/null )
[ -n "$device" ] && ( cd dist && sha256sum "egress-$device-$ip.exe" )
note ""
note "done: $version"
