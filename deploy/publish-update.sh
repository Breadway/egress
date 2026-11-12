#!/bin/sh
# Sign a generic egress release locally and upload it to Aegis.
#
#   ./deploy/publish-update.sh --binary dist/egress-linux-amd64 --os linux \
#       --arch amd64 --version 0.3.0 [--force] [--notes "text"]
#
# The signing key never leaves this machine. Aegis only receives the manifest
# and blob.
set -eu

key_file="${EGRESS_UPDATE_KEY:-$HOME/.keys/egress-update-signing.key}"
binary=""
goos=""
goarch=""
version=""
force=""
notes=""
aegis_host="${AEGIS_HOST:-aegis}"
dir="/var/lib/egress-updates"

while [ $# -gt 0 ]; do
    case "$1" in
        --binary) binary="$2"; shift 2 ;;
        --os) goos="$2"; shift 2 ;;
        --arch) goarch="$2"; shift 2 ;;
        --version) version="$2"; shift 2 ;;
        --force) force="--force"; shift ;;
        --notes) notes="$2"; shift 2 ;;
        --key-file) key_file="$2"; shift 2 ;;
        --aegis) aegis_host="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[ -n "$binary" ] && [ -n "$goos" ] && [ -n "$goarch" ] && [ -n "$version" ] || {
    echo "need --binary, --os, --arch and --version" >&2
    exit 2
}
[ -r "$key_file" ] || { echo "no signing key at $key_file" >&2; exit 2; }

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

go run . update-sign \
    --key-file "$key_file" \
    --binary "$binary" \
    --os "$goos" \
    --arch "$goarch" \
    --version "$version" \
    $force \
    ${notes:+--notes "$notes"} \
    --out "$stage"

tar -C "$stage" -cf - manifests blobs |
    ssh "$aegis_host" "sudo -n mkdir -p $dir && sudo -n tar -C $dir -xf -"

echo "published $version for $goos/$goarch"
