#!/usr/bin/env bash
# Test for the new-device.sh allocation lock: a held lock refuses cleanly
# before generating a key or touching Aegis. Runs locally with stubbed
# remotes. (Companion to new-device-test.sh, which lives on its own branch
# until EGRESS-31 merges.)
#
# Usage: ./new-device-lock-test.sh
set -euo pipefail

repo="$(cd "$(dirname "$0")" && pwd)"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work"/bin "$work"/keys
export HOME="$work"
export AEGIS_HOST=aegis

cat > "$work/bin/ssh" <<'STUB'
#!/usr/bin/env bash
remote="$*"
case "$remote" in
    *"ip -4 -o addr show wg0"*) printf '1: wg0    inet 10.88.0.1/24 scope global wg0\n' ;;
esac
exit 0
STUB
cat > "$work/bin/wg" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
cat > "$work/bin/go" <<'STUB'
#!/usr/bin/env bash
exit 0
STUB
chmod +x "$work/bin/ssh" "$work/bin/wg" "$work/bin/go"
export PATH="$work/bin:/usr/bin:/bin"

fail=0
mkdir -p "$HOME/.keys"
mkdir "$HOME/.keys/egress-peers.tsv.lock"
if "$repo/new-device.sh" --name t3 --os linux >/dev/null 2>"$work/phase3.err"; then
    printf 'FAIL: contended lock should refuse\n'
    fail=1
fi
grep -q 'another provisioning run is in progress' "$work/phase3.err" \
    || { printf 'FAIL: lock refusal message missing\n'; fail=1; }
if compgen -G "$HOME/.keys/egress-t3-*" > /dev/null; then
    printf 'FAIL: key generated despite held lock\n'
    fail=1
fi
rmdir "$HOME/.keys/egress-peers.tsv.lock"

if [ "$fail" -eq 0 ]; then
    printf 'new-device lock tests passed\n'
fi
exit "$fail"
