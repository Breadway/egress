#!/usr/bin/env bash
# Test for new-device.sh: proves a build failure after enrollment still
# leaves a registry row (so remove-device can undo it), and that the success
# path fills the binaries back in. Runs locally with stubbed ssh/wg; phase 2
# uses the real Go toolchain for one linux build.
#
# Usage: ./new-device-test.sh
set -euo pipefail

repo="$(cd "$(dirname "$0")" && pwd)"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work"/bin "$work"/keys
export HOME="$work"
export AEGIS_HOST=aegis

# Stub ssh: emulates an empty Aegis (nothing used, peer .1 server).
cat > "$work/bin/ssh" <<'STUB'
#!/usr/bin/env bash
remote="$*"
case "$remote" in
    *"grep -qF"*) exit 0 ;;
    *"grep -oE"*) exit 0 ;;
    *"ip -4 -o addr show wg0"*) printf '1: wg0    inet 10.88.0.1/24 scope global wg0\n' ;;
    *"tee -a"*) cat >/dev/null ;;
    *"true"*) : ;;
esac
exit 0
STUB
cat > "$work/bin/wg" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = "genkey" ]; then
    printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' | head -c 44
elif [ "$1" = "pubkey" ]; then
    cat >/dev/null
    printf 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n' | head -c 44
fi
STUB
# Phase 1: every build fails.
cat > "$work/bin/go" <<'STUB'
#!/usr/bin/env bash
exit 1
STUB
chmod +x "$work/bin/ssh" "$work/bin/wg" "$work/bin/go"
export PATH="$work/bin:/usr/bin:/bin"

fail=0
row() { awk -F'\t' -v l="$1" '$1 == l { print }' "$HOME/.keys/egress-peers.tsv"; }

# Phase 1: enroll succeeds, build fails. Must exit non-zero with a row that
# carries the peer but no binaries, plus a working recovery command.
if "$repo/new-device.sh" --name t1 --os linux 2>"$work/phase1.err"; then
    printf 'FAIL: phase 1 should exit non-zero on build failure\n'
    fail=1
fi
r=$(row t1)
[ -n "$r" ] || { printf 'FAIL: no provisional registry row after failed build\n'; fail=1; }
[ "$(printf '%s' "$r" | awk -F'\t' '{print $3}')" = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" ] \
    || { printf 'FAIL: provisional row lost the peer pubkey\n'; fail=1; }
[ -z "$(printf '%s' "$r" | awk -F'\t' '{print $5}')" ] \
    || { printf 'FAIL: provisional row must have empty binaries\n'; fail=1; }
grep -q "remove-device.sh --name 't1'" "$work/phase1.err" \
    || { printf 'FAIL: recovery command missing from failure output\n'; fail=1; }

# Phase 2: real toolchain builds; the row must gain binaries.
rm -f "$work/bin/go"
if ! "$repo/new-device.sh" --name t2 --os linux >/dev/null 2>"$work/phase2.err"; then
    printf 'FAIL: phase 2 with working toolchain should succeed\n'
    cat "$work/phase2.err" | tail -3
    fail=1
else
    r=$(row t2)
    [ -n "$(printf '%s' "$r" | awk -F'\t' '{print $5}')" ] \
        || { printf 'FAIL: success path left binaries empty\n'; fail=1; }
    bin=$(printf '%s' "$r" | awk -F'\t' '{print $5}')
    [ -f "$bin" ] || { printf 'FAIL: recorded binary missing: %s\n' "$bin"; fail=1; }
    rm -f "$bin"
fi

if [ "$fail" -eq 0 ]; then
    printf 'new-device failure-path tests passed\n'
fi
exit "$fail"
