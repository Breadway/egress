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
if [ "$1" = "genkey" ]; then
    # Hold the lock a while so a concurrent run overlaps inside it.
    sleep 2
    printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n' | head -c 44
elif [ "$1" = "pubkey" ]; then
    cat >/dev/null
    printf 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n' | head -c 44
fi
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

# Phase 2: two concurrent runs must not both enroll. The stubbed Aegis looks
# empty to both, so without the lock they would pick the same /32; with it,
# exactly one dies at acquisition.
"$repo/new-device.sh" --name race1 --os linux >/dev/null 2>"$work/race1.err" &
p1=$!
sleep 0.5
"$repo/new-device.sh" --name race2 --os linux >/dev/null 2>"$work/race2.err" &
p2=$!
wait $p1 || s1=$?
wait $p2 || s2=$?
refused=0
for f in "$work/race1.err" "$work/race2.err"; do
    if grep -q 'another provisioning run is in progress' "$f"; then
        refused=$((refused+1))
    fi
done
if [ "$refused" -ne 1 ]; then
    printf 'FAIL: concurrent runs: statuses %s/%s, %s lock refusal(s), want exactly 1\n' "$s1" "$s2" "$refused"
    fail=1
fi
rows=$(awk -F'\t' '/^race/ {print}' "$HOME/.keys/egress-peers.tsv" 2>/dev/null | wc -l) || rows=0
if [ "$rows" -ne 1 ]; then
    printf 'FAIL: concurrent runs left %s registry rows, want 1\n' "$rows"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    printf 'new-device lock tests passed\n'
fi
exit "$fail"
