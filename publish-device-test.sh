#!/usr/bin/env bash
# Test for publish-device.sh: proves the admin token and the download
# password never appear in any process argv (local ssh, remote bash, remote
# curl), that the binary is piped to install with no staging file, and that
# nasty passwords survive the quoting. Runs entirely locally with stubbed
# ssh/sudo/curl; needs nothing on Aegis.
#
# Usage: ./publish-device-test.sh
set -euo pipefail

repo="$(cd "$(dirname "$0")" && pwd)"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work"/bin "$work"/keys "$work"/logs
export HOME="$work"

# Fake registry row: label, ip, pubkey, key path, binaries, host, created, comment.
printf 'testdev\t10.88.0.99\tQUJDRA==\t%s\t%s\taegis\t2026-01-01\tcomment\n' \
    "$work/keys/testdev.key" "$work/testdev-bin" > "$work/.keys-egress-peers.tsv"
mkdir -p "$work/.keys"
mv "$work/.keys-egress-peers.tsv" "$work/.keys/egress-peers.tsv"
printf 'fake-key' > "$work/keys/testdev.key"
printf 'fake-binary-bytes' > "$work/testdev-bin"

export STUB_LOG="$work/logs"
export FAKE_TOKEN="tok-9f8c7b6a5d4e"

# Stub ssh: records argv + stdin per call, then emulates the Aegis side.
cat > "$work/bin/ssh" <<'STUB'
#!/usr/bin/env bash
n=$(ls "$STUB_LOG"/argv.* 2>/dev/null | wc -l)
printf '%s\n' "$*" > "$STUB_LOG/argv.$n"
if [ ! -t 0 ]; then cat > "$STUB_LOG/stdin.$n"; else : > "$STUB_LOG/stdin.$n"; fi
remote="$*"
case "$remote" in
    *"cat /etc/bypass/admin-token"*) printf '%s' "$FAKE_TOKEN" ;;
    *"install -o bypass"*) cat "$STUB_LOG/stdin.$n" > "$STUB_LOG/uploaded" ;;
    *"bash -s"*) PATH="$STUB_LOG/stubbin:$PATH" bash -s < "$STUB_LOG/stdin.$n" ;;
esac
exit 0
STUB
chmod +x "$work/bin/ssh"

# Stubs used inside the emulated remote script.
mkdir -p "$STUB_LOG/stubbin"
cat > "$STUB_LOG/stubbin/sudo" <<'STUB'
#!/usr/bin/env bash
if [ "$1" = "-n" ]; then shift; fi
exec "$@"
STUB
cat > "$STUB_LOG/stubbin/curl" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$STUB_LOG/curl-argv"
cat >> "$STUB_LOG/curl-stdin"
for arg in "$@"; do
    case "$arg" in
        password@*) printf 'RESOLVED-PASSWORD:%s\n' "$(cat "${arg#password@}")" >> "$STUB_LOG/curl-stdin" ;;
    esac
done
if printf '%s\n' "$*" | grep -q '/admin/api/link'; then
    printf 'linked\n200'
else
    printf 'registered\n201'
fi
STUB
chmod +x "$STUB_LOG/stubbin/sudo" "$STUB_LOG/stubbin/curl"
export PATH="$work/bin:/usr/bin:/bin"

fail=0
check() {
    if ! "$@"; then
        printf 'FAIL: %s\n' "$*"
        fail=1
    fi
}

NASTY='p@ss "w\ord$!'
# Note: no backtick here on purpose; a literal backtick in this file's double
# quotes would trigger command substitution in the harness itself. The remote
# heredoc body is literal either way, and ", \, $, space and ! already cover
# the quoting hazards.
"$repo/publish-device.sh" --name testdev --user testuser --password "$NASTY" \
    --os linux --application abcdef0123456789 >/dev/null \
    || { printf 'FAIL: publish-device exited %s\n' "$?"; fail=1; }

# 1. No argv anywhere may contain the token or the password.
if grep -rF -e "$FAKE_TOKEN" -e "$NASTY" "$STUB_LOG"/argv.* "$STUB_LOG"/curl-argv >/dev/null 2>&1; then
    printf 'FAIL: secret found in process argv\n'
    grep -rF -l -e "$FAKE_TOKEN" -e "$NASTY" "$STUB_LOG"/argv.* "$STUB_LOG"/curl-argv || true
    fail=1
fi

# 2. The uploaded bytes must equal the binary, with no staging involved.
check cmp -s "$work/testdev-bin" "$STUB_LOG/uploaded"
if ls "$STUB_LOG"/stdin.* >/dev/null 2>&1 && grep -l 'bypass-upload' "$STUB_LOG"/stdin.* >/dev/null 2>&1; then
    printf 'FAIL: predictable /tmp staging path still referenced\n'
    fail=1
fi

# 3. The remote curl must have received the token (header) and taken the
# password through the @file indirection.
check grep -qF "Authorization: Bearer $FAKE_TOKEN" "$STUB_LOG/curl-stdin"
check grep -qF 'password@/tmp/bypass-pw-' "$STUB_LOG/curl-argv"
# The password file the remote script wrote must have held the exact nasty
# value at curl time (the script's trap deletes it afterwards).
check grep -qF "RESOLVED-PASSWORD:$NASTY" "$STUB_LOG/curl-stdin"

# 4. A newline password must be refused before any registration call.
if "$repo/publish-device.sh" --name testdev --user testuser --password "$(printf 'bad\npw0123456789')" \
    --os linux >/dev/null 2>&1; then
    printf 'FAIL: newline password was accepted\n'
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    printf 'publish-device secrecy tests passed\n'
fi
exit "$fail"
