#!/usr/bin/env bash
# Cross-build the Windows GUI from Linux with the MSVC toolchain that
# cargo-xwin provides, then package the portable zip. No Windows host needed.
#
#   ./deploy/build-windows-gui.sh 0.5.1
set -euo pipefail

version="${1:?usage: build-windows-gui.sh <version>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

command -v cargo-xwin >/dev/null 2>&1 || cargo install cargo-xwin
rustup target add x86_64-pc-windows-msvc >/dev/null

(cd gui/frontend && npm ci && npm run build)
(cd gui/src && cargo xwin build --release --locked --target x86_64-pc-windows-msvc)

pkg="dist/egress-gui-${version}-windows-x86_64"
rm -rf "$pkg"
mkdir -p "$pkg"
cp gui/src/target/x86_64-pc-windows-msvc/release/egress-gui.exe "$pkg/egress-gui.exe"
cp deploy/windows-gui-README.txt "$pkg/README.txt"

python3 - "$pkg" "dist/$(basename "$pkg").zip" <<'PY'
import pathlib
import sys
import zipfile

src, out = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
    for path in src.rglob("*"):
        archive.write(path, path.relative_to(src.parent))
PY

cp "$pkg/egress-gui.exe" dist/egress-gui-windows-x86_64.exe
(cd dist && sha256sum "egress-gui-windows-x86_64.exe" "$(basename "$pkg").zip" \
    > "egress-gui-${version}-windows-x86_64.sha256")

echo "built $pkg and dist/$(basename "$pkg").zip"
