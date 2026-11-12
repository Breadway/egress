# assets/

Pinned vendor binaries embedded into delivery builds via `//go:embed`.
They are git-ignored (see `../.gitignore`); fetch them on the build machine.

Required files and SHA-256:

| File | Source | SHA-256 |
|---|---|---|
| `wstunnel-linux-amd64` | `wstunnel` 11.1.0 linux/amd64 binary (e.g. copy from `/usr/local/bin/wstunnel`) | `62b26d0ee0f2211cef15fa1b85173fe687bc6698121842bf324359b412afc151` |
| `wstunnel-windows-amd64.exe` | `wstunnel_11.1.0_windows_amd64.tar.gz` from `https://github.com/erebe/wstunnel/releases/download/v11.1.0/`, extract `wstunnel.exe` and rename | `c7b5b53c1476995310fe10b2f3f6d19006e5a5948984d8d25682b47e8ecb8f73` |
| `wireguard-amd64-1.1.1.msi` | `https://download.wireguard.com/windows-client/wireguard-amd64-1.1.1.msi` | `7bfed60ad61b785c914b38b61555a975488e1d3ec472dbfb2fcdf498fca75242` |

`build.sh` / `build.ps1` verify these digests before compiling and fail
otherwise. The Linux constant lives in `platform_linux.go`
(`wstunnelLinuxSHA256`); the Windows constants live in `platform_windows.go`.
Keep all three places in sync when bumping versions.
