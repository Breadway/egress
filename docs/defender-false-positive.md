# Defender false positive: Trojan:Win32/Kepavll!rfn

Windows Defender labels part of an egress install as `Trojan:Win32/Kepavll!rfn`
(Severe). It is a false positive. This file is the evidence and the submission
text, so each flagged build can be reported in a couple of minutes.

## What the detection means

`Kepavll` is a generic name for behaviour that resembles a downloader or
backdoor. The `!rfn` suffix marks a reputation-based verdict rather than a
signature match: the file is unsigned, rare, and does something that looks like
dropping an executable. Microsoft's own encyclopedia entry says the detection
"can often result in false positives, as it behaves similar to game modding
tools, legit system utilities, and software development apps".

## What is actually in the build

- `egress.exe` is a Go program built from this repository. It installs a DNS
  over HTTPS resolver and a WireGuard or WebSocket tunnel.
- It extracts `wstunnel.exe`, an unmodified upstream release
  (`erebe/wstunnel` v11.1.0, Windows amd64), verified against a pinned SHA-256
  before it is used. The extraction is why the behaviour looks like a dropper.
- Nothing is downloaded from an untrusted source and nothing is executed from
  the network: the payload is compiled into the binary and checked against a
  hard-coded digest.

Upstream wstunnel has the same report open. So does `cloudflared`, which is
signed and published by Cloudflare.

## Hashes to submit

| File | SHA-256 |
|---|---|
| `egress-windows-amd64-0.4.39.exe` | `28db612b836114978ccabcd48640b05f264ab8201c56d0f2440fd5df3eebf9d3` |
| `wstunnel.exe` (upstream v11.1.0) | `c7b5b53c1476995310fe10b2f3f6d19006e5a5948984d8d25682b47e8ecb8f73` |

Recompute for a new build with `sha256sum dist/egress-windows-amd64-<version>.exe`.

## Submit

1. Open https://www.microsoft.com/en-us/wdsi/filesubmission
2. Choose **Developer** submission, then **Incorrectly detected as malware**.
3. Upload the flagged file. If the detection names `wstunnel.exe`, submit that
   file; if it names `egress.exe`, submit that. Submitting both is fine.
4. Paste the text below, adjusting the version line.

> egress is a DNS-over-HTTPS and WireGuard client for Windows, distributed at
> https://bypass.breadway.dev. The binary is a Go program that installs a
> resolver and a tunnel; the file Defender flags, wstunnel.exe, is an
> unmodified upstream release of erebe/wstunnel v11.1.0, verified against a
> pinned SHA-256 before use. Detection name: Trojan:Win32/Kepavll!rfn. The
> software does not download or execute code from the network, does not persist
> outside its own ProgramData directory and a scheduled task, and can be
> removed with `egress remove`. The same detection has been reported for
> cloudflared (signed by Cloudflare) and for wstunnel itself, and Microsoft's
> encyclopedia entry for Kepavll notes it is prone to false positives.
> SHA-256 of the submitted file: <hash>.

## What to do on a machine meanwhile

Until the build is signed, a machine that has already quarantined the file has
two options:

- `egress allow-defender` adds an exclusion for the install directory and
  states the cost. `egress allow-defender --remove` or `egress remove` takes it
  back out.
- Wait for the submission to clear. The detection is per file hash, so the
  build that was flagged stays flagged.

Signing with Authenticode is the structural fix: reputation detections fall
away for signed binaries, and application-control policies on managed machines
block unsigned ones regardless of heuristics. The other structural fix is
removing the dropped third-party binary entirely by compiling the WebSocket
fallback into `egress.exe`.
