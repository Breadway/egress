# Laws

Properties egress must never violate, written as statements of impossibility.
Each one comes from a real failure observed on a real machine during the week of
17 November 2026, and each is enforced by code plus a test that fails if the
code stops enforcing it.

These are executable laws, not proofs. A model checker would be the next step if
we want the state machine itself verified; see the last section.

## 1. An update never leaves the service stopped

Installing stops the supervisor. Every exit path of `update-apply` must start it
again, or the machine has no resolver and no way to run `enable` without a
console.

- Code: `defer` in `cmdUpdateApply` (`internal/egress/windows_update.go`)
- Enforced by: the defer runs on success, failure, rollback and error

## 2. An install never leaves a binary Windows refuses to load

A file can land with the right bytes and an empty DACL: only its owner can touch
it, an administrator gets `access denied`, and Defender is never involved.

- Code: grants before `/inheritance:r`, child ACL reset, writability probe,
  per-binary ACL repair (`internal/platform/platform_windows.go`)
- Tests: `TestInstallDirACLArgs` (grants first), `TestBinaryACLScript`,
  `TestStartLauncherFailsOpen`

## 3. DNS is always applied, even when its bookkeeping fails

The DHCP server we remember as a fallback lives in a file that can be stale or
locked. Failing to write it must never stop `Set-DnsClientServerAddress`.

- Code: `applyDNSScript` wraps the fallback read and write
- Test: `TestApplyDNSScriptKeepsFallback` asserts the wrap and that the apply is
  not optional

## 4. A machine that checks for updates is never reported as off

The update check runs every minute and heartbeats. A recent report without a
heartbeat means an old build or a broken updater, not a dead machine.

- Code: `deviceState` in `bypass-server/enroll.go`
- Tests: `TestDeviceStateLaws`, `TestDeviceStateOffWhenSilent`

## 5. Enrollment survives a failed install

The relay credential and the device identity are written when enrollment returns
them, and written again after the directory is proven writable, so a failure
later in the install cannot strand a bound device with no credential.

- Code: `runInstall` (`internal/egress/main.go`)
- Test: identity replacement through the ACL-aware hook (`health.RemoveStale`)

## 6. A missing boot task is recreated, not refused

The task is deleted by a failed install and by manual cleanup. `enable` must
recreate it from the installed binary.

- Code: `Enable` (`internal/platform/platform_windows.go`)

## 7. Every enrolled device can report

Reports are gated on enrollment. Devices enrolled by token live in
`devices.json`, not `users.json`; the gate must accept both or every working
install is invisible.

- Code: `peerEnrolled` (`bypass-server/reports.go`)
- Test: `TestReportAcceptedForEnrolledDevice`

## 8. Support uploads are bounded and attributable

Only an enrolled device may upload, the body is capped, the payload must be a
zip, and only the newest few bundles per device are kept.

- Code: `apiSupport` (`bypass-server/support.go`)
- Test: `TestSupportUploadStoresForEnrolledDevice`

## 9. One inventory

Applications, Devices, Logins and Overview derive their numbers from one join,
so two pages cannot disagree about the same machine.

- Code: `fleet` (`bypass-server/fleet.go`)
- Test: `TestFleetCountsAgree`

## What is not proven

These are unit and integration laws: they pin the code that implements each
property, including the exact ACL argument order and the exact script shape.
They do not prove the absence of every interleaving.

If machine-checked impossibility is wanted, the updater and installer are the
right target: model `{installed, staged, applying, applied, rolled-back,
parked}` with calls `{check, apply, fail-verify, fail-swap, start}` in TLA+ or
Alloy, and assert the four invariants above over every reachable state. That is
a small spec, and it would catch ordering mistakes that no single unit test can.
