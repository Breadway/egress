# First-activation enrollment

A new device can bind its own key instead of receiving one baked into the
installer. The download carries at most a one-time token, so a shared file stops
being a working identity after it is used once.

Existing devices are unaffected: their embedded-key builds keep working, and
their peers and relay users are never touched by this path.

## Flow

1. The admin approves the application. Approval issues the invite and prepares
   the installer automatically; the token is shown once.
2. The applicant opens their status page (the browser remembers it) and
   downloads `egress-setup.zip`, which contains the installer, `enroll.txt` and
   instructions. Manually, the token also works with:

   ```powershell
   .\egress.exe install --enroll-token <token>
   ```

   As administrator, from any folder.
3. The installer generates a WireGuard keypair locally and posts only the
   public key to `POST /api/enroll` with the token.
4. The server checks the token, allocates the next free address in
   `10.88.0.20-199`, and hands the claim to the root enrollment agent.
5. The agent validates the claim, appends the peer to `wg0.conf`, applies it
   live, and adds the relay credential. It only ever appends.
6. The installer receives the address and relay credential (Windows split uses
   the credential for the per-user proxy), writes its local identity, and
   continues with the normal install and verification.

## Properties

- The private key is generated on the device and never transmitted.
- A token works once, expires after 72 hours, and cannot change a bound device.
- Replacing a device needs a new invite; the admin issues one.
- Enrollment is rate limited per source address.
- Revoking an unbound invite deletes it. A bound device is never removed
  automatically.

## Server files

- `/var/lib/bypass/devices.json` (0600) holds invites and bindings. Token
  hashes only; the token itself is shown once.
- `/var/lib/bypass/enroll/` is the claim spool between the web server (bypass)
  and the root agent.
- `egress-enroll-agent.service` runs the agent. It requires `wg-quick@wg0`.

## Deploy

```sh
go build -o dist/egress-enroll-agent ./cmd/egress-enroll-agent
scp dist/egress-enroll-agent aegis:/tmp/
ssh aegis 'sudo install -o root -g root -m 0755 /tmp/egress-enroll-agent /usr/local/bin/egress-enroll-agent'
ssh aegis 'sudo install -m 0644 /dev/stdin /etc/systemd/system/egress-enroll-agent.service' \
    < deploy/egress-enroll-agent.service
ssh aegis 'sudo systemctl enable --now egress-enroll-agent'
```

The web server binary must also be current; it owns the invite page and the
enroll endpoint.

## Limits

- First activation needs a path to `bypass.breadway.dev`. An offline install
  cannot enroll and needs the embedded-key build instead.
- The generic installer must exist in `/var/lib/bypass/binaries/` as
  `egress-windows-amd64-<version>.exe`; approval fails with a clear message
  until it is present.
- If an install fails after the token was consumed, the device is bound but not
  installed. Its identity file still holds the key on Linux; on Windows split
  the relay credential lives in the per-user profile once the split step ran.
  A persistent failure needs a fresh invite.
