# Residential exit for sites that refuse the cloud one

A filtered network pushes blocked destinations into the tunnel. Those exit at
Aegis, which is a cloud address, and some sites answer a cloud address with a
block page. reddit is the example: `403 blocked by network security` from
Aegis, `200` from hestia's home connection.

`egress-exit` keeps the cloud exit as the default and learns the exceptions. It
runs on Aegis only.

## Path

```
client -> wg0 (10.88.0.x) -> Aegis -> wg0 peer "hestia" (home 125.253.50.4)
                                          -> hestia NAT -> internet
```

- hestia dials Aegis:7105 as an ordinary wg0 peer, so it works behind NAT and
  needs no new inbound port on Aegis.
- Its peer entry on Aegis allows `0.0.0.0/0`. That is only a mapping: nothing
  goes to hestia unless a route sends it there. `/etc/wireguard/wg0.conf` sets
  `Table = off`, so wg-quick never installs that default.
- hestia keeps `AllowedIPs = 10.88.0.0/24`, routes that subnet over the link,
  forwards, and masquerades `10.88.0.0/24` out its uplink. Client source
  addresses are preserved end to end, so Aegis needs no second NAT.

## Learning

`egress-exit` reads the fleet's shared block table (`/var/lib/bypass/split/`)
plus `/etc/egress-exit/domains`, resolves each blocked name, and asks it twice:

- cloud exit, socket marked `0x44`, routing table 812 (default via ens3)
- home exit, socket marked `0x45`, routing table 811 (default via wg0)

The marks guarantee a learned route cannot make the cloud check follow the home
exit. A site that refuses the cloud exit (`403`, `451`, `429`, or no HTTP answer
at all) while the home exit serves it (`2xx`/`3xx`) has its `/24`s routed over
wg0, which sends them to hestia. A site that the cloud exit serves again
releases its prefixes on the next cycle. Entries expire after seven days
without a successful observation, and at most 400 prefixes are kept.

The `/24` granularity survives a CDN answer changing between lookups. The
learner resolves names itself, so an address the client sees but Aegis never
resolves is still reached over the cloud exit; extend the learner to consume
client-observed addresses if that shows up in practice.

State lives in `/var/lib/egress-exit/state.json`; routes are restored from it
when the service starts.

## Deploy

Everything below is scripted and idempotent. Run it from the repo root, with
ssh access to both hosts:

```sh
./deploy/install-exit.sh
```

A second run reports `no changes`. It builds and installs `egress-exit`,
installs and enables the unit, adds the hestia peer and `Table = off` to
`wg0.conf` (backing the file up first, never restarting wg0), writes hestia's
`wgexit.conf` only when it differs, enables `wg-quick@wgexit`, and verifies the
handshake and the learner.

Check the learner's decision without changing routes:

```sh
sudo /usr/local/bin/egress-exit --once --dry-run --verbose
```

## hestia side

`deploy/install-exit.sh` writes this file; it is shown so the forwarding and NAT
can be reviewed. The private key stays on hestia.
## hestia side

The interface carries `Address = 10.99.0.2/32`, routes `10.88.0.0/24` back to
Aegis, forwards and masquerades that subnet out the detected uplink, and clamps
TCP MSS. The clamp matters: this path is two WireGuard layers deep, and without
it large responses stall. The peer points at the Aegis endpoint with
`AllowedIPs = 10.88.0.0/24` and a persistent keepalive, so it reconnects after
either side restarts.
