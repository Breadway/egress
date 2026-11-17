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

```sh
go build -o dist/egress-exit ./cmd/egress-exit
scp dist/egress-exit aegis:/tmp/egress-exit
ssh aegis 'sudo install -o root -g root -m 0755 /tmp/egress-exit /usr/local/bin/egress-exit'
ssh aegis 'sudo install -m 0644 /dev/stdin /etc/systemd/system/egress-exit.service' < deploy/egress-exit.service
ssh aegis 'sudo systemctl enable --now egress-exit'
```

Check the decision without changing routes:

```sh
sudo /usr/local/bin/egress-exit --once --dry-run --verbose
```

## hestia side

`/etc/wireguard/wgexit.conf` (private key stays on hestia):

```ini
[Interface]
PrivateKey = <hestia key>
Address = 10.99.0.2/32
MTU = 1420
PostUp = sysctl -qw net.ipv4.ip_forward=1; ip route replace 10.88.0.0/24 dev %i
PostUp = iptables -C FORWARD -i %i -o enp9s0 -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i %i -o enp9s0 -j ACCEPT
PostUp = iptables -C FORWARD -i enp9s0 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -I FORWARD 1 -i enp9s0 -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
PostUp = iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
PostUp = iptables -t nat -C POSTROUTING -s 10.88.0.0/24 -o enp9s0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.88.0.0/24 -o enp9s0 -j MASQUERADE

[Peer]
PublicKey = <aegis wg0 public key>
Endpoint = 152.69.174.7:7105
AllowedIPs = 10.88.0.0/24
PersistentKeepalive = 25
```

`systemctl enable --now wg-quick@wgexit`. The TCP MSS clamp matters: this path
is two WireGuard layers deep, and without it large responses stall.
