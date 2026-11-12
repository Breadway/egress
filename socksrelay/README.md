# socksrelay

Authenticated SOCKS5 relay for `egress` split mode on Windows. It listens on
loopback only and is reachable through the existing WebSocket path on
`dns.breadway.dev`, so a filtered network sees the same TLS session it already
allows for DoH and the WireGuard fallback.

The relay refuses loopback, private, link-local, carrier-grade NAT (including
Tailscale) and benchmarking destinations, so a client cannot use Aegis as a
bounce into its own services or the tailnet.

## Server layout on Aegis

```
client browser
  -> 127.0.0.1:1080            local wstunnel TCP forward
  -> wss://dns.breadway.dev/socks
  -> Caddy -> wstunnel server 127.0.0.1:7110
  -> socksrelay 127.0.0.1:7109 -> destination
```

## Install

```sh
useradd --system --no-create-home --shell /usr/sbin/nologin egress-socks
install -d -m 0750 -o root -g egress-socks /etc/egress-socks
printf 'sam:%s\n' "$(openssl rand -base64 24)" > /etc/egress-socks/auth
chmod 0640 /etc/egress-socks/auth
chown root:egress-socks /etc/egress-socks/auth

cd socksrelay && go build -o /usr/local/bin/socksrelay .
install -m 0644 deploy/egress-socks.service /etc/systemd/system/
systemctl enable --now egress-socks
```

The credential is baked into the delivery build of the Windows client, the same
way the WireGuard key is. Treat the built client as a credential.

## wstunnel server and Caddy

A second server instance fronts the relay on a distinct path:

```
wstunnel server --restrict-http-upgrade-path-prefix socks \
  --restrict-to 127.0.0.1:7109 ws://127.0.0.1:7110
```

In the `dns.breadway.dev` Caddy block, before the DoH handler:

```
handle /socks* {
    reverse_proxy 127.0.0.1:7110
}
```

The path prefix is obscurity, not authentication; the SOCKS username and
password are the actual gate.

## Client

```
wstunnel client --http-upgrade-path-prefix socks \
  --dns-resolver dns://127.0.0.1:7103 --dns-resolver-prefer-ipv4 \
  --tls-verify-certificate \
  -L tcp://127.0.0.1:1080:127.0.0.1:7109 \
  wss://dns.breadway.dev
```

Then point the PAC or browser at `SOCKS5 127.0.0.1:1080`.
