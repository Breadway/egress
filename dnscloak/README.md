# dnscloak

Answers selected names with the relay address `10.88.0.254` and forwards
everything else to the real resolver. Runs on Aegis between doh-proxy
(`:7101`) and dnsproxy (`:7102`), so every DoH client gets the same answers
without rebuilding anything.

## Chain

```text
client -> Caddy :443 -> doh-proxy :7101 -> dnscloak :7103 -> dnsproxy :7102 -> Quad9
```

Microsoft names resolve to `10.88.0.254`. Aegis DNATs that address to
Hestia:7106 for the whole tunnel subnet (`microsoft-hestia.nft` in the infra
worktree), and Hestia reads the TLS SNI and connects from its own address.
UDP/443 to the relay address is rejected so QUIC falls back to TCP.

## Names

One suffix per line in `suffixes.txt`. A name matches when it equals a suffix
or sits under one, so `teams.microsoft.com` matches `microsoft.com`. A leading
`*.` is accepted and ignored. AAAA answers are empty (NOERROR, no records), so
clients use IPv4.

To change the list, edit `suffixes.txt`, copy it to
`/etc/dnscloak/suffixes.txt` on Aegis, and restart `dnscloak.service`. No
rebuild needed.

## Notes

- stdlib only, no dependencies. UDP and TCP on the same port.
- Only single-question IN queries are inspected; anything else is forwarded
  untouched. Truncated UDP answers fall back to TCP upstream.
- Drops instead of answering only happen on upstream failure (SERVFAIL).
