# xdns-bpf: High-Performance eBPF DNS Interception & Transparent Traffic Redirection

`xdns-bpf` is a standalone, kernel-level network utility designed for OpenWrt routers and Linux gateways. It uses eBPF (Extended Berkeley Packet Filter) on the Traffic Control (TC) subsystem to dynamically intercept DNS queries, dynamically learn resolved IP addresses, and transparently steer restricted traffic into high-speed encrypted tunnels (such as `xkcptun`).

## Key Features

1. **Kernel-Level DNS Query Interception (TC Ingress)**
   - Wire-speed DNS inspection on `br-lan`.
   - In-kernel domain matching using 64-bit FNV-1a hashing against a BPF Hash Map.
   - Automatic wildcard subdomain matching (e.g. `google.com` automatically covers `*.google.com`).
   - Non-whitelisted queries return `TC_ACT_UNSPEC`, allowing seamless chaining with other TC filters (e.g. `aw-bpf`).

2. **Dynamic In-Kernel IP Learning (TC Egress)**
   - Parses clean DNS responses returning from the encrypted tunnel (e.g. port 5353).
   - Dynamically populates the BPF LRU Hash Map (`xdns_ip_set`) with real IP addresses and exact TTL expiration.
   - Restores original DNS transaction headers via reverse-SNAT so clients see a completely transparent reply.

3. **Wire-Speed TCP Redirection (TC Ingress)**
   - Checks outgoing TCP SYN destination IPs against `xdns_ip_set`.
   - Transparently rewrites destination to local `xkcptun` proxy port (e.g. 12345).
   - Zero user-space overhead or iptables/nftables bloat.

4. **Coexistence with Existing Flow Control**
   - Designed to run at `pref 1`. Any non-matched packet falls through cleanly to `pref 2` (such as `aw-bpf`).

## Architecture

```
[LAN Client]
    │ DNS Query (e.g. github.com)
    ▼
[br-lan: TC Ingress (xdns_bpf pref 1)]
    ├─► Match Whitelist? ──YES──► DNAT to 127.0.0.1:5353 (xkcptun UDP Tunnel)
    │                                │
    └─► NO ──► TC_ACT_UNSPEC ────────┼──► pref 2 (aw-bpf / default flow)
                                     ▼
                      [xkcptun Encrypted Tunnel]
                                     │
                                     ▼ (Pure DNS Response)
[br-lan: TC Egress (xdns_bpf pref 1)]
    ├─► Parse A record IP ➔ Save to BPF Map 'xdns_ip_set' (with TTL)
    └─► Reverse SNAT to original DNS IP ➔ Return to Client
                                     │
[LAN Client connects TCP] ───────────┘
    ▼
[br-lan: TC Ingress]
    └─► Destination IP in 'xdns_ip_set'? ──YES──► DNAT to 192.168.8.1:12345 (xkcptun REDIRECT / SOCKS5)
```

## CLI Usage (`xdns-ctl`)

```bash
# Add single domain to whitelist
xdns-ctl add-domain github.com

# Remove domain from whitelist
xdns-ctl del-domain github.com

# Batch load domains from file
xdns-ctl load-whitelist /etc/xdns/whitelist.txt

# Inspect currently learned active IP set and remaining TTLs
xdns-ctl list-ips

# View real-time interception statistics
xdns-ctl stats
```

## License

GPL-2.0-or-later
