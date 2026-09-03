# xdns-bpf: High-Performance eBPF DNS Interception & Transparent Traffic Redirection

`xdns-bpf` is a standalone, kernel-level network utility designed for OpenWrt routers and Linux gateways. It uses eBPF (Extended Berkeley Packet Filter) on the Traffic Control (TC) subsystem to dynamically intercept DNS queries, dynamically learn resolved IP addresses, and transparently steer restricted traffic into high-speed encrypted tunnels (such as `xkcptun`).

## Key Features

1. **Kernel-Level DNS Query Interception (TC Ingress)**
   - Wire-speed DNS inspection on `br-lan`.
   - In-kernel domain matching using 64-bit FNV-1a hashing against a BPF Hash Map (`xdns_domains`).
   - Automatic wildcard subdomain matching (e.g. `github.com` automatically covers `*.github.com`).
   - Non-proxied queries return `TC_ACT_UNSPEC`, allowing seamless chaining with other TC filters (e.g. `aw-bpf`).

2. **Dynamic In-Kernel IP Learning (TC Egress)**
   - Parses clean DNS responses returning from the encrypted tunnel (e.g. port 5353).
   - Loops through Answer RRs, properly handling CNAME aliases and multiple A records.
   - Dynamically populates the BPF LRU Hash Map (`xdns_ip_set`) with real IP addresses and exact TTL expiration.
   - Restores original DNS transaction headers via reverse-SNAT so clients see a completely transparent reply.

3. **Wire-Speed Bidirectional TCP NAT & Session Tracking (Option A)**
   - Pure eBPF transparent proxying without Netfilter / TPROXY dependencies.
   - Robust TCP state machine: pure SYN packets check `xdns_ip_set` and purge stale reused ports.
   - TC Ingress: Intercepts outgoing TCP SYN/data to IPs in `xdns_ip_set`, records session, and DNATs to transparent proxy port.
   - TC Egress: Automatically Reverse-SNATs returning TCP traffic to the original foreign IP and port, enabling instant 3-way handshake without client RST.
   - Downstream cascade: Returns `TC_ACT_UNSPEC` after packet rewrites so downstream filters (e.g. `aw-bpf`) still receive traffic for MAC/IP accounting and EDT rate limiting.

4. **Wildcard & Subdomain Auto-Matching**
   - Shift Suffix Hashing automatically matches subdomains against base domains (e.g. `github.com` covers `api.github.com`, `raw.githubusercontent.com`).

5. **Standalone Control CLI (`xdns-ctl`)**
   - Manage proxy domains dynamically with instant kernel sync and file persistence.
   - Monitor real-time active TCP sessions and learned IP TTLs.

## Architecture

```
[LAN Client]
    │ DNS Query (e.g. github.com)
    ▼
[br-lan: TC Ingress (xdns_bpf pref 1)]
    ├─► Match Proxy Domains? ──YES──► DNAT to 192.168.8.1:5353 (xkcptun UDP Tunnel)
    │                                │
    └─► NO / Pass ──► TC_ACT_UNSPEC ─┼──► pref 2 (aw-bpf: MAC/IP accounting & EDT QoS)
                                     ▼
                      [xkcptun Encrypted Tunnel]
                                     │
                                     ▼ (Pure DNS Response)
[br-lan: TC Egress (xdns_bpf pref 1)]
    ├─► Parse A record IP ➔ Save to BPF Map 'xdns_ip_set' (with TTL)
    └─► Reverse SNAT to original DNS IP ➔ TC_ACT_UNSPEC ➔ Return to Client
                                     │
[LAN Client connects TCP] ───────────┘
    ▼
[br-lan: TC Ingress (pref 1)]
    ├─► Destination IP in 'xdns_ip_set'?
    │   └── YES: Save session to 'xdns_tcp_sessions' + DNAT to 12345 ➔ TC_ACT_UNSPEC ➔ pref 2 (aw-bpf)
    ▼
[xkcptun redir tunnel on 12345]
    ├─► Reads /sys/fs/bpf/xdns_tcp_sessions to extract real remote destination
    └─► Forwards payload through encrypted KCP tunnel to remote VPS
    ▼
[br-lan: TC Egress (pref 1)]
    └─► Reverse-SNAT source back to original destination IP:Port ➔ TC_ACT_UNSPEC ➔ Client
```

## CLI Usage (`xdns-ctl`)

```bash
# Add domain to proxy list (supports *.prefix, takes effect immediately & persists)
xdns-ctl add-domain github.com
xdns-ctl add-domain '*.cloudflare.com'

# Remove domain from proxy list
xdns-ctl del-domain github.com

# List proxy domains and their active kernel status
xdns-ctl list-domains

# Batch load domains from file (additive; does not remove stale kernel entries)
xdns-ctl load-domains /etc/xdns/proxy_domains.txt

# Replace kernel domain map from file and clear all learned IPs
xdns-ctl reload-domains /etc/xdns/proxy_domains.txt

# List currently learned dynamic hijacked IP set and TTLs
xdns-ctl list-ips

# Drop all learned IPs (stops steering until DNS is learned again)
xdns-ctl clear-ips

# List active transparent TCP proxy sessions
xdns-ctl list-sessions

# View real-time interception statistics
xdns-ctl stats
```

## Building

```bash
# Build userspace CLI (xdns-ctl)
make xdns-ctl

# Build eBPF object (requires clang and linux headers)
make xdns_bpf.o

# Or build via CMake
cmake -B build -S .
cmake --build build
```

## License

GPL-2.0-or-later
