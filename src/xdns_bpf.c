#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdns_bpf.h"

#ifndef LIBBPF_PIN_BY_NAME
#define LIBBPF_PIN_BY_NAME 1
#endif

#define MAX_DNS_NAME_LEN 128
#define MAX_DNS_LABELS   8

/* Domain proxy map: 64-bit domain hash -> 1 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdns_domains SEC(".maps");

/* DNS session map for reverse-SNAT */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct xdns_session_key);
    __type(value, struct xdns_session_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdns_sessions SEC(".maps");

/* TCP session map for transparent redirect and reverse-SNAT */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct xdns_tcp_session_key);
    __type(value, struct xdns_tcp_session_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdns_tcp_sessions SEC(".maps");

/* Socket cookie tracking map for Host mode transparent proxy */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct xdns_cookie_val);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdns_cookie_map SEC(".maps");

/* Resolved IP set: IPv4 (network byte order) -> expire timestamp (ns) */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, __u32);
    __type(value, __u64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdns_ip_set SEC(".maps");

/* Config map */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdns_config);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdns_config_map SEC(".maps");

/* Statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdns_stats);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdns_stats_map SEC(".maps");

/* DNS Header */
struct dnshdr {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
} __attribute__((packed));


/* Parse DNS QNAME from payload and test against proxy domains (supports 2 levels of wildcard subdomains) */
static inline int match_dns_qname(void *data, void *data_end, __u32 udp_offset)
{
    unsigned char *ptr = (unsigned char *)data + udp_offset + sizeof(struct udphdr) + sizeof(struct dnshdr);
    __u64 h_full = XDNS_FNV1A_64_OFFSET;
    __u64 h_sub1 = 0;
    __u64 h_sub2 = 0;
    int started = 0;

    /* Single linear scan of QNAME (up to 64 bytes) */
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        if ((void *)(ptr + 1) > data_end)
            return 0;

        unsigned char c = *ptr;
        ptr++;

        if (c == 0) {
            /* End of QNAME: check full domain and parent subdomains */
            __u8 *found = bpf_map_lookup_elem(&xdns_domains, &h_full);
            if (found && *found == 1) return 1;

            if (h_sub2) {
                found = bpf_map_lookup_elem(&xdns_domains, &h_sub2);
                if (found && *found == 1) return 1;
            }
            if (h_sub1) {
                found = bpf_map_lookup_elem(&xdns_domains, &h_sub1);
                if (found && *found == 1) return 1;
            }
            return 0;
        }

        if (c <= 63) {
            if (!started) {
                started = 1;
                continue;
            }
            h_sub2 = h_sub1;
            h_sub1 = XDNS_FNV1A_64_OFFSET;
            c = '.';
        } else if (c >= 'A' && c <= 'Z') {
            c += ('a' - 'A');
        }

        h_full ^= c;
        h_full *= XDNS_FNV1A_64_PRIME;

        if (c == '.') {
            if (h_sub2 && h_sub2 != XDNS_FNV1A_64_OFFSET) {
                h_sub2 ^= c;
                h_sub2 *= XDNS_FNV1A_64_PRIME;
            }
        } else {
            if (h_sub1) {
                h_sub1 ^= c;
                h_sub1 *= XDNS_FNV1A_64_PRIME;
            }
            if (h_sub2) {
                h_sub2 ^= c;
                h_sub2 *= XDNS_FNV1A_64_PRIME;
            }
        }
    }

    return 0;
}

/*
 * Process outbound traffic (Client requests):
 * - DNS query interception and DNAT redirect to xkcptun DNS port
 * - TCP SYN interception and redirect to xkcptun transparent proxy port
 */
static __always_inline int process_outbound(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_UNSPEC;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_UNSPEC;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_UNSPEC;

    __u32 cfg_key = 0;
    struct xdns_config *cfg = bpf_map_lookup_elem(&xdns_config_map, &cfg_key);
    if (!cfg || cfg->enabled == 0)
        return TC_ACT_UNSPEC;

    __u32 stats_key = 0;
    struct xdns_stats *stats = bpf_map_lookup_elem(&xdns_stats_map, &stats_key);

    /* 1. Handle UDP DNS queries */
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)((char *)ip + (ip->ihl * 4));
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_UNSPEC;

        if (udp->dest == bpf_htons(53)) {
            if (stats) stats->dns_queries_total++;

            __u32 udp_offset = sizeof(struct ethhdr) + (ip->ihl * 4);
            struct dnshdr *dns = (void *)((char *)udp + sizeof(struct udphdr));
            if ((void *)(dns + 1) > data_end)
                return TC_ACT_UNSPEC;

            /* Check QR == 0 (Query) and QDCOUNT > 0 */
            if ((bpf_ntohs(dns->flags) & 0x8000) == 0 && bpf_ntohs(dns->qdcount) > 0) {
                if (match_dns_qname(data, data_end, udp_offset)) {
                    if (stats) stats->dns_queries_proxied++;

                    /* Record session for reverse-SNAT */
                    struct xdns_session_key s_key = {
                        .client_ip = ip->saddr,
                        .client_port = udp->source,
                        .tx_id = dns->id,
                    };
                    struct xdns_session_val s_val = {
                        .orig_dst_ip = ip->daddr,
                        .orig_dst_port = udp->dest,
                        .timestamp = bpf_ktime_get_ns(),
                    };
                    bpf_map_update_elem(&xdns_sessions, &s_key, &s_val, BPF_ANY);

                    /* DNAT: Rewrite IP and Port to xkcptun DNS port (5353) */
                    __u32 old_daddr = ip->daddr;
                    __u32 new_daddr = cfg->xkcp_dns_ip;
                    __u16 old_dport = udp->dest;
                    __u16 new_dport = cfg->xkcp_dns_port;

                    ip->daddr = new_daddr;
                    udp->dest = new_dport;

                    bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                                        old_daddr, new_daddr, 4);

                    bpf_l4_csum_replace(skb, udp_offset + offsetof(struct udphdr, check),
                                        old_daddr, new_daddr, 4 | BPF_F_PSEUDO_HDR);
                    bpf_l4_csum_replace(skb, udp_offset + offsetof(struct udphdr, check),
                                        old_dport, new_dport, 2);

                    /* Cascade to downstream filter */
                    return TC_ACT_UNSPEC;
                }
            }
        }
    }

    /* 2. Handle TCP traffic for proxied target IPs */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((char *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_UNSPEC;

        struct xdns_tcp_session_key t_key = {
            .client_ip = ip->saddr,
            .client_port = tcp->source,
            .pad = 0,
        };

        int is_syn = (tcp->syn && !tcp->ack);
        int is_rst = tcp->rst;
        int redirect = 0;

        if (is_syn) {
            /* A pure SYN packet indicates a brand-new TCP connection.
             * Always verify destination IP against dynamic xdns_ip_set.
             */
            __u32 dst_ip = ip->daddr;
            __u64 *expire_ts = bpf_map_lookup_elem(&xdns_ip_set, &dst_ip);
            __u64 now = bpf_ktime_get_ns();

            if (expire_ts && now < *expire_ts) {
                if (stats) stats->tcp_redirected++;

                struct xdns_tcp_session_val t_val = {
                    .orig_dst_ip = ip->daddr,
                    .orig_dst_port = tcp->dest,
                    .pad = 0,
                    .timestamp = now,
                };
                bpf_map_update_elem(&xdns_tcp_sessions, &t_key, &t_val, BPF_ANY);
                redirect = 1;
            } else {
                /* New connection to non-proxied IP: clear any stale session
                 * lingering on this reused client ephemeral port.
                 */
                bpf_map_delete_elem(&xdns_tcp_sessions, &t_key);
            }
        } else {
            /* Established packet: verify session matches exact original destination */
            struct xdns_tcp_session_val *existing = bpf_map_lookup_elem(&xdns_tcp_sessions, &t_key);
            if (existing && existing->orig_dst_ip == ip->daddr && existing->orig_dst_port == tcp->dest) {
                redirect = 1;
                if (is_rst) {
                    bpf_map_delete_elem(&xdns_tcp_sessions, &t_key);
                }
            }
        }

        if (redirect) {
            /* DNAT: Rewrite destination to xkcptun transparent proxy port */
            __u32 old_daddr = ip->daddr;
            __u32 new_daddr = cfg->xkcp_tcp_ip;
            __u16 old_dport = tcp->dest;
            __u16 new_dport = cfg->xkcp_tcp_port;

            __u32 tcp_offset = sizeof(struct ethhdr) + (ip->ihl * 4);

            ip->daddr = new_daddr;
            tcp->dest = new_dport;

            bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                                old_daddr, new_daddr, 4);

            bpf_l4_csum_replace(skb, tcp_offset + offsetof(struct tcphdr, check),
                                old_daddr, new_daddr, 4 | BPF_F_PSEUDO_HDR);
            bpf_l4_csum_replace(skb, tcp_offset + offsetof(struct tcphdr, check),
                                old_dport, new_dport, 2);

            /* Cascade to downstream filter */
            return TC_ACT_UNSPEC;
        }
    }

    /* Fall through to next filter */
    return TC_ACT_UNSPEC;
}

/*
 * Process inbound traffic (Server/Tunnel responses):
 * - Parse DNS response answers and cache resolved IPs into xdns_ip_set with TTL
 * - Reverse-SNAT for DNS query replies
 * - Reverse-SNAT for TCP proxy return packets
 */
static __always_inline int process_inbound(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_UNSPEC;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_UNSPEC;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_UNSPEC;

    __u32 cfg_key = 0;
    struct xdns_config *cfg = bpf_map_lookup_elem(&xdns_config_map, &cfg_key);
    if (!cfg || cfg->enabled == 0)
        return TC_ACT_UNSPEC;

    /* 1. Handle UDP DNS responses from xkcptun */
    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)((char *)ip + (ip->ihl * 4));
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_UNSPEC;

        /* Check if packet is DNS response from xkcptun (source port 5353) */
        if (udp->source == cfg->xkcp_dns_port) {
            struct dnshdr *dns = (void *)((char *)udp + sizeof(struct udphdr));
            if ((void *)(dns + 1) > data_end)
                return TC_ACT_UNSPEC;

            /* QR == 1 (Response) */
            if ((bpf_ntohs(dns->flags) & 0x8000) != 0) {
                __u16 ancount = bpf_ntohs(dns->ancount);
                if (ancount > 0) {
                    __u32 stats_key = 0;
                    struct xdns_stats *stats = bpf_map_lookup_elem(&xdns_stats_map, &stats_key);
                    if (stats) stats->dns_responses_parsed++;

                    /* Parse response answer: skip Question QNAME */
                    unsigned char *ptr = (unsigned char *)dns + sizeof(struct dnshdr);
                    #pragma unroll
                    for (int step = 0; step < 64; step++) {
                        if ((void *)(ptr + 1) > data_end) break;
                        unsigned char l = *ptr;
                        ptr++;
                        if (l == 0) break;
                        if ((l & 0xC0) == 0xC0) {
                            ptr++; /* pointer is 2 bytes total */
                            break;
                        }
                    }
                    /* Skip QTYPE (2) + QCLASS (2) */
                    ptr += 4;

                    /* Parse Answer RRs in loop (up to 4 answers) to support CNAME chains and multi-A records */
                    for (int a = 0; a < 4; a++) {
                        if (a >= ancount) break;
                        if ((void *)(ptr + 2) > data_end) break;

                        /* Skip Answer NAME: standard compression pointer (0xC0xx) or root */
                        unsigned char a0 = *ptr;
                        if ((a0 & 0xC0) == 0xC0) {
                            ptr += 2;
                        } else if (a0 == 0) {
                            ptr += 1;
                        } else {
                            break;
                        }

                        /* Require type(2) + class(2) + ttl(4) + rdlength(2) = 10 bytes */
                        if ((void *)(ptr + 10) > data_end) break;

                        __u16 atype = *(__u16 *)ptr;
                        __u32 attl = 0;
                        __builtin_memcpy(&attl, ptr + 4, 4);
                        __u16 raw_rdlen = 0;
                        __builtin_memcpy(&raw_rdlen, ptr + 8, 2);
                        __u16 rdlen = bpf_ntohs(raw_rdlen);

                        /* Type A (1) and IPv4 length 4 */
                        if (atype == bpf_htons(1) && rdlen == 4) {
                            if ((void *)(ptr + 14) > data_end) break;
                            __u32 ans_ip = 0;
                            __builtin_memcpy(&ans_ip, ptr + 10, 4);
                            __u32 ttl_sec = bpf_ntohl(attl);
                            if (ttl_sec < 60) ttl_sec = 60;
                            if (ttl_sec > 86400) ttl_sec = 86400;

                            __u64 expire_ts = bpf_ktime_get_ns() + ((__u64)ttl_sec * 1000000000ULL);
                            bpf_map_update_elem(&xdns_ip_set, &ans_ip, &expire_ts, BPF_ANY);
                        }

                        /* Advance pointer to next RR (handles both CNAME and A records) */
                        if (rdlen > 128) break;
                        ptr += 10;
                        ptr += (rdlen & 0x7f);
                        if ((void *)ptr > data_end) break;
                    }
                }

                /* Lookup session to reverse-SNAT */
                struct xdns_session_key s_key = {
                    .client_ip = ip->daddr,
                    .client_port = udp->dest,
                    .tx_id = dns->id,
                };
                struct xdns_session_val *s_val = bpf_map_lookup_elem(&xdns_sessions, &s_key);
                if (s_val) {
                    __u32 old_saddr = ip->saddr;
                    __u32 new_saddr = s_val->orig_dst_ip;
                    __u16 old_sport = udp->source;
                    __u16 new_sport = s_val->orig_dst_port;

                    __u32 udp_offset = sizeof(struct ethhdr) + (ip->ihl * 4);

                    ip->saddr = new_saddr;
                    udp->source = new_sport;

                    bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                                        old_saddr, new_saddr, 4);

                    bpf_l4_csum_replace(skb, udp_offset + offsetof(struct udphdr, check),
                                        old_saddr, new_saddr, 4 | BPF_F_PSEUDO_HDR);
                    bpf_l4_csum_replace(skb, udp_offset + offsetof(struct udphdr, check),
                                        old_sport, new_sport, 2);

                    bpf_map_delete_elem(&xdns_sessions, &s_key);
                    /* Cascade to downstream filter */
                    return TC_ACT_UNSPEC;
                }
            }
        }
    }

    /* 2. Handle TCP traffic returning from xkcptun transparent proxy */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)((char *)ip + (ip->ihl * 4));
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_UNSPEC;

        /* Check if packet originated from xkcptun TCP redirect port */
        if (ip->saddr == cfg->xkcp_tcp_ip && tcp->source == cfg->xkcp_tcp_port) {
            struct xdns_tcp_session_key t_key = {
                .client_ip = ip->daddr,
                .client_port = tcp->dest,
                .pad = 0,
            };
            struct xdns_tcp_session_val *t_val = bpf_map_lookup_elem(&xdns_tcp_sessions, &t_key);
            if (t_val) {
                __u32 old_saddr = ip->saddr;
                __u32 new_saddr = t_val->orig_dst_ip;
                __u16 old_sport = tcp->source;
                __u16 new_sport = t_val->orig_dst_port;

                __u32 tcp_offset = sizeof(struct ethhdr) + (ip->ihl * 4);
                int is_closing = (tcp->fin || tcp->rst);

                ip->saddr = new_saddr;
                tcp->source = new_sport;

                bpf_l3_csum_replace(skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
                                    old_saddr, new_saddr, 4);

                bpf_l4_csum_replace(skb, tcp_offset + offsetof(struct tcphdr, check),
                                    old_saddr, new_saddr, 4 | BPF_F_PSEUDO_HDR);
                bpf_l4_csum_replace(skb, tcp_offset + offsetof(struct tcphdr, check),
                                    old_sport, new_sport, 2);

                if (is_closing) {
                    bpf_map_delete_elem(&xdns_tcp_sessions, &t_key);
                }

                /* Cascade to downstream filter */
                return TC_ACT_UNSPEC;
            }
        }
    }

    return TC_ACT_UNSPEC;
}

/*
 * XDNS_MODE_GATEWAY controls whether we are running on a Router/Gateway or Host:
 * - XDNS_MODE_GATEWAY = 1 (Gateway Mode): Ingress intercepts LAN clients, Egress handles return traffic
 * - XDNS_MODE_GATEWAY = 0 (Host Mode, Default): Egress intercepts local host apps, Ingress handles return traffic
 */
#ifndef XDNS_MODE_GATEWAY
#define XDNS_MODE_GATEWAY 0
#endif

SEC("tc/ingress")
int tc_xdns_ingress(struct __sk_buff *skb)
{
#if XDNS_MODE_GATEWAY
    return process_outbound(skb);
#else
    return process_inbound(skb);
#endif
}

SEC("tc/egress")
int tc_xdns_egress(struct __sk_buff *skb)
{
#if XDNS_MODE_GATEWAY
    return process_inbound(skb);
#else
    return process_outbound(skb);
#endif
}

#define SOL_IP 0
#define SO_ORIGINAL_DST 80
#define AF_INET 2

/*
 * Host Mode cgroup programs:
 * Intercept connect(), track socket cookies upon establishment,
 * and provide original destination via getsockopt(SO_ORIGINAL_DST).
 */
SEC("cgroup/connect4")
int xdns_connect4(struct bpf_sock_addr *ctx)
{
    __u32 cfg_key = 0;
    struct xdns_config *cfg = bpf_map_lookup_elem(&xdns_config_map, &cfg_key);
    if (!cfg || cfg->enabled == 0)
        return 1;

    /* Handle UDP DNS connect redirect (optional for connected UDP sockets) */
    if (ctx->protocol == IPPROTO_UDP && ctx->user_port == bpf_htons(53)) {
        if (cfg->xkcp_dns_ip && cfg->xkcp_dns_port) {
            ctx->user_ip4 = cfg->xkcp_dns_ip;
            ctx->user_port = cfg->xkcp_dns_port;
        }
        return 1;
    }

    /* Handle TCP connections */
    if (ctx->protocol == IPPROTO_TCP) {
        __u32 dst_ip = ctx->user_ip4;
        __u64 *expire_ts = bpf_map_lookup_elem(&xdns_ip_set, &dst_ip);
        __u64 now = bpf_ktime_get_ns();

        if (expire_ts && now < *expire_ts) {
            __u64 cookie = bpf_get_socket_cookie(ctx);
            struct xdns_cookie_val val = {
                .orig_dst_ip = dst_ip,
                .orig_dst_port = ctx->user_port,
                .pad = 0,
            };
            bpf_map_update_elem(&xdns_cookie_map, &cookie, &val, BPF_ANY);

            /* Redirect to configured transparent TCP proxy address */
            ctx->user_ip4 = cfg->xkcp_tcp_ip;
            ctx->user_port = cfg->xkcp_tcp_port;

            __u32 stats_key = 0;
            struct xdns_stats *stats = bpf_map_lookup_elem(&xdns_stats_map, &stats_key);
            if (stats) stats->tcp_redirected++;
        }
    }
    return 1;
}

SEC("cgroup/sendmsg4")
int xdns_sendmsg4(struct bpf_sock_addr *ctx)
{
    __u32 cfg_key = 0;
    struct xdns_config *cfg = bpf_map_lookup_elem(&xdns_config_map, &cfg_key);
    if (!cfg || cfg->enabled == 0)
        return 1;

    /* Intercept unconnected UDP DNS queries (standard getaddrinfo / musl / glibc) */
    if (ctx->user_port == bpf_htons(53)) {
        if (cfg->xkcp_dns_ip && cfg->xkcp_dns_port) {
            ctx->user_ip4 = cfg->xkcp_dns_ip;
            ctx->user_port = cfg->xkcp_dns_port;

            __u32 stats_key = 0;
            struct xdns_stats *stats = bpf_map_lookup_elem(&xdns_stats_map, &stats_key);
            if (stats) stats->dns_queries_proxied++;
        }
    }
    return 1;
}

SEC("sockops")
int xdns_sockops(struct bpf_sock_ops *skops)
{
    if (skops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        __u64 cookie = bpf_get_socket_cookie(skops);
        struct xdns_cookie_val *val = bpf_map_lookup_elem(&xdns_cookie_map, &cookie);
        if (val) {
            /* skops->local_port is stored in host byte order */
            struct xdns_tcp_session_key key = {
                .client_ip = skops->local_ip4,
                .client_port = bpf_htons((__u16)skops->local_port),
                .pad = 0,
            };
            struct xdns_tcp_session_val sval = {
                .orig_dst_ip = val->orig_dst_ip,
                .orig_dst_port = val->orig_dst_port,
                .pad = 0,
                .timestamp = bpf_ktime_get_ns(),
            };
            bpf_map_update_elem(&xdns_tcp_sessions, &key, &sval, BPF_ANY);
            bpf_map_delete_elem(&xdns_cookie_map, &cookie);
        }
    }
    return 1;
}

SEC("cgroup/getsockopt")
int xdns_getsockopt(struct bpf_sockopt *ctx)
{
    if (ctx->level == SOL_IP && ctx->optname == SO_ORIGINAL_DST) {
        struct bpf_sock *sk = ctx->sk;
        if (sk) {
            /* Look up original destination using client endpoint */
            struct xdns_tcp_session_key key = {
                .client_ip = sk->dst_ip4,
                .client_port = bpf_htons((__u16)sk->dst_port),
                .pad = 0,
            };
            struct xdns_tcp_session_val *sval = bpf_map_lookup_elem(&xdns_tcp_sessions, &key);
            if (!sval) {
                key.client_port = (__u16)sk->dst_port;
                sval = bpf_map_lookup_elem(&xdns_tcp_sessions, &key);
            }

            if (sval) {
                struct sockaddr_in *sa = ctx->optval;
                if ((void *)(sa + 1) <= ctx->optval_end) {
                    sa->sin_family = AF_INET;
                    sa->sin_port = sval->orig_dst_port;
                    sa->sin_addr.s_addr = sval->orig_dst_ip;
                    *(volatile int *)&ctx->optlen = sizeof(struct sockaddr_in);
                    ctx->retval = 0;
                    return 1;
                }
            }
        }
    }
    return 1;
}

char _license[] SEC("license") = "GPL";
