#ifndef _XDNS_BPF_H_
#define _XDNS_BPF_H_

#include <linux/types.h>

#define XDNS_FNV1A_64_OFFSET 14695981039346656037ULL
#define XDNS_FNV1A_64_PRIME  1099511628211ULL
#define XDNS_MAX_DNS_ANSWERS 4

/* Session tracking key for DNS queries */
struct xdns_session_key {
    __u32 client_ip;
    __u16 client_port;
    __u16 tx_id;
};

/* Session tracking value (original DNS server destination) */
struct xdns_session_val {
    __u32 orig_dst_ip;
    __u16 orig_dst_port;
    __u64 timestamp;
    __u64 name_hash; /* FNV-1a of the proxy-list name that matched */
};

/* Session tracking key for TCP transparent redirect */
struct xdns_tcp_session_key {
    __u32 client_ip;   /* Network byte order */
    __u16 client_port; /* Network byte order */
    __u16 pad;
};

/* Session tracking value for TCP transparent redirect */
struct xdns_tcp_session_val {
    __u32 orig_dst_ip;   /* Network byte order */
    __u16 orig_dst_port; /* Network byte order */
    __u16 pad;
    __u64 timestamp;
};

/* Host socket cookie tracking value for connect4 -> sockops -> getsockopt */
struct xdns_cookie_val {
    __u32 orig_dst_ip;   /* Network byte order */
    __u16 orig_dst_port; /* Network byte order */
    __u16 pad;
};

/* Runtime configuration passed from userspace via Map */
struct xdns_config {
    __u32 xkcp_dns_ip;    /* Network byte order, e.g. 127.0.0.1 */
    __u16 xkcp_dns_port;  /* Network byte order, e.g. 5353 */
    __u32 xkcp_tcp_ip;    /* Network byte order, e.g. 192.168.8.1 */
    __u16 xkcp_tcp_port;  /* Network byte order, e.g. 12345 */
    __u32 enabled;        /* 1 = active, 0 = bypass all */
};

/* Operational statistics. DNS counters mean the same thing on TC and host:
 * proxied is a query actually redirected to the forwarder, passed is a query
 * left on its original resolver, failed is a redirect or reply that could
 * not be completed. Host UDP cannot see the qname, so every UDP/53 rewrite
 * there is proxied rather than passed.
 */
struct xdns_stats {
    __u64 dns_queries_proxied;
    __u64 dns_queries_passed;
    __u64 dns_forward_failed;
    __u64 dns_answers_learned;
    __u64 tcp_connections;
    __u64 tcp_packets;
    __u64 tcp_bytes;
};

/* Per hijacked IPv4 address. Values are per-CPU and summed in userspace. */
struct xdns_ip_traffic {
    __u64 packets;
    __u64 bytes;
    __u64 connections;
};

/* Proxy-list domain hash remembered with each learned address. */
struct xdns_ip_name {
    __u64 hash;
};

/* DNS Resource Record header in answer */
struct xdns_rr_hdr {
    __u16 name_ptr;   /* 0xc0xx or label pointer */
    __u16 type;       /* 1 = A, 28 = AAAA */
    __u16 class;      /* 1 = IN */
    __u32 ttl;        /* seconds */
    __u16 rdlength;   /* 4 for IPv4 */
} __attribute__((packed));

#endif /* _XDNS_BPF_H_ */
