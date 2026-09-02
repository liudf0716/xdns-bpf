#ifndef _XDNS_BPF_H_
#define _XDNS_BPF_H_

#include <linux/types.h>

#define XDNS_FNV1A_64_OFFSET 14695981039346656037ULL
#define XDNS_FNV1A_64_PRIME  1099511628211ULL

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

/* Runtime configuration passed from userspace via Map */
struct xdns_config {
    __u32 xkcp_dns_ip;    /* Network byte order, e.g. 127.0.0.1 */
    __u16 xkcp_dns_port;  /* Network byte order, e.g. 5353 */
    __u32 xkcp_tcp_ip;    /* Network byte order, e.g. 192.168.8.1 */
    __u16 xkcp_tcp_port;  /* Network byte order, e.g. 12345 */
    __u32 enabled;        /* 1 = active, 0 = bypass all */
};

/* Operational statistics */
struct xdns_stats {
    __u64 dns_queries_total;
    __u64 dns_queries_hijacked;
    __u64 dns_responses_parsed;
    __u64 tcp_redirected;
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
