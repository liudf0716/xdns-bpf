#ifndef _XDNS_HASH_H_
#define _XDNS_HASH_H_

#include <linux/types.h>
#include "xdns_bpf.h"

/* Compute 64-bit FNV-1a hash of a standard dot-separated domain string */
static inline __u64 xdns_hash_domain(const char *domain)
{
    __u64 hash = XDNS_FNV1A_64_OFFSET;
    if (!domain) return 0;

    for (int i = 0; domain[i] != '\0' && i < 256; i++) {
        unsigned char c = (unsigned char)domain[i];
        if (c >= 'A' && c <= 'Z')
            c += ('a' - 'A'); // normalize to lowercase
        hash ^= c;
        hash *= XDNS_FNV1A_64_PRIME;
    }
    return hash;
}

#endif /* _XDNS_HASH_H_ */
