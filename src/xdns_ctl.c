#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <time.h>
#include <linux/bpf.h>

#include "xdns_bpf.h"
#include "xdns_hash.h"

#define BPF_FS_TC_PATH "/sys/fs/bpf/tc/globals"
#define BPF_FS_PATH    "/sys/fs/bpf"

static int bpf_sys(int cmd, union bpf_attr *attr)
{
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int bpf_open_map(const char *name)
{
    char path[256];
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    /* Try tc/globals first */
    snprintf(path, sizeof(path), "%s/%s", BPF_FS_TC_PATH, name);
    attr.pathname = (__u64)(long)path;
    int fd = bpf_sys(BPF_OBJ_GET, &attr);
    if (fd >= 0) return fd;

    /* Fallback to root BPF FS */
    snprintf(path, sizeof(path), "%s/%s", BPF_FS_PATH, name);
    attr.pathname = (__u64)(long)path;
    return bpf_sys(BPF_OBJ_GET, &attr);
}

static int bpf_map_update(int fd, const void *key, const void *value, __u64 flags)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = (__u64)(long)key;
    attr.value = (__u64)(long)value;
    attr.flags = flags;
    return bpf_sys(BPF_MAP_UPDATE_ELEM, &attr);
}

static int bpf_map_lookup(int fd, const void *key, void *value)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = (__u64)(long)key;
    attr.value = (__u64)(long)value;
    return bpf_sys(BPF_MAP_LOOKUP_ELEM, &attr);
}

static int bpf_map_delete(int fd, const void *key)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = (__u64)(long)key;
    return bpf_sys(BPF_MAP_DELETE_ELEM, &attr);
}

static int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = fd;
    attr.key = (__u64)(long)key;
    attr.next_key = (__u64)(long)next_key;
    return bpf_sys(BPF_MAP_GET_NEXT_KEY, &attr);
}

static void print_usage(const char *prog)
{
    printf("xdns-ctl - Control CLI for xdns-bpf\n\n");
    printf("Usage: %s <command> [arguments]\n\n", prog);
    printf("Commands:\n");
    printf("  add-domain <domain> [file]         Add domain to kernel and persistent whitelist\n");
    printf("  del-domain <domain> [file]         Remove domain from kernel and whitelist file\n");
    printf("  list-whitelist [file]              List whitelisted domains and kernel map status\n");
    printf("  load-whitelist <file>              Batch load domain whitelist file\n");
    printf("  list-ips                           List dynamic hijacked IP set\n");
    printf("  list-sessions                      List active transparent TCP proxy sessions\n");
    printf("  set-config <dns_ip:port> <tcp_ip:port> [enable:1|0]\n");
    printf("                                     Configure xkcptun redirect endpoints\n");
    printf("  stats                              Display interception statistics\n");
    printf("\n");
}

static const char *get_default_whitelist_path(const char *user_file)
{
    if (user_file && user_file[0] != '\0')
        return user_file;
    if (access("/etc/xdns/whitelist.txt", F_OK) == 0 || access("/etc/xdns", W_OK) == 0)
        return "/etc/xdns/whitelist.txt";
    if (access("files/whitelist.txt", F_OK) == 0)
        return "files/whitelist.txt";
    return "whitelist.txt";
}

static void normalize_domain(const char *in, char *out, size_t maxlen)
{
    while (*in == ' ' || *in == '\t') in++;
    /* Strip leading *. or . if user specified wildcard prefix */
    if (in[0] == '*' && in[1] == '.') in += 2;
    else if (in[0] == '.') in += 1;

    size_t i = 0;
    while (*in && i < maxlen - 1) {
        char c = *in++;
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '#') break;
        if (c >= 'A' && c <= 'Z') c += ('a' - 'A');
        out[i++] = c;
    }
    out[i] = '\0';
}

static int cmd_add_domain(const char *domain, const char *file)
{
    char norm[256];
    normalize_domain(domain, norm, sizeof(norm));
    if (norm[0] == '\0') {
        fprintf(stderr, "Error: Invalid domain name '%s'\n", domain);
        return 1;
    }

    int fd = bpf_open_map("xdns_whitelist");
    if (fd < 0) {
        perror("Failed to open xdns_whitelist map");
        return 1;
    }
    __u64 hash = xdns_hash_domain(norm);
    __u8 val = 1;
    if (bpf_map_update(fd, &hash, &val, BPF_ANY) < 0) {
        perror("Failed to update whitelist map");
        close(fd);
        return 1;
    }
    close(fd);

    printf("Kernel: Activated '%s' (hash: 0x%016llx)\n", norm, (unsigned long long)hash);

    /* Persist to whitelist file */
    const char *target_file = get_default_whitelist_path(file);
    int already_in_file = 0;
    FILE *fp = fopen(target_file, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            char existing[256];
            normalize_domain(line, existing, sizeof(existing));
            if (strcasecmp(existing, norm) == 0) {
                already_in_file = 1;
                break;
            }
        }
        fclose(fp);
    }

    if (!already_in_file) {
        fp = fopen(target_file, "a");
        if (fp) {
            fprintf(fp, "%s\n", norm);
            fclose(fp);
            printf("File  : Appended '%s' to %s\n", norm, target_file);
        } else {
            fprintf(stderr, "Notice: Could not write to %s (read-only or permission denied)\n", target_file);
        }
    } else {
        printf("File  : Domain '%s' already exists in %s\n", norm, target_file);
    }

    return 0;
}

static int cmd_del_domain(const char *domain, const char *file)
{
    char norm[256];
    normalize_domain(domain, norm, sizeof(norm));
    if (norm[0] == '\0') {
        fprintf(stderr, "Error: Invalid domain name '%s'\n", domain);
        return 1;
    }

    int fd = bpf_open_map("xdns_whitelist");
    if (fd < 0) {
        perror("Failed to open xdns_whitelist map");
        return 1;
    }
    __u64 hash = xdns_hash_domain(norm);
    if (bpf_map_delete(fd, &hash) < 0) {
        printf("Kernel: Domain '%s' was not active in whitelist map\n", norm);
    } else {
        printf("Kernel: Removed '%s' from active whitelist\n", norm);
    }
    close(fd);

    /* Remove from whitelist file */
    const char *target_file = get_default_whitelist_path(file);
    FILE *fp = fopen(target_file, "r");
    if (fp) {
        char temp_file[512];
        snprintf(temp_file, sizeof(temp_file), "%s.tmp", target_file);
        FILE *wfp = fopen(temp_file, "w");
        if (wfp) {
            char line[256];
            int removed = 0;
            while (fgets(line, sizeof(line), fp)) {
                char existing[256];
                normalize_domain(line, existing, sizeof(existing));
                if (existing[0] != '\0' && strcasecmp(existing, norm) == 0) {
                    removed = 1;
                    continue;
                }
                fputs(line, wfp);
            }
            fclose(wfp);
            fclose(fp);
            if (removed) {
                rename(temp_file, target_file);
                printf("File  : Removed '%s' from %s\n", norm, target_file);
            } else {
                unlink(temp_file);
                printf("File  : Domain '%s' was not found in %s\n", norm, target_file);
            }
        } else {
            fclose(fp);
        }
    }

    return 0;
}

static int cmd_load_whitelist(const char *file)
{
    FILE *fp = fopen(file, "r");
    if (!fp) {
        perror("Failed to open whitelist file");
        return 1;
    }
    int fd = bpf_open_map("xdns_whitelist");
    if (fd < 0) {
        perror("Failed to open xdns_whitelist map");
        fclose(fp);
        return 1;
    }

    char line[256];
    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\r' || *p == '\n' || *p == '\0') continue;
        char *end = p + strlen(p) - 1;
        while (end >= p && (*end == '\r' || *end == '\n' || *end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }
        if (strlen(p) == 0) continue;

        __u64 hash = xdns_hash_domain(p);
        __u8 val = 1;
        if (bpf_map_update(fd, &hash, &val, BPF_ANY) == 0) {
            count++;
        }
    }
    fclose(fp);
    close(fd);
    printf("Successfully loaded %d domains into whitelist\n", count);
    return 0;
}

static int cmd_list_whitelist(const char *file)
{
    const char *path = file ? file : "/etc/xdns/whitelist.txt";
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fp = fopen("whitelist.txt", "r");
        if (!fp) {
            fprintf(stderr, "Whitelist file not found: %s\n", path);
            return 1;
        }
    }

    int fd = bpf_open_map("xdns_whitelist");

    printf("%-32s %-20s %-12s\n", "Domain", "FNV1a-64 Hash", "Kernel State");
    printf("--------------------------------------------------------------------\n");

    char line[256];
    int count = 0;
    int active_count = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\r' || *p == '\n' || *p == '\0') continue;
        char *end = p + strlen(p) - 1;
        while (end >= p && (*end == '\r' || *end == '\n' || *end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }
        if (strlen(p) == 0) continue;

        __u64 hash = xdns_hash_domain(p);
        const char *state = "Not Loaded";
        if (fd >= 0) {
            __u8 val = 0;
            if (bpf_map_lookup(fd, &hash, &val) == 0 && val == 1) {
                state = "Active";
                active_count++;
            }
        } else {
            state = "Map Unloaded";
        }

        printf("%-32s 0x%016llx   %-12s\n", p, (unsigned long long)hash, state);
        count++;
    }
    fclose(fp);
    if (fd >= 0) close(fd);

    printf("--------------------------------------------------------------------\n");
    printf("Total domains listed: %d (Active in kernel: %d)\n", count, active_count);
    return 0;
}

static int cmd_list_ips(void)
{
    int fd = bpf_open_map("xdns_ip_set");
    if (fd < 0) {
        perror("Failed to open xdns_ip_set map");
        return 1;
    }

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    __u64 now_ns = (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;

    printf("%-18s %-12s\n", "IP Address", "Expires In");
    printf("------------------------------------\n");

    __u32 key, next_key;
    int has_first = 0;
    int count = 0;

    if (bpf_map_get_next_key(fd, NULL, &next_key) == 0) {
        has_first = 1;
        key = next_key;
    }

    while (has_first) {
        __u64 expire_ts = 0;
        if (bpf_map_lookup(fd, &key, &expire_ts) == 0) {
            char ip_str[INET_ADDRSTRLEN];
            struct in_addr in;
            in.s_addr = key;
            inet_ntop(AF_INET, &in, ip_str, sizeof(ip_str));

            long long remaining_sec = 0;
            if (expire_ts > now_ns) {
                remaining_sec = (expire_ts - now_ns) / 1000000000ULL;
            }
            printf("%-18s %llds\n", ip_str, remaining_sec);
            count++;
        }

        if (bpf_map_get_next_key(fd, &key, &next_key) != 0)
            break;
        key = next_key;
    }

    printf("Total active proxy IPs: %d\n", count);
    close(fd);
    return 0;
}

static int cmd_list_sessions(void)
{
    int fd = bpf_open_map("xdns_tcp_sessions");
    if (fd < 0) {
        perror("Failed to open xdns_tcp_sessions map");
        return 1;
    }

    printf("%-24s %-24s %-12s\n", "Client Endpoint", "Original Target", "Last Seen");
    printf("--------------------------------------------------------------------\n");

    struct xdns_tcp_session_key key, next_key;
    memset(&key, 0, sizeof(key));
    memset(&next_key, 0, sizeof(next_key));

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    __u64 now_ns = (__u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    int count = 0;
    int has_first = 0;
    if (bpf_map_get_next_key(fd, NULL, &next_key) == 0) {
        has_first = 1;
        key = next_key;
    }

    while (has_first) {
        struct xdns_tcp_session_val val;
        if (bpf_map_lookup(fd, &key, &val) == 0) {
            char cip[INET_ADDRSTRLEN], tip[INET_ADDRSTRLEN];
            struct in_addr ca, ta;
            ca.s_addr = key.client_ip;
            ta.s_addr = val.orig_dst_ip;
            inet_ntop(AF_INET, &ca, cip, sizeof(cip));
            inet_ntop(AF_INET, &ta, tip, sizeof(tip));

            char cstr[32], tstr[32];
            snprintf(cstr, sizeof(cstr), "%s:%u", cip, ntohs(key.client_port));
            snprintf(tstr, sizeof(tstr), "%s:%u", tip, ntohs(val.orig_dst_port));

            unsigned long long age_sec = (now_ns > val.timestamp) ? (now_ns - val.timestamp) / 1000000000ULL : 0;
            printf("%-24s %-24s %llus ago\n", cstr, tstr, age_sec);
            count++;
        }

        if (bpf_map_get_next_key(fd, &key, &next_key) != 0)
            break;
        key = next_key;
    }

    close(fd);
    printf("--------------------------------------------------------------------\n");
    printf("Total active TCP sessions: %d\n", count);
    return 0;
}

static int cmd_set_config(const char *dns_ep, const char *tcp_ep, int enabled)
{
    int fd = bpf_open_map("xdns_config_map");
    if (fd < 0) {
        perror("Failed to open xdns_config_map");
        return 1;
    }

    struct xdns_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = enabled;

    /* Parse dns_ep (e.g. 127.0.0.1:5353) */
    char buf[128];
    snprintf(buf, sizeof(buf), "%s", dns_ep);
    char *colon = strchr(buf, ':');
    if (colon) {
        *colon = '\0';
        cfg.xkcp_dns_port = htons(atoi(colon + 1));
    } else {
        cfg.xkcp_dns_port = htons(5353);
    }
    inet_pton(AF_INET, buf, &cfg.xkcp_dns_ip);

    /* Parse tcp_ep (e.g. 192.168.8.1:12345) */
    snprintf(buf, sizeof(buf), "%s", tcp_ep);
    colon = strchr(buf, ':');
    if (colon) {
        *colon = '\0';
        cfg.xkcp_tcp_port = htons(atoi(colon + 1));
    } else {
        cfg.xkcp_tcp_port = htons(12345);
    }
    inet_pton(AF_INET, buf, &cfg.xkcp_tcp_ip);

    __u32 key = 0;
    if (bpf_map_update(fd, &key, &cfg, BPF_ANY) < 0) {
        perror("Failed to update config map");
        close(fd);
        return 1;
    }

    printf("Updated xdns-bpf runtime config:\n");
    printf("  DNS Target : %s\n", dns_ep);
    printf("  TCP Target : %s\n", tcp_ep);
    printf("  Enabled    : %s\n", enabled ? "Yes" : "No");
    close(fd);
    return 0;
}

static int cmd_stats(void)
{
    int fd = bpf_open_map("xdns_stats_map");
    if (fd < 0) {
        perror("Failed to open xdns_stats_map");
        return 1;
    }

    long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus < 1) ncpus = 1;
    struct xdns_stats *stats_arr = calloc(ncpus, sizeof(struct xdns_stats));
    __u32 key = 0;

    if (bpf_map_lookup(fd, &key, stats_arr) < 0) {
        perror("Failed to lookup stats map");
        free(stats_arr);
        close(fd);
        return 1;
    }

    struct xdns_stats total;
    memset(&total, 0, sizeof(total));
    for (int i = 0; i < ncpus; i++) {
        total.dns_queries_total += stats_arr[i].dns_queries_total;
        total.dns_queries_hijacked += stats_arr[i].dns_queries_hijacked;
        total.dns_responses_parsed += stats_arr[i].dns_responses_parsed;
        total.tcp_redirected += stats_arr[i].tcp_redirected;
    }
    free(stats_arr);
    close(fd);

    printf("================ xdns-bpf Statistics ================\n");
    printf("  DNS Queries Intercepted  : %llu\n", (unsigned long long)total.dns_queries_total);
    printf("  DNS Whitelist Hijacked   : %llu\n", (unsigned long long)total.dns_queries_hijacked);
    printf("  DNS Responses Learned    : %llu\n", (unsigned long long)total.dns_responses_parsed);
    printf("  TCP Connections Proxied  : %llu\n", (unsigned long long)total.tcp_redirected);
    printf("======================================================\n");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "add-domain") == 0 && argc >= 3) {
        return cmd_add_domain(argv[2], argc >= 4 ? argv[3] : NULL);
    } else if (strcmp(argv[1], "del-domain") == 0 && argc >= 3) {
        return cmd_del_domain(argv[2], argc >= 4 ? argv[3] : NULL);
    } else if (strcmp(argv[1], "list-whitelist") == 0 || strcmp(argv[1], "list-domains") == 0) {
        return cmd_list_whitelist(argc >= 3 ? argv[2] : NULL);
    } else if (strcmp(argv[1], "load-whitelist") == 0 && argc >= 3) {
        return cmd_load_whitelist(argv[2]);
    } else if (strcmp(argv[1], "list-ips") == 0) {
        return cmd_list_ips();
    } else if (strcmp(argv[1], "list-sessions") == 0) {
        return cmd_list_sessions();
    } else if (strcmp(argv[1], "set-config") == 0 && argc >= 4) {
        int enabled = (argc >= 5) ? atoi(argv[4]) : 1;
        return cmd_set_config(argv[2], argv[3], enabled);
    } else if (strcmp(argv[1], "stats") == 0) {
        return cmd_stats();
    } else {
        print_usage(argv[0]);
        return 1;
    }
}
