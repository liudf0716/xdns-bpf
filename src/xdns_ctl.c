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

#define BPF_FS_HOST_PATH "/sys/fs/bpf"
#define BPF_FS_TC_PATH   "/sys/fs/bpf/tc/globals"
#define BPF_FS_PATH      "/sys/fs/bpf"

static int bpf_sys(int cmd, union bpf_attr *attr)
{
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int bpf_open_map(const char *name)
{
    char path[256];
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    /* 1. Try host path (/sys/fs/bpf) first */
    snprintf(path, sizeof(path), "%s/%s", BPF_FS_HOST_PATH, name);
    attr.pathname = (__u64)(long)path;
    int fd = bpf_sys(BPF_OBJ_GET, &attr);
    if (fd >= 0) return fd;

    /* 2. Try tc/globals next (gateway mode) */
    snprintf(path, sizeof(path), "%s/%s", BPF_FS_TC_PATH, name);
    attr.pathname = (__u64)(long)path;
    fd = bpf_sys(BPF_OBJ_GET, &attr);
    if (fd >= 0) return fd;

    /* 3. Fallback to root BPF FS */
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
    printf("  add-domain <domain> [file]         Add domain to kernel and persistent proxy domains\n");
    printf("  del-domain <domain> [file]         Remove domain from kernel and proxy domains file\n");
    printf("  list-domains [file]                List proxy domains and kernel map status\n");
    printf("  load-domains <file>                Batch load proxy domains file (additive)\n");
    printf("  reload-domains [file]              Replace kernel domains from file and clear resolved IPs\n");
    printf("  list-ips                           List hijacked IPs and steered traffic\n");
    printf("  clear-ips                          Clear all resolved IPs from kernel map\n");
    printf("  list-sessions                      List active transparent TCP proxy sessions\n");
    printf("  set-config <dns_ip:port> <tcp_ip:port> [enable:1|0]\n");
    printf("                                     Configure xkcptun redirect endpoints\n");
    printf("  host-start [obj_file] [cgroup_dir] Start Host mode eBPF cgroup redirection\n");
    printf("  host-stop [cgroup_dir]             Stop Host mode eBPF cgroup redirection\n");
    printf("  status                             Report whether tc filters are attached\n");
    printf("  stats                              Display interception statistics\n");
    printf("\n");
}

static const char *get_default_domains_path(const char *user_file)
{
    if (user_file && user_file[0] != '\0')
        return user_file;
    if (access("/etc/xdns/proxy_domains.txt", F_OK) == 0 || access("/etc/xdns", W_OK) == 0)
        return "/etc/xdns/proxy_domains.txt";
    if (access("files/proxy_domains.txt", F_OK) == 0)
        return "files/proxy_domains.txt";
    return "proxy_domains.txt";
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

    int fd = bpf_open_map("xdns_domains");
    if (fd < 0) {
        perror("Failed to open xdns_domains map");
        return 1;
    }
    __u64 hash = xdns_hash_domain(norm);
    __u8 val = 1;
    if (bpf_map_update(fd, &hash, &val, BPF_ANY) < 0) {
        perror("Failed to update domains map");
        close(fd);
        return 1;
    }
    close(fd);

    printf("Kernel: Activated '%s' (hash: 0x%016llx)\n", norm, (unsigned long long)hash);

    /* Persist to domains file */
    const char *target_file = get_default_domains_path(file);
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

    int fd = bpf_open_map("xdns_domains");
    if (fd < 0) {
        perror("Failed to open xdns_domains map");
        return 1;
    }
    __u64 hash = xdns_hash_domain(norm);
    if (bpf_map_delete(fd, &hash) < 0) {
        printf("Kernel: Domain '%s' was not active in domains map\n", norm);
    } else {
        printf("Kernel: Removed '%s' from active domains\n", norm);
    }
    close(fd);

    /* Remove from domains file */
    const char *target_file = get_default_domains_path(file);
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

/* Delete every remaining element. Passing NULL as current key always yields
 * the first key still present, which is the safe pattern while deleting. */
static int bpf_map_clear(int fd, void *key, size_t key_size)
{
    int deleted = 0;

    while (bpf_map_get_next_key(fd, NULL, key) == 0) {
        if (bpf_map_delete(fd, key) != 0)
            return -1;
        deleted++;
        memset(key, 0, key_size);
    }
    return deleted;
}

static int cmd_load_domains_into(int fd, const char *file, int *loaded)
{
    FILE *fp = fopen(file, "r");
    if (!fp) {
        perror("Failed to open domains file");
        return 1;
    }

    char line[256];
    int count = 0;
    while (fgets(line, sizeof(line), fp)) {
        char norm[256];
        normalize_domain(line, norm, sizeof(norm));
        if (norm[0] == '\0') continue;

        __u64 hash = xdns_hash_domain(norm);
        __u8 val = 1;
        if (bpf_map_update(fd, &hash, &val, BPF_ANY) == 0)
            count++;
    }
    fclose(fp);
    if (loaded)
        *loaded = count;
    return 0;
}

static int cmd_load_domains(const char *file)
{
    int fd = bpf_open_map("xdns_domains");
    if (fd < 0) {
        perror("Failed to open xdns_domains map");
        return 1;
    }

    int count = 0;
    int rc = cmd_load_domains_into(fd, file, &count);
    close(fd);
    if (rc != 0)
        return rc;

    printf("Successfully loaded %d domains into proxy domain list\n", count);
    return 0;
}

static int cmd_clear_ips(void)
{
    int fd = bpf_open_map("xdns_ip_set");
    if (fd < 0) {
        perror("Failed to open xdns_ip_set map");
        return 1;
    }

    __u32 key = 0;
    int deleted = bpf_map_clear(fd, &key, sizeof(key));
    close(fd);
    if (deleted < 0) {
        perror("Failed to clear xdns_ip_set");
        return 1;
    }
    int tfd = bpf_open_map("xdns_ip_traffic");
    if (tfd >= 0) {
        key = 0;
        bpf_map_clear(tfd, &key, sizeof(key));
        close(tfd);
    }
    int nfd = bpf_open_map("xdns_ip_name");
    if (nfd >= 0) {
        key = 0;
        bpf_map_clear(nfd, &key, sizeof(key));
        close(nfd);
    }

    printf("Cleared %d resolved IPs from xdns_ip_set\n", deleted);
    return 0;
}

static int cmd_reload_domains(const char *file)
{
    const char *path = get_default_domains_path(file);
    int fd = bpf_open_map("xdns_domains");
    if (fd < 0) {
        perror("Failed to open xdns_domains map");
        return 1;
    }

    __u64 dkey = 0;
    int removed = bpf_map_clear(fd, &dkey, sizeof(dkey));
    if (removed < 0) {
        perror("Failed to clear xdns_domains");
        close(fd);
        return 1;
    }

    int loaded = 0;
    int rc = cmd_load_domains_into(fd, path, &loaded);
    close(fd);
    if (rc != 0)
        return rc;

    printf("Kernel domains replaced from %s: removed %d, loaded %d\n",
           path, removed, loaded);

    /* Learned IPs belong to the previous domain set; drop them so traffic
     * is not still steered until TTL expiry. */
    return cmd_clear_ips();
}

static int cmd_list_domains(const char *file)
{
    const char *path = file ? file : get_default_domains_path(NULL);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Domains file not found: %s\n", path);
        return 1;
    }

    int fd = bpf_open_map("xdns_domains");

    printf("%-32s %-20s %-12s\n", "Domain", "FNV1a-64 Hash", "Kernel State");
    printf("--------------------------------------------------------------------\n");

    char line[256];
    int count = 0;
    int active_count = 0;
    while (fgets(line, sizeof(line), fp)) {
        char norm[256];
        normalize_domain(line, norm, sizeof(norm));
        if (norm[0] == '\0') continue;

        __u64 hash = xdns_hash_domain(norm);
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
        printf("%-32s 0x%016llx   %-12s\n", norm, (unsigned long long)hash, state);
        count++;
    }
    fclose(fp);
    if (fd >= 0) close(fd);

    printf("--------------------------------------------------------------------\n");
    printf("Total domains listed: %d (Active in kernel: %d)\n", count, active_count);
    return 0;
}

static void sum_ip_traffic(int tfd, __u32 ip, long ncpus, __u64 *packets, __u64 *bytes, __u64 *conns)
{
    *packets = *bytes = *conns = 0;
    if (tfd < 0)
        return;
    struct xdns_ip_traffic *arr = calloc(ncpus, sizeof(*arr));
    if (!arr)
        return;
    if (bpf_map_lookup(tfd, &ip, arr) == 0) {
        for (long i = 0; i < ncpus; i++) {
            *packets += arr[i].packets;
            *bytes += arr[i].bytes;
            *conns += arr[i].connections;
        }
    }
    free(arr);
}

struct name_ent {
    __u64 hash;
    char name[256];
};

static int load_name_table(struct name_ent **out, int *nout)
{
    *out = NULL;
    *nout = 0;
    FILE *fp = fopen(get_default_domains_path(NULL), "r");
    if (!fp)
        return 0;
    struct name_ent *tab = NULL;
    int n = 0, cap = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char norm[256];
        normalize_domain(line, norm, sizeof(norm));
        if (!norm[0])
            continue;
        if (n == cap) {
            cap = cap ? cap * 2 : 64;
            struct name_ent *grown = realloc(tab, (size_t)cap * sizeof(*tab));
            if (!grown)
                break;
            tab = grown;
        }
        tab[n].hash = xdns_hash_domain(norm);
        snprintf(tab[n].name, sizeof(tab[n].name), "%s", norm);
        n++;
    }
    fclose(fp);
    *out = tab;
    *nout = n;
    return n;
}

static const char *lookup_name(struct name_ent *tab, int n, __u64 hash)
{
    for (int i = 0; i < n; i++) {
        if (tab[i].hash == hash)
            return tab[i].name;
    }
    return NULL;
}

static int cmd_list_ips(void)
{
    int fd = bpf_open_map("xdns_ip_set");
    if (fd < 0) {
        perror("Failed to open xdns_ip_set map");
        return 1;
    }
    int tfd = bpf_open_map("xdns_ip_traffic");
    long ncpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpus < 1) ncpus = 1;

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    __u64 now_ns = (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;

    int nfd = bpf_open_map("xdns_ip_name");
    struct name_ent *names = NULL;
    int nnames = 0;
    load_name_table(&names, &nnames);

    printf("%-40s %-18s %-12s %-12s %-14s %-12s\n", "Website", "IP Address", "Expires In", "Connections", "Packets", "Bytes");
    printf("----------------------------------------------------------------------------------------------------------------\n");

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
            struct xdns_ip_name nm;
            const char *website = "-";
            memset(&nm, 0, sizeof(nm));
            if (nfd >= 0 && bpf_map_lookup(nfd, &key, &nm) == 0 && nm.hash) {
                const char *found = lookup_name(names, nnames, nm.hash);
                if (found)
                    website = found;
            }
            __u64 packets = 0, bytes = 0, conns = 0;
            sum_ip_traffic(tfd, key, ncpus, &packets, &bytes, &conns);
            printf("%-40s %-18s %-12lld %-12llu %-14llu %-12llu\n", website, ip_str, remaining_sec,
                   (unsigned long long)conns, (unsigned long long)packets,
                   (unsigned long long)bytes);
            count++;
        }

        if (bpf_map_get_next_key(fd, &key, &next_key) != 0)
            break;
        key = next_key;
    }

    printf("Total active proxy IPs: %d\n", count);
    free(names);
    if (tfd >= 0)
        close(tfd);
    if (nfd >= 0)
        close(nfd);
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

    int nfd = bpf_open_map("xdns_ip_name");
    struct name_ent *names = NULL;
    int nnames = 0;
    load_name_table(&names, &nnames);

    printf("%-32s %-24s %-24s %-12s\n", "Website", "Client Endpoint", "Original Target", "Last Seen");
    printf("------------------------------------------------------------------------------------------------\n");

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

            const char *website = "-";
            struct xdns_ip_name nm;
            memset(&nm, 0, sizeof(nm));
            if (nfd >= 0 && bpf_map_lookup(nfd, &val.orig_dst_ip, &nm) == 0 && nm.hash) {
                const char *found = lookup_name(names, nnames, nm.hash);
                if (found)
                    website = found;
            }

            unsigned long long age_sec = (now_ns > val.timestamp) ? (now_ns - val.timestamp) / 1000000000ULL : 0;
            printf("%-32s %-24s %-24s %llus ago\n", website, cstr, tstr, age_sec);
            count++;
        }

        if (bpf_map_get_next_key(fd, &key, &next_key) != 0)
            break;
        key = next_key;
    }

    free(names);
    if (nfd >= 0)
        close(nfd);
    close(fd);
    printf("------------------------------------------------------------------------------------------------\n");
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

static int ifname_ok(const char *s)
{
    if (!s || !s[0] || strlen(s) >= 16)
        return 0;
    for (const char *p = s; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '-' || *p == '_' || *p == '.'))
            return 0;
    }
    return 1;
}

static void read_ifname(char *out, size_t outlen)
{
    snprintf(out, outlen, "br-lan");
    FILE *fp = popen("uci -q get xdns.global.ifname", "r");
    if (!fp)
        return;
    char buf[64];
    if (fgets(buf, sizeof(buf), fp)) {
        buf[strcspn(buf, "\r\n")] = '\0';
        if (ifname_ok(buf))
            snprintf(out, outlen, "%s", buf);
    }
    pclose(fp);
}

static int tc_has(const char *ifname, const char *dir, const char *needle)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "tc filter show dev %s %s 2>/dev/null", ifname, dir);
    FILE *fp = popen(cmd, "r");
    if (!fp)
        return 0;
    char line[512];
    int hit = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, needle)) {
            hit = 1;
            break;
        }
    }
    pclose(fp);
    return hit;
}

/* xdns has no daemon. Running means both tc programs are attached. */
static int cmd_status(void)
{
    char ifname[16];
    read_ifname(ifname, sizeof(ifname));
    int ingress = tc_has(ifname, "ingress", "tc_xdns_ingress");
    int egress = tc_has(ifname, "egress", "tc_xdns_egress");
    printf("Interface : %s\n", ifname);
    printf("Ingress   : %s\n", ingress ? "attached" : "missing");
    printf("Egress    : %s\n", egress ? "attached" : "missing");
    printf("Running   : %s\n", (ingress && egress) ? "yes" : "no");
    return (ingress && egress) ? 0 : 1;
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
        total.dns_queries_proxied += stats_arr[i].dns_queries_proxied;
        total.dns_queries_passed += stats_arr[i].dns_queries_passed;
        total.dns_forward_failed += stats_arr[i].dns_forward_failed;
        total.dns_answers_learned += stats_arr[i].dns_answers_learned;
        total.tcp_connections += stats_arr[i].tcp_connections;
        total.tcp_packets += stats_arr[i].tcp_packets;
        total.tcp_bytes += stats_arr[i].tcp_bytes;
    }
    free(stats_arr);
    close(fd);

    printf("================ xdns-bpf Statistics ================\n");
    printf("  DNS Queries Proxied      : %llu\n", (unsigned long long)total.dns_queries_proxied);
    printf("  DNS Queries Passed       : %llu\n", (unsigned long long)total.dns_queries_passed);
    printf("  DNS Forward Failed       : %llu\n", (unsigned long long)total.dns_forward_failed);
    printf("  DNS A Records Learned    : %llu\n", (unsigned long long)total.dns_answers_learned);
    printf("  TCP Connections Steered  : %llu\n", (unsigned long long)total.tcp_connections);
    printf("  TCP Packets Steered      : %llu\n", (unsigned long long)total.tcp_packets);
    printf("  TCP Bytes Steered        : %llu\n", (unsigned long long)total.tcp_bytes);
    printf("======================================================\n");
    return 0;
}

static const char *get_default_bpf_obj(const char *user_path)
{
    if (user_path && user_path[0] != '\0')
        return user_path;
    if (access("build/xdns_bpf.o", F_OK) == 0)
        return "build/xdns_bpf.o";
    if (access("xdns_bpf.o", F_OK) == 0)
        return "xdns_bpf.o";
    if (access("/usr/lib/bpf/xdns_bpf.o", F_OK) == 0)
        return "/usr/lib/bpf/xdns_bpf.o";
    return "xdns_bpf.o";
}

static int cmd_host_start(const char *user_obj, const char *user_cgroup)
{
    const char *obj = get_default_bpf_obj(user_obj);
    const char *cg = (user_cgroup && user_cgroup[0]) ? user_cgroup : "/sys/fs/cgroup";

    if (access(obj, F_OK) != 0) {
        fprintf(stderr, "Error: BPF object file '%s' not found\n", obj);
        return 1;
    }
    if (access(cg, F_OK) != 0) {
        fprintf(stderr, "Error: cgroup path '%s' does not exist\n", cg);
        return 1;
    }

    char cmd[512];
    /* 1. Ensure pin directories exist */
    system("mkdir -p /sys/fs/bpf/tc/globals /sys/fs/bpf 2>/dev/null");

    /* 2. Load all programs from the BPF object and pin maps in /sys/fs/bpf/tc/globals */
    snprintf(cmd, sizeof(cmd), "bpftool prog loadall \"%s\" /sys/fs/bpf pinmaps " BPF_FS_TC_PATH " 2>/dev/null || bpftool prog loadall \"%s\" /sys/fs/bpf", obj, obj);
    int rc = system(cmd);
    if (rc != 0) {
        /* If already loaded, try using existing pinned programs */
        if (access("/sys/fs/bpf/xdns_connect4", F_OK) != 0) {
            fprintf(stderr, "Error: Failed to load BPF object '%s'\n", obj);
            return 1;
        }
    }

    /* 3. Attach programs to cgroup */
    snprintf(cmd, sizeof(cmd), "bpftool cgroup attach \"%s\" connect4 pinned /sys/fs/bpf/xdns_connect4 2>/dev/null", cg);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "bpftool cgroup attach \"%s\" sendmsg4 pinned /sys/fs/bpf/xdns_sendmsg4 2>/dev/null", cg);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "bpftool cgroup attach \"%s\" sock_ops pinned /sys/fs/bpf/xdns_sockops 2>/dev/null", cg);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "bpftool cgroup attach \"%s\" getsockopt pinned /sys/fs/bpf/xdns_getsockopt 2>/dev/null", cg);
    system(cmd);

    printf("xdns-bpf Host mode successfully attached to cgroup '%s'!\n", cg);
    return 0;
}

static int cmd_host_stop(const char *user_cgroup)
{
    const char *cg = (user_cgroup && user_cgroup[0]) ? user_cgroup : "/sys/fs/cgroup";
    char cmd[512];

    /* 1. Detach programs from cgroup */
    snprintf(cmd, sizeof(cmd), "bpftool cgroup detach \"%s\" connect4 pinned /sys/fs/bpf/xdns_connect4 2>/dev/null", cg);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "bpftool cgroup detach \"%s\" sendmsg4 pinned /sys/fs/bpf/xdns_sendmsg4 2>/dev/null", cg);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "bpftool cgroup detach \"%s\" sock_ops pinned /sys/fs/bpf/xdns_sockops 2>/dev/null", cg);
    system(cmd);

    snprintf(cmd, sizeof(cmd), "bpftool cgroup detach \"%s\" getsockopt pinned /sys/fs/bpf/xdns_getsockopt 2>/dev/null", cg);
    system(cmd);

    /* 2. Remove pinned host programs */
    system("rm -f /sys/fs/bpf/xdns_connect4 /sys/fs/bpf/xdns_sendmsg4 /sys/fs/bpf/xdns_sockops /sys/fs/bpf/xdns_getsockopt /sys/fs/bpf/tc_xdns_* 2>/dev/null");

    printf("xdns-bpf Host mode stopped and detached from '%s'.\n", cg);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if ((strcmp(argv[1], "add-domain") == 0 || strcmp(argv[1], "add-proxy-domain") == 0) && argc >= 3) {
        return cmd_add_domain(argv[2], argc >= 4 ? argv[3] : NULL);
    } else if ((strcmp(argv[1], "del-domain") == 0 || strcmp(argv[1], "del-proxy-domain") == 0) && argc >= 3) {
        return cmd_del_domain(argv[2], argc >= 4 ? argv[3] : NULL);
    } else if (strcmp(argv[1], "list-domains") == 0 || strcmp(argv[1], "list-whitelist") == 0) {
        return cmd_list_domains(argc >= 3 ? argv[2] : NULL);
    } else if ((strcmp(argv[1], "load-domains") == 0 || strcmp(argv[1], "load-whitelist") == 0) && argc >= 3) {
        return cmd_load_domains(argv[2]);
    } else if (strcmp(argv[1], "reload-domains") == 0) {
        return cmd_reload_domains(argc >= 3 ? argv[2] : NULL);
    } else if (strcmp(argv[1], "list-ips") == 0) {
        return cmd_list_ips();
    } else if (strcmp(argv[1], "clear-ips") == 0) {
        return cmd_clear_ips();
    } else if (strcmp(argv[1], "list-sessions") == 0) {
        return cmd_list_sessions();
    } else if (strcmp(argv[1], "set-config") == 0 && argc >= 4) {
        int enabled = (argc >= 5) ? atoi(argv[4]) : 1;
        return cmd_set_config(argv[2], argv[3], enabled);
    } else if (strcmp(argv[1], "host-start") == 0) {
        return cmd_host_start(argc >= 3 ? argv[2] : NULL, argc >= 4 ? argv[3] : NULL);
    } else if (strcmp(argv[1], "host-stop") == 0) {
        return cmd_host_stop(argc >= 3 ? argv[2] : NULL);
    } else if (strcmp(argv[1], "status") == 0) {
        return cmd_status();
    } else if (strcmp(argv[1], "stats") == 0) {
        return cmd_stats();
    } else {
        print_usage(argv[0]);
        return 1;
    }
}
