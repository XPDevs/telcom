#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "telcom_kern_shared.h"
#include "version.h"

static int bpf_syscall(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    int ret = syscall(__NR_bpf, cmd, attr, size);
    if (ret == -1)
        return -errno;
    return ret;
}

static int bpf_obj_get(const char *path)
{
    union bpf_attr attr = {};
    attr.pathname = (__u64)(unsigned long)path;
    return bpf_syscall(BPF_OBJ_GET, &attr, sizeof(attr));
}

static int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
    union bpf_attr attr = {};
    attr.map_fd = fd;
    attr.key = (__u64)(unsigned long)key;
    attr.next_key = (__u64)(unsigned long)next_key;
    return bpf_syscall(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

static int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
    union bpf_attr attr = {};
    attr.map_fd = fd;
    attr.key = (__u64)(unsigned long)key;
    attr.value = (__u64)(unsigned long)value;
    return bpf_syscall(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static void print_version(void)
{
    printf("telcom-peek %s\n", TELCOM_VERSION);
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-w] [-V]\n"
            "  -w           Watch mode (refresh every second)\n"
            "  -V, --version  Print version and exit\n",
            prog);
}

static void print_flow(struct flow_key *k, struct flow_value *v)
{
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &k->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &k->dst_ip, dst, sizeof(dst));

    __u64 avg = v->count ? v->sum / v->count : 0;

    time_t last = v->last_seen / 1000000000ULL;
    struct tm *tm = localtime(&last);
    char timebuf[32] = {};
    if (tm) strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);

    const char *qlabel;
    switch (v->queue_class) {
    case QUEUE_GAMING:    qlabel = "GAMING";  break;
    case QUEUE_STREAMING: qlabel = "STREAM";  break;
    default:              qlabel = "BULK";     break;
    }

    printf("%-15s :%-5u  %-15s :%-5u  %s  %5llu  %7llu  %7llu  %5llu  %4u  %4u  %-7s  %s\n",
           src, ntohs(k->src_port),
           dst, ntohs(k->dst_port),
           k->protocol == IPPROTO_TCP ? "TCP" : k->protocol == IPPROTO_UDP ? "UDP" : "OTH",
           (unsigned long long)v->packets,
           (unsigned long long)v->bytes,
           (unsigned long long)v->variance,
           (unsigned long long)avg,
           v->min_pkt, v->max_pkt,
           qlabel,
           timebuf);
}

static void dump_map(int map_fd)
{
    printf("%-15s  %-5s  %-15s  %-5s  %s  %5s  %7s  %7s  %5s  %4s  %4s  %-7s  %s\n",
           "SRC", "PORT", "DST", "PORT", "PROTO",
           "PKTS", "BYTES", "VAR", "AVG", "MIN", "MAX", "CLASS", "TIME");
    printf("----------------------------------------------------------------------------------------------------------\n");

    struct flow_key key = {};
    struct flow_value val;

    if (bpf_map_get_next_key(map_fd, NULL, &key) != 0) {
        printf("(no flows tracked yet)\n");
        return;
    }

    do {
        if (bpf_map_lookup_elem(map_fd, &key, &val) == 0)
            print_flow(&key, &val);
    } while (bpf_map_get_next_key(map_fd, &key, &key) == 0);
}

int main(int argc, char **argv)
{
    int watch = 0;
    int opt;

    static const struct option long_opts[] = {
        { "version", no_argument, NULL, 'V' },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "whV", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'w': watch = 1; break;
        case 'V': print_version(); return 0;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    int map_fd = bpf_obj_get("/sys/fs/bpf/telcom/flow_table");
    if (map_fd < 0) {
        fprintf(stderr, "Error: cannot open flow_table map (%s)\n"
                        "Is the daemon running?\n", strerror(-map_fd));
        return 1;
    }

    libbpf_set_print(NULL);

    if (watch) {
        while (1) {
            printf("\033[H\033[J");
            dump_map(map_fd);
            fflush(stdout);
            sleep(1);
        }
    } else {
        dump_map(map_fd);
    }

    close(map_fd);
    return 0;
}
