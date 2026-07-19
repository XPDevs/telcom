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

static int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
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
    return bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

static int bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
    union bpf_attr attr = {};
    attr.map_fd = fd;
    attr.key = (__u64)(unsigned long)key;
    attr.next_key = (__u64)(unsigned long)next_key;
    return bpf(BPF_MAP_GET_NEXT_KEY, &attr, sizeof(attr));
}

static int bpf_map_lookup_elem(int fd, const void *key, void *value)
{
    union bpf_attr attr = {};
    attr.map_fd = fd;
    attr.key = (__u64)(unsigned long)key;
    attr.value = (__u64)(unsigned long)value;
    return bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
}

static const char *proto_str(__u8 proto)
{
    switch (proto) {
    case IPPROTO_TCP: return "TCP";
    case IPPROTO_UDP: return "UDP";
    default:          return "OTHER";
    }
}

static const char *queue_class_str(__u8 qc)
{
    switch (qc) {
    case QUEUE_GAMING:    return "GAMING";
    case QUEUE_STREAMING: return "STREAM";
    default:              return "BULK";
    }
}

static void print_flow(struct flow_key *k, struct flow_value *v)
{
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &k->src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &k->dst_ip, dst, sizeof(dst));

    time_t t = v->last_seen / 1000000000ULL;
    struct tm *tm = localtime(&t);
    char timebuf[64];
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);

    printf("%-15s :%-5d  %-15s :%-5d  %4s  %5llu  %7llu  %8s  %s\n",
           src, k->src_port,
           dst, k->dst_port,
           proto_str(k->protocol),
           (unsigned long long)v->packets,
           (unsigned long long)v->variance,
           queue_class_str(v->queue_class),
           timebuf);
}

static void dump_map(int map_fd)
{
    printf("%-15s  %-8s  %-15s  %-8s  %4s  %5s  %8s  %8s  %s\n",
           "SRC IP", "PORT", "DST IP", "PORT", "PROTO",
           "PKTS", "VARIANCE", "CLASS", "LAST SEEN");
    printf("------------------------------------------------------------------------------------------\n");

    struct flow_key prev = {};
    struct flow_key key;
    struct flow_value val;

    if (bpf_map_get_next_key(map_fd, NULL, &key) != 0) {
        printf("No flows tracked yet.\n");
        return;
    }

    do {
        if (bpf_map_lookup_elem(map_fd, &key, &val) == 0)
            print_flow(&key, &val);
        memcpy(&prev, &key, sizeof(key));
    } while (bpf_map_get_next_key(map_fd, &prev, &key) == 0);
}

int main(int argc, char **argv)
{
    int watch = 0;
    int opt;

    while ((opt = getopt(argc, argv, "wh")) != -1) {
        switch (opt) {
        case 'w': watch = 1; break;
        case 'h':
            fprintf(stderr, "Usage: %s [-w]\n"
                            "  -w    Watch mode (refresh every second)\n",
                    argv[0]);
            return 0;
        default:
            fprintf(stderr, "Usage: %s [-w]\n", argv[0]);
            return 1;
        }
    }

    int map_fd = bpf_obj_get("/sys/fs/bpf/telcom/flow_table");
    if (map_fd < 0) {
        fprintf(stderr, "Error: cannot open flow_table map (%s)\n"
                        "Is the daemon running?\n", strerror(errno));
        return 1;
    }

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
