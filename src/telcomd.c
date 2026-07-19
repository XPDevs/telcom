#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <linux/if_link.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include <net/if.h>

#include "telcom_kern_shared.h"

static volatile sig_atomic_t exiting = 0;

static int xdp_attached = 0;
static int ifindex_global = 0;

static char bpf_obj_path[PATH_MAX];
static char config_path[PATH_MAX];

static int verbose = 0;

static struct telcom_config config = {
    .gaming_variance_threshold    = DEFAULT_GAMING_VARIANCE_THRESHOLD,
    .gaming_max_avg               = DEFAULT_GAMING_MAX_AVG,
    .streaming_variance_threshold = DEFAULT_STREAMING_VARIANCE_THRESHOLD,
    .streaming_min_avg            = DEFAULT_STREAMING_MIN_AVG,
};

static void handle_signal(int sig)
{
    exiting = 1;
}

static int setup_signal_handlers(void)
{
    if (signal(SIGINT, handle_signal) == SIG_ERR)
        return -1;
    if (signal(SIGTERM, handle_signal) == SIG_ERR)
        return -1;
    return 0;
}

static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s -i <interface> [-c <config>] [-v]\n"
            "  -i, --interface   Network interface to attach XDP\n"
            "  -c, --config      Path to config file (optional)\n"
            "  -v, --verbose     Verbose output (periodic status ticks)\n",
            prog);
}

static int is_wireless_interface(const char *ifname)
{
    char path[64];
    snprintf(path, sizeof(path), "/sys/class/net/%s/wireless", ifname);
    return access(path, F_OK) == 0;
}

static int resolve_bpf_obj_path(const char *argv0)
{
    char exe[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (len == -1) {
        perror("readlink /proc/self/exe");
        return -1;
    }
    exe[len] = '\0';

    char copy[PATH_MAX];
    strncpy(copy, exe, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';

    char *dir = dirname(copy);
    snprintf(bpf_obj_path, sizeof(bpf_obj_path),
             "%s/../bpf/telcom_kern.bpf.o", dir);

    if (access(bpf_obj_path, F_OK) == -1) {
        fprintf(stderr, "Error: BPF object not found at %s\n", bpf_obj_path);
        return -1;
    }
    return 0;
}

static int parse_config_line(char *line, struct telcom_config *cfg)
{
    char *eq = strchr(line, '=');
    if (!eq)
        return -1;

    *eq = '\0';
    char *key = line;
    char *val_str = eq + 1;

    while (*key == ' ' || *key == '\t') key++;
    char *end = key + strlen(key) - 1;
    while (end > key && (*end == ' ' || *end == '\t')) *end-- = '\0';

    while (*val_str == ' ' || *val_str == '\t') val_str++;
    end = val_str + strlen(val_str) - 1;
    while (end > val_str && (*end == ' ' || *end == '\t' || *end == '\r')) *end-- = '\0';

    __u32 val = (__u32)atol(val_str);

    if      (strcmp(key, "gaming_variance_threshold") == 0)    cfg->gaming_variance_threshold = val;
    else if (strcmp(key, "gaming_max_avg") == 0)               cfg->gaming_max_avg = val;
    else if (strcmp(key, "streaming_variance_threshold") == 0) cfg->streaming_variance_threshold = val;
    else if (strcmp(key, "streaming_min_avg") == 0)            cfg->streaming_min_avg = val;

    return 0;
}

static int load_config(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        f = fopen(path, "w");
        if (!f) {
            fprintf(stderr, "Warning: cannot create config %s, using defaults\n", path);
            return -1;
        }
        fprintf(f,
            "[thresholds]\n"
            "gaming_variance_threshold = %u\n"
            "gaming_max_avg = %u\n"
            "streaming_variance_threshold = %u\n"
            "streaming_min_avg = %u\n",
            config.gaming_variance_threshold,
            config.gaming_max_avg,
            config.streaming_variance_threshold,
            config.streaming_min_avg);
        fclose(f);
        printf("Created default config: %s\n", path);
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '[' || line[0] == '\n' || line[0] == '\r')
            continue;
        parse_config_line(line, &config);
    }

    fclose(f);
    return 0;
}

static int attach_xdp(struct bpf_program *prog, int ifindex, const char *ifname)
{
    int prog_fd = bpf_program__fd(prog);
    __u32 flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
    int err;

    err = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
    if (err == 0) {
        printf("XDP attached to %s (native/driver mode)\n", ifname);
        return 0;
    }

    if (err == -EOPNOTSUPP) {
        fprintf(stderr, "Native XDP not supported on %s, trying generic (SKB) mode...\n", ifname);
        flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
        err = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
        if (err == 0) {
            printf("XDP attached to %s (generic/SKB mode)\n", ifname);
            return 0;
        }
    }

    fprintf(stderr, "Error attaching XDP to %s: %s\n", ifname, strerror(-err));
    return err;
}

int main(int argc, char **argv)
{
    const char *ifname = NULL;
    const char *cfg_arg = NULL;
    int ifindex;
    int opt;

    static const struct option long_opts[] = {
        { "interface", required_argument, NULL, 'i' },
        { "config",    required_argument, NULL, 'c' },
        { "verbose",   no_argument,       NULL, 'v' },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "i:c:v", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i': ifname = optarg; break;
        case 'c': cfg_arg = optarg; break;
        case 'v': verbose = 1; break;
        default:  print_usage(argv[0]); return 1;
        }
    }

    if (!ifname) {
        print_usage(argv[0]);
        return 1;
    }

    if (resolve_bpf_obj_path(argv[0]))
        return 1;

    if (setup_signal_handlers()) {
        fprintf(stderr, "Failed to set up signal handlers\n");
        return 1;
    }

    if (cfg_arg) {
        load_config(cfg_arg);
    } else {
        char exe[PATH_MAX];
        ssize_t len = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
        if (len != -1) {
            exe[len] = '\0';
            char copy[PATH_MAX];
            strncpy(copy, exe, sizeof(copy) - 1);
            copy[sizeof(copy) - 1] = '\0';
            char *dir = dirname(copy);
            snprintf(config_path, sizeof(config_path), "%s/../telcom.toml", dir);
            load_config(config_path);
        }
    }

    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Error: interface '%s' not found\n", ifname);
        return 1;
    }
    ifindex_global = ifindex;

    if (is_wireless_interface(ifname)) {
        fprintf(stderr,
            "\033[33mWarning: Wi-Fi interface detected. "
            "TC egress shaping and power-saving PID loop will be disabled "
            "for this session. Use a virtio-net or wired interface for "
            "production testing.\033[0m\n");
    }

    struct bpf_object *obj = bpf_object__open_file(bpf_obj_path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Error opening BPF object: %s\n",
                libbpf_get_error(obj) == -ENOENT ? "file not found" : strerror(errno));
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Error loading BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "telcom_xdp");
    if (!prog) {
        fprintf(stderr, "Error: XDP program 'telcom_xdp' not found\n");
        goto cleanup;
    }

    struct bpf_map *cfg_map = bpf_object__find_map_by_name(obj, "config_map");
    if (!cfg_map) {
        fprintf(stderr, "Error: config_map not found\n");
        goto cleanup;
    }

    __u32 zero = 0;
    if (bpf_map__update_elem(cfg_map, &zero, sizeof(zero), &config, sizeof(config), BPF_ANY)) {
        fprintf(stderr, "Warning: failed to update config map\n");
    } else {
        printf("Config map updated (gaming_var=%u, gaming_avg=%u, stream_var=%u, stream_avg=%u)\n",
               config.gaming_variance_threshold, config.gaming_max_avg,
               config.streaming_variance_threshold, config.streaming_min_avg);
    }

    if (attach_xdp(prog, ifindex, ifname)) {
        xdp_attached = 0;
        goto cleanup;
    }
    xdp_attached = 1;

    mkdir("/sys/fs/bpf/telcom", 0755);

    if (bpf_object__pin_maps(obj, "/sys/fs/bpf/telcom")) {
        fprintf(stderr, "Warning: failed to pin maps\n");
    } else {
        printf("Maps pinned to /sys/fs/bpf/telcom/\n");
    }

    while (!exiting) {
        if (verbose) {
            time_t now = time(NULL);
            printf("[%.24s] daemon running\n", ctime(&now));
            fflush(stdout);
        }
        sleep(5);
    }

    printf("\nShutting down...\n");

cleanup:
    if (xdp_attached) {
        bpf_xdp_detach(ifindex_global, 0, NULL);
        printf("XDP detached from %s\n", ifname);
    }

    if (obj) {
        bpf_object__unpin_maps(obj, "/sys/fs/bpf/telcom");
        rmdir("/sys/fs/bpf/telcom");
        bpf_object__close(obj);
    }

    printf("Done.\n");
    return xdp_attached ? 0 : 1;
}
