#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include <net/if.h>

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

static volatile sig_atomic_t exiting = 0;

static int xdp_attached = 0;
static int tc_attached = 0;
static int ifindex_global = 0;
static int tc_ifindex_global = 0;

static char bpf_obj_path[PATH_MAX];
static char tc_obj_path[PATH_MAX];
static char config_path[PATH_MAX];

static int verbose = 0;
static int dry_run = 0;
static int force_clean = 0;
static int force_skb = 0;

static struct telcom_config config = {
    .gaming_variance_threshold    = DEFAULT_GAMING_VARIANCE_THRESHOLD,
    .gaming_max_avg               = DEFAULT_GAMING_MAX_AVG,
    .streaming_variance_threshold = DEFAULT_STREAMING_VARIANCE_THRESHOLD,
    .streaming_min_avg            = DEFAULT_STREAMING_MIN_AVG,
};

static struct pid_config pid_cfg = {
    .target_rtt_ms = 20,
    .kp = 1000,
    .ki = 100,
    .kd = 500,
};

static long long integral = 0;
static long long prev_error = 0;

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
            "Usage: %s -i <xdp-iface> [-e <tc-egress-iface>] [-c <config>] [-v] [--force] [--dry-run]\n"
            "  -i, --interface        XDP ingress interface\n"
            "  -e, --egress           TC egress interface (for shaping)\n"
            "  -c, --config           Path to config file (optional)\n"
            "  -v, --verbose          Verbose output\n"
            "  --force                Remove old pinned maps on startup\n"
            "  --dry-run              Print actions without executing\n"
            "  -V, --version          Print version and exit\n",
            prog);
}

static void print_version(void)
{
    printf("telcomd %s\n", TELCOM_VERSION);
}

static int is_wireless_interface(const char *ifname)
{
    char path[64];
    snprintf(path, sizeof(path), "/sys/class/net/%s/wireless", ifname);
    return access(path, F_OK) == 0;
}

static const char *supported_drivers[] = {
    "i40e", "ice", "mlx5_core", "nfp", NULL
};

static int check_driver(const char *ifname)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ethtool -i %s 2>/dev/null", ifname);

    FILE *fp = popen(cmd, "r");
    if (!fp)
        return -1;

    char driver[64] = {};
    while (fgets(driver, sizeof(driver), fp)) {
        if (strncmp(driver, "driver:", 7) == 0) {
            break;
        }
    }
    pclose(fp);

    if (driver[0] == '\0')
        return -1;

    char *val = driver + 7;
    while (*val == ' ' || *val == '\t') val++;
    char *nl = strchr(val, '\n');
    if (nl) *nl = '\0';

    for (int i = 0; supported_drivers[i]; i++) {
        if (strcmp(val, supported_drivers[i]) == 0) {
            if (verbose)
                printf("Driver: %s (supported)\n", val);
            return 0;
        }
    }

    fprintf(stderr,
        "\033[33mWarning: NIC driver '%s' is not in the tested list "
        "(i40e, ice, mlx5_core, nfp).\n"
        "  Native XDP may not achieve line rate. "
        "Falling back to generic (SKB) mode.\033[0m\n", val);
    force_skb = 1;
    return 1;
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
    snprintf(tc_obj_path, sizeof(tc_obj_path),
             "%s/../bpf/telcom_tc.bpf.o", dir);

    if (access(bpf_obj_path, F_OK) == -1) {
        fprintf(stderr, "Error: BPF object not found at %s\n", bpf_obj_path);
        return -1;
    }
    return 0;
}

static int parse_config_line(char *line)
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

    if      (strcmp(key, "gaming_variance_threshold") == 0)    config.gaming_variance_threshold = val;
    else if (strcmp(key, "gaming_max_avg") == 0)               config.gaming_max_avg = val;
    else if (strcmp(key, "streaming_variance_threshold") == 0) config.streaming_variance_threshold = val;
    else if (strcmp(key, "streaming_min_avg") == 0)            config.streaming_min_avg = val;
    else if (strcmp(key, "target_rtt_ms") == 0)                pid_cfg.target_rtt_ms = val;
    else if (strcmp(key, "kp") == 0)                           pid_cfg.kp = val;
    else if (strcmp(key, "ki") == 0)                           pid_cfg.ki = val;
    else if (strcmp(key, "kd") == 0)                           pid_cfg.kd = val;

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
            "streaming_min_avg = %u\n"
            "[pid]\n"
            "target_rtt_ms = %u\n"
            "kp = %u\n"
            "ki = %u\n"
            "kd = %u\n",
            config.gaming_variance_threshold,
            config.gaming_max_avg,
            config.streaming_variance_threshold,
            config.streaming_min_avg,
            pid_cfg.target_rtt_ms,
            pid_cfg.kp,
            pid_cfg.ki,
            pid_cfg.kd);
        fclose(f);
        printf("Created default config: %s\n", path);
        return 0;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r')
            continue;
        parse_config_line(line);
    }

    fclose(f);
    return 0;
}

static int attach_xdp(struct bpf_program *prog, int ifindex, const char *ifname, int force_skb)
{
    int prog_fd = bpf_program__fd(prog);
    __u32 flags;
    int err;

    if (force_skb) {
        flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;
        err = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
        if (err == 0) {
            printf("XDP attached to %s (generic/SKB mode)\n", ifname);
            return 0;
        }
        fprintf(stderr, "Error attaching XDP (SKB) to %s: %s\n", ifname, strerror(-err));
        return err;
    }

    flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
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

static __u32 measure_rtt_ms(void)
{
    static __u32 last_rtt = 50;
    FILE *fp = popen("ss -ti 2>/dev/null", "r");
    if (!fp)
        return last_rtt;

    char buf[4096];
    size_t pos = 0;
    while (pos < sizeof(buf) - 1) {
        size_t n = fread(buf + pos, 1, sizeof(buf) - 1 - pos, fp);
        if (n == 0) break;
        pos += n;
    }
    buf[pos] = '\0';
    int ret = pclose(fp);
    (void)ret;

    __u64 sum_us = 0;
    int count = 0;
    char *p = buf;

    while ((p = strstr(p, "rtt:")) != NULL) {
        if (p > buf && *(p - 1) != ' ' && *(p - 1) != '\t') {
            p += 4;
            continue;
        }
        p += 4;
        char *end = NULL;
        double val = strtod(p, &end);
        if (end == p)
            continue;
        __u32 us = val > 0 ? (__u32)(val * 1000.0 + 0.5) : 1;
        sum_us += us;
        count++;
        p = end;
    }

    if (count > 0) {
        __u32 avg_us = (__u32)((sum_us + count / 2) / count);
        __u32 avg_ms = (avg_us + 500) / 1000;
        if (avg_ms < 1)
            avg_ms = 1;
        if (avg_ms > 5000)
            avg_ms = 5000;
        last_rtt = avg_ms;
        return avg_ms;
    }

    return last_rtt;
}

static void run_pid_loop(struct bpf_object *tc_obj)
{
    __u32 current_rtt = measure_rtt_ms();
    long long error = (long long)pid_cfg.target_rtt_ms - (long long)current_rtt;
    long long dt = 5;

    integral += error * dt;

    if (integral > 100000) integral = 100000;
    if (integral < -100000) integral = -100000;

    long long derivative = (error - prev_error) / dt;

    long long output = (long long)pid_cfg.kp * error
                     + (long long)pid_cfg.ki * integral
                     + (long long)pid_cfg.kd * derivative;
    output /= 1000;

    if (output < 1500) {
        output = 1500;
        integral -= error;
    } else if (output > 200000) {
        output = 200000;
        integral -= error;
    }

    prev_error = error;

    if (verbose)
        printf("PID: rtt=%ums err=%lld integral=%lld deriv=%lld output=%lld\n",
               current_rtt, error, integral, derivative, output);

    if (!tc_obj)
        return;

    struct bpf_map *queue_map = bpf_object__find_map_by_name(tc_obj, "queue_map");
    if (!queue_map) {
        if (verbose)
            fprintf(stderr, "PID: queue_map not found in TC object\n");
        return;
    }

    int n_cpus = libbpf_num_possible_cpus();
    size_t cpu_buf_size = n_cpus * sizeof(struct class_queue);
    struct class_queue *qc_buf = malloc(cpu_buf_size);
    if (!qc_buf)
        return;

    __u32 clamped_output = (__u32)output;

    for (__u32 i = 0; i < NUM_CLASSES; i++) {
        __u32 key = i;

        if (bpf_map__lookup_elem(queue_map, &key, sizeof(key), qc_buf, cpu_buf_size, 0) == 0) {
            __u32 new_depth = clamped_output;

            for (int cpu = 0; cpu < n_cpus; cpu++)
                qc_buf[cpu].max_depth = new_depth;

            bpf_map__update_elem(queue_map, &key, sizeof(key), qc_buf, cpu_buf_size, BPF_ANY);
        }
    }

    free(qc_buf);
}

static void cleanup_pins(void)
{
    if (access("/sys/fs/bpf/telcom", F_OK) == 0) {
        printf("Cleaning up old pinned maps...\n");
        system("rm -rf /sys/fs/bpf/telcom");
        rmdir("/sys/fs/bpf/telcom");
    }
}

int main(int argc, char **argv)
{
    const char *ifname = NULL;
    const char *egress_ifname = NULL;
    const char *cfg_arg = NULL;
    int ifindex;
    int opt;

    struct bpf_object *tc_obj = NULL;

    static const struct option long_opts[] = {
        { "interface", required_argument, NULL, 'i' },
        { "egress",    required_argument, NULL, 'e' },
        { "config",    required_argument, NULL, 'c' },
        { "verbose",   no_argument,       NULL, 'v' },
        { "version",   no_argument,       NULL, 'V' },
        { "force",     no_argument,       NULL,  0  },
        { "dry-run",   no_argument,       NULL,  1  },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "i:e:c:vV", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i': ifname = optarg; break;
        case 'e': egress_ifname = optarg; break;
        case 'c': cfg_arg = optarg; break;
        case 'v': verbose = 1; break;
        case 'V': print_version(); return 0;
        case 0:  force_clean = 1; break;
        case 1:  dry_run = 1; break;
        default:  print_usage(argv[0]); return 1;
        }
    }

    if (force_clean) {
        cleanup_pins();
        return 0;
    }

    if (!ifname) {
        if (!dry_run) {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (resolve_bpf_obj_path(argv[0]))
        return 1;

    if (dry_run) {
        printf("[DRY-RUN] Would attach XDP to interface: %s\n", ifname ? ifname : "(none)");
        if (egress_ifname)
            printf("[DRY-RUN] Would attach TC egress to interface: %s\n", egress_ifname);
        printf("[DRY-RUN] Config: %s\n", cfg_arg ? cfg_arg : "default path");
        printf("[DRY-RUN] BPF object: %s\n", bpf_obj_path);
        printf("[DRY-RUN] TC object: %s\n", tc_obj_path);
        return 0;
    }

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

    if (egress_ifname) {
        tc_ifindex_global = if_nametoindex(egress_ifname);
        if (!tc_ifindex_global) {
            fprintf(stderr, "Error: egress interface '%s' not found\n", egress_ifname);
            return 1;
        }
    }

    if (is_wireless_interface(ifname)) {
        fprintf(stderr,
            "\033[33mWarning: Wi-Fi interface detected. "
            "TC egress shaping and power-saving PID loop will be disabled "
            "for this session. Use a virtio-net or wired interface for "
            "production testing.\033[0m\n");
    }

    cleanup_pins();

    int drv_ret = check_driver(ifname);
    if (drv_ret < 0 && verbose)
        fprintf(stderr, "Warning: could not determine NIC driver (ethtool missing?)\n");

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
    } else if (verbose) {
        printf("Config map updated (gaming_var=%u, gaming_avg=%u, stream_var=%u, stream_avg=%u)\n",
               config.gaming_variance_threshold, config.gaming_max_avg,
               config.streaming_variance_threshold, config.streaming_min_avg);
    }

    if (attach_xdp(prog, ifindex, ifname, force_skb)) {
        xdp_attached = 0;
        goto cleanup;
    }
    xdp_attached = 1;

    mkdir("/sys/fs/bpf/telcom", 0755);

    if (bpf_object__pin_maps(obj, "/sys/fs/bpf/telcom")) {
        fprintf(stderr, "Warning: failed to pin maps\n");
    } else if (verbose) {
        printf("XDP maps pinned to /sys/fs/bpf/telcom/\n");
    }

    if (egress_ifname) {
        tc_obj = bpf_object__open_file(tc_obj_path, NULL);
        if (libbpf_get_error(tc_obj)) {
            fprintf(stderr, "Warning: cannot open TC object %s, skipping\n", tc_obj_path);
            tc_obj = NULL;
        } else {
            struct bpf_map *tc_flow_map = bpf_object__find_map_by_name(tc_obj, "flow_table");
            if (!tc_flow_map) {
                fprintf(stderr, "Warning: flow_table not found in TC object, skipping\n");
                bpf_object__close(tc_obj);
                tc_obj = NULL;
            } else {
                int pinned_fd = bpf_obj_get("/sys/fs/bpf/telcom/flow_table");
                if (pinned_fd < 0) {
                    fprintf(stderr, "Warning: cannot open pinned flow_table, skipping TC\n");
                    bpf_object__close(tc_obj);
                    tc_obj = NULL;
                } else {
                    if (bpf_map__reuse_fd(tc_flow_map, pinned_fd)) {
                        fprintf(stderr, "Warning: failed to reuse flow_table fd, skipping TC\n");
                        close(pinned_fd);
                        bpf_object__close(tc_obj);
                        tc_obj = NULL;
                    } else {
                        close(pinned_fd);

                        if (bpf_object__load(tc_obj)) {
                            fprintf(stderr, "Warning: failed to load TC object: %s\n", strerror(errno));
                            bpf_object__close(tc_obj);
                            tc_obj = NULL;
                        } else {
                            struct bpf_program *tc_prog = bpf_object__find_program_by_name(tc_obj, "telcom_tc");
                            if (!tc_prog) {
                                fprintf(stderr, "Warning: TC program not found\n");
                                bpf_object__close(tc_obj);
                                tc_obj = NULL;
                            } else {
                                struct bpf_link *tc_link = bpf_program__attach_tcx(tc_prog, tc_ifindex_global, NULL);
                                if (libbpf_get_error(tc_link)) {
                                    fprintf(stderr, "Warning: TC attach failed: %s\n", strerror(errno));
                                    bpf_object__close(tc_obj);
                                    tc_obj = NULL;
                                } else {
                                    struct bpf_map *tc_qmap = bpf_object__find_map_by_name(tc_obj, "queue_map");
                                    if (tc_qmap && bpf_map__pin(tc_qmap, "/sys/fs/bpf/telcom/queue_map") && verbose)
                                        fprintf(stderr, "Warning: failed to pin queue_map\n");
                                    tc_attached = 1;
                                    printf("TC egress shaping active on %s\n", egress_ifname);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    printf("Daemon ready. PID %s.\n", tc_attached ? "active" : "inactive (no egress iface)");

    while (!exiting) {
        if (tc_obj) {
            run_pid_loop(tc_obj);
        } else if (verbose) {
            time_t now = time(NULL);
            printf("[%.24s] daemon running (no TC shaping)\n", ctime(&now));
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

    if (tc_obj) {
        bpf_object__close(tc_obj);
        printf("TC detach skipped (kernel cleans up on process exit)\n");
    }

    if (obj) {
        bpf_object__unpin_maps(obj, "/sys/fs/bpf/telcom");
        rmdir("/sys/fs/bpf/telcom");
        bpf_object__close(obj);
    }

    printf("Done.\n");
    return xdp_attached ? 0 : 1;
}
