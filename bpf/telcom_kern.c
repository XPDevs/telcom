// SPDX-License-Identifier: GPL-2.0
/* Telcom - eBPF XDP ingress classifier */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "telcom_kern_shared.h"

#define ETH_P_IP 0x0800

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} flow_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct telcom_config);
} config_map SEC(".maps");

static void update_flow_stats(struct flow_value *val, __u32 pkt_len)
{
    __u8 idx = val->buf_idx & 0xF;
    __u16 old_len = val->pkt_len_buf[idx];

    val->sum = val->sum - old_len + pkt_len;
    val->sum_sq = val->sum_sq - ((__u64)old_len * old_len) + ((__u64)pkt_len * pkt_len);

    val->pkt_len_buf[idx] = (__u16)pkt_len;
    val->buf_idx = (val->buf_idx + 1) & 0xF;

    if (val->count < RING_BUF_SIZE)
        val->count++;

    __sync_fetch_and_add(&val->packets, 1);
    __sync_fetch_and_add(&val->bytes, pkt_len);
    val->last_seen = bpf_ktime_get_ns();

    if (pkt_len < val->min_pkt)
        val->min_pkt = (__u16)pkt_len;
    if (pkt_len > val->max_pkt)
        val->max_pkt = (__u16)pkt_len;

    if (val->count > 0) {
        __u64 mean = val->sum / val->count;
        __u64 mean_sq = val->sum_sq / val->count;
        val->variance = mean_sq - (mean * mean);
    }
}

static void classify_flow(struct flow_value *val, struct telcom_config *cfg)
{
    if (val->count == 0) {
        val->queue_class = QUEUE_BULK;
        return;
    }

    __u64 avg = val->sum / val->count;

    if (avg <= cfg->gaming_max_avg && val->variance <= cfg->gaming_variance_threshold)
        val->queue_class = QUEUE_GAMING;
    else if (avg >= cfg->streaming_min_avg && val->variance <= cfg->streaming_variance_threshold)
        val->queue_class = QUEUE_STREAMING;
    else
        val->queue_class = QUEUE_BULK;
}

SEC("xdp")
int telcom_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    __u32 pkt_len  = (__u32)(data_end - data);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u16 src_port, dst_port;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    } else {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        src_port = bpf_ntohs(udp->source);
        dst_port = bpf_ntohs(udp->dest);
    }

    struct flow_key key = {
        .src_ip   = ip->saddr,
        .dst_ip   = ip->daddr,
        .src_port = src_port,
        .dst_port = dst_port,
        .protocol = ip->protocol,
    };

    __u32 zero = 0;
    struct telcom_config *cfg = bpf_map_lookup_elem(&config_map, &zero);

    struct flow_value *val = bpf_map_lookup_elem(&flow_table, &key);
    if (val) {
        update_flow_stats(val, pkt_len);
        if (cfg)
            classify_flow(val, cfg);
    } else {
        struct flow_value new_val = {};

        update_flow_stats(&new_val, pkt_len);
        new_val.min_pkt = (__u16)pkt_len;
        new_val.max_pkt = (__u16)pkt_len;
        new_val.last_seen = bpf_ktime_get_ns();

        if (cfg)
            classify_flow(&new_val, cfg);

        bpf_map_update_elem(&flow_table, &key, &new_val, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
