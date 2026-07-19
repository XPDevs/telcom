// SPDX-License-Identifier: GPL-2.0
/* Telcom - eBPF TC egress shaper */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "telcom_kern_shared.h"

#define ETH_P_IP    0x0800
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key);
    __type(value, struct flow_value);
} flow_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, NUM_CLASSES);
    __type(key, __u32);
    __type(value, struct class_queue);
} queue_map SEC(".maps");

SEC("tcx/egress")
int telcom_tc(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    __u16 src_port, dst_port;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        src_port = bpf_ntohs(tcp->source);
        dst_port = bpf_ntohs(tcp->dest);
    } else {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
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

    struct flow_value *flow = bpf_map_lookup_elem(&flow_table, &key);
    if (!flow)
        return TC_ACT_OK;

    __u32 class_idx = flow->queue_class;
    if (class_idx >= NUM_CLASSES)
        return TC_ACT_OK;

    struct class_queue *qc = bpf_map_lookup_elem(&queue_map, &class_idx);
    if (!qc)
        return TC_ACT_OK;

    __u64 now = bpf_ktime_get_ns();

    if (qc->current_depth > 0 && qc->last_tx_ns > 0) {
        __u64 elapsed = now - qc->last_tx_ns;
        __u32 decay = (__u32)(elapsed / 10000000ULL);
        if (decay > 0) {
            if (decay >= qc->current_depth)
                qc->current_depth = 0;
            else
                qc->current_depth -= decay;
        }
    }

    if (qc->current_depth >= qc->max_depth)
        return TC_ACT_SHOT;

    qc->current_depth++;
    qc->last_tx_ns = now;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
