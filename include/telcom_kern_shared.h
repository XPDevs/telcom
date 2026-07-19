#ifndef __TELCOM_KERN_SHARED_H
#define __TELCOM_KERN_SHARED_H

#define RING_BUF_SIZE 16

#define QUEUE_BULK      0
#define QUEUE_STREAMING 1
#define QUEUE_GAMING    2

#define DEFAULT_GAMING_VARIANCE_THRESHOLD  10000
#define DEFAULT_GAMING_MAX_AVG              300
#define DEFAULT_STREAMING_VARIANCE_THRESHOLD 100000
#define DEFAULT_STREAMING_MIN_AVG            500

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
} __attribute__((packed));

struct flow_value {
    __u64 packets;
    __u64 bytes;
    __u64 last_seen;

    __u64 sum;
    __u64 sum_sq;
    __u64 variance;

    __u16 pkt_len_buf[RING_BUF_SIZE];
    __u16 min_pkt;
    __u16 max_pkt;
    __u8  buf_idx;
    __u8  count;
    __u8  queue_class;
};

struct telcom_config {
    __u32 gaming_variance_threshold;
    __u32 gaming_max_avg;
    __u32 streaming_variance_threshold;
    __u32 streaming_min_avg;
};

#endif
