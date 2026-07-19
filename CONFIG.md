# Configuration Reference

The daemon reads `telcom.toml` at startup. If the file does not exist, a
default is created automatically.

## `[thresholds]` Entropy Classification

```
gaming_variance_threshold = 10000
gaming_max_avg            = 300
streaming_variance_threshold = 100000
streaming_min_avg         = 500
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `gaming_variance_threshold` | int | 10000 | Flows with variance below this AND avg <= `gaming_max_avg` → GAMING |
| `gaming_max_avg` | int | 300 | Max average packet size (bytes) for GAMING classification |
| `streaming_variance_threshold` | int | 100000 | Flows with variance above this AND avg >= `streaming_min_avg` → STREAMING |
| `streaming_min_avg` | int | 500 | Min average packet size (bytes) for STREAMING classification |
| (else) |   |   | Flows matching neither → BULK |

### Example: FTTH / Fiber (low latency, jitter < 2ms)

```toml
[thresholds]
gaming_variance_threshold = 5000
gaming_max_avg = 250
streaming_variance_threshold = 80000
streaming_min_avg = 600
```

### Example: 5G / LTE (higher latency and jitter)

```toml
[thresholds]
gaming_variance_threshold = 20000
gaming_max_avg = 400
streaming_variance_threshold = 200000
streaming_min_avg = 400
```

## `[pid]` Queue Depth Controller

```
target_rtt_ms = 20
kp            = 1000
ki            = 100
kd            = 500
```

| Field | Type | Scale | Description |
|-------|------|-------|-------------|
| `target_rtt_ms` | int | 1 | Desired round-trip time in milliseconds |
| `kp` | int | /1000 | Proportional gain |
| `ki` | int | /1000 | Integral gain |
| `kd` | int | /1000 | Derivative gain |

The PID formula is:

```
output = (kp × error + ki × integral + kd × derivative) / 1000
```

`output` is clamped to [1500, 200000] and written as `max_depth` for all
three class queues. Anti-windup subtracts `error` from `integral` whenever the
clamp is active.

### PID Tuning Guide

| Network | target_rtt_ms | kp | ki | kd |
|---------|--------------|----|----|-----|
| Data center (0.1–0.5ms RTT) | 5 | 2000 | 200 | 1000 |
| FTTH (1–5ms RTT) | 10 | 1500 | 150 | 750 |
| Cable / DSL (10–30ms RTT) | 30 | 800 | 80 | 400 |
| 5G NR (15–50ms RTT) | 40 | 500 | 50 | 250 |
| Satellite (400–800ms RTT) | 600 | 100 | 10 | 50 |

## Interface Selection

Configure the interface(s) via:

```bash
# /etc/default/telcomd
TELCOM_IFACE=eth0    # XDP ingress interface (required)
TC_IFACE=eth1        # TC egress interface (optional)
```

Or at the command line:

```bash
telcomd -i eth0 -e eth1 -c /etc/telcom/telcom.toml
```

Wi-Fi interfaces automatically disable TC shaping (yellow warning).
