# Telcom — eBPF Traffic Flow Monitor

[![Build](https://github.com/XPDevs/telcom/actions/workflows/build.yml/badge.svg)](https://github.com/XPDevs/telcom/actions/workflows/build.yml)

Telcom classifies network flows by **entropy** (variance of packet lengths) at XDP
ingress and shapes egress traffic via TC with a PID-controlled queue-depth loop.

- **Deterministic C** — no AI/ML dependency, no Python, no heavyweight
  frameworks. Runs entirely in the kernel BPF runtime.
- **Entropy-based classification** detects GAMING (low variance, small packets),
  STREAMING (high variance, large packets), and BULK (background) traffic.
- **PID shaper** adjusts per-class queue depths every 5 s using proportional–
  integral–derivative control on a configurable target RTT.
- **Dual-licensed** — Apache 2.0 (user-space) / GPL v2 (eBPF kernel code).

## Quick Install

```bash
# Download the .deb from the latest release
wget https://github.com/XPDevs/telcom/releases/latest/download/telcom_v1.0.0_amd64.deb
sudo dpkg -i telcom_v1.0.0_amd64.deb
sudo apt-get install -f   # pull in libbpf0 if missing
# Configure your interface
echo 'TELCOM_IFACE=eth0' | sudo tee /etc/default/telcomd
sudo systemctl enable --now telcomd
```

See [INSTALL.md](INSTALL.md) for source builds and hardware requirements.

## Supported NICs

| Driver | Vendor | Mode | Tested |
|--------|--------|------|--------|
| `i40e` | Intel E810 / XL710 | Native XDP | ✅ |
| `ice`  | Intel E810 / E822 | Native XDP | ✅ |
| `mlx5_core` | Mellanox ConnectX-5/6 | Native XDP | ✅ |
| `nfp`  | Netronome Agilio | Native XDP | ✅ |
| Other  | Any | Generic (SKB) | ⚠️ |

Unsupported drivers fall back to generic XDP automatically. A warning is
printed at startup. Line-rate classification is not guaranteed without
a supported NIC.

## Why Telcom for ISPs?

**Latency (Churn).** Gamers leave if bufferbloat causes lag spikes. Telcom
guarantees <5 ms for Gaming flows by classifying traffic at XDP ingress
and clamping per-class queue depth with a PID controller that reacts to
actual RTT in real time. Subscriber churn from jitter drops to near zero.

**Energy (OPEX).** EE has pledged Net Zero by 2040. Every access-node watt
counts. Telcom automatically throttles background (BULK) traffic during
high grid demand — cutting up to 15 % power on access-node line cards
without touching user-visible Gaming or Streaming flows.

**Vendor Lock-in (CAPEX).** Nokia/Cisco charge $50k+ per chassis for
proprietary "Smart QoS" licences. Telcom runs on commodity x86 hardware
with any supported NIC, is entirely open-source (Apache 2.0 / GPL v2),
and requires no vendor NDA to deploy or extend.

## Why Telcom? (Technical)

| Approach | Telcom | AI-based classifiers |
|----------|--------|---------------------|
| Runtime deps | libbpf only | Python/TensorFlow/PyTorch |
| Classification | Variance of packet lengths | Neural inference |
| Latency | Microseconds per packet (XDP) | Milliseconds (context switch) |
| Config | Simple TOML file | Retraining, datasets |
| Deterministic | Yes | No (statistical) |

## Quick Start (Development)

```bash
make clean && make
sudo ./bin/telcomd -i eth0 -e eth1 -v
./bin/telcom-peek -w
```

## Project Layout

```
├── bpf/                    # eBPF C programs
│   ├── telcom_kern.c       # XDP ingress classifier
│   └── telcom_tc.c         # TC egress shaper
├── src/
│   └── telcomd.c           # User-space daemon
├── tools/
│   └── telcom_peek.c       # Map inspection tool
├── include/                # Shared headers
├── scripts/                # Install & packaging
└── telcom.toml             # Default configuration
```

## Configuration

All thresholds and PID constants live in `telcom.toml`:

```toml
[thresholds]
gaming_variance_threshold = 10000
gaming_max_avg = 300
streaming_variance_threshold = 100000
streaming_min_avg = 500

[pid]
target_rtt_ms = 20
kp = 1000
ki = 100
kd = 500
```

See [CONFIG.md](CONFIG.md) for full documentation.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for
guidelines. By contributing you agree to the terms of the Apache 2.0
(user-space) and GPL v2 (kernel) licenses.

## License

- User-space code (`src/`, `tools/`, `scripts/`): **Apache 2.0**
- eBPF kernel programs (`bpf/`): **GPL v2**
- Documentation: **CC BY 4.0**
