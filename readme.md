# Telcom – A deterministic scheduler for ISP edge routers

This is an open source framework for managing packet queues, latency, and power usage on access network gear. It is designed for BNGs, OLTs, and 5G CU-UP nodes. It runs in the Linux kernel using eBPF and XDP.

The core idea is to use deterministic heuristics rather than machine learning. We think ML adds too much uncertainty for production networking. We are trying to keep per-packet overhead low, provide traceable behaviour, and avoid inspecting payload data for privacy reasons.

---

## What it does

- Classifies flows by looking at packet size and timing only. No DPI. We use entropy calculations to guess if a flow is gaming, streaming, bulk download, or interactive. Its not perfect but it works well enough for queue selection.
- Applies different queue treatments per class. Gaming flows get shallow buffers to keep latency low. Bulk flows get deeper buffers and are the first to be dropped when congestion hits.
- Tries to save power by slowing down bulk transfers when the grid is under stress or when the local hardware is running hot. This is done via a PID loop that monitors RTT and another loop that watches CPU temperature and local power frequency.
- Expands and shrinks buffer depth based on burstiness. The idea is to absorb sudden micro-bursts without adding steady-state latency.

---

## Why not AI?

We decided against AI for a few reasons.

- Inference takes time. Even optimised models are slower than simple integer math.
- You cannot easily prove an AI model will not do something odd under unusual traffic patterns. With deterministic code, you can test and validate the logic.
- Regulators and network engineers want to understand why a packet was dropped or delayed. Black boxes make that hard.
- AI models often need retraining when the hardware or subscriber mix changes. Our approach just needs config tuning.

---

## Requirements

We ship pre-compiled binaries so you dont need to build anything. You will need:

- A 64-bit x86 or ARM server. AMD EPYC, Intel Xeon, or Ampere Altra should work.
- A supported NIC. We have tested on Intel E810, Mellanox ConnectX-5/6, and Broadcom Stingray. Other cards might work if they support XDP but we cannot guarantee it.
- Linux kernel 5.10 or newer. We build against Ubuntu 20.04, RHEL 9, and Debian 11 but other distributions might work.

---

## Quick start

Download the latest tarball for your architecture. We sign the releases but you should also verify the checksums manually.

```
wget https://github.com/XPDevs/telcom/releases/latest/download/telcom-v1.0.0-x86_64.tar.gz
wget https://github.com/XPDevs/telcom/releases/latest/download/telcom-v1.0.0-x86_64.sha512
sha512sum -c telcom-v1.0.0-x86_64.sha512
tar -xzf telcom-v1.0.0-x86_64.tar.gz
sudo ./telcomd --install
```

Then run it on the interface you want to manage.

```
sudo telcomd --interface eth0 --config /etc/telcom/telcom.toml
```

The daemon loads the eBPF bytecode into the kernel and starts applying the scheduling logic. There is no compiler or external dependency required at runtime. The binary is statically linked against musl so it should run on most Linux installs.

---

## Configuration

Every network is different. What works on a fibre POP might not work on a microwave backhaul. We provide a tool called `telcom-calibrator` that you can run in passive mode for 24 hours. It watches your traffic and suggests a config file that matches your link characteristics.

```
sudo telcom-calibrator --interface eth0 --output /etc/telcom/telcom.toml
```

You can of course write the TOML file by hand if you understand the parameters. We try to keep the config readable but there are quite a few knobs. The calibrator is the easiest way to get started.

---

## Failure handling

We tried to make this safe to run on real networks.

- If the daemon process dies, the eBPF programs stay loaded. They revert to a mode that behaves like standard FQ-CoDel. The box stays up and passes traffic.
- If a flow is misclassified, it gets moved to the bulk queue within a couple of milliseconds. That might add some latency to that specific flow but it wont affect other flows.
- If the config file has invalid values, the daemon logs an error and exits. It does not try to apply broken config.

We still recommend running this in a staging environment before rolling it out to production.

---

## Roadmap

These are our rough plans. They might change.

- v0.1: basic eBPF classifier and buffer management on x86_64.
- v0.3: add the power scheduler and ARM64 builds.
- v1.0: integrate with O-RAN interfaces for 5G and add formal verification for the core logic.
- v1.5: support TR-369 so we can coordinate with home gateways.

---

## Contributing

We are looking for help from people who run networks, work on kernel code, or test hardware. We need:

- Test results from different hardware platforms.
- Anonymised traffic traces so we can improve the classifier.
- Reviews of the PID logic and the entropy calculations.

We keep the user-space daemon under Apache 2.0 so it can be integrated with proprietary systems. The kernel eBPF code is GPL 3.0 because it needs to stay open.

---

## Caveats

This is not a magic bullet. We are trying to improve latency and power usage without breaking things. It will not fix every congestion problem and it is not a replacement for proper capacity planning. We have seen good results in our own testing but your mileage will vary.

The code is provided as-is. There is no warranty or guarantee of performance. We accept bug reports and contributions but we cannot offer commercial support at this time.

---

For more details, see the GitHub issues page or start a discussion if you have questions.

[Report a Bug](https://github.com/XPDevs/telcom/issues) | [Request a Feature](https://github.com/XPDevs/telcom/discussions)
