# Installation Guide

## Hardware Requirements

- **NIC**: Intel E810 (100G), Mellanox ConnectX-5/6, or any virtio-net NIC
- **CPU**: x86-64 with BPF support (most Intel/AMD from 2015+)
- **RAM**: 1 GB minimum
- **Storage**: 50 MB (binary + BPF objects)

## Software Requirements

| Dependency | Version |
|------------|---------|
| Linux kernel | 5.10+ (6.x for full TCX support) |
| libbpf | >= 1.3.0 |
| libelf | >= 0.176 |
| clang | >= 11 |
| bpftool | optional (for debugging) |

## Option 1: Install from .deb

```bash
wget https://github.com/XPDevs/telcom/releases/latest/download/telcom_v0.9.0_amd64.deb
sudo dpkg -i telcom_v0.9.0_amd64.deb
sudo apt-get install -f    # resolves libbpf0 dependency
```

Configure the interface:

```bash
cat > /etc/default/telcomd << EOF
TELCOM_IFACE=eth0
TC_IFACE=eth1
EOF

sudo systemctl enable --now telcomd
journalctl -u telcomd -f
```

## Option 2: Build from Source

### 1. Install build dependencies

**Ubuntu / Debian**:
```bash
sudo apt-get install clang llvm libbpf-dev libelf-dev linux-headers-$(uname -r)
```

### 2. Generate vmlinux.h (if missing)

```bash
make vmlinux
```

### 3. Build

```bash
make clean && make
```

### 4. Install

```bash
sudo make install
```

### 5. Configure

Edit `/etc/telcom/telcom.toml` for your network, then:

```bash
echo 'TELCOM_IFACE=eth0' | sudo tee /etc/default/telcomd
sudo systemctl enable --now telcomd
```

## Verifying Installation

```bash
telcom-peek
```

You should see an empty flow table if the daemon is running. Generate traffic:

```bash
ping -c 100 $(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+')
telcom-peek
```

## Testing with veth

```bash
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up && sudo ip link set veth1 up
sudo ./bin/telcomd -i veth0 -e veth1 -v
```
