# Contributing to Telcom

## How to Contribute

1. Fork the repository and create a feature branch from `main`.
2. Make your changes, keeping code style consistent.
3. Run `make clean && make` to verify compilation.
4. Test with a veth pair (see below).
5. Submit a pull request with a clear description.

## Code Style

### eBPF programs (`bpf/`)

- Follow Linux kernel style for BPF C code (`checkpatch.pl`-compatible).
- All BPF helpers must pass the verifier - avoid loops, unbounded memory
  access, and variable-length stack.
- Use `__u8`, `__u16`, `__u32`, `__u64` from `vmlinux.h`.

### User-space (`src/`, `tools/`)

- Standard C99 with `-Wall -Wextra`.
- 4-space indentation, no tabs in user-space code.
- Functions prefixed with `telcom_` or kept `static`.
- Prefer `bpf_map__*` libbpf helpers over raw syscalls.

## Setting Up a veth Pair for Testing

```bash
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up && sudo ip link set veth1 up
sudo ./bin/telcomd -i veth0 -e veth1 -v
```

In another terminal:
```bash
./bin/telcom-peek -w
```

Generate traffic with `ping`, `iperf3`, or a custom UDP stream.

## Pull Request Checklist

- [ ] Compiles cleanly (`make clean && make`)
- [ ] No libbpf or verifier warnings
- [ ] Tested on a veth pair or real NIC
- [ ] Config defaults updated if thresholds changed
- [ ] Documentation updated (CONFIG.md, README.md)
