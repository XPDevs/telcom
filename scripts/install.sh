#!/bin/sh
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root" >&2
    exit 1
fi

MISSING=""

if ! command -v clang >/dev/null 2>&1; then
    MISSING="$MISSING clang"
fi

if ! dpkg -l libbpf-dev 2>/dev/null | grep -q '^ii'; then
    if [ ! -f /usr/include/bpf/libbpf.h ] && [ ! -f /usr/local/include/bpf/libbpf.h ]; then
        MISSING="$MISSING libbpf-dev"
    fi
fi

if [ -n "$MISSING" ]; then
    echo "Error: missing build dependencies:$MISSING" >&2
    echo "" >&2
    echo "Install them with:" >&2
    echo "  sudo apt-get install clang llvm libbpf-dev libelf-dev gcc make" >&2
    exit 1
fi

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

install -d /usr/local/bin
install -d /usr/local/lib/bpf
install -d /etc/telcom

install -m 755 "$REPO_DIR/bin/telcomd" /usr/local/bin/
install -m 755 "$REPO_DIR/bin/telcom-peek" /usr/local/bin/
install -m 644 "$REPO_DIR/bpf/telcom_kern.bpf.o" /usr/local/lib/bpf/
install -m 644 "$REPO_DIR/bpf/telcom_tc.bpf.o" /usr/local/lib/bpf/

if [ ! -f /etc/telcom/telcom.toml ]; then
    install -m 644 "$REPO_DIR/telcom.toml" /etc/telcom/telcom.toml
fi

install -m 644 "$REPO_DIR/scripts/telcomd.service" /etc/systemd/system/telcomd.service

systemctl daemon-reload
echo "Installation complete."
echo "To configure: edit /etc/default/telcomd (export TELCOM_IFACE=xdp_iface; export TC_IFACE=tc_iface)"
echo "Then: systemctl enable --now telcomd"
