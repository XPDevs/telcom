#!/bin/sh
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root" >&2
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
