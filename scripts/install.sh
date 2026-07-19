#!/bin/sh
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root" >&2
    exit 1
fi

if [ -z "$1" ]; then
    echo "Usage: $0 <interface>" >&2
    echo "Example: $0 eth0" >&2
    exit 1
fi

INTERFACE="$1"

install -d /usr/local/bin
install -d /usr/local/lib/bpf
install -m 755 bin/telcomd /usr/local/bin/
install -m 755 bin/telcom-peek /usr/local/bin/
install -m 644 bpf/telcom_kern.bpf.o /usr/local/lib/bpf/

if [ ! -f /etc/telcom.toml ]; then
    install -m 644 telcom.toml /etc/telcom.toml
fi

cat > /etc/systemd/system/telcomd.service << EOF
[Unit]
Description=Telcom eBPF traffic flow monitor
Documentation=https://github.com/user/telcom
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/telcomd -i ${INTERFACE} -c /etc/telcom.toml
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_ADMIN

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "Installed. Enable with: systemctl enable telcomd"
echo "Then start with: systemctl start telcomd"
