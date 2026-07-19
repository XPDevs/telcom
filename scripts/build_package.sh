#!/bin/sh
set -e

# Build a .deb package for telcom
# Requires: dpkg-deb, fakeroot (optional)

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(cat "$REPO_DIR/VERSION" | tr -d ' \n' | sed 's/^v//')"
PACKAGE_NAME="telcom"
ARCH="amd64"
DEB_DIR="$(mktemp -d)"

# Ensure binaries and BPF objects are built
cd "$REPO_DIR"
make build_bpf build_tc build_daemon build_tools

mkdir -p "$DEB_DIR/DEBIAN"
mkdir -p "$DEB_DIR/usr/local/bin"
mkdir -p "$DEB_DIR/usr/local/lib/bpf"
mkdir -p "$DEB_DIR/etc/telcom"
mkdir -p "$DEB_DIR/etc/default"
mkdir -p "$DEB_DIR/lib/systemd/system"

install -m 755 bin/telcomd       "$DEB_DIR/usr/local/bin/"
install -m 755 bin/telcom-peek   "$DEB_DIR/usr/local/bin/"
install -m 644 bpf/telcom_kern.bpf.o "$DEB_DIR/usr/local/lib/bpf/"
install -m 644 bpf/telcom_tc.bpf.o   "$DEB_DIR/usr/local/lib/bpf/"
install -m 644 telcom.toml       "$DEB_DIR/etc/telcom/telcom.toml"
install -m 644 scripts/telcomd.service "$DEB_DIR/lib/systemd/system/"

cat > "$DEB_DIR/etc/default/telcomd" << EOF
# Telcom daemon configuration
# Set the XDP ingress interface and optional TC egress interface
TELCOM_IFACE=eth0
TC_IFACE=
EOF

cat > "$DEB_DIR/DEBIAN/control" << EOF
Package: telcom
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: XPDevs <xpdevs.github.io.com@gmail.com>
Section: net
Priority: optional
Depends: libbpf0 (>= 1.3.0), libelf1 (>= 0.176), libc6 (>= 2.31)
Recommends: bpftool
Description: Telcom - eBPF traffic scheduling framework (Developer Preview)
 Telcom is a proof-of-concept framework for deterministic traffic
 scheduling using eBPF/XDP and TC.
 .
 This package provides the telcomd daemon and telcom-peek inspection
 tool.
 .
 Disclaimer:
 This is a developer preview release. It has been tested on veth pairs
 and Generic XDP (Wi-Fi) for logic validation. It has not been
 validated on production ISP hardware (Intel E810 / Mellanox
 ConnectX-6) at scale.
 .
 Known limitations:
  - RTT measurements are currently simulated (dummy values) in the PID
    loop.
  - Requires Linux Kernel 5.10+ and libbpf development headers to
    compile.
  - Use in lab environments only.
 .
 Core Features (Validated):
  - Entropy-based flow classification (No DPI / GDPR friendly).
  - TC egress queue depth management (BULK/STREAM/GAMING).
  - Live flow inspection via telcom-peek.
  - PID control loop logic (simulated feedback).
Homepage: https://github.com/XPDevs/telcom
EOF

cat > "$DEB_DIR/DEBIAN/postinst" << 'POSTINST'
#!/bin/sh
set -e
if [ -x /bin/systemctl ] || [ -x /usr/bin/systemctl ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
POSTINST
chmod 755 "$DEB_DIR/DEBIAN/postinst"

DEB_FILE="${REPO_DIR}/telcom_${VERSION}_${ARCH}.deb"
fakeroot dpkg-deb --build "$DEB_DIR" "$DEB_FILE" 2>/dev/null || dpkg-deb --build "$DEB_DIR" "$DEB_FILE"

rm -rf "$DEB_DIR"
echo "Package created: $DEB_FILE"
