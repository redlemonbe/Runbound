#!/usr/bin/env bash
# Runbound installer for Debian / Ubuntu / RHEL-compatible distros
# Downloads the latest release binary from GitHub — no Rust toolchain required.
#
# Usage:
#   sudo bash install.sh                  # install latest release
#   sudo bash install.sh --version 0.2.3  # install specific version
#   sudo bash install.sh --uninstall      # remove Runbound
set -euo pipefail

REPO="redlemonbe/Runbound"
BINARY_DST="/usr/local/sbin/runbound"
CONFIG_DIR="/etc/runbound"
DATA_DIR="/var/lib/runbound"
RUN_USER="runbound"
RUN_GROUP="runbound"
VERSION="${2:-latest}"   # --version <tag> or "latest"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || fail "Run as root: sudo bash install.sh"

# ── Uninstall ─────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--uninstall" ]]; then
    echo "Uninstalling Runbound…"
    systemctl stop runbound    2>/dev/null || true
    systemctl disable runbound 2>/dev/null || true
    rm -f /etc/systemd/system/runbound.service "$BINARY_DST"
    systemctl daemon-reload
    ok "Runbound uninstalled. Config in $CONFIG_DIR and $DATA_DIR were kept."
    exit 0
fi

# ── Detect architecture ───────────────────────────────────────────────────────
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)          ARCH_TAG="x86_64" ;;
    aarch64|arm64)   ARCH_TAG="aarch64" ;;
    *) fail "Unsupported architecture: $ARCH" ;;
esac

# Prefer musl (static, no dependency on glibc version)
ASSET="runbound-${VERSION}-${ARCH_TAG}-linux-musl"

# ── Resolve "latest" to an actual version tag ─────────────────────────────────
if [[ "$VERSION" == "latest" ]]; then
    if command -v curl &>/dev/null; then
        VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    elif command -v wget &>/dev/null; then
        VERSION=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" \
            | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    else
        fail "Neither curl nor wget found — cannot fetch release metadata"
    fi
    [ -n "$VERSION" ] || fail "Could not determine latest release version"
fi

# Strip leading 'v' if present to form the asset filename version segment
VER_TAG="$VERSION"
VER_BARE="${VERSION#v}"
ASSET="runbound-${VERSION}-${ARCH_TAG}-linux-musl"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${VER_TAG}/${ASSET}"

echo "Installing Runbound ${VER_TAG} (${ARCH_TAG}, static musl)…"
echo "Downloading: $DOWNLOAD_URL"

# ── Check for conflicting DNS services ────────────────────────────────────────
for svc in unbound bind9 systemd-resolved dnsmasq; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        warn "$svc is running — it may conflict on port 53. Stop it: systemctl stop $svc"
    fi
done

# ── Download binary ───────────────────────────────────────────────────────────
TMP_BIN="$(mktemp)"
if command -v curl &>/dev/null; then
    curl -fL --progress-bar "$DOWNLOAD_URL" -o "$TMP_BIN" \
        || fail "Download failed — check the URL: $DOWNLOAD_URL"
else
    wget -q --show-progress "$DOWNLOAD_URL" -O "$TMP_BIN" \
        || fail "Download failed — check the URL: $DOWNLOAD_URL"
fi
chmod 755 "$TMP_BIN"

# Smoke-test the binary
"$TMP_BIN" --version >/dev/null 2>&1 || fail "Downloaded binary failed --version test"
ok "Binary downloaded: runbound $("$TMP_BIN" --version)"

# ── XDP support detection ─────────────────────────────────────────────────────
XDP_SUPPORTED=false
XDP_REASON="unknown hardware"

detect_xdp_support() {
    # Check if running in a VM
    if systemd-detect-virt --quiet 2>/dev/null; then
        XDP_REASON="running in a VM ($(systemd-detect-virt 2>/dev/null)) — XDP copy mode only, disabled by default"
        return
    fi

    # Check for Intel XDP-native capable drivers on active interfaces
    for iface in /sys/class/net/*; do
        local name driver
        name=$(basename "$iface")
        [[ "$name" == "lo" ]] && continue
        driver=$(readlink "$iface/device/driver" 2>/dev/null | xargs basename 2>/dev/null || true)
        case "$driver" in
            ixgbe|ixgbevf|i40e|ice|igc|igb)
                XDP_SUPPORTED=true
                XDP_REASON="Intel NIC detected ($name, driver: $driver)"
                return
                ;;
        esac
    done

    XDP_REASON="no Intel XDP-native NIC detected (found: $(ls /sys/class/net/ | grep -v lo | tr '\n' ' '))"
}

detect_xdp_support

if $XDP_SUPPORTED; then
    ok "XDP kernel-bypass supported: $XDP_REASON"
else
    warn "XDP kernel-bypass disabled: $XDP_REASON"
    warn "XDP requires an Intel NIC (ixgbe/i40e/ice/igc) on bare metal."
    warn "Server will run normally without XDP (SO_REUSEPORT fast path still active)."
fi

# ── Create user / group ───────────────────────────────────────────────────────
if ! getent group "$RUN_GROUP" > /dev/null 2>&1; then
    groupadd --system "$RUN_GROUP"
    ok "Group '$RUN_GROUP' created"
fi
if ! getent passwd "$RUN_USER" > /dev/null 2>&1; then
    useradd --system --no-create-home --shell /sbin/nologin \
            --gid "$RUN_GROUP" "$RUN_USER"
    ok "User '$RUN_USER' created"
fi

# ── Directories ───────────────────────────────────────────────────────────────
install -d -m 0750 -o "$RUN_USER" -g "$RUN_GROUP" "$CONFIG_DIR"
install -d -m 0750 -o "$RUN_USER" -g "$RUN_GROUP" "$DATA_DIR"
ok "Directories: $CONFIG_DIR  $DATA_DIR"

# ── Install binary ────────────────────────────────────────────────────────────
install -m 0755 -o root -g root "$TMP_BIN" "$BINARY_DST"
rm -f "$TMP_BIN"
ok "Binary installed: $BINARY_DST"

# ── Default config (only if none exists) ─────────────────────────────────────
DEFAULT_CONF="$CONFIG_DIR/runbound.conf"
if [ ! -f "$DEFAULT_CONF" ]; then
    cat > "$DEFAULT_CONF" << 'CONF'
server:
    interface:  0.0.0.0
    port:       53

    do-ip4:     yes
    do-ip6:     yes
    do-udp:     yes
    do-tcp:     yes

    # ── Access control ───────────────────────────────────────────────────────
    access-control: 127.0.0.0/8      allow
    access-control: 192.168.0.0/16   allow
    access-control: 10.0.0.0/8       allow
    access-control: 0.0.0.0/0        refuse

    # ── Rate limiting ────────────────────────────────────────────────────────
    rate-limit:    200
    cache-max-ttl: 3600

    # ── DNS rebinding protection ─────────────────────────────────────────────
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 127.0.0.0/8

    # ── REST API key (prefer RUNBOUND_API_KEY env var in /etc/runbound/env) ──
    # api-key: change-me-to-a-strong-secret

    # ── TLS — DoT (853) / DoH (443) ─────────────────────────────────────────
    # runbound --gen-cert dns.example.com   to generate a self-signed cert
    # tls-service-pem: /etc/runbound/cert.pem
    # tls-service-key: /etc/runbound/key.pem

    # ── Local hostnames ──────────────────────────────────────────────────────
    # local-zone: "home.arpa." static
    # local-data: "router.home.arpa. 300 A 192.168.1.1"

forward-zone:
    name:                 "."
    forward-addr:         1.1.1.1@853
    forward-addr:         1.0.0.1@853
    forward-tls-upstream: yes
CONF
    chown "$RUN_USER:$RUN_GROUP" "$DEFAULT_CONF"
    chmod 640 "$DEFAULT_CONF"
    ok "Default config written to $DEFAULT_CONF"
else
    warn "Config already exists — not overwritten: $DEFAULT_CONF"
fi

# ── Write systemd unit ────────────────────────────────────────────────────────
UNIT_FILE="/etc/systemd/system/runbound.service"

if $XDP_SUPPORTED; then
cat > "$UNIT_FILE" << UNIT
[Unit]
Description=Runbound DNS Server ${VER_TAG}
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target
ConditionFileNotEmpty=${CONFIG_DIR}/runbound.conf

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_GROUP}
EnvironmentFile=-${CONFIG_DIR}/env
ExecStart=${BINARY_DST} ${CONFIG_DIR}/runbound.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s

AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_BPF

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_XDP
MemoryDenyWriteExecute=false
# ProtectKernelModules intentionally omitted — required for eBPF program loading
ReadWritePaths=${CONFIG_DIR} ${DATA_DIR}
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
UNIT
else
cat > "$UNIT_FILE" << UNIT
[Unit]
Description=Runbound DNS Server ${VER_TAG}
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target
ConditionFileNotEmpty=${CONFIG_DIR}/runbound.conf

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_GROUP}
EnvironmentFile=-${CONFIG_DIR}/env
ExecStart=${BINARY_DST} ${CONFIG_DIR}/runbound.conf
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s

AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryDenyWriteExecute=true
# XDP kernel-bypass is compiled in but disabled on this hardware.
# To enable on Intel bare metal NICs (ixgbe/i40e/ice), see:
# https://github.com/redlemonbe/Runbound/blob/main/docs/xdp.md
ReadWritePaths=${CONFIG_DIR} ${DATA_DIR}
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
UNIT
fi

chmod 644 "$UNIT_FILE"
ok "Systemd unit installed: $UNIT_FILE"

# ── API key env file ──────────────────────────────────────────────────────────
ENV_FILE="$CONFIG_DIR/env"
if [ ! -f "$ENV_FILE" ]; then
    echo "RUNBOUND_API_KEY=$(openssl rand -hex 32)" > "$ENV_FILE"
    chown "$RUN_USER:$RUN_GROUP" "$ENV_FILE"
    chmod 640 "$ENV_FILE"
    ok "API key generated: $ENV_FILE (chmod 640)"
else
    warn "API key file already exists — not overwritten: $ENV_FILE"
fi

# ── Enable and start ──────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable --now runbound

sleep 2
if systemctl is-active --quiet runbound; then
    ok "Runbound is running"
    API_KEY="$(grep RUNBOUND_API_KEY "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo '(see env file)')"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " Version:  runbound $("$BINARY_DST" --version)"
    echo " API key:  ${API_KEY}"
    echo " Config:   $DEFAULT_CONF"
    echo " Logs:     journalctl -u runbound -f"
    echo " Reload:   systemctl reload runbound"
    if $XDP_SUPPORTED; then
    echo " XDP:      kernel-bypass active ($(ip route 2>/dev/null | awk '/default/{print $5; exit}'))"
    else
    echo " XDP:      disabled (requires Intel bare metal NIC — see docs/xdp.md)"
    fi
    echo " Health:   curl -H 'Authorization: Bearer \$RUNBOUND_API_KEY' http://127.0.0.1:8081/health"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    fail "Runbound failed to start — check: journalctl -u runbound -n 50"
fi
