#!/usr/bin/env bash
# Runbound installer for Debian / Ubuntu
# Usage: sudo ./install.sh [--uninstall]
set -euo pipefail

BINARY_SRC="./target/release/runbound"
BINARY_DST="/usr/local/sbin/runbound"
SERVICE_SRC="./runbound.service"
SERVICE_DST="/etc/systemd/system/runbound.service"
CONFIG_DIR="/etc/runbound"
DATA_DIR="/var/lib/runbound"
RUN_USER="runbound"
RUN_GROUP="runbound"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# ── Root check ────────────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || fail "Run as root: sudo ./install.sh"

# ── Uninstall ─────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--uninstall" ]]; then
    echo "Uninstalling Runbound…"
    systemctl stop runbound  2>/dev/null || true
    systemctl disable runbound 2>/dev/null || true
    rm -f "$SERVICE_DST" "$BINARY_DST"
    systemctl daemon-reload
    ok "Runbound uninstalled. Config in $CONFIG_DIR and $DATA_DIR were kept."
    exit 0
fi

# ── Pre-flight ────────────────────────────────────────────────────────────────
echo "Installing Runbound $(${BINARY_SRC} --version 2>/dev/null || echo '(version unknown)')…"

[ -f "$BINARY_SRC" ] || fail "Binary not found: $BINARY_SRC — run 'cargo build --release' first"
[ -f "$SERVICE_SRC" ] || fail "Service file not found: $SERVICE_SRC"

# Check for conflicting DNS services
for svc in unbound bind9 systemd-resolved dnsmasq; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        warn "$svc is running — it may conflict on port 53. Stop it with: systemctl stop $svc"
    fi
done

# ── Create user / group ───────────────────────────────────────────────────────
if ! getent group "$RUN_GROUP" > /dev/null 2>&1; then
    groupadd --system "$RUN_GROUP"
    ok "Group '$RUN_GROUP' created"
fi

if ! getent passwd "$RUN_USER" > /dev/null 2>&1; then
    useradd --system --no-create-home --shell /sbin/nologin \
            --gid "$RUN_GROUP" "$RUN_USER"
    ok "User '$RUN_USER' created (no login shell, no home)"
fi

# ── Directories ───────────────────────────────────────────────────────────────
install -d -m 0750 -o "$RUN_USER" -g "$RUN_GROUP" "$CONFIG_DIR"
install -d -m 0750 -o "$RUN_USER" -g "$RUN_GROUP" "$DATA_DIR"
ok "Directories created: $CONFIG_DIR  $DATA_DIR"

# ── Default config (only if none exists) ─────────────────────────────────────
DEFAULT_CONF="$CONFIG_DIR/unbound.conf"
if [ ! -f "$DEFAULT_CONF" ]; then
    cat > "$DEFAULT_CONF" << 'CONF'
server:
    port: 53
    interface: 0.0.0.0
    do-ip4: yes
    do-ip6: yes

    # ── Rate limiting ────────────────────────────────────────────────────────
    # Maximum DNS queries per second per source IP (token bucket, burst = 2× RPS).
    # 200  — residential / home network (default)
    # 5000 — enterprise / shared resolver (NAT with many users behind one IP)
    rate-limit: 200

    # ── REST API key ─────────────────────────────────────────────────────────
    # Set a fixed key so it persists across restarts.
    # Overridden by RUNBOUND_API_KEY environment variable if both are set.
    # Leave commented to auto-generate a 256-bit random key on first start.
    # api-key: change-me-to-a-strong-secret

    # ── TLS — DoT (853) / DoH (443) / DoQ (853 UDP) ─────────────────────────
    # Generate a certificate with:  runbound --gen-cert dns.example.com
    # For production use Let's Encrypt: certbot certonly --standalone -d dns.example.com
    # tls-service-pem: /etc/runbound/cert.pem
    # tls-service-key: /etc/runbound/key.pem
    # tls-cert-hostname: dns.example.com

    # ── Local zones — add your private DNS entries here ───────────────────────
    # local-zone: "home.arpa." static
    # local-data: "router.home.arpa. 300 A 192.168.1.1"

forward-zone:
    name: "."
    forward-addr: 1.1.1.1@53
    forward-addr: 1.0.0.1@53
    forward-addr: 8.8.8.8@53
    forward-addr: 8.8.4.4@53
CONF
    chown "$RUN_USER:$RUN_GROUP" "$DEFAULT_CONF"
    chmod 640 "$DEFAULT_CONF"
    ok "Default config written to $DEFAULT_CONF"
else
    warn "Config already exists — skipping: $DEFAULT_CONF"
fi

# ── Install binary ────────────────────────────────────────────────────────────
install -m 0755 -o root -g root "$BINARY_SRC" "$BINARY_DST"
ok "Binary installed: $BINARY_DST"

# ── Install service ───────────────────────────────────────────────────────────
install -m 0644 -o root -g root "$SERVICE_SRC" "$SERVICE_DST"
ok "Service file installed: $SERVICE_DST"

systemctl daemon-reload
ok "systemd daemon reloaded"

# ── Enable and start ──────────────────────────────────────────────────────────
systemctl enable runbound
ok "Runbound enabled (starts at boot)"

systemctl restart runbound
sleep 2

if systemctl is-active --quiet runbound; then
    ok "Runbound is running"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo " API key:  $(cat $CONFIG_DIR/api.key 2>/dev/null || echo 'see journalctl -u runbound')"
    echo " Usage:    curl -H 'Authorization: Bearer <key>' http://127.0.0.1:8081/dns"
    echo " Logs:     journalctl -u runbound -f"
    echo " Config:   $DEFAULT_CONF"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
else
    fail "Runbound failed to start — check: journalctl -u runbound -n 50"
fi
