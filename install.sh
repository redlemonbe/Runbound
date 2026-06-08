#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2024-2026 RedLemonBe — https://github.com/redlemonbe/Runbound
set -euo pipefail

REPO="redlemonbe/Runbound"
BINARY_DST="/usr/local/sbin/runbound"
CONFIG_DIR="/etc/runbound"
DATA_DIR="/var/lib/runbound"
RUN_USER="runbound"
RUN_GROUP="runbound"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "Run as root: sudo bash install.sh"

if [[ "${1:-}" == "--uninstall" ]]; then
    systemctl stop runbound    2>/dev/null || true
    systemctl disable runbound 2>/dev/null || true
    rm -f /etc/systemd/system/runbound.service "$BINARY_DST"
    systemctl daemon-reload
    ok "Runbound uninstalled. Config in $CONFIG_DIR and $DATA_DIR were kept."
    exit 0
fi

# ── Architecture ──────────────────────────────────────────────────────────────
case "$(uname -m)" in
    x86_64)        ARCH_TAG="x86_64" ;;
    aarch64|arm64) ARCH_TAG="aarch64" ;;
    *) fail "Unsupported architecture: $(uname -m)" ;;
esac

# ── Latest version ────────────────────────────────────────────────────────────
if command -v curl &>/dev/null; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
else
    VERSION=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
fi
[ -n "$VERSION" ] || fail "Could not determine latest release version"

ASSET="runbound-${ARCH_TAG}-linux-musl"
DIRECT_URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"
echo "Installing Runbound ${VERSION} (${ARCH_TAG})…"

# ── Conflicting services on :53 — hard stop with guidance ─────────────────────
_conflict=""
for svc in unbound bind9 named systemd-resolved dnsmasq; do
    systemctl is-active --quiet "$svc" 2>/dev/null && _conflict="$_conflict $svc"
done
if [ -n "$_conflict" ]; then
    echo "" >&2
    fail "Port 53 is already held by another DNS service:${_conflict}
       Runbound needs port 53. Disable the current resolver, then re-run this installer:
$(for s in $_conflict; do echo "         sudo systemctl disable --now $s"; done)
       If you disable systemd-resolved, point /etc/resolv.conf at a real nameserver:
         echo 'nameserver 1.1.1.1' | sudo tee /etc/resolv.conf"
fi

# ── Download (with API fallback if direct URL fails) ─────────────────────────
TMP_BIN="$(mktemp)"
_download_ok=0

# Attempt 1 — direct browser_download_url
if command -v curl &>/dev/null; then
    curl -fL --progress-bar "$DIRECT_URL" -o "$TMP_BIN" 2>/dev/null && _download_ok=1
else
    wget -q --show-progress "$DIRECT_URL" -O "$TMP_BIN" 2>/dev/null && _download_ok=1
fi

# Attempt 2 — GitHub API asset download (fallback for CI publishing bugs)
if [ "$_download_ok" -eq 0 ]; then
    warn "Direct download failed — trying GitHub API fallback…"
    ASSET_ID=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/tags/${VERSION}" \
        | grep -B1 "\"name\": \"${ASSET}\"" | grep '"id"' | grep -o '[0-9]*' | head -1)
    if [ -n "$ASSET_ID" ]; then
        API_URL="https://api.github.com/repos/${REPO}/releases/assets/${ASSET_ID}"
        if command -v curl &>/dev/null; then
            curl -fL --progress-bar \
                -H "Accept: application/octet-stream" \
                "$API_URL" -o "$TMP_BIN" 2>/dev/null && _download_ok=1
        else
            wget -q --show-progress \
                --header="Accept: application/octet-stream" \
                "$API_URL" -O "$TMP_BIN" 2>/dev/null && _download_ok=1
        fi
    fi
fi

[ "$_download_ok" -eq 1 ] || fail "Download failed: $DIRECT_URL"

# ── Integrity: SHA256 (enforced when tools present) + minisign authenticity ───
MINISIGN_PUBKEY="RWT4uccC0fq9zgcaMtMsdH90azvmKpsNI1xlZrzlBuGH7xx1nDftTFJr"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
TMP_SUMS="$(mktemp)"; TMP_SIG="$(mktemp)"
_fetch() {  # $1 url  $2 dest
    if command -v curl &>/dev/null; then curl -fsSL "$1" -o "$2" 2>/dev/null
    else wget -qO "$2" "$1" 2>/dev/null; fi
}
_fetch "${BASE_URL}/SHA256SUMS" "$TMP_SUMS" || true

if command -v minisign >/dev/null 2>&1; then
    if _fetch "${BASE_URL}/SHA256SUMS.minisig" "$TMP_SIG" && [ -s "$TMP_SIG" ]; then
        minisign -Vm "$TMP_SUMS" -x "$TMP_SIG" -P "$MINISIGN_PUBKEY" >/dev/null 2>&1 \
            || { rm -f "$TMP_SUMS" "$TMP_SIG" "$TMP_BIN"; fail "minisign signature check FAILED for SHA256SUMS — aborting (possible tampering)"; }
        ok "Signature verified (minisign)"
    else
        warn "SHA256SUMS.minisig unavailable — skipping signature check"
    fi
else
    warn "minisign not installed — skipping signature authenticity (sha256 still enforced)"
fi

if command -v sha256sum >/dev/null 2>&1 && [ -s "$TMP_SUMS" ]; then
    EXPECTED="$(grep -E "[ *]${ASSET}\$" "$TMP_SUMS" | awk "{print \$1}" | head -1)"
    [ -n "$EXPECTED" ] || { rm -f "$TMP_SUMS" "$TMP_SIG" "$TMP_BIN"; fail "No SHA256 entry for ${ASSET} in SHA256SUMS"; }
    ACTUAL="$(sha256sum "$TMP_BIN" | awk "{print \$1}")"
    [ "$EXPECTED" = "$ACTUAL" ] || { rm -f "$TMP_SUMS" "$TMP_SIG" "$TMP_BIN"; fail "SHA256 mismatch for ${ASSET}: expected ${EXPECTED}, got ${ACTUAL}"; }
    ok "SHA256 verified"
else
    warn "sha256sum or SHA256SUMS unavailable — binary integrity NOT verified"
fi
rm -f "$TMP_SUMS" "$TMP_SIG"

chmod 755 "$TMP_BIN"
"$TMP_BIN" --version >/dev/null 2>&1 || fail "Binary failed --version check"
ok "Downloaded: $("$TMP_BIN" --version)"

# ── User / group / dirs ───────────────────────────────────────────────────────
getent group  "$RUN_GROUP" >/dev/null 2>&1 || groupadd --system "$RUN_GROUP"
getent passwd "$RUN_USER"  >/dev/null 2>&1 \
    || useradd --system --no-create-home --shell /sbin/nologin --gid "$RUN_GROUP" "$RUN_USER"
install -d -m 0750 -o "$RUN_USER" -g "$RUN_GROUP" "$CONFIG_DIR" "$DATA_DIR"

# ── Install binary ────────────────────────────────────────────────────────────
install -m 0755 -o root -g root "$TMP_BIN" "$BINARY_DST"
rm -f "$TMP_BIN"
ok "Binary installed: $BINARY_DST"

# ── Default config ────────────────────────────────────────────────────────────
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

    access-control: 127.0.0.0/8      allow
    access-control: 192.168.0.0/16   allow
    access-control: 10.0.0.0/8       allow
    access-control: 0.0.0.0/0        refuse

    rate-limit:    200
    cache-max-ttl: 3600

    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 127.0.0.0/8

    # api-key: change-me-to-a-strong-secret
    # tls-service-pem: /etc/runbound/cert.pem
    # tls-service-key: /etc/runbound/key.pem

forward-zone:
    name:                 "."
    forward-addr:         1.1.1.1@853
    forward-addr:         1.0.0.1@853
    forward-tls-upstream: yes
CONF
    chown "$RUN_USER:$RUN_GROUP" "$DEFAULT_CONF"
    chmod 640 "$DEFAULT_CONF"
    ok "Config written: $DEFAULT_CONF"
else
    warn "Config already exists — not overwritten: $DEFAULT_CONF"
fi

# ── API key ───────────────────────────────────────────────────────────────────
ENV_FILE="$CONFIG_DIR/env"
gen_api_key() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    elif [ -r /dev/urandom ]; then
        head -c 32 /dev/urandom | od -An -tx1 | tr -d " \n"
    fi
}
if [ ! -f "$ENV_FILE" ]; then
    API_KEY_GEN="$(gen_api_key)"
    [ ${#API_KEY_GEN} -ge 32 ] || fail "Could not generate API key (need openssl or a readable /dev/urandom)"
    echo "RUNBOUND_API_KEY=${API_KEY_GEN}" > "$ENV_FILE"
    chown "$RUN_USER:$RUN_GROUP" "$ENV_FILE"
    chmod 640 "$ENV_FILE"
    ok "API key generated: $ENV_FILE"
else
    warn "API key already exists — not overwritten: $ENV_FILE"
fi

# ── Systemd unit ──────────────────────────────────────────────────────────────
cat > /etc/systemd/system/runbound.service << UNIT
[Unit]
Description=Runbound DNS Server ${VERSION}
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
ReadWritePaths=${CONFIG_DIR} ${DATA_DIR}
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
UNIT
chmod 644 /etc/systemd/system/runbound.service
ok "Systemd unit installed"

# ── Start ─────────────────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable runbound 2>/dev/null || true
systemctl restart runbound || true
sleep 2

systemctl is-active --quiet runbound || fail "Runbound failed to start — check: journalctl -u runbound -n 50"
ok "Runbound is running"

API_KEY="$(grep RUNBOUND_API_KEY "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo '(see env file)')"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Version:  $("$BINARY_DST" --version)"
echo " API key:  ${API_KEY}"
echo " Config:   $DEFAULT_CONF"
echo " Logs:     journalctl -u runbound -f"
echo " XDP:      journalctl -u runbound | grep XDP"
echo " Health:   curl -H 'Authorization: Bearer \$RUNBOUND_API_KEY' http://127.0.0.1:8080/health"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
