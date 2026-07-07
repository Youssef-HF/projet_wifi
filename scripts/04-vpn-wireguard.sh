#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — scripts/04-vpn-wireguard.sh
# WireGuard VPN Client Configuration
#
# What this script does:
#   - Generates WireGuard Ed25519 keypair for this gadget
#   - Writes /etc/wireguard/wg0.conf with server peer configuration
#   - Configures routing: all C2 traffic goes through WireGuard over 5G
#   - Enables wg-quick@wg0 systemd service (auto-start on boot)
#   - Creates auto-reconnect watchdog (detects tunnel drops)
#   - Configures DNS to use VPN gateway
#   - Outputs public key for server-side registration
#
# Architecture:
#   WauditBox RPi5 → 5G modem → Internet → WireGuard Server
#   All C2/management traffic encrypted inside WireGuard tunnel
#   Pentest traffic (WiFi audit) goes through target network directly
#
# Run on: Kali Linux ARM64 RPi5
# Run after: 03-firewall-network.sh
# Reboot required: NO — WireGuard starts immediately
#
# Author: WauditBox Team
# Version: 2.0
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# --- [ BOOTSTRAP ] -----------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "${SCRIPT_DIR}/00-config.sh" ]]; then
    echo "ERROR: 00-config.sh not found in ${SCRIPT_DIR}"
    exit 1
fi

source "${SCRIPT_DIR}/00-config.sh"
check_root

mkdir -p "${LOG_DIR}"
touch "${SCRIPT_LOG}"

# =============================================================================
# WIREGUARD-SPECIFIC VARIABLES
# =============================================================================

WG_CONFIG_FILE="/etc/wireguard/${WG_IFACE}.conf"
WG_KEYS_DIR="/etc/wireguard/keys"
WG_PRIVATE_KEY_FILE="${WG_KEYS_DIR}/private.key"
WG_PUBLIC_KEY_FILE="${WG_KEYS_DIR}/public.key"
WG_PRESHARED_KEY_FILE="${WG_KEYS_DIR}/preshared.key"

# WireGuard keep-alive interval (seconds)
# Keeps the tunnel alive through 5G NAT
WG_KEEPALIVE=25

# DNS server through VPN (WireGuard gateway)
WG_DNS="10.200.0.1"

# Reconnect watchdog settings
WG_WATCHDOG_INTERVAL=60      # Check every 60 seconds
WG_WATCHDOG_MAX_FAILS=3      # Reconnect after 3 failures
WG_PING_TARGET="10.200.0.1"  # Ping VPN gateway to check tunnel health

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================
log_section "WauditBox v2.0 — 04-vpn-wireguard.sh — START"
log_info "Timestamp: $(date '+%Y-%m-%d %H:%M:%S %Z')"

# Check WireGuard is installed
log_info "Checking WireGuard installation..."
if ! command -v wg >/dev/null 2>&1; then
    log_error "WireGuard (wg) not found. Run 01-base-os.sh first."
    exit 1
fi

if ! command -v wg-quick >/dev/null 2>&1; then
    log_error "wg-quick not found. Run 01-base-os.sh first."
    exit 1
fi

log_info "WireGuard version: $(wg --version 2>&1)"
log_info "✓ WireGuard is installed."

# Check server endpoint is configured
if [[ "${WG_SERVER_ENDPOINT}" == *"REPLACE"* ]]; then
    log_warn "WG_SERVER_ENDPOINT in 00-config.sh is still a placeholder."
    log_warn "WireGuard config will be created but tunnel will not connect"
    log_warn "until you update the server endpoint."
    log_warn "Update 00-config.sh and re-run this script when server is ready."
    SERVER_CONFIGURED=false
else
    log_info "✓ Server endpoint configured: ${WG_SERVER_ENDPOINT}"
    SERVER_CONFIGURED=true
fi

# Check server public key is configured
if [[ "${WG_SERVER_PUBKEY}" == *"REPLACE"* ]]; then
    log_warn "WG_SERVER_PUBKEY in 00-config.sh is still a placeholder."
    SERVER_KEY_CONFIGURED=false
else
    log_info "✓ Server public key configured."
    SERVER_KEY_CONFIGURED=true
fi

# =============================================================================
# STEP 1: Generate WireGuard Keypair for This Gadget
# =============================================================================
log_section "STEP 1: Generate WireGuard Keypair"

# Create keys directory with strict permissions
log_info "Creating WireGuard keys directory..."
mkdir -p "${WG_KEYS_DIR}"
chmod 700 "${WG_KEYS_DIR}"

# Generate private key (only if not already exists)
if [[ ! -f "${WG_PRIVATE_KEY_FILE}" ]]; then
    log_info "Generating Ed25519 private key..."
    wg genkey > "${WG_PRIVATE_KEY_FILE}"
    chmod 600 "${WG_PRIVATE_KEY_FILE}"
    log_info "✓ Private key generated at ${WG_PRIVATE_KEY_FILE}"
else
    log_info "Private key already exists — keeping existing key."
    log_warn "If you want to regenerate, delete ${WG_PRIVATE_KEY_FILE} first."
fi

# Derive public key from private key
log_info "Deriving public key from private key..."
wg pubkey < "${WG_PRIVATE_KEY_FILE}" > "${WG_PUBLIC_KEY_FILE}"
chmod 644 "${WG_PUBLIC_KEY_FILE}"

# Read the keys into variables
WG_GADGET_PRIVATE_KEY=$(cat "${WG_PRIVATE_KEY_FILE}")
WG_GADGET_PUBLIC_KEY=$(cat "${WG_PUBLIC_KEY_FILE}")

log_info "✓ Public key derived."
log_info "Gadget Public Key: ${WG_GADGET_PUBLIC_KEY}"

# Handle preshared key
if [[ "${WG_PRESHARED_KEY}" == *"REPLACE"* ]]; then
    # Generate a new preshared key if not provided in config
    log_info "Generating preshared key (not set in config)..."
    wg genpsk > "${WG_PRESHARED_KEY_FILE}"
    chmod 600 "${WG_PRESHARED_KEY_FILE}"
    WG_PSK=$(cat "${WG_PRESHARED_KEY_FILE}")
    log_info "✓ Preshared key generated."
    log_warn "Add this preshared key to the server config for this peer."
else
    # Use the preshared key from config
    echo "${WG_PRESHARED_KEY}" > "${WG_PRESHARED_KEY_FILE}"
    chmod 600 "${WG_PRESHARED_KEY_FILE}"
    WG_PSK="${WG_PRESHARED_KEY}"
    log_info "✓ Preshared key from config stored."
fi

# =============================================================================
# STEP 2: Write WireGuard Configuration File
# =============================================================================
log_section "STEP 2: Write WireGuard Configuration"

log_info "Writing WireGuard config to ${WG_CONFIG_FILE}..."

# Backup existing config if present
if [[ -f "${WG_CONFIG_FILE}" ]]; then
    cp "${WG_CONFIG_FILE}" "${WG_CONFIG_FILE}.wauditbox.bak"
    log_info "Backed up existing config to ${WG_CONFIG_FILE}.wauditbox.bak"
fi

cat > "${WG_CONFIG_FILE}" << WG_CONF_EOF
# =============================================================================
# WauditBox v2.0 — WireGuard Client Configuration
# Interface: ${WG_IFACE}
# Gadget IP: ${WG_CLIENT_IP}
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
# Generated by: scripts/04-vpn-wireguard.sh
#
# DO NOT SHARE THIS FILE — Contains private key
# DO NOT COMMIT THIS FILE — .gitignore protects it
# =============================================================================

[Interface]
# This gadget's WireGuard IP address in the VPN pool
Address = ${WG_CLIENT_IP}

# Private key for this gadget (keep secret)
PrivateKey = ${WG_GADGET_PRIVATE_KEY}

# DNS through VPN gateway
# When tunnel is up, all DNS goes through the server
DNS = ${WG_DNS}

# Listen port (optional for clients — 0 = random)
ListenPort = 0

# PostUp: Commands to run when tunnel comes up
PostUp = ip rule add from ${WG_CLIENT_IP%/*} table main priority 100
PostUp = ip route add ${WG_SERVER_ENDPOINT%:*} via \$(ip route show dev ${MODEM_IFACE} | grep default | awk '{print \$3}' | head -1) dev ${MODEM_IFACE} 2>/dev/null || true
PostUp = logger -t wauditbox-wg "WireGuard tunnel UP — connected to ${WG_SERVER_ENDPOINT}"
PostUp = echo "WireGuard UP: \$(date)" >> /var/log/wauditbox/wireguard.log

# PostDown: Commands to run when tunnel goes down
PostDown = ip rule del from ${WG_CLIENT_IP%/*} table main priority 100 2>/dev/null || true
PostDown = logger -t wauditbox-wg "WireGuard tunnel DOWN"
PostDown = echo "WireGuard DOWN: \$(date)" >> /var/log/wauditbox/wireguard.log

# =============================================================================
[Peer]
# Central WireGuard Server
# =============================================================================

# Server's public key
PublicKey = ${WG_SERVER_PUBKEY}

# Preshared key (additional symmetric encryption layer)
PresharedKey = ${WG_PSK}

# Server address and port
Endpoint = ${WG_SERVER_ENDPOINT}

# Route only VPN subnet through tunnel (split tunnel)
# All C2 and management traffic goes through VPN
# Target WiFi audit traffic goes directly (not through VPN)
AllowedIPs = 10.200.0.0/16

# Keep-alive: Send keepalive packet every ${WG_KEEPALIVE} seconds
# Critical for 5G connections that close idle NAT sessions
PersistentKeepalive = ${WG_KEEPALIVE}
WG_CONF_EOF

chmod 600 "${WG_CONFIG_FILE}"
log_info "✓ WireGuard config written to ${WG_CONFIG_FILE}"

# =============================================================================
# STEP 3: Configure WireGuard Routing
# =============================================================================
log_section "STEP 3: WireGuard Routing Configuration"

log_info "Configuring routing tables for WireGuard split-tunnel..."

# Create a custom routing table for WireGuard
# This ensures C2 traffic goes through VPN regardless of other routes
if ! grep -q "200 wauditbox-vpn" /etc/iproute2/rt_tables 2>/dev/null; then
    echo "200 wauditbox-vpn" >> /etc/iproute2/rt_tables
    log_info "Added routing table: 200 wauditbox-vpn"
fi

# Create routing script for VPN table
cat > /usr/local/bin/wauditbox-wg-routing << 'WG_ROUTE_EOF'
#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — WireGuard Routing Script
# Sets up policy routing for VPN traffic
# Called by WireGuard PostUp/PostDown via wg-quick
# =============================================================================
ACTION="${1:-up}"
WG_IFACE="wg0"
VPN_SUBNET="10.200.0.0/16"
ROUTE_TABLE="200"

case "${ACTION}" in
    up)
        # Add route to VPN subnet via WireGuard
        ip route add "${VPN_SUBNET}" dev "${WG_IFACE}" table "${ROUTE_TABLE}" 2>/dev/null || true
        # Add policy rule: traffic to VPN subnet uses WG table
        ip rule add to "${VPN_SUBNET}" lookup "${ROUTE_TABLE}" priority 50 2>/dev/null || true
        logger -t wauditbox-wg "VPN routing table configured (up)"
        ;;
    down)
        # Clean up routing rules
        ip rule del to "${VPN_SUBNET}" lookup "${ROUTE_TABLE}" priority 50 2>/dev/null || true
        ip route del "${VPN_SUBNET}" dev "${WG_IFACE}" table "${ROUTE_TABLE}" 2>/dev/null || true
        logger -t wauditbox-wg "VPN routing table cleaned up (down)"
        ;;
esac
WG_ROUTE_EOF

chmod +x /usr/local/bin/wauditbox-wg-routing
log_info "✓ WireGuard routing script created."

# =============================================================================
# STEP 4: Enable WireGuard systemd Service
# =============================================================================
log_section "STEP 4: Enable WireGuard systemd Service"

log_info "Enabling wg-quick@${WG_IFACE} systemd service..."
systemctl enable "wg-quick@${WG_IFACE}" 2>&1 | tee -a "${SCRIPT_LOG}"

# Start WireGuard if server is configured
if [[ "${SERVER_CONFIGURED}" == "true" ]] && \
   [[ "${SERVER_KEY_CONFIGURED}" == "true" ]]; then

    log_info "Starting WireGuard tunnel..."

    # Stop existing tunnel if running
    systemctl stop "wg-quick@${WG_IFACE}" 2>/dev/null || true
    wg-quick down "${WG_IFACE}" 2>/dev/null || true
    sleep 2

    # Start tunnel
    if wg-quick up "${WG_IFACE}" 2>&1 | tee -a "${SCRIPT_LOG}"; then
        log_info "✓ WireGuard tunnel started successfully."

        # Wait for tunnel to establish
        sleep 3

        # Test tunnel connectivity
        log_info "Testing VPN tunnel connectivity..."
        if ping -c 3 -W 5 -I "${WG_IFACE}" "${WG_PING_TARGET}" >/dev/null 2>&1; then
            log_info "✓ VPN tunnel is reachable — ping to ${WG_PING_TARGET} OK"
        else
            log_warn "VPN gateway ${WG_PING_TARGET} not responding to ping."
            log_warn "Tunnel may be up but server may block ICMP."
            log_warn "Check: wg show"
        fi

        # Show tunnel status
        log_info "WireGuard tunnel status:"
        wg show "${WG_IFACE}" 2>&1 | tee -a "${SCRIPT_LOG}"

    else
        log_warn "Could not start WireGuard tunnel."
        log_warn "Server may not be reachable yet — tunnel will start on next boot."
        log_warn "Manual start: sudo wg-quick up ${WG_IFACE}"
    fi

else
    log_warn "Server endpoint or public key not configured."
    log_warn "WireGuard service is enabled but tunnel will not connect."
    log_warn "Update 00-config.sh with real server details and re-run."
    log_warn "Or manually edit: ${WG_CONFIG_FILE}"
fi

# =============================================================================
# STEP 5: WireGuard Auto-Reconnect Watchdog
# =============================================================================
log_section "STEP 5: WireGuard Auto-Reconnect Watchdog"

log_info "Creating WireGuard connectivity watchdog..."

cat > /usr/local/bin/wauditbox-wg-watchdog << WG_WATCHDOG_EOF
#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — WireGuard Watchdog
# Monitors VPN tunnel health and reconnects if tunnel drops
# Runs as systemd timer every ${WG_WATCHDOG_INTERVAL} seconds
# =============================================================================

WG_IFACE="${WG_IFACE}"
WG_PING_TARGET="${WG_PING_TARGET}"
WG_WATCHDOG_MAX_FAILS=${WG_WATCHDOG_MAX_FAILS}
LOG="/var/log/wauditbox/wg-watchdog.log"
STATE_FILE="/tmp/wauditbox-wg-fails"

mkdir -p "\$(dirname \${LOG})"

log_wg() {
    echo "\$(date '+%Y-%m-%d %H:%M:%S') \$*" >> "\${LOG}"
    logger -t wauditbox-wg-watchdog "\$*"
}

# Read current failure count
FAILS=0
if [[ -f "\${STATE_FILE}" ]]; then
    FAILS=\$(cat "\${STATE_FILE}" 2>/dev/null || echo 0)
fi

# Check 1: Is WireGuard interface up?
if ! ip link show "\${WG_IFACE}" >/dev/null 2>&1; then
    log_wg "✗ WireGuard interface \${WG_IFACE} is DOWN — attempting restart"
    FAILS=\$((FAILS + 1))
    echo "\${FAILS}" > "\${STATE_FILE}"

    if [[ \${FAILS} -ge \${WG_WATCHDOG_MAX_FAILS} ]]; then
        log_wg "Max failures reached (\${FAILS}) — forcing wg-quick restart"
        systemctl restart "wg-quick@\${WG_IFACE}" 2>&1 >> "\${LOG}" || true
        echo "0" > "\${STATE_FILE}"
    fi
    exit 1
fi

# Check 2: Is the tunnel actually passing traffic?
# Use WireGuard handshake timestamp (more reliable than ping)
LAST_HANDSHAKE=\$(wg show "\${WG_IFACE}" latest-handshakes 2>/dev/null | awk '{print \$2}' | head -1)
CURRENT_TIME=\$(date +%s)

if [[ -n "\${LAST_HANDSHAKE}" ]] && [[ "\${LAST_HANDSHAKE}" != "0" ]]; then
    TIME_DIFF=\$((CURRENT_TIME - LAST_HANDSHAKE))
    
    # If last handshake was more than 3 minutes ago, tunnel may be stale
    if [[ \${TIME_DIFF} -gt 180 ]]; then
        log_wg "⚠ Last WireGuard handshake was \${TIME_DIFF}s ago — tunnel may be stale"
        FAILS=\$((FAILS + 1))
        echo "\${FAILS}" > "\${STATE_FILE}"
    else
        log_wg "✓ WireGuard tunnel OK (last handshake: \${TIME_DIFF}s ago)"
        echo "0" > "\${STATE_FILE}"
        exit 0
    fi
fi

# Check 3: Can we ping the VPN gateway?
if ping -c 2 -W 5 -I "\${WG_IFACE}" "\${WG_PING_TARGET}" >/dev/null 2>&1; then
    log_wg "✓ VPN gateway reachable — tunnel OK"
    echo "0" > "\${STATE_FILE}"
    exit 0
fi

log_wg "✗ VPN gateway unreachable — failures: \${FAILS}/\${WG_WATCHDOG_MAX_FAILS}"
FAILS=\$((FAILS + 1))
echo "\${FAILS}" > "\${STATE_FILE}"

# Reconnect if max failures reached
if [[ \${FAILS} -ge \${WG_WATCHDOG_MAX_FAILS} ]]; then
    log_wg "=== Attempting WireGuard reconnect ==="
    
    # Try graceful restart first
    wg-quick down "\${WG_IFACE}" 2>&1 >> "\${LOG}" || true
    sleep 3
    wg-quick up "\${WG_IFACE}"   2>&1 >> "\${LOG}" || true
    sleep 5
    
    # Verify reconnect worked
    if ping -c 2 -W 5 -I "\${WG_IFACE}" "\${WG_PING_TARGET}" >/dev/null 2>&1; then
        log_wg "✓ WireGuard reconnected successfully"
        echo "0" > "\${STATE_FILE}"
    else
        log_wg "✗ Reconnect failed — trying full service restart"
        systemctl restart "wg-quick@\${WG_IFACE}" 2>&1 >> "\${LOG}" || true
        echo "0" > "\${STATE_FILE}"
    fi
fi
WG_WATCHDOG_EOF

chmod +x /usr/local/bin/wauditbox-wg-watchdog
log_info "✓ WireGuard watchdog script created."

# Create systemd service for watchdog
cat > /etc/systemd/system/wauditbox-wg-watchdog.service << WG_WD_SVC_EOF
# =============================================================================
# WauditBox v2.0 — WireGuard Watchdog Service
# =============================================================================
[Unit]
Description=WauditBox WireGuard Tunnel Watchdog
After=network.target wg-quick@${WG_IFACE}.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wauditbox-wg-watchdog
StandardOutput=journal
StandardError=journal
WG_WD_SVC_EOF

# Create systemd timer
cat > /etc/systemd/system/wauditbox-wg-watchdog.timer << WG_WD_TIMER_EOF
# =============================================================================
# WauditBox v2.0 — WireGuard Watchdog Timer
# Checks VPN tunnel health every 60 seconds
# =============================================================================
[Unit]
Description=WauditBox WireGuard Watchdog Timer
After=network.target

[Timer]
OnBootSec=90sec
OnUnitActiveSec=${WG_WATCHDOG_INTERVAL}sec
AccuracySec=10s
Persistent=true

[Install]
WantedBy=timers.target
WG_WD_TIMER_EOF

systemctl daemon-reload
systemctl enable wauditbox-wg-watchdog.timer 2>&1 | tee -a "${SCRIPT_LOG}"
systemctl start  wauditbox-wg-watchdog.timer 2>&1 | tee -a "${SCRIPT_LOG}"
log_info "✓ WireGuard watchdog timer enabled (runs every ${WG_WATCHDOG_INTERVAL}s)."

# =============================================================================
# STEP 6: UFW — Update Rules for WireGuard
# =============================================================================
log_section "STEP 6: Update UFW for WireGuard Interface"

log_info "Updating UFW rules for WireGuard interface..."

# Ensure WireGuard interface is allowed in UFW
ufw allow in  on "${WG_IFACE}" 2>&1 | tee -a "${SCRIPT_LOG}" || true
ufw allow out on "${WG_IFACE}" 2>&1 | tee -a "${SCRIPT_LOG}" || true

# Allow traffic from VPN subnet (operator connections)
ufw allow from 10.200.0.0/16 2>&1 | tee -a "${SCRIPT_LOG}" || true

ufw --force reload 2>&1 | tee -a "${SCRIPT_LOG}"
log_info "✓ UFW rules updated for WireGuard."

# =============================================================================
# STEP 7: Create Server Registration Info File
# =============================================================================
log_section "STEP 7: Server Registration Information"

log_info "Creating server registration info file..."

# This file contains what the server admin needs to add a peer
REGISTRATION_FILE="${WAUDITBOX_BASE_DIR}/configs/server-registration.txt"

cat > "${REGISTRATION_FILE}" << REG_EOF
# =============================================================================
# WauditBox v2.0 — Server Registration Info
# Generated: $(date '+%Y-%m-%d %H:%M:%S')
#
# SEND THIS TO YOUR SERVER ADMINISTRATOR
# Add this block to the WireGuard server config
# =============================================================================

[Peer]
# WauditBox Gadget — $(hostname)
PublicKey    = ${WG_GADGET_PUBLIC_KEY}
PresharedKey = ${WG_PSK}
AllowedIPs   = ${WG_CLIENT_IP%/*}/32

# =============================================================================
# Server-side command to add this peer:
#
# wg set wg0 \
#   peer ${WG_GADGET_PUBLIC_KEY} \
#   preshared-key <(echo "${WG_PSK}") \
#   allowed-ips ${WG_CLIENT_IP%/*}/32
#
# Then save: wg-quick save wg0
# =============================================================================
REG_EOF

chmod 600 "${REGISTRATION_FILE}"
log_info "✓ Server registration info saved to: ${REGISTRATION_FILE}"

# =============================================================================
# STEP 8: Final Verification
# =============================================================================
log_section "STEP 8: Final Verification"

log_info "WireGuard interface status:"
if ip link show "${WG_IFACE}" >/dev/null 2>&1; then
    ip addr show "${WG_IFACE}" 2>&1 | tee -a "${SCRIPT_LOG}"
    wg show "${WG_IFACE}"      2>&1 | tee -a "${SCRIPT_LOG}"
else
    log_warn "WireGuard interface ${WG_IFACE} is not up yet."
    log_warn "Start manually: sudo wg-quick up ${WG_IFACE}"
fi

log_info "WireGuard service status:"
systemctl is-enabled "wg-quick@${WG_IFACE}" 2>&1 | tee -a "${SCRIPT_LOG}"

log_info "Watchdog timer status:"
systemctl is-active wauditbox-wg-watchdog.timer 2>&1 | tee -a "${SCRIPT_LOG}"

log_info "Routing table:"
ip route show 2>&1 | tee -a "${SCRIPT_LOG}"

# =============================================================================
# SUMMARY
# =============================================================================
cat << SUMMARY_EOF | tee -a "${SCRIPT_LOG}"

╔══════════════════════════════════════════════════════════════════════╗
║          WauditBox v2.0 — WireGuard VPN Setup Complete              ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  KEYS GENERATED:                                                     ║
║  Private key : ${WG_KEYS_DIR}/private.key (SECRET - never share)    ║
║  Public key  : ${WG_GADGET_PUBLIC_KEY:0:44}                         ║
║  PSK file    : ${WG_KEYS_DIR}/preshared.key                         ║
║                                                                      ║
║  CONFIGURATION:                                                      ║
║  ✓  Config file: ${WG_CONFIG_FILE}                                   ║
║  ✓  Interface : ${WG_IFACE} — IP: ${WG_CLIENT_IP}                   ║
║  ✓  Server    : ${WG_SERVER_ENDPOINT}                                ║
║  ✓  AllowedIPs: 10.200.0.0/16 (split tunnel)                        ║
║  ✓  Keepalive : ${WG_KEEPALIVE}s (5G NAT persistence)               ║
║                                                                      ║
║  SERVICES:                                                           ║
║  ✓  wg-quick@${WG_IFACE} enabled (auto-start on boot)               ║
║  ✓  Watchdog timer: checks tunnel every ${WG_WATCHDOG_INTERVAL}s    ║
║                                                                      ║
║  SERVER REGISTRATION:                                                ║
║  ✓  Peer config saved to:                                            ║
║     ${WAUDITBOX_BASE_DIR}/configs/server-registration.txt           ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  ACTION REQUIRED — Register gadget on server:                       ║
║                                                                      ║
║  1. Copy server-registration.txt to your server                     ║
║  2. Add the [Peer] block to /etc/wireguard/wg0.conf on server       ║
║  3. Run: wg-quick save wg0 on server                                ║
║  4. Test: ping 10.200.1.1 from server                               ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  USEFUL COMMANDS:                                                    ║
║                                                                      ║
║  Check tunnel: sudo wg show                                          ║
║  Start tunnel: sudo wg-quick up wg0                                 ║
║  Stop tunnel : sudo wg-quick down wg0                               ║
║  View logs   : journalctl -u wg-quick@wg0 -f                        ║
║  View WD log : tail -f /var/log/wauditbox/wg-watchdog.log           ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  NEXT STEP: Run 05-killswitch.sh                                    ║
╚══════════════════════════════════════════════════════════════════════╝

SUMMARY_EOF

log_info "Full log: ${SCRIPT_LOG}"
log_info "04-vpn-wireguard.sh COMPLETE — No reboot required."

# =============================================================================
# END OF SCRIPT
# =============================================================================
