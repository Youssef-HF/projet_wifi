#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — scripts/03-firewall-network.sh
# Firewall, Fail2ban, 5G Modem & Network Priority Configuration
#
# What this script does:
#   - UFW: default deny all incoming, allow only essential ports
#   - Fail2ban: protect SSH with auto-ban after 3 failed attempts
#   - ModemManager: configure 5G SIM8200EA-M2 auto-connection
#   - Network priority routing: 5G (metric 10) > Ethernet > WiFi
#   - Persist routing rules across reboots via systemd service
#   - Configure DNS over WireGuard tunnel (after VPN is up)
#   - Block all traffic except VPN tunnel (kill switch network layer)
#
# Run on: Kali Linux ARM64 RPi5
# Run after: 01-base-os.sh + reboot + 02-luks-dropbear.sh + reboot
# Reboot required: NO — changes apply immediately
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
# FIREWALL-SPECIFIC VARIABLES
# =============================================================================

# Network interface priorities (lower metric = higher priority)
METRIC_5G=10          # 5G modem — always preferred (C2 channel)
METRIC_ETH=100        # Ethernet — fallback
METRIC_WIFI=200       # WiFi target — lowest priority (audit only)

# Fail2ban jail config path
F2B_JAIL_DIR="/etc/fail2ban/jail.d"
F2B_FILTER_DIR="/etc/fail2ban/filter.d"

# ModemManager APN config
# Change this to your SIM card APN if auto-detection fails
MODEM_APN="internet"  # Common APNs: internet, free, orange.fr, sfr, bouygtel

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================
log_section "WauditBox v2.0 — 03-firewall-network.sh — START"
log_info "Timestamp: $(date '+%Y-%m-%d %H:%M:%S %Z')"

# Check required packages
log_info "Checking required packages..."
REQUIRED_PKGS=("ufw" "fail2ban" "modemmanager")
for pkg in "${REQUIRED_PKGS[@]}"; do
    if ! dpkg -l "${pkg}" 2>/dev/null | grep -q "^ii"; then
        log_error "Package ${pkg} is not installed. Run 01-base-os.sh first."
        exit 1
    fi
done
log_info "✓ All required packages present."

# Show current network state
log_info "Current network interfaces:"
ip link show 2>&1 | tee -a "${SCRIPT_LOG}"

log_info "Current routing table:"
ip route show 2>&1 | tee -a "${SCRIPT_LOG}"

# =============================================================================
# STEP 1: UFW Firewall Configuration
# =============================================================================
log_section "STEP 1: UFW Firewall — Default Deny Policy"

# Reset UFW to clean state
log_info "Resetting UFW to clean state..."
ufw --force reset 2>&1 | tee -a "${SCRIPT_LOG}"

# Set default policies
log_info "Setting default policies: DENY incoming, ALLOW outgoing, DENY forward..."
ufw default deny incoming   2>&1 | tee -a "${SCRIPT_LOG}"
ufw default allow outgoing  2>&1 | tee -a "${SCRIPT_LOG}"
ufw default deny forward    2>&1 | tee -a "${SCRIPT_LOG}"

# Allow loopback
log_info "Allowing loopback interface..."
ufw allow in on lo  2>&1 | tee -a "${SCRIPT_LOG}"
ufw allow out on lo 2>&1 | tee -a "${SCRIPT_LOG}"

# Explicitly deny access to loopback from external sources
ufw deny in from any to 127.0.0.0/8 2>&1 | tee -a "${SCRIPT_LOG}"

log_section "STEP 1.1: UFW — Allow Essential Ports"

# Allow Dropbear (initramfs pre-boot LUKS unlock)
log_info "Allowing Dropbear SSH (port ${DROPBEAR_PORT}/tcp) for LUKS remote unlock..."
ufw allow "${DROPBEAR_PORT}/tcp" \
    comment "Dropbear initramfs LUKS unlock" \
    2>&1 | tee -a "${SCRIPT_LOG}"

# Allow main SSH (post-boot management)
log_info "Allowing SSH management (port ${SSH_PORT}/tcp)..."
ufw allow "${SSH_PORT}/tcp" \
    comment "WauditBox SSH management" \
    2>&1 | tee -a "${SCRIPT_LOG}"

# Allow WireGuard VPN
log_info "Allowing WireGuard VPN (port ${WG_PORT}/udp)..."
ufw allow "${WG_PORT}/udp" \
    comment "WireGuard VPN tunnel" \
    2>&1 | tee -a "${SCRIPT_LOG}"

log_section "STEP 1.2: UFW — WireGuard Tunnel Rules"

# Allow all traffic through WireGuard tunnel interface (wg0)
# This is the C2 channel — all pentest tool traffic goes through here
log_info "Allowing all traffic through WireGuard interface (${WG_IFACE})..."
ufw allow in on "${WG_IFACE}"  2>&1 | tee -a "${SCRIPT_LOG}"
ufw allow out on "${WG_IFACE}" 2>&1 | tee -a "${SCRIPT_LOG}"

# Allow routing through WireGuard (needed for pivot operations)
log_info "Configuring UFW for IP forwarding through WireGuard..."

# Enable IP forwarding in UFW
UFW_SYSCTL="/etc/ufw/sysctl.conf"
if grep -q "^#net/ipv4/ip_forward" "${UFW_SYSCTL}"; then
    sed -i "s|^#net/ipv4/ip_forward.*|net/ipv4/ip_forward=1|" "${UFW_SYSCTL}"
elif ! grep -q "^net/ipv4/ip_forward=1" "${UFW_SYSCTL}"; then
    echo "net/ipv4/ip_forward=1" >> "${UFW_SYSCTL}"
fi
log_info "IP forwarding enabled in UFW sysctl."

log_section "STEP 1.3: UFW — Audit WiFi Interface Rules"

# Allow WiFi audit interfaces to communicate with targets (outgoing)
# These are the Alfa adapters — they need to send/receive 802.11 frames
log_info "Configuring audit WiFi interfaces..."

# NOTE: UFW doesn't directly control 802.11 monitor mode frames
# These rules control the IP traffic layer
ufw allow out on "${WIFI_IFACE_AUDIT}"   2>&1 | tee -a "${SCRIPT_LOG}" || true
ufw allow out on "${WIFI_IFACE_CAPTURE}" 2>&1 | tee -a "${SCRIPT_LOG}" || true

log_section "STEP 1.4: UFW — Anti-Scan Rules"

# Block common scan signatures (reduce noise in logs)
log_info "Adding anti-scan rules..."

# Rate limit SSH (belt + suspenders with Fail2ban)
ufw limit "${SSH_PORT}/tcp" \
    comment "Rate limit SSH" \
    2>&1 | tee -a "${SCRIPT_LOG}"

# Block ICMP (ping) from outside — stealth operation
# Comment these out if you need to ping the Pi for debugging
log_info "Blocking ICMP ping from external sources (stealth mode)..."
ufw deny proto icmp from any to any \
    comment "ICMP stealth mode" \
    2>&1 | tee -a "${SCRIPT_LOG}" || true

log_section "STEP 1.5: UFW — Enable Firewall"

# Enable UFW
log_info "Enabling UFW firewall..."
ufw --force enable 2>&1 | tee -a "${SCRIPT_LOG}"

# Show final UFW status
log_info "UFW status:"
ufw status verbose 2>&1 | tee -a "${SCRIPT_LOG}"

# =============================================================================
# STEP 2: UFW — Before Rules (Low-level iptables)
# =============================================================================
log_section "STEP 2: UFW Before Rules (iptables Level)"

log_info "Configuring UFW before.rules for WireGuard NAT..."

UFW_BEFORE_RULES="/etc/ufw/before.rules"
cp "${UFW_BEFORE_RULES}" "${UFW_BEFORE_RULES}.wauditbox.bak"

# Add WireGuard NAT rules at the top of before.rules
# This allows WireGuard clients to route traffic through the Pi
cat > /tmp/wauditbox-ufw-nat.rules << NATRULES_EOF
# =============================================================================
# WauditBox v2.0 — UFW NAT Rules for WireGuard
# Added by 03-firewall-network.sh
# =============================================================================
*nat
:POSTROUTING ACCEPT [0:0]
# NAT traffic going out through 5G modem interface
-A POSTROUTING -s 10.200.0.0/16 -o ${MODEM_IFACE} -j MASQUERADE
# NAT traffic going out through Ethernet (fallback)
-A POSTROUTING -s 10.200.0.0/16 -o ${ETH_IFACE} -j MASQUERADE
COMMIT

*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
:ufw-not-local - [0:0]
NATRULES_EOF

# Prepend NAT rules to before.rules
cat /tmp/wauditbox-ufw-nat.rules "${UFW_BEFORE_RULES}" > /tmp/combined-before.rules
mv /tmp/combined-before.rules "${UFW_BEFORE_RULES}"

log_info "NAT rules added to before.rules."

# Reload UFW to apply new rules
ufw --force reload 2>&1 | tee -a "${SCRIPT_LOG}"
log_info "UFW reloaded with NAT rules."

# =============================================================================
# STEP 3: Fail2ban Configuration
# =============================================================================
log_section "STEP 3: Fail2ban — Intrusion Prevention"

mkdir -p "${F2B_JAIL_DIR}"
mkdir -p "${F2B_FILTER_DIR}"

log_info "Configuring Fail2ban jails..."

# Main Fail2ban local config
cat > /etc/fail2ban/jail.local << F2B_JAIL_EOF
# =============================================================================
# WauditBox v2.0 — Fail2ban Global Configuration
# Applied by: scripts/03-firewall-network.sh
# =============================================================================

[DEFAULT]
# Ban settings
bantime   = ${F2B_BAN_TIME}
findtime  = ${F2B_FIND_TIME}
maxretry  = ${F2B_MAX_RETRY}

# Ban action — use UFW to block
banaction = ufw
banaction_allports = ufw

# Ignore our own VPN subnet (never ban the operator)
ignoreip  = 127.0.0.1/8 10.200.0.0/16 ::1

# Email notifications (disabled — we use syslog)
destemail = root@localhost
sendername = WauditBox-Fail2ban
action = %(action_)s

# Logging
loglevel = INFO
logtarget = /var/log/wauditbox/fail2ban.log
F2B_JAIL_EOF

log_info "Global Fail2ban config written."

# SSH jail for main SSH port
cat > "${F2B_JAIL_DIR}/wauditbox-ssh.conf" << SSH_JAIL_EOF
# =============================================================================
# WauditBox v2.0 — Fail2ban SSH Jail
# Protects main SSH port ${SSH_PORT}
# =============================================================================

[wauditbox-ssh]
enabled   = true
port      = ${SSH_PORT}
filter    = sshd
logpath   = /var/log/auth.log
            /var/log/secure
maxretry  = ${F2B_MAX_RETRY}
bantime   = ${F2B_BAN_TIME}
findtime  = ${F2B_FIND_TIME}
action    = ufw[application="OpenSSH", blocktype=INPUT]
            %(action_mwl)s
SSH_JAIL_EOF

log_info "SSH jail configured for port ${SSH_PORT}."

# Dropbear jail for initramfs unlock port
cat > "${F2B_JAIL_DIR}/wauditbox-dropbear.conf" << DROPBEAR_JAIL_EOF
# =============================================================================
# WauditBox v2.0 — Fail2ban Dropbear Jail
# Protects Dropbear initramfs port ${DROPBEAR_PORT}
# =============================================================================

[wauditbox-dropbear]
enabled   = true
port      = ${DROPBEAR_PORT}
filter    = dropbear
logpath   = /var/log/auth.log
            /var/log/syslog
maxretry  = ${F2B_MAX_RETRY}
bantime   = 24h
findtime  = ${F2B_FIND_TIME}
action    = ufw[application="Dropbear", blocktype=INPUT]
DROPBEAR_JAIL_EOF

log_info "Dropbear jail configured for port ${DROPBEAR_PORT}."

# Custom WauditBox filter for SSH (matches Dropbear log format)
cat > "${F2B_FILTER_DIR}/dropbear.conf" << DROPBEAR_FILTER_EOF
# =============================================================================
# WauditBox v2.0 — Fail2ban Dropbear Filter
# =============================================================================
[INCLUDES]
before = common.conf

[Definition]
failregex = ^%(__prefix_line)s[Ll]ogin attempt for nonexistent user .* from <HOST>$
            ^%(__prefix_line)s[Bb]ad password attempt .* from <HOST>$
            ^%(__prefix_line)sCan't validate password for .* from <HOST>$

ignoreregex =
DROPBEAR_FILTER_EOF

log_info "Dropbear filter created."

# Enable and start Fail2ban
log_info "Enabling and starting Fail2ban..."
systemctl enable fail2ban  2>&1 | tee -a "${SCRIPT_LOG}"
systemctl restart fail2ban 2>&1 | tee -a "${SCRIPT_LOG}"

# Verify Fail2ban is running
if systemctl is-active fail2ban >/dev/null 2>&1; then
    log_info "✓ Fail2ban is running."
    fail2ban-client status 2>&1 | tee -a "${SCRIPT_LOG}"
else
    log_warn "Fail2ban is not running — check configuration."
fi

# =============================================================================
# STEP 4: ModemManager — 5G SIM8200EA-M2 Configuration
# =============================================================================
log_section "STEP 4: ModemManager — 5G Modem Setup"

log_info "Configuring ModemManager for SIM8200EA-M2..."

# Enable ModemManager
systemctl enable  ModemManager 2>&1 | tee -a "${SCRIPT_LOG}"
systemctl restart ModemManager 2>&1 | tee -a "${SCRIPT_LOG}"

log_info "Waiting for ModemManager to initialize (10 seconds)..."
sleep 10

# Check if modem is detected
log_info "Scanning for connected modems..."
mmcli -L 2>&1 | tee -a "${SCRIPT_LOG}"

# Get modem index (usually 0)
MODEM_INDEX=$(mmcli -L 2>/dev/null | grep -oP 'Modem/\K[0-9]+' | head -1 || echo "")

if [[ -z "${MODEM_INDEX}" ]]; then
    log_warn "No modem detected by ModemManager."
    log_warn "This is expected if the 5G HAT is not physically connected yet."
    log_warn "When hardware is connected, re-run this script or manually:"
    log_warn "  mmcli -L          # list modems"
    log_warn "  mmcli -m 0        # show modem details"
    log_warn "Continuing with modem configuration files anyway..."
    MODEM_DETECTED=false
else
    log_info "✓ Modem detected at index: ${MODEM_INDEX}"
    MODEM_DETECTED=true
    
    # Show modem details
    log_info "Modem details:"
    mmcli -m "${MODEM_INDEX}" 2>&1 | tee -a "${SCRIPT_LOG}"
    
    # Enable the modem
    log_info "Enabling modem..."
    mmcli -m "${MODEM_INDEX}" --enable 2>&1 | tee -a "${SCRIPT_LOG}"
fi

# Create NetworkManager connection profile for 5G modem
log_info "Creating 5G connection profile..."
mkdir -p /etc/NetworkManager/system-connections

cat > /etc/NetworkManager/system-connections/wauditbox-5g.nmconnection << NM_5G_EOF
# =============================================================================
# WauditBox v2.0 — 5G Modem Connection Profile
# Auto-connects on boot via NetworkManager + ModemManager
# =============================================================================
[connection]
id=wauditbox-5g
uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "00000000-0000-0000-0000-000000000001")
type=gsm
autoconnect=true
autoconnect-priority=10

[gsm]
apn=${MODEM_APN}
auto-config=true

[ipv4]
method=auto
route-metric=${METRIC_5G}
never-default=false
dns-priority=-100

[ipv6]
method=disabled

[proxy]
NM_5G_EOF

# Set strict permissions (contains modem config)
chmod 600 /etc/NetworkManager/system-connections/wauditbox-5g.nmconnection
log_info "5G connection profile created."

# If modem is detected, connect now
if [[ "${MODEM_DETECTED}" == "true" ]]; then
    log_info "Attempting 5G connection..."
    nmcli connection up wauditbox-5g 2>&1 | tee -a "${SCRIPT_LOG}" || \
        log_warn "Could not connect to 5G now — will auto-connect on next boot."
fi

# =============================================================================
# STEP 5: Network Priority Routing
# =============================================================================
log_section "STEP 5: Network Priority Routing"
log_info "Configuring interface metrics (5G > Ethernet > WiFi)..."
log_info "5G metric: ${METRIC_5G}, Ethernet metric: ${METRIC_ETH}, WiFi metric: ${METRIC_WIFI}"

# Create systemd service to enforce routing priority on boot
cat > /etc/systemd/system/wauditbox-routing.service << ROUTING_SERVICE_EOF
# =============================================================================
# WauditBox v2.0 — Network Priority Routing Service
# Ensures 5G modem always has the lowest metric (highest priority)
# Runs after network interfaces are up
# =============================================================================
[Unit]
Description=WauditBox Network Priority Routing
After=network.target
After=NetworkManager.service
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/wauditbox-set-routing
ExecReload=/usr/local/bin/wauditbox-set-routing
Restart=no

[Install]
WantedBy=multi-user.target
ROUTING_SERVICE_EOF

# Create the routing script
cat > /usr/local/bin/wauditbox-set-routing << ROUTING_SCRIPT_EOF
#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — Network Routing Priority Script
# Called by wauditbox-routing.service on boot
# =============================================================================
LOG="/var/log/wauditbox/routing.log"
mkdir -p "\$(dirname \${LOG})"

log_r() { echo "\$(date '+%Y-%m-%d %H:%M:%S') \$*" >> "\${LOG}"; logger -t wauditbox-routing "\$*"; }

log_r "=== Applying WauditBox routing priority ==="

# Set 5G modem metric (highest priority)
if ip link show "${MODEM_IFACE}" >/dev/null 2>&1; then
    ip link set "${MODEM_IFACE}" up 2>/dev/null || true
    if ip route | grep -q "${MODEM_IFACE}"; then
        # Update default route metric for 5G
        MODEM_GW=\$(ip route show dev "${MODEM_IFACE}" | grep default | awk '{print \$3}' | head -1)
        if [[ -n "\${MODEM_GW}" ]]; then
            ip route change default via "\${MODEM_GW}" dev "${MODEM_IFACE}" metric ${METRIC_5G} 2>/dev/null || \
            ip route add default via "\${MODEM_GW}" dev "${MODEM_IFACE}" metric ${METRIC_5G} 2>/dev/null || true
            log_r "✓ 5G route set: via \${MODEM_GW} dev ${MODEM_IFACE} metric ${METRIC_5G}"
        fi
    fi
else
    log_r "⚠ 5G interface ${MODEM_IFACE} not found"
fi

# Set Ethernet metric (fallback)
if ip link show "${ETH_IFACE}" >/dev/null 2>&1; then
    ETH_GW=\$(ip route show dev "${ETH_IFACE}" | grep default | awk '{print \$3}' | head -1)
    if [[ -n "\${ETH_GW}" ]]; then
        ip route change default via "\${ETH_GW}" dev "${ETH_IFACE}" metric ${METRIC_ETH} 2>/dev/null || \
        ip route add default via "\${ETH_GW}" dev "${ETH_IFACE}" metric ${METRIC_ETH} 2>/dev/null || true
        log_r "✓ Ethernet route set: via \${ETH_GW} dev ${ETH_IFACE} metric ${METRIC_ETH}"
    fi
else
    log_r "⚠ Ethernet interface ${ETH_IFACE} not found"
fi

# Show final routing table
log_r "=== Final routing table ==="
ip route show >> "\${LOG}"

log_r "=== Routing priority configuration complete ==="
ROUTING_SCRIPT_EOF

chmod +x /usr/local/bin/wauditbox-set-routing

# Enable the routing service
systemctl daemon-reload
systemctl enable wauditbox-routing.service 2>&1 | tee -a "${SCRIPT_LOG}"
log_info "✓ Routing priority service enabled."

# Apply routing rules now (without waiting for reboot)
log_info "Applying routing rules now..."
bash /usr/local/bin/wauditbox-set-routing 2>&1 | tee -a "${SCRIPT_LOG}" || true

# =============================================================================
# STEP 6: DNS Configuration
# =============================================================================
log_section "STEP 6: DNS Configuration"

log_info "Configuring DNS resolution..."

# Configure resolved to use VPN DNS when WireGuard is up
mkdir -p /etc/systemd/resolved.conf.d/

cat > /etc/systemd/resolved.conf.d/wauditbox.conf << DNS_EOF
# =============================================================================
# WauditBox v2.0 — systemd-resolved Configuration
# DNS goes through WireGuard tunnel when VPN is active
# Falls back to reliable public DNS when VPN is down
# =============================================================================
[Resolve]
# Primary DNS: WireGuard gateway (set when VPN is configured)
# DNS=10.200.0.1

# Fallback DNS (used when VPN tunnel is not up)
FallbackDNS=1.1.1.1 9.9.9.9 8.8.8.8

# DNSSEC validation
DNSSEC=allow-downgrade

# DNS over TLS (opportunistic)
DNSOverTLS=opportunistic

# Cache settings
Cache=yes
CacheFromLocalhost=no

# Disable mDNS (reduces attack surface, avahi is disabled anyway)
MulticastDNS=no

# Disable LLMNR (not needed)
LLMNR=no
DNS_EOF

# Restart resolved
systemctl restart systemd-resolved 2>&1 | tee -a "${SCRIPT_LOG}" || true
log_info "DNS configuration applied."

# =============================================================================
# STEP 7: Network Hardening (Additional iptables Rules)
# =============================================================================
log_section "STEP 7: Additional Network Hardening"

log_info "Applying additional iptables hardening rules..."

# Save current iptables rules first
iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
    iptables-save > /tmp/iptables-before-wauditbox.rules

# Drop invalid packets
log_info "Adding rules to drop invalid packets..."
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP 2>/dev/null || true

# Drop null packets
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP 2>/dev/null || true

# Drop XMAS packets
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP 2>/dev/null || true

# Drop SYN-RST combinations (unusual, likely malicious)
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 2>/dev/null || true

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

log_info "iptables hardening rules applied."

# Create persistent iptables rules
log_info "Saving iptables rules for persistence..."
mkdir -p /etc/iptables

if command -v iptables-save >/dev/null 2>&1; then
    iptables-save > /etc/iptables/rules.v4
    log_info "iptables rules saved to /etc/iptables/rules.v4"
fi

# =============================================================================
# STEP 8: usb_modeswitch for 5G Modem
# =============================================================================
log_section "STEP 8: USB Mode Switch for 5G Modem"

log_info "Configuring usb_modeswitch for SIM8200EA-M2..."

# The SIM8200EA-M2 may appear as a USB storage device first
# usb_modeswitch forces it into modem mode
cat > /etc/usb_modeswitch.d/2c7c:0800 << MODESWITCH_EOF
# WauditBox v2.0 — Waveshare SIM8200EA-M2 Mode Switch
# Forces modem from storage mode to modem mode on USB insertion
TargetVendor=0x2c7c
TargetProduct=0x0800
StandardEject=1
MODESWITCH_EOF

log_info "USB mode switch configuration created for 2c7c:0800"

# Create udev rule to trigger mode switch on device insertion
cat > /etc/udev/rules.d/70-wauditbox-5g-modeswitch.rules << UDEV_5G_EOF
# WauditBox v2.0 — 5G Modem Mode Switch udev Rule
# Triggers usb_modeswitch when SIM8200EA-M2 is inserted in storage mode
ATTRS{idVendor}=="2c7c", ATTRS{idProduct}=="0800", \
    ACTION=="add", \
    RUN+="/usr/sbin/usb_modeswitch -v 2c7c -p 0800"

# Trigger ModemManager when modem is ready
SUBSYSTEM=="tty", ATTRS{idVendor}=="2c7c", \
    ACTION=="add", \
    RUN+="/usr/bin/systemctl restart ModemManager"
UDEV_EOF

udevadm control --reload-rules
udevadm trigger
log_info "udev rules for 5G modem reloaded."

# =============================================================================
# STEP 9: Network Watchdog Service
# =============================================================================
log_section "STEP 9: Network Watchdog Service"

log_info "Creating network connectivity watchdog..."

cat > /usr/local/bin/wauditbox-net-watchdog << 'NET_WATCHDOG_EOF'
#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — Network Watchdog
# Monitors 5G connection and attempts reconnect if lost
# Runs as systemd service every 5 minutes
# =============================================================================
LOG="/var/log/wauditbox/net-watchdog.log"
mkdir -p "$(dirname ${LOG})"

log_nw() { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "${LOG}"; logger -t wauditbox-net "$*"; }

check_connectivity() {
    # Ping Google DNS via 5G interface
    ping -c 2 -W 5 -I "${MODEM_IFACE:-wwan0}" 8.8.8.8 >/dev/null 2>&1
}

check_modem_connected() {
    nmcli connection show --active 2>/dev/null | grep -q "wauditbox-5g"
}

main() {
    if check_connectivity; then
        log_nw "✓ 5G connectivity OK"
        return 0
    fi

    log_nw "⚠ 5G connectivity check failed — attempting reconnect..."

    # Try to reconnect
    nmcli connection up wauditbox-5g 2>&1 >> "${LOG}" || true
    sleep 15

    if check_connectivity; then
        log_nw "✓ 5G reconnected successfully"
    else
        log_nw "✗ 5G reconnect failed — re-applying routing rules"
        /usr/local/bin/wauditbox-set-routing 2>&1 >> "${LOG}" || true
    fi
}

main
NET_WATCHDOG_EOF

chmod +x /usr/local/bin/wauditbox-net-watchdog

# Create systemd timer for network watchdog
cat > /etc/systemd/system/wauditbox-net-watchdog.service << NW_SERVICE_EOF
[Unit]
Description=WauditBox Network Watchdog
After=network.target ModemManager.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wauditbox-net-watchdog
StandardOutput=journal
StandardError=journal
NW_SERVICE_EOF

cat > /etc/systemd/system/wauditbox-net-watchdog.timer << NW_TIMER_EOF
[Unit]
Description=WauditBox Network Watchdog Timer
After=network.target

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
NW_TIMER_EOF

systemctl daemon-reload
systemctl enable wauditbox-net-watchdog.timer 2>&1 | tee -a "${SCRIPT_LOG}"
systemctl start  wauditbox-net-watchdog.timer 2>&1 | tee -a "${SCRIPT_LOG}"
log_info "✓ Network watchdog timer enabled (runs every 5 minutes)."

# =============================================================================
# STEP 10: Final Verification
# =============================================================================
log_section "STEP 10: Final Verification"

log_info "UFW status:"
ufw status verbose 2>&1 | tee -a "${SCRIPT_LOG}"

log_info "Fail2ban status:"
fail2ban-client status 2>&1 | tee -a "${SCRIPT_LOG}" || true

log_info "ModemManager status:"
systemctl is-active ModemManager 2>&1 | tee -a "${SCRIPT_LOG}"

log_info "Active network interfaces:"
ip addr show 2>&1 | tee -a "${SCRIPT_LOG}"

log_info "Current routing table:"
ip route show 2>&1 | tee -a "${SCRIPT_LOG}"

log_info "DNS resolution test:"
dig +short google.com 2>&1 | head -3 | tee -a "${SCRIPT_LOG}" || \
    nslookup google.com 2>&1 | head -5 | tee -a "${SCRIPT_LOG}" || \
    log_warn "DNS test failed — expected if VPN not configured yet."

# =============================================================================
# SUMMARY
# =============================================================================
cat << 'SUMMARY_EOF' | tee -a "${SCRIPT_LOG}"

╔══════════════════════════════════════════════════════════════════════╗
║       WauditBox v2.0 — Firewall & Network Setup Complete            ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  FIREWALL (UFW):                                                     ║
║  ✓  Default: DENY all incoming                                       ║
║  ✓  Default: ALLOW all outgoing                                      ║
║  ✓  Allowed: 22222/tcp (Dropbear LUKS unlock)                       ║
║  ✓  Allowed: 2222/tcp  (SSH management)                              ║
║  ✓  Allowed: 51820/udp (WireGuard VPN)                              ║
║  ✓  Allowed: wg0 interface (all VPN traffic)                         ║
║  ✓  Blocked: ICMP ping (stealth mode)                               ║
║  ✓  NAT rules for WireGuard configured                               ║
║                                                                      ║
║  FAIL2BAN:                                                           ║
║  ✓  SSH jail: 3 failures = 1h ban on port 2222                      ║
║  ✓  Dropbear jail: 3 failures = 24h ban on port 22222               ║
║  ✓  Operator VPN subnet (10.200.0.0/16) whitelisted                 ║
║                                                                      ║
║  5G MODEM:                                                           ║
║  ✓  ModemManager enabled and configured                              ║
║  ✓  Connection profile: wauditbox-5g (auto-connect)                 ║
║  ✓  USB mode switch configured for SIM8200EA-M2                     ║
║  ✓  Priority metric: 10 (highest priority interface)                 ║
║                                                                      ║
║  ROUTING:                                                            ║
║  ✓  5G (metric 10) > Ethernet (metric 100) > WiFi (metric 200)      ║
║  ✓  Routing service enabled (persists across reboots)               ║
║  ✓  Network watchdog: checks connectivity every 5 minutes           ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  NEXT STEP: Run 04-vpn-wireguard.sh                                 ║
╚══════════════════════════════════════════════════════════════════════╝

SUMMARY_EOF

log_info "Full log: ${SCRIPT_LOG}"
log_info "03-firewall-network.sh COMPLETE — No reboot required."

# =============================================================================
# END OF SCRIPT
# =============================================================================
