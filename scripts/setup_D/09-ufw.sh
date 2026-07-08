#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root

log_section "UFW Firewall [ENV: ${WAUDITBOX_ENV}]"

if ! command -v ufw >/dev/null 2>&1; then
    log_warn "ufw not installed — skipping."
    exit 0
fi

# Reset to clean state
ufw --force reset

# Default policies
ufw default deny incoming
ufw default allow outgoing
ufw default deny forward

# Loopback
ufw allow in  on lo
ufw allow out on lo
ufw deny in from any to 127.0.0.0/8

# Essential ports
ufw allow "${DROPBEAR_PORT}/tcp" comment "Dropbear LUKS unlock"
ufw limit  "${SSH_PORT}/tcp"     comment "SSH management"
ufw allow  "${WG_PORT}/udp"      comment "WireGuard VPN"

# WireGuard interface
ufw allow in  on "${WG_IFACE}"
ufw allow out on "${WG_IFACE}"

# IP forwarding in UFW
UFW_SYSCTL="/etc/ufw/sysctl.conf"
if grep -q "^#net/ipv4/ip_forward" "${UFW_SYSCTL}"; then
    sed -i "s|^#net/ipv4/ip_forward.*|net/ipv4/ip_forward=1|" "${UFW_SYSCTL}"
elif ! grep -q "^net/ipv4/ip_forward=1" "${UFW_SYSCTL}"; then
    echo "net/ipv4/ip_forward=1" >> "${UFW_SYSCTL}"
fi

# Audit interfaces (production only — interfaces may not exist in dev)
if is_production; then
    ufw allow out on "${WIFI_IFACE_AUDIT}"   || true
    ufw allow out on "${WIFI_IFACE_CAPTURE}" || true
else
    log_warn "[DEV] Skipping audit interface rules (${WIFI_IFACE_AUDIT}, ${WIFI_IFACE_CAPTURE})."
fi

# Stealth — block ICMP
ufw deny proto icmp from any to any comment "ICMP stealth" || true

# NAT rules for WireGuard (before.rules)
UFW_BEFORE="/etc/ufw/before.rules"
cp -n "${UFW_BEFORE}" "${UFW_BEFORE}.wauditbox.bak"

# Only prepend if not already done
if ! grep -q "WauditBox NAT" "${UFW_BEFORE}"; then
    cat > /tmp/wauditbox-nat.rules << EOF
# WauditBox NAT Rules
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.200.0.0/16 -o ${MODEM_IFACE} -j MASQUERADE
-A POSTROUTING -s 10.200.0.0/16 -o ${ETH_IFACE}   -j MASQUERADE
COMMIT

EOF
    cat /tmp/wauditbox-nat.rules "${UFW_BEFORE}" > /tmp/combined.rules
    mv /tmp/combined.rules "${UFW_BEFORE}"
    log_info "NAT rules prepended to before.rules."
fi

ufw --force enable
ufw --force reload

log_info "UFW status:"
ufw status verbose
