#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — 03-firewall-network.sh
# UFW default-deny, allow WireGuard+SSH+Dropbear
# Fail2ban configuration
# 5G modem: ModemManager + systemd-networkd priority routing
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root
log_section "03-firewall-network.sh — START"
log_warn "PLACEHOLDER — Full firewall + 5G script — coming next"
