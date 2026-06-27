#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — 04-vpn-wireguard.sh
# WireGuard client setup: key generation, config, systemd service
# Connects to central server at WG_SERVER_ENDPOINT (defined in 00-config.sh)
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root
log_section "04-vpn-wireguard.sh — START"
log_warn "PLACEHOLDER — Full WireGuard client script — coming next"
