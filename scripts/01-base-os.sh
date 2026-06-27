#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — 01-base-os.sh
# OS Hardening: packages, hostname, LEDs off, sysctl, SSH, USB block,
# AppArmor, AIDE, auditd, NetworkManager, disable services
# Run on booted Kali ARM64 RPi5 as root — REQUIRES REBOOT after
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root; check_rpi5
mkdir -p "${LOG_DIR}"
log_section "01-base-os.sh — START"
# >>> FULL SCRIPT BODY IS IN THE MAIN CONVERSATION <<<
# This placeholder will be replaced with the full hardening script
log_warn "PLACEHOLDER — Replace with full 01-base-os.sh content"
