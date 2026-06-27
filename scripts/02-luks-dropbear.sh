#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — 02-luks-dropbear.sh
# LUKS2 AES-256-XTS encryption + Dropbear initramfs + LUKS Nuke setup
# WARNING: DESTRUCTIVE — backs up data first, then re-encrypts root partition
# Run AFTER 01-base-os.sh and reboot
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root
log_section "02-luks-dropbear.sh — START"
log_warn "PLACEHOLDER — Full LUKS2 + Dropbear script — coming next"
