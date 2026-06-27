#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — setup.sh
# MASTER SCRIPT — Runs all deployment scripts in sequence
# Usage: sudo bash scripts/setup.sh
#        sudo bash scripts/setup.sh --step 03   (start from specific step)
# =============================================================================
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root

# Parse arguments
START_STEP="${1:-01}"
[[ "${1:-}" == "--step" ]] && START_STEP="${2:-01}"

log_section "WauditBox v2.0 — Master Setup Script"
log_info "Starting from step: ${START_STEP}"

STEPS=(
    "01:01-base-os.sh:OS Hardening (requires reboot after)"
    "02:02-luks-dropbear.sh:LUKS2 + Dropbear (requires reboot after)"
    "03:03-firewall-network.sh:Firewall + 5G Network"
    "04:04-vpn-wireguard.sh:WireGuard VPN"
    "05:05-killswitch.sh:Kill Switch Watchdog"
)

for step_entry in "${STEPS[@]}"; do
    step_num="${step_entry%%:*}"
    rest="${step_entry#*:}"
    script_name="${rest%%:*}"
    description="${rest#*:}"

    [[ "${step_num}" < "${START_STEP}" ]] && continue

    log_section "STEP ${step_num}: ${description}"
    log_info "Running: ${SCRIPT_DIR}/${script_name}"

    if [[ -f "${SCRIPT_DIR}/${script_name}" ]]; then
        bash "${SCRIPT_DIR}/${script_name}"
    else
        log_error "Script not found: ${script_name}"
        exit 1
    fi

    # Steps 01 and 02 require reboot before continuing
    if [[ "${step_num}" == "01" || "${step_num}" == "02" ]]; then
        log_warn "REBOOT REQUIRED before continuing to next step."
        log_warn "After reboot, run: sudo bash scripts/setup.sh --step $(printf '%02d' $((10#${step_num}+1)))"
        read -r -p "Reboot now? [Y/n] " rb
        [[ "${rb,,}" != "n" ]] && reboot
        break
    fi
done

log_section "All steps complete!"
log_info "WauditBox v2.0 deployment finished."
