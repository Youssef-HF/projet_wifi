#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root

STEPS=(
    01-packages.sh
    02-hostname.sh
    03-kernel.sh
    04-ssh.sh
    05-network-manager.sh
    07-apparmor.sh
    06-services.sh
    08-tmp.sh
)

log_section "WauditBox v2.0 — Full OS Hardening"

for step in "${STEPS[@]}"; do
    log_info "━━━ Running: ${step} ━━━"
    bash "${SCRIPT_DIR}/${step}"
    log_info "━━━ Done: ${step} ━━━"
    echo ""
done

log_section "All steps complete — reboot required"
read -r -p "Reboot now? [Y/n] " ans
[[ "${ans,,}" != "n" ]] && { sync; reboot; } || \
    log_info "Reboot when ready: sudo reboot"
