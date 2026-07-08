#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root

log_section "Disable Unnecessary Services"

SERVICES=(
    bluetooth
    avahi-daemon
    cups
    cups-browsed
    triggerhappy
    rpcbind
    nfs-server
)

for svc in "${SERVICES[@]}"; do
    if systemctl list-unit-files "${svc}.service" 2>/dev/null | grep -q "${svc}"; then
        systemctl disable "${svc}" 2>/dev/null || true
        systemctl stop "${svc}" 2>/dev/null || true
        log_info "Disabled: ${svc}"
    else
        log_info "Not found (skip): ${svc}"
    fi
done
