#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root

log_section "Hostname Configuration"

CURRENT="$(hostname)"

if [[ "${CURRENT}" == "${WAUDITBOX_HOSTNAME}" ]]; then
    log_info "Hostname already set to ${WAUDITBOX_HOSTNAME}."
    exit 0
fi

hostnamectl set-hostname "${WAUDITBOX_HOSTNAME}"

if ! grep -q "${WAUDITBOX_HOSTNAME}" /etc/hosts; then
    echo "127.0.1.1    ${WAUDITBOX_HOSTNAME}" >> /etc/hosts
fi

log_info "Hostname: ${CURRENT} → ${WAUDITBOX_HOSTNAME}"
