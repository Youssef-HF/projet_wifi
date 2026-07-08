#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root

log_section "Secure /tmp with tmpfs"

if grep -q "tmpfs /tmp" /etc/fstab; then
    log_info "/tmp tmpfs already in /etc/fstab."
    exit 0
fi

echo "tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec,size=512M 0 0" >> /etc/fstab
log_info "tmpfs /tmp added to /etc/fstab — takes effect after reboot."
