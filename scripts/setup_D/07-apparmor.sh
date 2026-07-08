#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root

log_section "AppArmor"

systemctl enable apparmor
systemctl start apparmor

if command -v aa-enforce >/dev/null 2>&1; then
    find /etc/apparmor.d/ -maxdepth 1 -type f \
        ! -name "*.dpkg-*" ! -name "README" \
        -exec aa-enforce {} \; 2>/dev/null || true
    log_info "AppArmor profiles set to enforce mode."
else
    log_warn "aa-enforce not found — profiles may be in complain mode."
fi

aa-status 2>/dev/null | head -10 || true
