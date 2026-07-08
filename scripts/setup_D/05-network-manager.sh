#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root

log_section "NetworkManager Configuration"

NM_CONF_DIR="/etc/NetworkManager/conf.d"
mkdir -p "${NM_CONF_DIR}"

cat > "${NM_CONF_DIR}/99-wauditbox.conf" << 'EOF'
[main]
plugins=ifupdown,keyfile

[ifupdown]
managed=false

[device]
wifi.scan-rand-mac-address=no
EOF

cat > "${NM_CONF_DIR}/10-unmanaged-audit-wifi.conf" << EOF
[keyfile]
unmanaged-devices=interface-name:${WIFI_IFACE_AUDIT};interface-name:${WIFI_IFACE_CAPTURE}
EOF

systemctl is-active NetworkManager >/dev/null 2>&1 && \
    systemctl restart NetworkManager || \
    log_warn "NetworkManager not running — config applies on next boot."

log_info "Audit interfaces unmanaged: ${WIFI_IFACE_AUDIT}, ${WIFI_IFACE_CAPTURE}"
