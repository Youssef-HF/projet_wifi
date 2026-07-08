#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root

log_section "Network Priority Routing [ENV: ${WAUDITBOX_ENV}]"

METRIC_5G=10
METRIC_ETH=100

# Routing script
cat > /usr/local/bin/wauditbox-set-routing << EOF
#!/usr/bin/env bash
LOG="${LOG_DIR}/routing.log"
mkdir -p "\$(dirname \${LOG})"

_log() { echo "\$(date '+%Y-%m-%d %H:%M:%S') \$*" >> "\${LOG}"; logger -t wauditbox-routing "\$*"; }

_set_metric() {
    local iface="\$1" metric="\$2"
    local gw
    gw=\$(ip route show dev "\${iface}" 2>/dev/null | awk '/default/{print \$3}' | head -1)
    [[ -z "\${gw}" ]] && { _log "No default route on \${iface}"; return; }
    ip route change default via "\${gw}" dev "\${iface}" metric "\${metric}" 2>/dev/null || \
    ip route add    default via "\${gw}" dev "\${iface}" metric "\${metric}" 2>/dev/null || true
    _log "Route set: \${iface} via \${gw} metric \${metric}"
}

_log "=== Applying routing priority ==="
ip link show "${MODEM_IFACE}" >/dev/null 2>&1 && _set_metric "${MODEM_IFACE}" ${METRIC_5G}  || _log "No ${MODEM_IFACE}"
ip link show "${ETH_IFACE}"   >/dev/null 2>&1 && _set_metric "${ETH_IFACE}"   ${METRIC_ETH} || _log "No ${ETH_IFACE}"
_log "=== Done. Routing table: ==="
ip route show >> "\${LOG}"
EOF

chmod +x /usr/local/bin/wauditbox-set-routing

# Systemd service
cat > /etc/systemd/system/wauditbox-routing.service << 'EOF'
[Unit]
Description=WauditBox Network Priority Routing
After=network.target NetworkManager.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/wauditbox-set-routing

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wauditbox-routing.service
log_info "Routing service enabled."

if is_production; then
    bash /usr/local/bin/wauditbox-set-routing || true
    log_info "Routing rules applied."
else
    log_warn "[DEV] Skipping live routing (interfaces may not exist)."
    log_info "[DEV] Service ready — will apply on production boot."
fi

log_info "Routing table:"
ip route show || true
