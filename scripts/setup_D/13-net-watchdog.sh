#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root

log_section "Network Watchdog [ENV: ${WAUDITBOX_ENV}]"

# Watchdog script
cat > /usr/local/bin/wauditbox-net-watchdog << EOF
#!/usr/bin/env bash
LOG="${LOG_DIR}/net-watchdog.log"
mkdir -p "\$(dirname \${LOG})"
_log() { echo "\$(date '+%Y-%m-%d %H:%M:%S') \$*" >> "\${LOG}"; logger -t wauditbox-net "\$*"; }

_check() { ping -c 2 -W 5 -I "${MODEM_IFACE}" 8.8.8.8 >/dev/null 2>&1; }

if _check; then
    _log "✓ 5G connectivity OK"
    exit 0
fi

_log "⚠ 5G connectivity lost — attempting reconnect..."
nmcli connection up wauditbox-5g >> "\${LOG}" 2>&1 || true
sleep 15

if _check; then
    _log "✓ Reconnected."
else
    _log "✗ Reconnect failed — re-applying routing."
    /usr/local/bin/wauditbox-set-routing >> "\${LOG}" 2>&1 || true
fi
EOF

chmod +x /usr/local/bin/wauditbox-net-watchdog

# Systemd service + timer
cat > /etc/systemd/system/wauditbox-net-watchdog.service << 'EOF'
[Unit]
Description=WauditBox Network Watchdog
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/wauditbox-net-watchdog
EOF

cat > /etc/systemd/system/wauditbox-net-watchdog.timer << 'EOF'
[Unit]
Description=WauditBox Network Watchdog Timer
After=network.target

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable wauditbox-net-watchdog.timer

if is_production; then
    systemctl start wauditbox-net-watchdog.timer
    log_info "✓ Watchdog timer started."
else
    log_warn "[DEV] Watchdog enabled but not started (no modem interface)."
fi
