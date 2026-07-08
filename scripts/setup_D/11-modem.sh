#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root

log_section "5G Modem Setup [ENV: ${WAUDITBOX_ENV}]"

MODEM_APN="internet"

if is_dev; then
    log_warn "[DEV] No physical modem — writing config files only."
fi

# usb_modeswitch config
mkdir -p /etc/usb_modeswitch.d
cat > /etc/usb_modeswitch.d/2c7c:0800 << 'EOF'
TargetVendor=0x2c7c
TargetProduct=0x0800
StandardEject=1
EOF

# udev rule for modem
cat > /etc/udev/rules.d/70-wauditbox-5g-modeswitch.rules << 'EOF'
ATTRS{idVendor}=="2c7c", ATTRS{idProduct}=="0800", \
    ACTION=="add", \
    RUN+="/usr/sbin/usb_modeswitch -v 2c7c -p 0800"

SUBSYSTEM=="tty", ATTRS{idVendor}=="2c7c", \
    ACTION=="add", \
    RUN+="/usr/bin/systemctl restart ModemManager"
EOF

udevadm control --reload-rules
udevadm trigger
log_info "udev + modeswitch rules applied."

# NetworkManager connection profile
mkdir -p /etc/NetworkManager/system-connections

cat > /etc/NetworkManager/system-connections/wauditbox-5g.nmconnection << EOF
[connection]
id=wauditbox-5g
uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "00000000-0000-0000-0000-000000000001")
type=gsm
autoconnect=true
autoconnect-priority=10

[gsm]
apn=${MODEM_APN}
auto-config=true

[ipv4]
method=auto
route-metric=10
never-default=false
dns-priority=-100

[ipv6]
method=disabled

[proxy]
EOF

chmod 600 /etc/NetworkManager/system-connections/wauditbox-5g.nmconnection
log_info "5G connection profile created."

# ModemManager — only interact with hardware in production
if is_production; then
    if ! command -v mmcli >/dev/null 2>&1; then
        log_warn "mmcli not found — install modemmanager first."
        exit 1
    fi

    systemctl enable ModemManager
    systemctl restart ModemManager

    log_info "Waiting 10s for ModemManager..."
    sleep 10

    MODEM_INDEX=$(mmcli -L 2>/dev/null | grep -oP 'Modem/\K[0-9]+' | head -1 || echo "")

    if [[ -z "${MODEM_INDEX}" ]]; then
        log_warn "No modem detected — connect hardware and re-run."
    else
        log_info "Modem detected at index: ${MODEM_INDEX}"
        mmcli -m "${MODEM_INDEX}" --enable || true
        nmcli connection up wauditbox-5g 2>/dev/null || \
            log_warn "Could not connect now — will auto-connect on boot."
    fi
else
    log_warn "[DEV] Skipping ModemManager interaction."
    log_info "[DEV] Config files written — ready for production."
fi
