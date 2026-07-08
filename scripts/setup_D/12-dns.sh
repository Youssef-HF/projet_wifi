#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root

log_section "DNS Configuration [ENV: ${WAUDITBOX_ENV}]"

if ! systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1; then
    log_warn "systemd-resolved not available — skipping."
    exit 0
fi

mkdir -p /etc/systemd/resolved.conf.d

cat > /etc/systemd/resolved.conf.d/wauditbox.conf << 'EOF'
[Resolve]
# Primary DNS set by 04-vpn-wireguard.sh when tunnel is up
# DNS=10.200.0.1
FallbackDNS=1.1.1.1 9.9.9.9 8.8.8.8
DNSSEC=allow-downgrade
DNSOverTLS=opportunistic
Cache=yes
CacheFromLocalhost=no
MulticastDNS=no
LLMNR=no
EOF

systemctl restart systemd-resolved || true
log_info "DNS config applied."

# Quick resolution test
if getent hosts github.com >/dev/null 2>&1; then
    log_info "✓ DNS resolution working."
else
    log_warn "DNS resolution test failed — expected if VPN not up yet."
fi
