#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root

log_section "Fail2ban [ENV: ${WAUDITBOX_ENV}]"

if ! command -v fail2ban-client >/dev/null 2>&1; then
    log_warn "fail2ban not installed — skipping."
    exit 0
fi

mkdir -p /etc/fail2ban/jail.d
mkdir -p /etc/fail2ban/filter.d
mkdir -p "${LOG_DIR}"

# Global config
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime   = ${F2B_BAN_TIME}
findtime  = ${F2B_FIND_TIME}
maxretry  = ${F2B_MAX_RETRY}
banaction = ufw
banaction_allports = ufw
ignoreip  = 127.0.0.1/8 10.200.0.0/16 ::1
loglevel  = INFO
logtarget = ${LOG_DIR}/fail2ban.log
EOF

# SSH jail
cat > /etc/fail2ban/jail.d/wauditbox-ssh.conf << EOF
[wauditbox-ssh]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
logpath  = /var/log/auth.log
           /var/log/secure
maxretry = ${F2B_MAX_RETRY}
bantime  = ${F2B_BAN_TIME}
findtime = ${F2B_FIND_TIME}
EOF

# Dropbear jail (production only — no dropbear in dev)
if is_production; then
    cat > /etc/fail2ban/jail.d/wauditbox-dropbear.conf << EOF
[wauditbox-dropbear]
enabled  = true
port     = ${DROPBEAR_PORT}
filter   = dropbear
logpath  = /var/log/auth.log
           /var/log/syslog
maxretry = ${F2B_MAX_RETRY}
bantime  = 24h
findtime = ${F2B_FIND_TIME}
EOF

    cat > /etc/fail2ban/filter.d/dropbear.conf << 'EOF'
[INCLUDES]
before = common.conf

[Definition]
failregex = ^%(__prefix_line)s[Ll]ogin attempt for nonexistent user .* from <HOST>$
            ^%(__prefix_line)s[Bb]ad password attempt .* from <HOST>$
            ^%(__prefix_line)sCan't validate password for .* from <HOST>$
ignoreregex =
EOF
    log_info "Dropbear jail configured for port ${DROPBEAR_PORT}."
else
    log_warn "[DEV] Skipping Dropbear jail."
fi

systemctl enable fail2ban
systemctl restart fail2ban

systemctl is-active fail2ban >/dev/null 2>&1 && \
    log_info "✓ Fail2ban running." || \
    log_warn "Fail2ban not running — check config."

fail2ban-client status 2>/dev/null || true
