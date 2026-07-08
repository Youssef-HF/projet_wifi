#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root

log_section "SSH Hardening"

SSHD_CONFIG="/etc/ssh/sshd_config"
cp -n "${SSHD_CONFIG}" "${SSHD_CONFIG}.wauditbox.bak"

cat > "${SSHD_CONFIG}" << EOF
Port ${SSH_PORT}
AddressFamily inet
ListenAddress 0.0.0.0

PermitRootLogin prohibit-password
PubkeyAuthentication yes
AuthorizedKeysFile /etc/ssh/authorized_keys/%u .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes

HostKey /etc/ssh/ssh_host_ed25519_key

PubkeyAcceptedAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org

LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 120
ClientAliveCountMax 3

X11Forwarding no
AllowTcpForwarding yes
AllowAgentForwarding yes
PermitTunnel no
GatewayPorts no
PrintMotd no
PrintLastLog yes

KerberosAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes

LogLevel VERBOSE
SyslogFacility AUTH
MaxStartups 10:30:60
PerSourceMaxStartups 3

Banner /etc/ssh/wauditbox_banner
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

# Authorized keys
mkdir -p /etc/ssh/authorized_keys
chmod 755 /etc/ssh/authorized_keys

if [[ "${OPERATOR_PUBKEY}" == *"REPLACE"* ]]; then
    log_warn "OPERATOR_PUBKEY is a placeholder — SSH key auth will not work."
    log_warn "Set it in 00-config.sh, then re-run this script."
else
    echo "${OPERATOR_PUBKEY}" > /etc/ssh/authorized_keys/root
    chmod 600 /etc/ssh/authorized_keys/root
    log_info "Root SSH key installed."

    if id -u kali >/dev/null 2>&1; then
        echo "${OPERATOR_PUBKEY}" > /etc/ssh/authorized_keys/kali
        chmod 600 /etc/ssh/authorized_keys/kali
        log_info "Kali user SSH key installed."
    fi
fi

# Banner
cat > /etc/ssh/wauditbox_banner << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                    WauditBox v2.0                            ║
║               AUTHORIZED ACCESS ONLY                         ║
║   This system is for authorized research only.              ║
║   All activities are logged and monitored.                   ║
╚══════════════════════════════════════════════════════════════╝
EOF

# Host keys — Ed25519 only
rm -f /etc/ssh/ssh_host_{rsa,dsa,ecdsa}_key* 2>/dev/null || true
[[ -f /etc/ssh/ssh_host_ed25519_key ]] || \
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q

sshd -t || { log_error "sshd config syntax error."; exit 1; }

systemctl restart ssh 2>/dev/null || systemctl restart sshd
log_info "SSH running on port ${SSH_PORT}."
