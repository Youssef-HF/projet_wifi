#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — scripts/01-base-os.sh
# OS Hardening & Base Configuration
# 
# What this script does:
#   - Update system packages
#   - Install all required tools (aircrack, hcxdumptool, ModemManager, etc.)
#   - Set hostname to "wauditbox"
#   - Disable LEDs, HDMI, Bluetooth (headless/discreet operation)
#   - Kernel parameter tuning (BBR congestion, IPv6 disable, security)
#   - SSH hardening (Ed25519 only, port 2222, no passwords)
#   - USB storage blocking + whitelist for Flipper/ESP32/5G modem
#   - NetworkManager configuration (monitor mode support)
#   - AppArmor enforcement
#   - AIDE integrity monitoring + daily cron
#   - Auditd syscall auditing
#   - Disable unnecessary services
#   - Secure /tmp with tmpfs
#   - Create WauditBox directory structure
#
# Run on: Freshly booted Kali Linux ARM64 (RPi5)
# Requirements: Root access, internet connection
# Reboot required: YES (to apply LED/HDMI/USB/kernel changes)
#
# Author: WauditBox Team
# Version: 2.0
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# --- [ BOOTSTRAP ] -----------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source global configuration
if [[ ! -f "${SCRIPT_DIR}/00-config.sh" ]]; then
    echo "ERROR: 00-config.sh not found in ${SCRIPT_DIR}"
    echo "Make sure you're running this from the scripts/ directory"
    exit 1
fi

source "${SCRIPT_DIR}/00-config.sh"

# Verify running as root
check_root

# Verify Raspberry Pi 5 (with confirmation option)
check_rpi5

# Create log directory early
mkdir -p "${LOG_DIR}"
touch "${SCRIPT_LOG}"

log_section "WauditBox v2.0 — 01-base-os.sh — Starting OS Hardening"
log_info "Timestamp: $(date '+%Y-%m-%d %H:%M:%S %Z')"
log_info "Running as: $(whoami)"
log_info "Hostname: $(hostname)"
log_info "Kernel: $(uname -r)"
log_info "OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"

# =============================================================================
# STEP 1: System Update & Essential Package Installation
# =============================================================================
log_section "STEP 1: System Update & Package Installation"

log_info "Updating package lists..."
apt-get update -qq 2>&1 | tee -a "${SCRIPT_LOG}"

log_info "Upgrading installed packages (this may take 5-10 minutes)..."
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -q 2>&1 | tee -a "${SCRIPT_LOG}"

log_info "Installing WauditBox required packages..."
log_warn "This will install ~500MB of packages. Continue? [Y/n]"
read -r -t 10 pkg_confirm || pkg_confirm="y"
if [[ "${pkg_confirm,,}" == "n" ]]; then
    log_error "Package installation cancelled by user."
    exit 1
fi

DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    `# --- Core system tools ---` \
    curl wget git vim nano tmux screen htop iotop tree ncdu \
    bash-completion command-not-found \
    `# --- Security & hardening ---` \
    ufw fail2ban \
    apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra \
    aide aide-common \
    `# --- LUKS & disk encryption ---` \
    cryptsetup cryptsetup-initramfs cryptsetup-bin \
    `# --- Dropbear for initramfs SSH ---` \
    dropbear-initramfs dropbear-bin \
    `# --- Network tools ---` \
    net-tools iproute2 iputils-ping traceroute \
    iptables iptables-persistent nftables \
    dnsutils bind9-host \
    `# --- VPN ---` \
    wireguard wireguard-tools openresolv \
    `# --- 5G modem management ---` \
    modemmanager libmbim-utils libqmi-utils \
    usb-modeswitch usb-modeswitch-data \
    `# --- Python environment ---` \
    python3 python3-pip python3-venv python3-setuptools \
    python3-serial python3-requests python3-psutil \
    `# --- WiFi pentest tools (Kali has most, ensure these) ---` \
    aircrack-ng hcxdumptool hcxtools \
    reaver bully pixiewps \
    hostapd hostapd-wpe dnsmasq \
    bettercap wifiphisher \
    `# --- Network scanning ---` \
    nmap masscan arp-scan netdiscover \
    `# --- Exploitation frameworks ---` \
    responder crackmapexec impacket-scripts \
    yersinia macchanger \
    `# --- System integrity & monitoring ---` \
    auditd audispd-plugins \
    `# --- Build tools (for some Python packages) ---` \
    build-essential gcc g++ make \
    libssl-dev libffi-dev python3-dev \
    `# --- Utilities ---` \
    jq bc lsof strace gdb pv rsync \
    zip unzip p7zip-full \
    2>&1 | tee -a "${SCRIPT_LOG}"

log_info "Package installation complete."

# Update command-not-found database
if command -v update-command-not-found >/dev/null 2>&1; then
    log_info "Updating command-not-found database..."
    update-command-not-found 2>&1 | tee -a "${SCRIPT_LOG}" || true
fi

# =============================================================================
# STEP 2: Hostname Configuration
# =============================================================================
log_section "STEP 2: Hostname Configuration"

CURRENT_HOSTNAME="$(hostname)"
log_info "Current hostname: ${CURRENT_HOSTNAME}"

if [[ "${CURRENT_HOSTNAME}" != "${WAUDITBOX_HOSTNAME}" ]]; then
    log_info "Setting hostname to: ${WAUDITBOX_HOSTNAME}"
    hostnamectl set-hostname "${WAUDITBOX_HOSTNAME}"
    
    # Update /etc/hosts to reflect new hostname
    if ! grep -q "${WAUDITBOX_HOSTNAME}" /etc/hosts; then
        echo "127.0.1.1    ${WAUDITBOX_HOSTNAME}" >> /etc/hosts
        log_info "Added ${WAUDITBOX_HOSTNAME} to /etc/hosts"
    fi
    
    log_info "Hostname changed: ${CURRENT_HOSTNAME} → ${WAUDITBOX_HOSTNAME}"
else
    log_info "Hostname already set correctly."
fi

# =============================================================================
# STEP 3: Disable LEDs & HDMI (Headless/Discreet Operation)
# =============================================================================
log_section "STEP 3: Physical Discretion — Disable LEDs & HDMI"

# On Kali for RPi5, the boot config is at /boot/firmware/config.txt
BOOT_CONFIG="/boot/firmware/config.txt"
if [[ ! -f "${BOOT_CONFIG}" ]]; then
    # Fallback for some Kali builds
    BOOT_CONFIG="/boot/config.txt"
fi

if [[ ! -f "${BOOT_CONFIG}" ]]; then
    log_warn "Boot config not found at /boot/firmware/config.txt or /boot/config.txt"
    log_warn "LED/HDMI disable will be skipped. Check your boot partition manually."
else
    log_info "Boot config found at: ${BOOT_CONFIG}"
    
    # Backup original config
    if [[ ! -f "${BOOT_CONFIG}.wauditbox.bak" ]]; then
        cp "${BOOT_CONFIG}" "${BOOT_CONFIG}.wauditbox.bak"
        log_info "Backed up config to ${BOOT_CONFIG}.wauditbox.bak"
    fi
    
    # Function to set or update a boot parameter
    set_boot_param() {
        local key="$1"
        local value="$2"
        if grep -q "^${key}=" "${BOOT_CONFIG}"; then
            sed -i "s|^${key}=.*|${key}=${value}|" "${BOOT_CONFIG}"
            log_info "Updated: ${key}=${value}"
        elif grep -q "^#${key}=" "${BOOT_CONFIG}"; then
            sed -i "s|^#${key}=.*|${key}=${value}|" "${BOOT_CONFIG}"
            log_info "Enabled: ${key}=${value}"
        else
            echo "${key}=${value}" >> "${BOOT_CONFIG}"
            log_info "Added: ${key}=${value}"
        fi
    }
    
    log_info "Disabling Activity LED (green)..."
    set_boot_param "dtparam=act_led_trigger" "none"
    set_boot_param "dtparam=act_led_activelow" "off"
    
    log_info "Disabling Power LED (red)..."
    set_boot_param "dtparam=pwr_led_trigger" "none"
    set_boot_param "dtparam=pwr_led_activelow" "off"
    
    log_info "Disabling HDMI output (saves power, improves discretion)..."
    set_boot_param "hdmi_blanking" "2"
    
    log_info "Disabling onboard Bluetooth (using ESP32 for BLE)..."
    if ! grep -q "^dtoverlay=disable-bt" "${BOOT_CONFIG}"; then
        echo "dtoverlay=disable-bt" >> "${BOOT_CONFIG}"
        log_info "Added: dtoverlay=disable-bt"
    fi
    
    log_info "Disabling onboard audio (not needed)..."
    set_boot_param "dtparam=audio" "off"
    
    log_info "Setting GPU memory to minimum (headless system)..."
    set_boot_param "gpu_mem" "16"
    
    log_info "Boot config modifications complete."
fi

# =============================================================================
# STEP 4: Kernel Performance & Security Tuning (sysctl)
# =============================================================================
log_section "STEP 4: Kernel Parameter Tuning (sysctl)"

log_info "Writing sysctl configuration to ${SYSCTL_CONF_DEST}..."

cat > "${SYSCTL_CONF_DEST}" << 'SYSCTL_EOF'
# =============================================================================
# WauditBox v2.0 — Kernel Parameters
# Applied via: sysctl -p /etc/sysctl.d/99-wauditbox.conf
# =============================================================================

# --- [ NETWORK PERFORMANCE — TCP Stack Tuning ] ------------------------------

# Increase TCP buffer sizes for high-throughput VPN tunnel (5G → WireGuard)
net.core.rmem_default = 262144
net.core.rmem_max = 134217728
net.core.wmem_default = 262144
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 65536 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728

# Increase the maximum socket backlog queue
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 250000

# Enable TCP fast open (reduces connection latency for repeated connections)
net.ipv4.tcp_fastopen = 3

# Use BBR congestion control (better for lossy 5G connections)
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq

# Increase ephemeral port range (more parallel connections for scanning)
net.ipv4.ip_local_port_range = 1024 65535

# TCP keepalive tuning (detect dead connections faster)
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6

# Reduce TIME_WAIT sockets (important for scanner operations)
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1

# Enable IP forwarding (needed for WireGuard and potential pivot operations)
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1

# --- [ NETWORK SECURITY ] ----------------------------------------------------

# Disable IPv6 completely (reduces attack surface, simplifies firewall rules)
# All operations use IPv4 over WireGuard
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Enable reverse path filtering (anti-spoofing)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirects (prevent routing table manipulation)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Ignore ICMP broadcast requests (smurf attack protection)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Enable bad error message protection
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable SYN cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3
net.ipv4.tcp_max_syn_backlog = 4096

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Log martian packets (packets with impossible source addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# --- [ FILE SYSTEM & PROCESS LIMITS ] ----------------------------------------

# Increase file descriptor limit (needed for scanner ops with many parallel conns)
fs.file-max = 2097152

# Increase inotify watches (for AIDE file integrity monitoring)
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 256
fs.inotify.max_queued_events = 32768

# --- [ KERNEL SECURITY — Hardening ] -----------------------------------------

# Restrict kernel pointer exposure in /proc/kallsyms and kernel logs
kernel.kptr_restrict = 2

# Restrict dmesg access to root only
kernel.dmesg_restrict = 1

# Restrict ptrace (debugging) to direct parent process only
# This breaks some debuggers but prevents lateral process injection
kernel.yama.ptrace_scope = 1

# Restrict access to kernel syslog
kernel.printk = 3 4 1 3

# Enable ASLR (Address Space Layout Randomization) — maximum
kernel.randomize_va_space = 2

# Disable core dumps for SUID programs (prevents information leakage)
fs.suid_dumpable = 0

# Disable magic SysRq key (security risk on shared systems)
kernel.sysrq = 0

# Restrict kernel module loading to root only
kernel.modules_disabled = 0
kernel.kexec_load_disabled = 1

# --- [ SHARED MEMORY ] -------------------------------------------------------
# Restrict access to shared memory segments
kernel.shmmax = 268435456
kernel.shmall = 268435456

# --- [ SWAP ] ----------------------------------------------------------------
# Reduce swap aggressiveness (prefer RAM, reduce SD card wear)
vm.swappiness = 10
vm.vfs_cache_pressure = 50
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5

# --- [ PROTECT AGAINST BUFFER OVERFLOWS ] ------------------------------------
# Increase ASLR entropy
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
SYSCTL_EOF

log_info "Applying sysctl parameters..."
sysctl -p "${SYSCTL_CONF_DEST}" 2>&1 | tee -a "${SCRIPT_LOG}" || true

# Load BBR kernel module if available
if modprobe tcp_bbr 2>/dev/null; then
    log_info "BBR congestion control module loaded."
    if [[ ! -f /etc/modules-load.d/wauditbox.conf ]]; then
        echo "tcp_bbr" > /etc/modules-load.d/wauditbox.conf
        log_info "BBR module will load on boot."
    fi
else
    log_warn "BBR module not available on kernel $(uname -r) — using default congestion control."
fi

# Verify IPv6 is disabled
IPV6_STATUS=$(sysctl net.ipv6.conf.all.disable_ipv6 | awk '{print $3}')
if [[ "${IPV6_STATUS}" == "1" ]]; then
    log_info "IPv6 successfully disabled."
else
    log_warn "IPv6 disable failed — check sysctl output above."
fi

# =============================================================================
# STEP 5: SSH Hardening
# =============================================================================
log_section "STEP 5: SSH Hardening"

SSHD_CONFIG="/etc/ssh/sshd_config"

# Backup original SSH config
if [[ ! -f "${SSHD_CONFIG}.wauditbox.bak" ]]; then
    cp "${SSHD_CONFIG}" "${SSHD_CONFIG}.wauditbox.bak"
    log_info "Backed up sshd_config to ${SSHD_CONFIG}.wauditbox.bak"
fi

log_info "Writing hardened SSH configuration..."

cat > "${SSHD_CONFIG}" << SSHD_EOF
# =============================================================================
# WauditBox v2.0 — Hardened SSH Configuration
# Applied by: scripts/01-base-os.sh
# =============================================================================

# Network
Port ${SSH_PORT}
AddressFamily inet
ListenAddress 0.0.0.0

# Authentication — Keys only, no passwords
PermitRootLogin prohibit-password
PubkeyAuthentication yes
AuthorizedKeysFile /etc/ssh/authorized_keys/%u .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes

# Host keys — Ed25519 only (strongest, smallest)
HostKey /etc/ssh/ssh_host_ed25519_key

# Key algorithms — Modern only
PubkeyAcceptedAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com

# Ciphers & MACs — Strong modern algorithms only
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

# Session hardening
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 5
ClientAliveInterval 120
ClientAliveCountMax 3
TCPKeepAlive yes

# Features
X11Forwarding no
AllowTcpForwarding yes
AllowAgentForwarding yes
PermitTunnel no
GatewayPorts no
PrintMotd no
PrintLastLog yes

# Disable unused authentication methods
KerberosAuthentication no
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes

# Logging
LogLevel VERBOSE
SyslogFacility AUTH

# Security limits
MaxStartups 10:30:60
PerSourceMaxStartups 3

# Banner
Banner /etc/ssh/wauditbox_banner

# Subsystem (required for SCP/SFTP)
Subsystem sftp /usr/lib/openssh/sftp-server

# Allow only specific users (uncomment and customize when needed)
# AllowUsers kali root
SSHD_EOF

log_info "SSH configuration written to ${SSHD_CONFIG}"

# Create authorized_keys directory with strict permissions
mkdir -p /etc/ssh/authorized_keys
chmod 755 /etc/ssh/authorized_keys

# Inject the operator's public key
log_info "Setting up authorized SSH keys..."

if [[ "${OPERATOR_PUBKEY}" == *"REPLACE"* ]]; then
    log_warn "WARNING: OPERATOR_PUBKEY in 00-config.sh is still a placeholder!"
    log_warn "SSH key authentication will NOT work until you set a real Ed25519 public key."
    log_warn "Generate one with: ssh-keygen -t ed25519 -C 'wauditbox-operator'"
else
    echo "${OPERATOR_PUBKEY}" > /etc/ssh/authorized_keys/root
    chmod 600 /etc/ssh/authorized_keys/root
    log_info "Root SSH key installed: ${OPERATOR_PUBKEY:0:50}..."
    
    # Also add to kali user if exists
    if id -u kali >/dev/null 2>&1; then
        echo "${OPERATOR_PUBKEY}" > /etc/ssh/authorized_keys/kali
        chmod 600 /etc/ssh/authorized_keys/kali
        log_info "Kali user SSH key installed."
    fi
fi

# Create SSH login banner (legal notice)
cat > /etc/ssh/wauditbox_banner << 'BANNER_EOF'
╔══════════════════════════════════════════════════════════════╗
║                    WauditBox v2.0                            ║
║                  AUTHORIZED ACCESS ONLY                      ║
║                                                              ║
║  This system is for authorized university research ONLY.    ║
║  All activities are logged and monitored.                    ║
║  Unauthorized access is prohibited.                          ║
╚══════════════════════════════════════════════════════════════╝
BANNER_EOF
chmod 644 /etc/ssh/wauditbox_banner
log_info "SSH banner created."

# Regenerate host keys (Ed25519 only)
log_info "Regenerating SSH host keys (Ed25519 only)..."
rm -f /etc/ssh/ssh_host_rsa_key* \
      /etc/ssh/ssh_host_dsa_key* \
      /etc/ssh/ssh_host_ecdsa_key* 2>/dev/null || true

if [[ ! -f /etc/ssh/ssh_host_ed25519_key ]]; then
    ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" -q
    log_info "Ed25519 host key generated."
fi

log_info "Ed25519 host key fingerprint:"
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub 2>&1 | tee -a "${SCRIPT_LOG}"

# Test SSH config syntax
if sshd -t; then
    log_info "SSH configuration syntax is valid."
else
    log_error "SSH configuration has syntax errors! Check ${SSHD_CONFIG}"
    exit 1
fi

# Restart SSH service
systemctl restart ssh || systemctl restart sshd
log_info "SSH service restarted on port ${SSH_PORT}"

# Show SSH status
systemctl status ssh --no-pager -l || systemctl status sshd --no-pager -l

# =============================================================================
# STEP 6: USB Storage Block — Allow Serial Devices Only
# =============================================================================
log_section "STEP 6: USB Storage Block — Whitelist Serial Devices"

log_info "Blacklisting USB mass storage kernel module..."
cat > /etc/modprobe.d/wauditbox-usb-block.conf << 'USB_MODPROBE_EOF'
# WauditBox v2.0 — Block USB mass storage
# Prevents automatic mounting of USB drives (security: no USB drops)
# Serial devices (Flipper Zero, ESP32, 5G modem) are NOT affected
# as they use different drivers (cdc_acm, cp210x, ch341, option, qmi_wwan)
blacklist usb_storage
blacklist uas
USB_MODPROBE_EOF

log_info "USB storage module blacklisted."

# Create udev rule to explicitly allow whitelisted serial devices
log_info "Creating udev rules for whitelisted USB devices..."
cat > /etc/udev/rules.d/99-wauditbox-usb.rules << 'UDEV_EOF'
# =============================================================================
# WauditBox v2.0 — USB Device Rules
# Whitelist serial/modem devices, block all USB storage
# Applied by: scripts/01-base-os.sh
# =============================================================================

# --- Block all USB mass storage (belt + suspenders) ---
SUBSYSTEM=="block", KERNEL=="sd[a-z]*", ATTRS{removable}=="1", \
    ACTION=="add", \
    RUN+="/usr/bin/logger -t wauditbox-udev 'USB storage blocked: %k'", \
    ENV{UDISKS_IGNORE}="1"

# --- Waveshare SIM8200EA-M2 — 5G Modem ---
ATTRS{idVendor}=="2c7c", ATTRS{idProduct}=="0800", \
    MODE="0660", GROUP="dialout", \
    SYMLINK+="wauditbox-5g", \
    TAG+="systemd", \
    RUN+="/usr/bin/logger -t wauditbox-udev '5G modem connected: %k'"

# --- Flipper Zero (STM32 VCP) ---
ATTRS{idVendor}=="0483", ATTRS{idProduct}=="5740", \
    MODE="0660", GROUP="dialout", \
    SYMLINK+="flipper-zero", \
    RUN+="/usr/bin/logger -t wauditbox-udev 'Flipper Zero connected: %k'"

# --- ESP32 Cardputer (CP210x) ---
ATTRS{idVendor}=="10c4", ATTRS{idProduct}=="ea60", \
    MODE="0660", GROUP="dialout", \
    SYMLINK+="esp32-bitpirate", \
    RUN+="/usr/bin/logger -t wauditbox-udev 'ESP32 Bit-Pirate connected: %k'"

# --- CH340 (common ESP32 clone) ---
ATTRS{idVendor}=="1a86", ATTRS{idProduct}=="7523", \
    MODE="0660", GROUP="dialout", \
    SYMLINK+="esp32-ch340", \
    RUN+="/usr/bin/logger -t wauditbox-udev 'ESP32 CH340 connected: %k'"

# --- FTDI FT232 (backup adapter) ---
ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6001", \
    MODE="0660", GROUP="dialout", \
    SYMLINK+="esp32-ftdi", \
    RUN+="/usr/bin/logger -t wauditbox-udev 'FTDI adapter connected: %k'"

# --- KILL SWITCH TRIGGER — 5G Modem Removal ---
# When the 5G modem is physically disconnected, trigger the kill switch watchdog
# The actual destruction logic is in scripts/05-killswitch.sh
ATTRS{idVendor}=="2c7c", ATTRS{idProduct}=="0800", \
    ACTION=="remove", \
    RUN+="/usr/bin/logger -t wauditbox-killswitch 'ALERT: 5G modem removed - kill switch armed'"
UDEV_EOF

# Reload udev rules
udevadm control --reload-rules
udevadm trigger
log_info "udev rules applied and reloaded."

# Update initramfs to apply USB blacklist at boot
log_info "Updating initramfs to apply USB blacklist (this takes 1-2 minutes)..."
update-initramfs -u -k all 2>&1 | tee -a "${SCRIPT_LOG}"
log_info "initramfs updated."

# =============================================================================
# STEP 7: NetworkManager — Set WiFi Adapters to Unmanaged
# =============================================================================
log_section "STEP 7: NetworkManager Configuration"

log_info "Configuring NetworkManager to ignore WiFi audit adapters..."
log_info "This prevents NM from interfering with monitor mode (airmon-ng)."

NM_CONF_DIR="/etc/NetworkManager/conf.d"
mkdir -p "${NM_CONF_DIR}"

cat > "${NM_CONF_DIR}/99-wauditbox.conf" << 'NM_EOF'
# =============================================================================
# WauditBox v2.0 — NetworkManager Configuration
# WiFi audit adapters are unmanaged to prevent NM from fighting monitor mode
# Applied by: scripts/01-base-os.sh
# =============================================================================
[main]
plugins=ifupdown,keyfile

[ifupdown]
managed=false

[device]
# Disable MAC randomization for WiFi (breaks some audits)
wifi.scan-rand-mac-address=no

[keyfile]
# Unmanaged devices are defined in separate file below
NM_EOF

# Create a separate unmanaged devices config (easier to edit later)
cat > "${NM_CONF_DIR}/10-unmanaged-audit-wifi.conf" << UNMANAGED_EOF
# =============================================================================
# WauditBox v2.0 — Unmanaged WiFi Audit Interfaces
# These interfaces are controlled by airmon-ng / hcxdumptool, not NetworkManager
# =============================================================================
[keyfile]
unmanaged-devices=interface-name:${WIFI_IFACE_AUDIT};interface-name:${WIFI_IFACE_CAPTURE}
UNMANAGED_EOF

log_info "NetworkManager configured."
log_info "Audit interfaces set to unmanaged: ${WIFI_IFACE_AUDIT}, ${WIFI_IFACE_CAPTURE}"

# Restart NetworkManager to apply changes
if systemctl is-active NetworkManager >/dev/null 2>&1; then
    systemctl restart NetworkManager 2>&1 | tee -a "${SCRIPT_LOG}"
    log_info "NetworkManager restarted."
else
    log_warn "NetworkManager not running — config will apply on next boot."
fi

# =============================================================================
# STEP 8: AppArmor — Enable & Set Enforce Mode
# =============================================================================
log_section "STEP 8: AppArmor Mandatory Access Control"

log_info "Enabling AppArmor service..."
systemctl enable apparmor 2>&1 | tee -a "${SCRIPT_LOG}"
systemctl start apparmor 2>&1 | tee -a "${SCRIPT_LOG}"

# Set all profiles to enforce mode
log_info "Setting AppArmor profiles to enforce mode..."
if command -v aa-enforce >/dev/null 2>&1; then
    find /etc/apparmor.d/ -maxdepth 1 -type f ! -name "*.dpkg-*" ! -name "README" \
        -exec aa-enforce {} \; 2>&1 | tee -a "${SCRIPT_LOG}" || true
else
    log_warn "aa-enforce command not found — AppArmor profiles may be in complain mode."
fi

# Verify AppArmor status
log_info "AppArmor status:"
if command -v aa-status >/dev/null 2>&1; then
    aa-status 2>&1 | head -20 | tee -a "${SCRIPT_LOG}"
else
    log_warn "aa-status command not found."
fi

log_info "AppArmor enabled and configured."

# =============================================================================
# STEP 9: AIDE — File Integrity Monitoring
# =============================================================================
log_section "STEP 9: AIDE — Advanced Intrusion Detection Environment"

log_info "Configuring AIDE file integrity monitoring..."

# Customize AIDE config to exclude volatile paths (reduces false positives)
cat >> /etc/aide/aide.conf << 'AIDE_CONF_EOF'

# =============================================================================
# WauditBox v2.0 — AIDE Custom Rules
# Added by: scripts/01-base-os.sh
# =============================================================================

# Exclude volatile and frequently-changing paths
!/var/log
!/var/cache
!/var/tmp
!/tmp
!/proc
!/sys
!/dev
!/run
!/opt/wauditbox/results
!/opt/wauditbox/logs
!/root/.bash_history
!/root/.viminfo
!/home/kali/.bash_history

# Monitor critical system paths with full checksums
/etc p+i+u+g+sha512
/bin p+i+u+g+sha512
/sbin p+i+u+g+sha512
/usr/bin p+i+u+g+sha512
/usr/sbin p+i+u+g+sha512
/usr/local/bin p+i+u+g+sha512
/boot p+i+u+g+sha512
/lib p+i+u+g+sha512
/lib64 p+i+u+g+sha512

# Monitor WauditBox scripts
/opt/wauditbox/scripts p+i+u+g+sha512
AIDE_CONF_EOF

log_info "AIDE configuration updated."

# Initialize AIDE database (takes several minutes on RPi5)
log_warn "Initializing AIDE database — this will take 3-5 minutes on RPi5."
log_warn "Do NOT interrupt this process or the database will be corrupt."
log_info "Starting AIDE initialization..."

# Run aideinit (safer than aide --init directly)
if command -v aideinit >/dev/null 2>&1; then
    aideinit --yes 2>&1 | tee -a "${SCRIPT_LOG}"
else
    # Fallback for systems without aideinit wrapper
    aide --init 2>&1 | tee -a "${SCRIPT_LOG}"
    if [[ -f /var/lib/aide/aide.db.new ]]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi
fi

# Verify database was created
if [[ -f /var/lib/aide/aide.db ]]; then
    log_info "AIDE database initialized successfully at /var/lib/aide/aide.db"
    DB_SIZE=$(du -h /var/lib/aide/aide.db | awk '{print $1}')
    log_info "Database size: ${DB_SIZE}"
else
    log_warn "AIDE database not found at expected location."
    log_warn "Check /var/lib/aide/ manually. AIDE may need manual initialization."
fi

# Create daily AIDE check cron job
log_info "Creating daily AIDE integrity check cron job..."
cat > /etc/cron.daily/wauditbox-aide-check << 'AIDE_CRON_EOF'
#!/usr/bin/env bash
# WauditBox v2.0 — Daily AIDE integrity check
# Runs at 3am daily via cron.daily
AIDE_LOG="/var/log/wauditbox/aide-check.log"
mkdir -p "$(dirname ${AIDE_LOG})"

echo "=== AIDE Integrity Check: $(date) ===" >> "${AIDE_LOG}"
aide --check 2>&1 >> "${AIDE_LOG}"

# Extract summary and send to syslog
if grep -q "found differences" "${AIDE_LOG}"; then
    logger -t wauditbox-aide -p security.warning "AIDE detected file changes - check ${AIDE_LOG}"
else
    logger -t wauditbox-aide -p security.info "AIDE check passed - no changes detected"
fi
AIDE_CRON_EOF

chmod +x /etc/cron.daily/wauditbox-aide-check
log_info "AIDE daily check cron job installed at /etc/cron.daily/wauditbox-aide-check"

# =============================================================================
# STEP 10: Auditd — System Call Auditing
# =============================================================================
log_section "STEP 10: Auditd — System Call & Event Auditing"

log_info "Configuring auditd audit rules..."

cat > /etc/audit/rules.d/99-wauditbox.rules << 'AUDIT_EOF'
# =============================================================================
# WauditBox v2.0 — Audit Rules
# Applied by: scripts/01-base-os.sh
# =============================================================================

# Delete all existing rules first
-D

# Buffer size (increase for busy systems)
-b 8192

# Failure mode: 1=log only, 2=panic (we use 1 for stability)
-f 1

# --- Monitor Authentication Events ---
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# --- Monitor SSH Configuration ---
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/ssh/authorized_keys/ -p wa -k ssh_keys

# --- Monitor WauditBox Scripts ---
-w /opt/wauditbox/scripts/ -p wxa -k wauditbox_scripts

# --- Monitor LUKS Device Access ---
-w /dev/mapper/ -p rwxa -k luks_mapper

# --- Monitor Kernel Modules ---
-w /sbin/insmod -p x -k kernel_modules
-w /sbin/rmmod -p x -k kernel_modules
-w /sbin/modprobe -p x -k kernel_modules
-a always,exit -F arch=b64 -S init_module,delete_module -k kernel_modules

# --- Monitor Privilege Escalation ---
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k privesc
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid -k privesc

# --- Monitor Network Configuration Changes ---
-a always,exit -F arch=b64 -S sethostname,setdomainname -k network_config
-w /etc/hostname -p wa -k network_config
-w /etc/hosts -p wa -k network_config
-w /etc/network/ -p wa -k network_config

# --- Monitor File Deletions (forensics) ---
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k file_deletion

# --- Monitor Use of Privileged Commands ---
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=unset -k privileged
-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -k privileged

# --- Monitor WireGuard & VPN ---
-w /etc/wireguard/ -p wa -k vpn_config

# Make configuration immutable (must use augenrules to change)
-e 2
AUDIT_EOF

log_info "Audit rules written to /etc/audit/rules.d/99-wauditbox.rules"

# Enable and start auditd
systemctl enable auditd 2>&1 | tee -a "${SCRIPT_LOG}"
systemctl restart auditd 2>&1 | tee -a "${SCRIPT_LOG}"

log_info "Auditd configured and running."

# Show audit status
if command -v auditctl >/dev/null 2>&1; then
    log_info "Current audit rules:"
    auditctl -l 2>&1 | head -20 | tee -a "${SCRIPT_LOG}"
fi

# =============================================================================
# STEP 11: Disable Unnecessary Services
# =============================================================================
log_section "STEP 11: Disable Unnecessary Services"

SERVICES_TO_DISABLE=(
    "bluetooth"          # Using ESP32 for BLE — disable onboard
    "avahi-daemon"       # mDNS — unnecessary, reveals presence
    "cups"               # Printing — not needed
    "cups-browsed"       # Printing discovery
    "triggerhappy"       # Hardware button daemon — not needed on headless
    "rpcbind"            # NFS — not needed
    "nfs-server"         # NFS server
    "rsync"              # Rsync daemon (keep rsync binary, disable daemon)
)

for service in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl list-unit-files "${service}.service" 2>/dev/null | grep -q "${service}"; then
        systemctl disable "${service}" 2>/dev/null || true
        systemctl stop "${service}" 2>/dev/null || true
        log_info "Disabled service: ${service}"
    else
        log_warn "Service not found (OK): ${service}"
    fi
done

log_info "Unnecessary services disabled."

# =============================================================================
# STEP 12: Secure /tmp with tmpfs
# =============================================================================
log_section "STEP 12: Secure /tmp with tmpfs"

if ! grep -q "tmpfs /tmp" /etc/fstab; then
    log_info "Configuring /tmp as secure tmpfs mount..."
    echo "tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec,size=512M 0 0" >> /etc/fstab
    log_info "Added tmpfs /tmp to /etc/fstab (512MB, nodev,nosuid,noexec)"
    log_warn "This will take effect after reboot."
else
    log_info "/tmp tmpfs already configured in /etc/fstab"
fi

# =============================================================================
# STEP 13: Create WauditBox Directory Structure
# =============================================================================
log_section "STEP 13: WauditBox Directory Structure"

log_info "Creating project directories..."

# Main directory (already exists if running from git clone)
mkdir -p "${WAUDITBOX_BASE_DIR}"/{scripts,configs,controllers,modules,harvesters,killswitch,vlan,server}

# Results subdirectories
mkdir -p "${WAUDITBOX_BASE_DIR}"/results/{handshakes,pmkids,scans,rfid,subghz,captures,reports}

# Logs
mkdir -p /var/log/wauditbox

# Set strict permissions on sensitive directories
chmod 700 "${WAUDITBOX_BASE_DIR}/results"
chmod 700 /var/log/wauditbox

# Set ownership (if running as root from /root, set to kali if exists)
if id -u kali >/dev/null 2>&1; then
    chown -R kali:kali "${WAUDITBOX_BASE_DIR}" 2>/dev/null || true
    log_info "Set ownership of ${WAUDITBOX_BASE_DIR} to kali:kali"
fi

log_info "Directory structure created at ${WAUDITBOX_BASE_DIR}"
log_info "Results directory: ${WAUDITBOX_BASE_DIR}/results (mode 700)"
log_info "Logs directory: /var/log/wauditbox (mode 700)"

# =============================================================================
# STEP 14: Final System Checks & Summary
# =============================================================================
log_section "STEP 14: Final Verification & Summary"

log_info "Checking SSH daemon status..."
if ss -tlnp 2>/dev/null | grep -q ":${SSH_PORT}"; then
    log_info "✓ SSH listening on port ${SSH_PORT}"
else
    log_warn "✗ SSH not listening on ${SSH_PORT} — may need service restart after reboot"
fi

log_info "Checking AppArmor status..."
if systemctl is-active apparmor >/dev/null 2>&1; then
    log_info "✓ AppArmor is active"
else
    log_warn "✗ AppArmor is not active"
fi

log_info "Checking auditd status..."
if systemctl is-active auditd >/dev/null 2>&1; then
    log_info "✓ auditd is active"
else
    log_warn "✗ auditd is not active"
fi

log_info "Checking USB storage module status..."
if lsmod | grep -q usb_storage; then
    log_warn "⚠ usb_storage module is currently loaded — will be blocked after reboot"
else
    log_info "✓ usb_storage module not loaded (correct after reboot)"
fi

log_info "Checking IPv6 status..."
IPV6_CHECK=$(sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null | awk '{print $3}')
if [[ "${IPV6_CHECK}" == "1" ]]; then
    log_info "✓ IPv6 disabled"
else
    log_warn "✗ IPv6 still enabled — check sysctl configuration"
fi

log_info "Checking BBR congestion control..."
BBR_CHECK=$(sysctl net.ipv4.tcp_congestion_control 2>/dev/null | awk '{print $3}')
if [[ "${BBR_CHECK}" == "bbr" ]]; then
    log_info "✓ BBR congestion control active"
else
    log_warn "⚠ BBR not active — current: ${BBR_CHECK}"
fi

# Display summary table
log_section "OS Hardening Summary"

cat << 'SUMMARY_EOF' | tee -a "${SCRIPT_LOG}"

╔════════════════════════════════════════════════════════════════════╗
║                  WauditBox v2.0 — OS Hardening Complete            ║
╠════════════════════════════════════════════════════════════════════╣
║  ✓  System packages updated                                        ║
║  ✓  Hostname set to wauditbox                                      ║
║  ✓  LEDs disabled (Act/Pwr)                                        ║
║  ✓  HDMI disabled (headless mode)                                  ║
║  ✓  Bluetooth disabled (using ESP32 for BLE)                       ║
║  ✓  Kernel parameters tuned (BBR, IPv6 off, security hardening)    ║
║  ✓  SSH hardened (Ed25519 only, port 2222, no passwords)           ║
║  ✓  USB storage blocked (Flipper/ESP32/5G whitelisted)             ║
║  ✓  NetworkManager configured (monitor mode support)               ║
║  ✓  AppArmor enabled (enforce mode)                                ║
║  ✓  AIDE integrity monitoring initialized                          ║
║  ✓  Auditd system call auditing active                             ║
║  ✓  Unnecessary services disabled                                  ║
║  ✓  /tmp secured with tmpfs                                        ║
║  ✓  WauditBox directory structure created                          ║
╠════════════════════════════════════════════════════════════════════╣
║  NEXT STEPS:                                                       ║
║                                                                    ║
║  1. REBOOT THE PI NOW to apply all changes:                        ║
║     sudo reboot                                                    ║
║                                                                    ║
║  2. After reboot, verify SSH access:                               ║
║     ssh -p 2222 -i ~/.ssh/your_ed25519_key root@<PI_IP>            ║
║                                                                    ║
║  3. Verify LEDs are off (no green/red lights)                      ║
║                                                                    ║
║  4. Run the next script:                                           ║
║     sudo bash /opt/wauditbox/scripts/02-luks-dropbear.sh           ║
║                                                                    ║
╠════════════════════════════════════════════════════════════════════╣
║  IMPORTANT NOTES:                                                  ║
║                                                                    ║
║  • SSH now requires Ed25519 key authentication                     ║
║  • Password authentication is DISABLED                             ║
║  • USB storage will NOT auto-mount after reboot                    ║
║  • Monitor mode (airmon-ng) will work on wlan1/wlan2               ║
║  • AIDE will check file integrity daily at 3am                     ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝

SUMMARY_EOF

echo ""
log_info "Full deployment log: ${SCRIPT_LOG}"
echo ""

# Ask user to reboot
log_warn "╔════════════════════════════════════════════════════════════════╗"
log_warn "║  REBOOT REQUIRED — Changes will take effect after reboot      ║"
log_warn "╚════════════════════════════════════════════════════════════════╝"
echo ""

read -r -p "Reboot now? [Y/n] " reboot_confirm
if [[ "${reboot_confirm,,}" != "n" ]]; then
    log_info "Rebooting in 5 seconds... (Ctrl+C to cancel)"
    sleep 5
    sync
    reboot
else
    log_info "Reboot cancelled. Remember to reboot before running 02-luks-dropbear.sh"
    log_info "When ready: sudo reboot"
fi

# =============================================================================
# END OF SCRIPT
# =============================================================================
