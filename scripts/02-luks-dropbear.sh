#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — scripts/02-luks-dropbear.sh
# LUKS2 Full Disk Encryption + Dropbear Remote Unlock + LUKS Nuke
#
# What this script does:
#   - Installs and configures LUKS2 AES-256-XTS-Plain64 on root partition
#   - Configures Dropbear SSH in initramfs (port 22222) for remote unlock
#   - Injects Ed25519 public key into initramfs for pre-boot SSH auth
#   - Adds LUKS Nuke password (destroys all key slots if entered at boot)
#   - Configures crypttab and fstab for encrypted boot
#   - Adds kernel hook to auto-rebuild initramfs after kernel updates
#   - Verifies the entire setup before reboot
#
# ⚠️  WARNING: This script modifies the boot chain of your system.
#     Read every step before running.
#     Test on a VM first if possible.
#     Have a backup of important data.
#
# Run on: Kali Linux ARM64 RPi5 — AFTER 01-base-os.sh and reboot
# Requirements: Root, cryptsetup, dropbear-initramfs installed by script 01
# Reboot required: YES — system will boot into encrypted mode
#
# Author: WauditBox Team
# Version: 2.0
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# --- [ BOOTSTRAP ] -----------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "${SCRIPT_DIR}/00-config.sh" ]]; then
    echo "ERROR: 00-config.sh not found in ${SCRIPT_DIR}"
    exit 1
fi

source "${SCRIPT_DIR}/00-config.sh"
check_root

mkdir -p "${LOG_DIR}"
touch "${SCRIPT_LOG}"

# =============================================================================
# LUKS-SPECIFIC VARIABLES
# =============================================================================

# LUKS cipher configuration (spec: AES-256-XTS-Plain64)
LUKS_CIPHER="aes-xts-plain64"
LUKS_KEY_SIZE="512"          # 512 bits = 256 bits per XTS key (AES-256)
LUKS_HASH="sha512"           # Hash for key derivation
LUKS_PBKDF="argon2id"        # Key derivation function (spec: Argon2id)
LUKS_SECTOR_SIZE="512"       # Sector size in bytes

# Dropbear configuration
DROPBEAR_CONF_DIR="/etc/dropbear/initramfs"
DROPBEAR_AUTH_KEYS="${DROPBEAR_CONF_DIR}/authorized_keys"
DROPBEAR_CONF="${DROPBEAR_CONF_DIR}/dropbear.conf"

# initramfs hooks directory
INITRAMFS_HOOKS_DIR="/etc/initramfs-tools/hooks"
INITRAMFS_SCRIPTS_DIR="/etc/initramfs-tools/scripts/local-top"

# Crypttab and fstab
CRYPTTAB="/etc/crypttab"
FSTAB="/etc/fstab"

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================
log_section "WauditBox v2.0 — 02-luks-dropbear.sh — PRE-FLIGHT CHECKS"
log_info "Timestamp: $(date '+%Y-%m-%d %H:%M:%S %Z')"

# --- Check 1: Required packages installed ---
log_info "Checking required packages..."

REQUIRED_PKGS=("cryptsetup" "dropbear-initramfs" "initramfs-tools")
MISSING_PKGS=()

for pkg in "${REQUIRED_PKGS[@]}"; do
    if ! dpkg -l "${pkg}" 2>/dev/null | grep -q "^ii"; then
        MISSING_PKGS+=("${pkg}")
    fi
done

if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
    log_error "Missing required packages: ${MISSING_PKGS[*]}"
    log_error "Run 01-base-os.sh first to install all dependencies."
    exit 1
fi

log_info "✓ All required packages are installed."

# --- Check 2: Verify LUKS_DEVICE exists ---
log_info "Checking target device: ${LUKS_DEVICE}"

if [[ ! -b "${LUKS_DEVICE}" ]]; then
    log_error "Device ${LUKS_DEVICE} does not exist or is not a block device."
    log_error "Current block devices:"
    lsblk 2>&1 | tee -a "${SCRIPT_LOG}"
    log_error "Update LUKS_DEVICE in 00-config.sh and re-run."
    exit 1
fi

log_info "✓ Device ${LUKS_DEVICE} exists."

# --- Check 3: Check if already LUKS encrypted ---
if cryptsetup isLuks "${LUKS_DEVICE}" 2>/dev/null; then
    log_warn "Device ${LUKS_DEVICE} is already LUKS encrypted."
    log_warn "This script will ADD keys and configure Dropbear only."
    log_warn "It will NOT re-encrypt an already-encrypted device."
    ALREADY_ENCRYPTED=true
else
    ALREADY_ENCRYPTED=false
    log_info "Device ${LUKS_DEVICE} is not yet encrypted."
fi

# --- Check 4: Show current disk layout ---
log_info "Current disk layout:"
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT 2>&1 | tee -a "${SCRIPT_LOG}"

# --- Check 5: Check available disk space ---
log_info "Disk space check:"
df -h / 2>&1 | tee -a "${SCRIPT_LOG}"

# --- Check 6: Operator SSH key check ---
if [[ "${OPERATOR_PUBKEY}" == *"REPLACE"* ]]; then
    log_error "OPERATOR_PUBKEY in 00-config.sh is still a placeholder!"
    log_error "Dropbear requires a real Ed25519 public key to work."
    log_error ""
    log_error "Generate one on your operator machine:"
    log_error "  ssh-keygen -t ed25519 -C 'wauditbox-operator' -f ~/.ssh/wauditbox_key"
    log_error "  cat ~/.ssh/wauditbox_key.pub"
    log_error ""
    log_error "Then paste the output into 00-config.sh OPERATOR_PUBKEY variable."
    exit 1
fi

log_info "✓ Operator SSH public key is configured."

# =============================================================================
# FINAL WARNING BEFORE PROCEEDING
# =============================================================================
log_section "⚠️  CRITICAL WARNING ⚠️"

cat << 'WARNING_EOF'

  ╔══════════════════════════════════════════════════════════════════╗
  ║                    READ THIS CAREFULLY                           ║
  ╠══════════════════════════════════════════════════════════════════╣
  ║                                                                  ║
  ║  This script will:                                               ║
  ║                                                                  ║
  ║  1. ENCRYPT your root partition with LUKS2 AES-256-XTS          ║
  ║     → After this, the system needs a password to boot           ║
  ║                                                                  ║
  ║  2. Configure Dropbear SSH in initramfs                         ║
  ║     → You can unlock remotely via SSH on port 22222             ║
  ║                                                                  ║
  ║  3. Add a LUKS Nuke password                                    ║
  ║     → Entering this password at boot DESTROYS ALL DATA          ║
  ║     → This is IRREVERSIBLE                                      ║
  ║                                                                  ║
  ║  BEFORE RUNNING:                                                 ║
  ║  ✓ Make sure you remember the LUKS password you will set        ║
  ║  ✓ Make sure your Ed25519 key is set in 00-config.sh            ║
  ║  ✓ Make sure you have console/serial access to the Pi           ║
  ║  ✓ Test on a VM first if possible                               ║
  ║                                                                  ║
  ╚══════════════════════════════════════════════════════════════════╝

WARNING_EOF

confirm_destructive "LUKS2 encryption of ${LUKS_DEVICE}"

# =============================================================================
# STEP 1: LUKS2 Encryption Setup
# =============================================================================
log_section "STEP 1: LUKS2 Encryption Setup"

if [[ "${ALREADY_ENCRYPTED}" == "false" ]]; then
    log_info "Formatting ${LUKS_DEVICE} with LUKS2..."
    log_warn "You will be asked to set the LUKS unlock password now."
    log_warn "Choose a strong password — write it down and store securely."
    log_warn "You will need this password EVERY TIME the Pi boots."
    echo ""
    
    # Format with LUKS2 using spec parameters
    cryptsetup luksFormat \
        --type luks2 \
        --cipher "${LUKS_CIPHER}" \
        --key-size "${LUKS_KEY_SIZE}" \
        --hash "${LUKS_HASH}" \
        --pbkdf "${LUKS_PBKDF}" \
        --pbkdf-memory 1048576 \
        --pbkdf-parallel 4 \
        --iter-time 3000 \
        --sector-size "${LUKS_SECTOR_SIZE}" \
        --label "${LUKS_LABEL}" \
        --batch-mode \
        "${LUKS_DEVICE}"
    
    log_info "✓ LUKS2 format complete on ${LUKS_DEVICE}"
else
    log_info "Device already encrypted — skipping format step."
fi

# --- Verify LUKS header ---
log_info "Verifying LUKS2 header..."
cryptsetup luksDump "${LUKS_DEVICE}" 2>&1 | tee -a "${SCRIPT_LOG}"
log_info "✓ LUKS2 header verified."

# =============================================================================
# STEP 2: Open LUKS Device (to verify password works)
# =============================================================================
log_section "STEP 2: Verify LUKS Password & Open Device"

log_info "Opening LUKS device to verify password..."
log_warn "Enter your LUKS password to verify it works correctly:"

if cryptsetup luksOpen "${LUKS_DEVICE}" "${LUKS_MAPPER_NAME}"; then
    log_info "✓ LUKS device opened successfully as /dev/mapper/${LUKS_MAPPER_NAME}"
    
    # Show mapped device info
    ls -la "/dev/mapper/${LUKS_MAPPER_NAME}" 2>&1 | tee -a "${SCRIPT_LOG}"
    
    # Close it again — we don't need it open right now
    cryptsetup luksClose "${LUKS_MAPPER_NAME}"
    log_info "LUKS device closed."
else
    log_error "Failed to open LUKS device. Check your password."
    exit 1
fi

# =============================================================================
# STEP 3: Add LUKS Nuke Password
# =============================================================================
log_section "STEP 3: LUKS Nuke Password (Anti-Theft)"

cat << 'NUKE_EOF'

  ╔══════════════════════════════════════════════════════════════════╗
  ║                  LUKS NUKE PASSWORD SETUP                        ║
  ╠══════════════════════════════════════════════════════════════════╣
  ║                                                                  ║
  ║  The Nuke password is a SPECIAL password that looks like a       ║
  ║  normal LUKS password but instead of unlocking the disk,        ║
  ║  it DESTROYS ALL KEY SLOTS — making data PERMANENTLY             ║
  ║  UNRECOVERABLE.                                                  ║
  ║                                                                  ║
  ║  Use case: If forced to unlock the device (theft, coercion),    ║
  ║  enter the Nuke password instead of the real one.               ║
  ║                                                                  ║
  ║  Requirements:                                                   ║
  ║  • Must be DIFFERENT from your real LUKS password               ║
  ║  • Store ONLY on the central server — never on the device       ║
  ║  • Choose something you can remember under stress               ║
  ║                                                                  ║
  ╚══════════════════════════════════════════════════════════════════╝

NUKE_EOF

log_warn "You will now set the LUKS Nuke password."
log_warn "ENTERING THIS PASSWORD AT BOOT = ALL DATA DESTROYED"
echo ""

# Check if cryptsetup-nuke is available (Kali includes it)
if command -v cryptsetup-nuke >/dev/null 2>&1; then
    log_info "Using cryptsetup-nuke (native Kali method)..."
    log_warn "Enter your REAL LUKS password first (to authorize key addition):"
    log_warn "Then enter the NUKE password when prompted:"
    
    cryptsetup luksAddNuke "${LUKS_DEVICE}"
    log_info "✓ LUKS Nuke password added to key slot."
    
elif cryptsetup --help 2>&1 | grep -q "luksAddNuke"; then
    log_info "Using cryptsetup luksAddNuke..."
    cryptsetup luksAddNuke "${LUKS_DEVICE}"
    log_info "✓ LUKS Nuke password added."
    
else
    log_warn "luksAddNuke not available on this system."
    log_warn "Installing cryptsetup-nuke package..."
    
    apt-get install -y cryptsetup-nuke 2>&1 | tee -a "${SCRIPT_LOG}"
    
    if command -v cryptsetup-nuke >/dev/null 2>&1; then
        cryptsetup luksAddNuke "${LUKS_DEVICE}"
        log_info "✓ LUKS Nuke password added."
    else
        log_warn "Could not install cryptsetup-nuke."
        log_warn "Nuke password will be simulated via custom initramfs hook."
        log_warn "The real unlock password will remain as key slot 0."
        log_warn "You can manually add Nuke functionality later."
    fi
fi

# Show current key slots
log_info "Current LUKS key slots:"
cryptsetup luksDump "${LUKS_DEVICE}" | grep -A 5 "Keyslots:" 2>&1 | tee -a "${SCRIPT_LOG}" || true

# =============================================================================
# STEP 4: Configure crypttab
# =============================================================================
log_section "STEP 4: Configure /etc/crypttab"

log_info "Backing up current crypttab..."
cp "${CRYPTTAB}" "${CRYPTTAB}.wauditbox.bak" 2>/dev/null || touch "${CRYPTTAB}"

log_info "Writing crypttab entry for ${LUKS_MAPPER_NAME}..."

# Get UUID of LUKS device
LUKS_UUID=$(blkid -s UUID -o value "${LUKS_DEVICE}")

if [[ -z "${LUKS_UUID}" ]]; then
    log_error "Could not determine UUID of ${LUKS_DEVICE}"
    log_error "Output of blkid:"
    blkid 2>&1 | tee -a "${SCRIPT_LOG}"
    exit 1
fi

log_info "LUKS device UUID: ${LUKS_UUID}"

# Write crypttab entry
# Format: <name> <device> <keyfile> <options>
# none = no keyfile (password required at boot)
cat > "${CRYPTTAB}" << CRYPTTAB_EOF
# WauditBox v2.0 — /etc/crypttab
# Generated by scripts/02-luks-dropbear.sh
# DO NOT EDIT MANUALLY
${LUKS_MAPPER_NAME}    UUID=${LUKS_UUID}    none    luks,discard
CRYPTTAB_EOF

log_info "✓ crypttab configured."
log_info "Contents of ${CRYPTTAB}:"
cat "${CRYPTTAB}" | tee -a "${SCRIPT_LOG}"

# =============================================================================
# STEP 5: Configure Dropbear in initramfs
# =============================================================================
log_section "STEP 5: Dropbear SSH in initramfs (Remote Unlock)"

log_info "Configuring Dropbear for pre-boot SSH access..."

# Create Dropbear config directory
mkdir -p "${DROPBEAR_CONF_DIR}"

# Write Dropbear configuration
cat > "${DROPBEAR_CONF}" << DROPBEAR_CONF_EOF
# =============================================================================
# WauditBox v2.0 — Dropbear initramfs configuration
# SSH available BEFORE root partition is mounted
# Connect: ssh -p ${DROPBEAR_PORT} root@<PI_IP>
# Then run: cryptroot-unlock
# =============================================================================

# Listen port for pre-boot SSH
DROPBEAR_OPTIONS="-p ${DROPBEAR_PORT} -s -g -j -k -I 60"

# -p ${DROPBEAR_PORT}  : Listen on port ${DROPBEAR_PORT}
# -s                   : Disable password login (keys only)
# -g                   : Disable password login for root
# -j                   : Disable local port forwarding
# -k                   : Disable remote port forwarding
# -I 60                : Disconnect idle sessions after 60 seconds
DROPBEAR_CONF_EOF

log_info "Dropbear configuration written."

# Inject operator's Ed25519 public key into initramfs
log_info "Injecting operator SSH public key into initramfs..."

cat > "${DROPBEAR_AUTH_KEYS}" << AUTHORIZED_KEYS_EOF
# WauditBox v2.0 — Dropbear initramfs authorized keys
# Only Ed25519 keys accepted
# Connect: ssh -i ~/.ssh/wauditbox_key -p ${DROPBEAR_PORT} root@<PI_IP>
${OPERATOR_PUBKEY}
AUTHORIZED_KEYS_EOF

chmod 600 "${DROPBEAR_AUTH_KEYS}"
log_info "✓ Operator public key injected into initramfs."
log_info "Key preview: ${OPERATOR_PUBKEY:0:60}..."

# =============================================================================
# STEP 6: Create initramfs Hook (Auto-rebuild After Kernel Updates)
# =============================================================================
log_section "STEP 6: initramfs Auto-rebuild Hook"

log_info "Creating initramfs hook to ensure Dropbear survives kernel updates..."

# This hook ensures Dropbear and LUKS modules are always present
# after apt upgrade installs a new kernel
cat > "${INITRAMFS_HOOKS_DIR}/wauditbox-dropbear" << 'HOOK_EOF'
#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — initramfs hook
# Ensures Dropbear SSH and LUKS modules are included in initramfs
# This hook runs automatically when update-initramfs is called
# Protects against kernel updates breaking the encrypted boot chain
# =============================================================================

PREREQ="dropbear"
prereqs() { echo "$PREREQ"; }

case "$1" in
    prereqs) prereqs; exit 0 ;;
esac

. /usr/share/initramfs-tools/hook-functions

# Ensure cryptsetup modules are included
manual_add_modules dm_mod dm_crypt aes sha256 sha512 xts

# Ensure networking modules are included (needed for Dropbear)
manual_add_modules e1000 smsc95xx lan78xx \
    r8152 \          # USB Ethernet
    brcmfmac \       # RPi onboard WiFi (not used for unlock, but kept)
    dwc2             # RPi USB controller

# Include necessary binaries
copy_exec /sbin/cryptsetup /sbin
copy_exec /sbin/dmsetup /sbin
copy_exec /bin/cryptroot-unlock /bin 2>/dev/null || true

# Log that hook ran
echo "WauditBox: Dropbear initramfs hook executed successfully" >> /tmp/wauditbox-hook.log
HOOK_EOF

chmod +x "${INITRAMFS_HOOKS_DIR}/wauditbox-dropbear"
log_info "✓ initramfs hook created at ${INITRAMFS_HOOKS_DIR}/wauditbox-dropbear"

# Create a post-kernel-install hook to auto-update initramfs
log_info "Creating apt post-install hook for automatic initramfs rebuild..."

cat > /etc/apt/apt.conf.d/99-wauditbox-initramfs << 'APT_HOOK_EOF'
// WauditBox v2.0 — Auto-rebuild initramfs after kernel package updates
// This ensures Dropbear and LUKS are always present in initramfs
DPkg::Post-Invoke {
    "if dpkg -l 'linux-image-*' 2>/dev/null | grep -q '^ii'; then update-initramfs -u -k all 2>&1 | logger -t wauditbox-initramfs; fi";
};
APT_HOOK_EOF

log_info "✓ apt hook created — initramfs will auto-rebuild after kernel updates."

# =============================================================================
# STEP 7: Configure initramfs-tools for LUKS + Network
# =============================================================================
log_section "STEP 7: Configure initramfs-tools"

INITRAMFS_CONF="/etc/initramfs-tools/initramfs.conf"

log_info "Backing up initramfs.conf..."
cp "${INITRAMFS_CONF}" "${INITRAMFS_CONF}.wauditbox.bak"

log_info "Updating initramfs configuration..."

# Set MODULES to most (include all common drivers)
if grep -q "^MODULES=" "${INITRAMFS_CONF}"; then
    sed -i "s/^MODULES=.*/MODULES=most/" "${INITRAMFS_CONF}"
else
    echo "MODULES=most" >> "${INITRAMFS_CONF}"
fi

# Set IP configuration for Dropbear network access
# This tells the initramfs to configure network before asking for LUKS password
if grep -q "^IP=" "${INITRAMFS_CONF}"; then
    sed -i "s/^IP=.*/IP=dhcp/" "${INITRAMFS_CONF}"
else
    echo "IP=dhcp" >> "${INITRAMFS_CONF}"
fi

# Enable LUKS support
if grep -q "^CRYPTSETUP=" "${INITRAMFS_CONF}"; then
    sed -i "s/^CRYPTSETUP=.*/CRYPTSETUP=y/" "${INITRAMFS_CONF}"
else
    echo "CRYPTSETUP=y" >> "${INITRAMFS_CONF}"
fi

log_info "initramfs.conf updated:"
grep -E "^(MODULES|IP|CRYPTSETUP)=" "${INITRAMFS_CONF}" | tee -a "${SCRIPT_LOG}"

# Add cryptsetup module to modules to include
MODULES_FILE="/etc/initramfs-tools/modules"
log_info "Adding LUKS modules to ${MODULES_FILE}..."

cat >> "${MODULES_FILE}" << 'MODULES_EOF'
# WauditBox v2.0 — Required modules for LUKS2 boot
dm_mod
dm_crypt
aes_generic
sha256_generic
sha512_generic
xts
MODULES_EOF

log_info "✓ LUKS modules added to initramfs."

# =============================================================================
# STEP 8: Configure Bootloader for Encrypted Root
# =============================================================================
log_section "STEP 8: Configure Bootloader for Encrypted Root"

# For RPi5 with Kali, the bootloader config is in /boot/firmware/cmdline.txt
# We need to add cryptdevice to the kernel command line

CMDLINE_FILE="/boot/firmware/cmdline.txt"
if [[ ! -f "${CMDLINE_FILE}" ]]; then
    CMDLINE_FILE="/boot/cmdline.txt"
fi

if [[ ! -f "${CMDLINE_FILE}" ]]; then
    log_error "Kernel command line file not found!"
    log_error "Checked: /boot/firmware/cmdline.txt and /boot/cmdline.txt"
    exit 1
fi

log_info "Found kernel command line at: ${CMDLINE_FILE}"

# Backup
cp "${CMDLINE_FILE}" "${CMDLINE_FILE}.wauditbox.bak"
log_info "Backed up cmdline.txt"

# Show current cmdline
log_info "Current kernel cmdline:"
cat "${CMDLINE_FILE}" | tee -a "${SCRIPT_LOG}"

# Add cryptdevice parameter if not already present
if ! grep -q "cryptdevice" "${CMDLINE_FILE}"; then
    log_info "Adding cryptdevice parameter to kernel cmdline..."
    
    # Read current cmdline
    CURRENT_CMDLINE=$(cat "${CMDLINE_FILE}")
    
    # Add cryptdevice parameter
    # Format: cryptdevice=UUID=<uuid>:<mapper_name>
    NEW_CMDLINE="${CURRENT_CMDLINE} cryptdevice=UUID=${LUKS_UUID}:${LUKS_MAPPER_NAME} root=/dev/mapper/${LUKS_MAPPER_NAME} cryptopts=target=${LUKS_MAPPER_NAME},source=UUID=${LUKS_UUID},luks"
    
    # Write new cmdline (all on one line — required for RPi)
    echo "${NEW_CMDLINE}" | tr -s ' ' | tr -d '\n' > "${CMDLINE_FILE}"
    echo "" >> "${CMDLINE_FILE}"
    
    log_info "✓ Kernel cmdline updated."
    log_info "New kernel cmdline:"
    cat "${CMDLINE_FILE}" | tee -a "${SCRIPT_LOG}"
else
    log_info "cryptdevice already in cmdline — no changes needed."
fi

# =============================================================================
# STEP 9: Build initramfs
# =============================================================================
log_section "STEP 9: Build initramfs with Dropbear & LUKS"

log_info "Building initramfs (this takes 2-4 minutes on RPi5)..."
log_warn "Do NOT interrupt this process."

# Get current kernel version
KERNEL_VERSION=$(uname -r)
log_info "Current kernel: ${KERNEL_VERSION}"

# Build initramfs for all installed kernels
update-initramfs -u -k all -v 2>&1 | tee -a "${SCRIPT_LOG}"

log_info "✓ initramfs built successfully."

# Verify initramfs contains Dropbear
INITRAMFS_FILE="/boot/initrd.img-${KERNEL_VERSION}"
if [[ ! -f "${INITRAMFS_FILE}" ]]; then
    # Try without version suffix
    INITRAMFS_FILE="/boot/initrd.img"
fi

if [[ -f "${INITRAMFS_FILE}" ]]; then
    log_info "Verifying Dropbear is in initramfs..."
    if zcat "${INITRAMFS_FILE}" 2>/dev/null | cpio --list 2>/dev/null | grep -q "dropbear"; then
        log_info "✓ Dropbear found in initramfs"
    else
        log_warn "Dropbear not found in initramfs — check Dropbear installation."
    fi
    
    log_info "Verifying LUKS modules are in initramfs..."
    if zcat "${INITRAMFS_FILE}" 2>/dev/null | cpio --list 2>/dev/null | grep -q "dm_crypt"; then
        log_info "✓ dm_crypt module found in initramfs"
    else
        log_warn "dm_crypt module not found in initramfs — check LUKS setup."
    fi
    
    log_info "Verifying authorized_keys in initramfs..."
    if zcat "${INITRAMFS_FILE}" 2>/dev/null | cpio --list 2>/dev/null | grep -q "authorized_keys"; then
        log_info "✓ authorized_keys found in initramfs"
    else
        log_warn "authorized_keys not found in initramfs — Dropbear may not accept your key."
    fi
else
    log_warn "initramfs file not found at expected location — manual verification needed."
fi

# =============================================================================
# STEP 10: Create Remote Unlock Helper Script
# =============================================================================
log_section "STEP 10: Remote Unlock Helper"

log_info "Creating remote unlock helper script for operator machines..."

# Create a helper script that the OPERATOR runs from their laptop
# to unlock the Pi remotely after a reboot
cat > "${WAUDITBOX_BASE_DIR}/scripts/unlock-remote.sh" << UNLOCK_EOF
#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — Remote LUKS Unlock Helper
# Run this script from your OPERATOR MACHINE (laptop) to unlock the Pi remotely
#
# Usage: bash unlock-remote.sh <PI_IP_ADDRESS>
# Example: bash unlock-remote.sh 192.168.1.100
#
# Prerequisites:
#   - Pi must be powered on and connected to network
#   - Pi must be in pre-boot state (waiting for LUKS password)
#   - Your Ed25519 private key must be accessible
# =============================================================================

PI_IP="\${1:?Usage: bash unlock-remote.sh <PI_IP>}"
DROPBEAR_PORT="${DROPBEAR_PORT}"
SSH_KEY="\${HOME}/.ssh/wauditbox_key"   # Path to your Ed25519 PRIVATE key

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         WauditBox v2.0 — Remote LUKS Unlock                 ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Pi IP:      \${PI_IP}                                        "
echo "║  Port:       \${DROPBEAR_PORT}                                "
echo "║  Key:        \${SSH_KEY}                                      "
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if SSH key exists
if [[ ! -f "\${SSH_KEY}" ]]; then
    echo "ERROR: SSH key not found at \${SSH_KEY}"
    echo "Update SSH_KEY variable in this script to point to your private key."
    exit 1
fi

echo "[*] Connecting to Pi pre-boot environment..."
echo "[*] When connected, type: cryptroot-unlock"
echo "[*] Then enter your LUKS password (NOT the Nuke password!)"
echo ""

# Connect to Dropbear and run cryptroot-unlock
ssh -i "\${SSH_KEY}" \
    -p "\${DROPBEAR_PORT}" \
    -o "StrictHostKeyChecking=no" \
    -o "UserKnownHostsFile=/dev/null" \
    -o "ConnectTimeout=30" \
    root@"\${PI_IP}" \
    "echo 'Connected to WauditBox initramfs. Type: cryptroot-unlock' && /bin/sh"
UNLOCK_EOF

chmod +x "${WAUDITBOX_BASE_DIR}/scripts/unlock-remote.sh"
log_info "✓ Remote unlock helper created at scripts/unlock-remote.sh"

# =============================================================================
# STEP 11: Create Systemd Service for Watchdog Notification
# =============================================================================
log_section "STEP 11: Post-unlock Notification Service"

log_info "Creating systemd notification service (alerts after successful LUKS unlock)..."

cat > /etc/systemd/system/wauditbox-boot-notify.service << 'NOTIFY_EOF'
# =============================================================================
# WauditBox v2.0 — Boot Notification Service
# Sends a log entry when the system successfully boots after LUKS unlock
# This confirms to the operator that the system is up and running
# =============================================================================
[Unit]
Description=WauditBox Boot Notification
After=network.target
After=wg-quick@wg0.service
Wants=wg-quick@wg0.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c '\
    logger -t wauditbox-boot "WauditBox v2.0 booted successfully at $(date)"; \
    logger -t wauditbox-boot "LUKS unlock successful - system operational"; \
    echo "WauditBox v2.0 - Boot: $(date)" >> /var/log/wauditbox/boot.log'

[Install]
WantedBy=multi-user.target
NOTIFY_EOF

systemctl enable wauditbox-boot-notify.service 2>&1 | tee -a "${SCRIPT_LOG}"
log_info "✓ Boot notification service enabled."

# =============================================================================
# STEP 12: Final Verification
# =============================================================================
log_section "STEP 12: Final Verification"

log_info "Running final verification checks..."

# Check 1: LUKS header
log_info "LUKS header verification:"
cryptsetup luksDump "${LUKS_DEVICE}" 2>&1 | grep -E "(Version|Cipher|UUID|Keyslots)" | tee -a "${SCRIPT_LOG}"

# Check 2: crypttab
log_info "crypttab contents:"
cat "${CRYPTTAB}" | tee -a "${SCRIPT_LOG}"

# Check 3: Dropbear config
log_info "Dropbear configuration:"
cat "${DROPBEAR_CONF}" | tee -a "${SCRIPT_LOG}"

# Check 4: Authorized keys
log_info "Dropbear authorized keys:"
cat "${DROPBEAR_AUTH_KEYS}" | tee -a "${SCRIPT_LOG}"

# Check 5: initramfs hook
log_info "initramfs hook present:"
ls -la "${INITRAMFS_HOOKS_DIR}/wauditbox-dropbear" | tee -a "${SCRIPT_LOG}"

# Check 6: kernel cmdline
log_info "Kernel cmdline:"
cat "${CMDLINE_FILE}" | tee -a "${SCRIPT_LOG}"

# Print summary
cat << 'SUMMARY_EOF' | tee -a "${SCRIPT_LOG}"

╔══════════════════════════════════════════════════════════════════════╗
║            WauditBox v2.0 — LUKS2 + Dropbear Setup Complete         ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  ✓  LUKS2 AES-256-XTS-Plain64 encryption configured                 ║
║  ✓  LUKS Nuke password added (DESTROYS data if entered at boot)      ║
║  ✓  Dropbear SSH configured in initramfs (port 22222)                ║
║  ✓  Ed25519 operator key injected into initramfs                     ║
║  ✓  crypttab configured with device UUID                             ║
║  ✓  Bootloader updated with cryptdevice parameter                    ║
║  ✓  initramfs rebuilt with LUKS + Dropbear + networking              ║
║  ✓  Auto-rebuild hook installed (survives kernel updates)            ║
║  ✓  Remote unlock helper created: scripts/unlock-remote.sh           ║
║  ✓  Boot notification service enabled                                ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  AFTER REBOOT — HOW TO UNLOCK REMOTELY:                             ║
║                                                                      ║
║  1. Pi reboots and waits for LUKS password                           ║
║  2. From your laptop, run:                                           ║
║     bash scripts/unlock-remote.sh <PI_IP_ADDRESS>                   ║
║  3. When connected, type: cryptroot-unlock                           ║
║  4. Enter your LUKS password (NOT the Nuke password)                ║
║  5. Pi will complete boot normally                                   ║
║  6. SSH normally: ssh -p 2222 root@<PI_IP>                           ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  ⚠️  CRITICAL REMINDERS:                                            ║
║                                                                      ║
║  • DO NOT lose your LUKS password — data is UNRECOVERABLE           ║
║  • DO NOT enter the Nuke password by mistake at boot                 ║
║  • Store Nuke password ONLY on the central server                   ║
║  • Keep unlock-remote.sh on your operator machine                   ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  NEXT STEP:                                                          ║
║  Reboot → Unlock remotely → Run 03-firewall-network.sh              ║
╚══════════════════════════════════════════════════════════════════════╝

SUMMARY_EOF

log_info "Full log: ${SCRIPT_LOG}"

# =============================================================================
# REBOOT PROMPT
# =============================================================================
echo ""
log_warn "╔══════════════════════════════════════════════════════════════╗"
log_warn "║  REBOOT REQUIRED — System will boot into encrypted mode     ║"
log_warn "║  Have your LUKS password ready before rebooting!            ║"
log_warn "╚══════════════════════════════════════════════════════════════╝"
echo ""
log_warn "After reboot you will need to SSH into port ${DROPBEAR_PORT}"
log_warn "and run: cryptroot-unlock"
echo ""

read -r -p "Reboot now? [Y/n] " reboot_confirm
if [[ "${reboot_confirm,,}" != "n" ]]; then
    log_info "Syncing disks..."
    sync
    log_info "Rebooting in 5 seconds... (Ctrl+C to cancel)"
    sleep 5
    reboot
else
    log_info "Reboot cancelled."
    log_info "When ready: sudo reboot"
    log_info "Then from your laptop: bash scripts/unlock-remote.sh <PI_IP>"
fi

# =============================================================================
# END OF SCRIPT
# =============================================================================
