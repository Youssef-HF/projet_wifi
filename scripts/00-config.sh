#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — 00-config.sh
# Global configuration — sourced by all other scripts
# EDIT THIS FILE FIRST before running any other script
# =============================================================================

# --- [ IDENTITY ] ------------------------------------------------------------
export WAUDITBOX_VERSION="2.0"
export WAUDITBOX_HOSTNAME="wauditbox"
export WAUDITBOX_BASE_DIR="/opt/wauditbox"

# --- [ STORAGE ] -------------------------------------------------------------
# Verify with 'lsblk' before running 02-luks-dropbear.sh
export LUKS_DEVICE="/dev/mmcblk0p2"
export LUKS_MAPPER_NAME="wauditbox-crypt"

# --- [ NETWORK INTERFACES ] --------------------------------------------------
# Verify with 'ip link show' after first boot
export ETH_IFACE="eth0"
export WIFI_IFACE_AUDIT="wlan1"       # Alfa AWUS036ACH
export WIFI_IFACE_CAPTURE="wlan2"     # Alfa AWUS036NHA
export MODEM_IFACE="wwan0"           # 5G SIM8200EA-M2
export MODEM_USB_ID="2c7c:0800"      # lsusb VID:PID — verify on your hardware

# --- [ SSH ] -----------------------------------------------------------------
export SSH_PORT="2222"
export DROPBEAR_PORT="22222"
# REPLACE with your actual Ed25519 public key:
# Generate: ssh-keygen -t ed25519 -C "wauditbox-operator"
export OPERATOR_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI__REPLACE_WITH_YOUR_KEY__ wauditbox-operator"

# --- [ WIREGUARD ] -----------------------------------------------------------
export WG_IFACE="wg0"
export WG_PORT="51820"
export WG_CLIENT_IP="10.200.1.1/16"
export WG_SERVER_ENDPOINT="REPLACE_WITH_SERVER_IP_OR_DOMAIN:51820"
export WG_SERVER_PUBKEY="REPLACE_WITH_SERVER_WG_PUBLIC_KEY"
export WG_PRESHARED_KEY="REPLACE_WITH_PRESHARED_KEY"

# --- [ KILL SWITCH ] ---------------------------------------------------------
export HEARTBEAT_SERVER="10.200.0.1"
export HEARTBEAT_INTERVAL=60
export HEARTBEAT_MAX_FAILURES=3

# --- [ UFW ] -----------------------------------------------------------------
export UFW_SSH_PORT="${SSH_PORT}"
export UFW_DROPBEAR_PORT="${DROPBEAR_PORT}"
export UFW_WG_PORT="${WG_PORT}"

# --- [ FAIL2BAN ] ------------------------------------------------------------
export F2B_MAX_RETRY=3
export F2B_BAN_TIME="1h"
export F2B_FIND_TIME="10m"

# --- [ LOGGING ] -------------------------------------------------------------
export LOG_DIR="/var/log/wauditbox"
export SCRIPT_LOG="${LOG_DIR}/deploy.log"

# --- [ COLORS ] --------------------------------------------------------------
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[1;33m'
export BLUE='\033[0;34m'
export CYAN='\033[0;36m'
export BOLD='\033[1m'
export NC='\033[0m'

# --- [ HELPERS ] -------------------------------------------------------------
log_info()    { echo -e "${GREEN}[+]${NC} $*" | tee -a "${SCRIPT_LOG:-/tmp/wauditbox.log}"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $*" | tee -a "${SCRIPT_LOG:-/tmp/wauditbox.log}"; }
log_error()   { echo -e "${RED}[-]${NC} $*" | tee -a "${SCRIPT_LOG:-/tmp/wauditbox.log}"; }
log_section() { echo -e "\n${BLUE}${BOLD}[===] $* [===]${NC}" | tee -a "${SCRIPT_LOG:-/tmp/wauditbox.log}"; }

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo -e "${RED}[-]${NC} Must be run as root: sudo bash $0"
        exit 1
    fi
}

check_rpi5() {
    if ! grep -q "Raspberry Pi 5" /proc/cpuinfo 2>/dev/null; then
        log_warn "Not detected as RPi5. Continue? [y/N]"
        read -r c; [[ "${c,,}" != "y" ]] && exit 1
    fi
}

confirm_destructive() {
    log_warn "DESTRUCTIVE: $1 — Type CONFIRM to proceed:"
    read -r c; [[ "${c}" != "CONFIRM" ]] && { log_error "Aborted."; exit 1; }
}
