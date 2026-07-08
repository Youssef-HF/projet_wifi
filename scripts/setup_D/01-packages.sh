#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/00-config.sh"
check_root

log_section "Package Installation"

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -q

DEBIAN_FRONTEND=noninteractive apt-get install -y -q \
    curl wget git vim tmux htop tree \
    ufw fail2ban \
    apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra \
    aide aide-common \
    cryptsetup cryptsetup-initramfs cryptsetup-bin \
    dropbear-initramfs dropbear-bin \
    net-tools iproute2 iputils-ping traceroute \
    iptables iptables-persistent nftables \
    dnsutils \
    wireguard wireguard-tools openresolv \
    modemmanager libmbim-utils libqmi-utils \
    usb-modeswitch usb-modeswitch-data \
    python3 python3-pip python3-venv \
    python3-serial python3-requests python3-psutil \
    aircrack-ng hcxdumptool hcxtools \
    reaver bully pixiewps \
    hostapd dnsmasq \
    bettercap \
    nmap masscan arp-scan netdiscover \
    macchanger \
    auditd audispd-plugins \
    build-essential libssl-dev libffi-dev python3-dev \
    jq bc lsof pv rsync \
    zip unzip

log_info "Packages installed."
