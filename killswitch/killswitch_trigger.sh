#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — killswitch/killswitch_trigger.sh
# Deployed to /usr/local/bin/wauditbox-killswitch-trigger by 05-killswitch.sh
# Called by: watchdog.py, udev rule (modem removal), systemd timer
# ARGUMENT: reason string (e.g., "heartbeat_failed", "modem_removed")
# WARNING: This script DESTROYS LUKS keys. Data becomes UNRECOVERABLE.
# =============================================================================
set -euo pipefail

REASON="${1:-unknown}"
LUKS_DEVICE="/dev/mmcblk0p2"          # Set by 00-config.sh at deploy time
WIPE_MB=100
LOG="/var/log/wauditbox/killswitch.log"

mkdir -p "$(dirname "${LOG}")"

log_ks() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] KILLSWITCH [${REASON}]: $*" | tee -a "${LOG}"
    logger -t wauditbox-killswitch "$*"
}

log_ks "=== KILL SWITCH ACTIVATED === Reason: ${REASON}"

# Step 1: Destroy LUKS key slots
log_ks "Step 1: Destroying LUKS key slots..."
cryptsetup luksKillSlot "${LUKS_DEVICE}" 0 --batch-mode 2>>"${LOG}" || true
cryptsetup luksKillSlot "${LUKS_DEVICE}" 1 --batch-mode 2>>"${LOG}" || true
log_ks "LUKS key slots destroyed."

# Step 2: Overwrite LUKS header (partial wipe — fast)
log_ks "Step 2: Overwriting LUKS header with random data (${WIPE_MB}MB)..."
dd if=/dev/urandom of="${LUKS_DEVICE}" bs=1M count="${WIPE_MB}" 2>>"${LOG}" || true
log_ks "Partial wipe complete."

# Step 3: Shutdown
log_ks "Step 3: Initiating emergency shutdown."
sync
shutdown -h now "WauditBox Kill Switch Activated: ${REASON}"
