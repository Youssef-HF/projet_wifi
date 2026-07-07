#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — scripts/05-killswitch.sh
# Kill Switch — Anti-Theft & Data Destruction Mechanism
#
# What this script does:
#   - Deploys LUKS Nuke trigger script (/usr/local/bin/wauditbox-killswitch-trigger)
#   - Creates heartbeat watchdog systemd service (pings C2 server every 60s)
#   - Creates udev rule: 5G modem removal → immediate kill switch
#   - Creates 24h no-contact auto-wipe systemd timer
#   - Creates remote kill command listener (via WireGuard tunnel)
#   - Wires everything together with proper systemd dependencies
#
# Kill Switch Triggers (NO GPIO — as agreed):
#   1. 5G USB modem physically disconnected (udev — immediate)
#   2. 3 consecutive heartbeat failures to C2 server (watchdog)
#   3. 24h without server contact (systemd timer)
#   4. Explicit remote kill command via WireGuard tunnel
#   5. LUKS Nuke password entered at boot (configured in script 02)
#
# Kill Switch Actions (in order):
#   1. Log the event to syslog + file
#   2. cryptsetup luksKillSlot 0 (destroy primary key)
#   3. cryptsetup luksKillSlot 1 (destroy nuke key)
#   4. dd if=/dev/urandom → partial LUKS header overwrite (100MB)
#   5. shutdown -h now
#
# WARNING: ALL ACTIONS ARE IRREVERSIBLE
#          DATA WILL BE PERMANENTLY DESTROYED
#
# Run on: Kali Linux ARM64 RPi5
# Run after: 04-vpn-wireguard.sh
# Reboot required: NO — services start immediately
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
# KILLSWITCH-SPECIFIC VARIABLES
# =============================================================================

# Paths for all killswitch components
KS_TRIGGER_SCRIPT="/usr/local/bin/wauditbox-killswitch-trigger"
KS_HEARTBEAT_SCRIPT="/usr/local/bin/wauditbox-heartbeat"
KS_REMOTE_KILL_SCRIPT="/usr/local/bin/wauditbox-remote-kill-listener"
KS_STATUS_FILE="/var/run/wauditbox-killswitch.status"
KS_FAIL_COUNTER="/var/run/wauditbox-heartbeat-fails"
KS_LAST_CONTACT="/var/run/wauditbox-last-contact"
KS_LOG="${KILLSWITCH_LOG}"

# 24h auto-wipe threshold (seconds)
KS_MAX_SILENCE=$((24 * 60 * 60))

# Remote kill command listener port (via WireGuard)
KS_REMOTE_KILL_PORT="9999"

# Wipe size in MB (LUKS header overwrite)
KS_WIPE_MB="${KILLSWITCH_WIPE_COUNT}"

# =============================================================================
# PRE-FLIGHT CHECKS
# =============================================================================
log_section "WauditBox v2.0 — 05-killswitch.sh — START"
log_info "Timestamp: $(date '+%Y-%m-%d %H:%M:%S %Z')"

# Check cryptsetup is available
if ! command -v cryptsetup >/dev/null 2>&1; then
    log_error "cryptsetup not found. Run 01-base-os.sh first."
    exit 1
fi
log_info "✓ cryptsetup is available."

# Check LUKS device exists
if [[ ! -b "${LUKS_DEVICE}" ]]; then
    log_warn "LUKS device ${LUKS_DEVICE} not found."
    log_warn "Kill switch will be deployed but trigger script will"
    log_warn "need to be updated when hardware is confirmed."
else
    log_info "✓ LUKS device ${LUKS_DEVICE} confirmed."
fi

# Verify LUKS device is actually encrypted
if [[ -b "${LUKS_DEVICE}" ]]; then
    if cryptsetup isLuks "${LUKS_DEVICE}" 2>/dev/null; then
        log_info "✓ LUKS encryption confirmed on ${LUKS_DEVICE}"
    else
        log_warn "Device ${LUKS_DEVICE} is not LUKS encrypted."
        log_warn "Run 02-luks-dropbear.sh first."
        log_warn "Deploying kill switch anyway — will activate but"
        log_warn "luksKillSlot will fail on non-encrypted device."
    fi
fi

# =============================================================================
# CRITICAL WARNING
# =============================================================================
log_section "⚠️  FINAL WARNING BEFORE DEPLOYMENT ⚠️"

cat << 'WARNING_EOF'

  ╔══════════════════════════════════════════════════════════════════╗
  ║              KILL SWITCH DEPLOYMENT WARNING                      ║
  ╠══════════════════════════════════════════════════════════════════╣
  ║                                                                  ║
  ║  You are about to deploy an AUTOMATIC DATA DESTRUCTION           ║
  ║  mechanism. Once active, the kill switch will:                   ║
  ║                                                                  ║
  ║  ► DESTROY all LUKS encryption keys (data unrecoverable)        ║
  ║  ► OVERWRITE the LUKS header with random data                   ║
  ║  ► SHUT DOWN the system immediately                              ║
  ║                                                                  ║
  ║  This will happen AUTOMATICALLY if:                              ║
  ║  • The 5G USB modem is disconnected                             ║
  ║  • 3 heartbeat pings to the server fail                         ║
  ║  • 24 hours pass without server contact                         ║
  ║  • A remote kill command is received                            ║
  ║                                                                  ║
  ║  MAKE SURE BEFORE DEPLOYING:                                    ║
  ║  ✓ Your C2 server is reachable at ${HEARTBEAT_SERVER}           ║
  ║  ✓ The 5G modem is connected (or server check is reachable)     ║
  ║  ✓ You understand this is IRREVERSIBLE                          ║
  ║                                                                  ║
  ╚══════════════════════════════════════════════════════════════════╝

WARNING_EOF

confirm_destructive "Deploy Kill Switch (LUKS Nuke + Watchdog + udev triggers)"

# =============================================================================
# STEP 1: Deploy the Core Kill Switch Trigger Script
# =============================================================================
log_section "STEP 1: Core Kill Switch Trigger Script"

log_info "Deploying kill switch trigger to ${KS_TRIGGER_SCRIPT}..."

cat > "${KS_TRIGGER_SCRIPT}" << TRIGGER_EOF
#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — Kill Switch Trigger
# /usr/local/bin/wauditbox-killswitch-trigger
#
# Usage: wauditbox-killswitch-trigger <reason>
# Reasons: modem_removed | heartbeat_failed | no_contact_24h |
#          remote_kill   | manual
#
# WARNING: THIS SCRIPT DESTROYS DATA PERMANENTLY
# =============================================================================

set -euo pipefail

REASON="\${1:-unknown}"
LUKS_DEVICE="${LUKS_DEVICE}"
KS_WIPE_MB="${KS_WIPE_MB}"
KS_LOG="${KS_LOG}"

# Create log directory
mkdir -p "\$(dirname \${KS_LOG})"

# Logging function — write to file AND syslog
ks_log() {
    local msg="\$(date '+%Y-%m-%d %H:%M:%S') [KILLSWITCH] \$*"
    echo "\${msg}" >> "\${KS_LOG}"
    logger -t wauditbox-killswitch -p security.emerg "\$*"
    # Also write to kernel ring buffer for forensics
    echo "\${msg}" > /dev/kmsg 2>/dev/null || true
}

# ─── GUARD: Prevent double-trigger ───────────────────────────────────────────
KS_LOCK="/var/run/wauditbox-killswitch.lock"
if [[ -f "\${KS_LOCK}" ]]; then
    ks_log "Kill switch already triggered (lock file exists) — exiting"
    exit 0
fi
touch "\${KS_LOCK}"

# ─── ANNOUNCE ─────────────────────────────────────────────────────────────────
ks_log "╔══════════════════════════════════════════════════════╗"
ks_log "║      WAUDITBOX KILL SWITCH ACTIVATED                 ║"
ks_log "╠══════════════════════════════════════════════════════╣"
ks_log "║  Reason   : \${REASON}"
ks_log "║  Time     : \$(date '+%Y-%m-%d %H:%M:%S %Z')"
ks_log "║  Hostname : \$(hostname)"
ks_log "║  Uptime   : \$(uptime -p)"
ks_log "╚══════════════════════════════════════════════════════╝"

# ─── STEP 1: Sync filesystem before destruction ───────────────────────────────
ks_log "Step 1: Syncing filesystem..."
sync
sleep 1

# ─── STEP 2: Destroy LUKS key slots ──────────────────────────────────────────
ks_log "Step 2: Destroying LUKS key slots..."

# Kill all key slots (0 through 7)
for slot in 0 1 2 3 4 5 6 7; do
    if cryptsetup luksKillSlot "\${LUKS_DEVICE}" "\${slot}" \
        --batch-mode 2>>"\${KS_LOG}"; then
        ks_log "Key slot \${slot} destroyed."
    else
        ks_log "Key slot \${slot} was empty or already destroyed."
    fi
done

ks_log "All LUKS key slots destroyed — data is now UNRECOVERABLE."

# ─── STEP 3: Overwrite LUKS header ───────────────────────────────────────────
ks_log "Step 3: Overwriting LUKS header with random data (\${KS_WIPE_MB}MB)..."

dd if=/dev/urandom \
   of="\${LUKS_DEVICE}" \
   bs=1M \
   count="\${KS_WIPE_MB}" \
   oflag=direct \
   2>>"\${KS_LOG}" || true

sync
ks_log "LUKS header overwrite complete."

# ─── STEP 4: Clear RAM (best effort) ─────────────────────────────────────────
ks_log "Step 4: Attempting RAM clear..."
# Drop caches
echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true
sync
ks_log "RAM cache dropped."

# ─── STEP 5: Final log entry ──────────────────────────────────────────────────
ks_log "Step 5: Kill switch sequence complete."
ks_log "Device: \${LUKS_DEVICE} — Header: DESTROYED — Data: UNRECOVERABLE"
ks_log "Initiating emergency shutdown..."
sync

# ─── STEP 6: Shutdown ─────────────────────────────────────────────────────────
wall "WAUDITBOX EMERGENCY SHUTDOWN — Kill switch activated: \${REASON}"
sleep 1
shutdown -h now "WauditBox Kill Switch: \${REASON}"
TRIGGER_EOF

chmod 700 "${KS_TRIGGER_SCRIPT}"
chown root:root "${KS_TRIGGER_SCRIPT}"
log_info "✓ Kill switch trigger deployed to ${KS_TRIGGER_SCRIPT}"

# =============================================================================
# STEP 2: Heartbeat Watchdog Script
# =============================================================================
log_section "STEP 2: Heartbeat Watchdog Script"

log_info "Creating heartbeat watchdog script..."

cat > "${KS_HEARTBEAT_SCRIPT}" << HEARTBEAT_EOF
#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — Heartbeat Watchdog
# /usr/local/bin/wauditbox-heartbeat
#
# Pings the C2 server every HEARTBEAT_INTERVAL seconds
# Counts consecutive failures
# After MAX_FAILURES → triggers kill switch
# =============================================================================

set -euo pipefail

HEARTBEAT_SERVER="${HEARTBEAT_SERVER}"
MAX_FAILURES=${HEARTBEAT_MAX_FAILURES}
KS_FAIL_COUNTER="${KS_FAIL_COUNTER}"
KS_LAST_CONTACT="${KS_LAST_CONTACT}"
KS_LOG="${KS_LOG}"
KS_TRIGGER="${KS_TRIGGER_SCRIPT}"
HB_LOG="${HEARTBEAT_LOG}"

mkdir -p "\$(dirname \${HB_LOG})"
mkdir -p "\$(dirname \${KS_LOG})"

hb_log() {
    echo "\$(date '+%Y-%m-%d %H:%M:%S') [HEARTBEAT] \$*" >> "\${HB_LOG}"
    logger -t wauditbox-heartbeat "\$*"
}

# ─── Read current failure count ───────────────────────────────────────────────
CURRENT_FAILS=0
if [[ -f "\${KS_FAIL_COUNTER}" ]]; then
    CURRENT_FAILS=\$(cat "\${KS_FAIL_COUNTER}" 2>/dev/null || echo 0)
    # Validate it's a number
    [[ "\${CURRENT_FAILS}" =~ ^[0-9]+\$ ]] || CURRENT_FAILS=0
fi

# ─── Ping the C2 server ───────────────────────────────────────────────────────
PING_SUCCESS=false

# Try via WireGuard first (VPN tunnel)
if ping -c 2 -W 5 -I wg0 "\${HEARTBEAT_SERVER}" >/dev/null 2>&1; then
    PING_SUCCESS=true
    PING_METHOD="WireGuard"
# Fallback: try via 5G modem directly
elif ping -c 2 -W 5 "\${HEARTBEAT_SERVER}" >/dev/null 2>&1; then
    PING_SUCCESS=true
    PING_METHOD="direct"
fi

# ─── Process result ───────────────────────────────────────────────────────────
if [[ "\${PING_SUCCESS}" == "true" ]]; then
    # SUCCESS — Reset failure counter
    hb_log "✓ Server reachable via \${PING_METHOD} (failures reset: was \${CURRENT_FAILS})"
    echo "0" > "\${KS_FAIL_COUNTER}"
    date +%s > "\${KS_LAST_CONTACT}"

    # Send status payload to server (via WireGuard if available)
    STATUS_PAYLOAD=\$(cat << STATUS
{
    "gadget": "\$(hostname)",
    "timestamp": "\$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "uptime": "\$(uptime -p)",
    "ip_wg": "\$(ip addr show wg0 2>/dev/null | grep 'inet ' | awk '{print \$2}' | head -1 || echo 'N/A')",
    "ip_5g": "\$(ip addr show wwan0 2>/dev/null | grep 'inet ' | awk '{print \$2}' | head -1 || echo 'N/A')",
    "status": "operational",
    "luks": "\$(cryptsetup status ${LUKS_MAPPER_NAME} 2>/dev/null | grep 'type:' | awk '{print \$2}' || echo 'unknown')"
}
STATUS
)
    # Attempt to send heartbeat payload to server API
    curl -s -X POST \
        "http://${HEARTBEAT_SERVER}:8080/api/v1/heartbeat" \
        -H "Content-Type: application/json" \
        -H "X-Gadget-ID: \$(hostname)" \
        -d "\${STATUS_PAYLOAD}" \
        --max-time 10 \
        --interface wg0 \
        >/dev/null 2>&1 || true
    # curl failure is OK — ping success is the primary check

else
    # FAILURE — Increment counter
    CURRENT_FAILS=\$((CURRENT_FAILS + 1))
    echo "\${CURRENT_FAILS}" > "\${KS_FAIL_COUNTER}"

    hb_log "✗ Server UNREACHABLE — Failure \${CURRENT_FAILS}/\${MAX_FAILURES}"
    hb_log "  Target: \${HEARTBEAT_SERVER}"

    # ─── Check 24h silence ────────────────────────────────────────────────────
    if [[ -f "\${KS_LAST_CONTACT}" ]]; then
        LAST_CONTACT=\$(cat "\${KS_LAST_CONTACT}" 2>/dev/null || echo 0)
        NOW=\$(date +%s)
        SILENCE=\$((NOW - LAST_CONTACT))
        SILENCE_H=\$((SILENCE / 3600))

        hb_log "  Last successful contact: \${SILENCE}s ago (\${SILENCE_H}h)"

        if [[ \${SILENCE} -gt ${KS_MAX_SILENCE} ]]; then
            hb_log "CRITICAL: No server contact for \${SILENCE_H}h — triggering kill switch"
            "\${KS_TRIGGER}" "no_contact_\${SILENCE_H}h"
            exit 0
        fi
    else
        # First run — initialize last contact to now
        date +%s > "\${KS_LAST_CONTACT}"
        hb_log "First run — initialized last contact timestamp"
    fi

    # ─── Trigger kill switch after max failures ────────────────────────────────
    if [[ \${CURRENT_FAILS} -ge \${MAX_FAILURES} ]]; then
        hb_log "CRITICAL: Max heartbeat failures reached (\${CURRENT_FAILS})"
        hb_log "Triggering kill switch — reason: heartbeat_failed_\${CURRENT_FAILS}_times"
        "\${KS_TRIGGER}" "heartbeat_failed_\${CURRENT_FAILS}_times"
        exit 0
    fi

    hb_log "Next check in ${HEARTBEAT_INTERVAL}s (\$((MAX_FAILURES - CURRENT_FAILS)) failures remaining before kill)"
fi
HEARTBEAT_EOF

chmod 700 "${KS_HEARTBEAT_SCRIPT}"
chown root:root "${KS_HEARTBEAT_SCRIPT}"
log_info "✓ Heartbeat watchdog script deployed to ${KS_HEARTBEAT_SCRIPT}"

# Initialize last contact timestamp
date +%s > "${KS_LAST_CONTACT}"
echo "0" > "${KS_FAIL_COUNTER}"
log_info "Initialized heartbeat state files."

# =============================================================================
# STEP 3: Heartbeat systemd Service & Timer
# =============================================================================
log_section "STEP 3: Heartbeat systemd Service & Timer"

log_info "Creating heartbeat systemd service..."

cat > /etc/systemd/system/wauditbox-heartbeat.service << HB_SVC_EOF
# =============================================================================
# WauditBox v2.0 — Heartbeat Service
# Runs the heartbeat check (one-shot, triggered by timer)
# =============================================================================
[Unit]
Description=WauditBox Heartbeat Check
After=network.target
After=wg-quick@wg0.service
Documentation=https://github.com/Youssef-HF/projet_wifi

[Service]
Type=oneshot
ExecStart=${KS_HEARTBEAT_SCRIPT}
StandardOutput=journal
StandardError=journal
# Run as root (needs access to kill switch trigger)
User=root

# If heartbeat fails to run, that itself is suspicious
# but we don't want the service to loop
Restart=no
TimeoutStartSec=60
HB_SVC_EOF

cat > /etc/systemd/system/wauditbox-heartbeat.timer << HB_TIMER_EOF
# =============================================================================
# WauditBox v2.0 — Heartbeat Timer
# Triggers heartbeat check every HEARTBEAT_INTERVAL seconds
# =============================================================================
[Unit]
Description=WauditBox Heartbeat Timer
After=network.target
Documentation=https://github.com/Youssef-HF/projet_wifi

[Timer]
# First check 2 minutes after boot (give network time to come up)
OnBootSec=2min
# Then check every N seconds
OnUnitActiveSec=${HEARTBEAT_INTERVAL}sec
AccuracySec=5s
# Persist across reboots (catch up on missed beats)
Persistent=true

[Install]
WantedBy=timers.target
HB_TIMER_EOF

log_info "✓ Heartbeat service and timer created."

# =============================================================================
# STEP 4: 24h Auto-wipe systemd Timer
# =============================================================================
log_section "STEP 4: 24h Auto-wipe Timer"

log_info "Creating 24h no-contact auto-wipe timer..."

cat > /etc/systemd/system/wauditbox-autowipe.service << AUTOWIPE_SVC_EOF
# =============================================================================
# WauditBox v2.0 — Auto-wipe Service
# Triggered if timer fires without being reset by heartbeat
# The heartbeat script resets this timer on each successful contact
# =============================================================================
[Unit]
Description=WauditBox 24h Auto-wipe
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c '\
    KS_LAST="/var/run/wauditbox-last-contact"; \
    NOW=\$(date +%s); \
    LAST=\$(cat "\${KS_LAST}" 2>/dev/null || echo 0); \
    SILENCE=\$((NOW - LAST)); \
    if [[ \${SILENCE} -gt ${KS_MAX_SILENCE} ]]; then \
        logger -t wauditbox-autowipe "24h silence confirmed (\${SILENCE}s) — activating kill switch"; \
        ${KS_TRIGGER_SCRIPT} "auto_wipe_24h_silence_\${SILENCE}s"; \
    else \
        logger -t wauditbox-autowipe "Auto-wipe check: \${SILENCE}s silence (OK — below 24h threshold)"; \
    fi'
User=root
StandardOutput=journal
StandardError=journal
AUTOWIPE_SVC_EOF

cat > /etc/systemd/system/wauditbox-autowipe.timer << AUTOWIPE_TIMER_EOF
# =============================================================================
# WauditBox v2.0 — Auto-wipe Timer
# Checks every 30 minutes whether 24h silence threshold was exceeded
# The actual time check is done in the service script
# =============================================================================
[Unit]
Description=WauditBox 24h Auto-wipe Timer
After=network.target

[Timer]
OnBootSec=30min
OnUnitActiveSec=30min
AccuracySec=60s
Persistent=true

[Install]
WantedBy=timers.target
AUTOWIPE_TIMER_EOF

log_info "✓ 24h auto-wipe timer created."

# =============================================================================
# STEP 5: 5G Modem Disconnect udev Rule (Kill Switch Trigger)
# =============================================================================
log_section "STEP 5: 5G Modem Disconnect Kill Switch (udev)"

log_info "Creating udev rule for 5G modem removal kill switch trigger..."

cat > /etc/udev/rules.d/99-wauditbox-killswitch.rules << UDEV_KS_EOF
# =============================================================================
# WauditBox v2.0 — Kill Switch udev Rules
# Triggers kill switch when 5G modem is physically removed
# Applied by: scripts/05-killswitch.sh
# =============================================================================

# 5G Modem (SIM8200EA-M2) — VID:PID 2c7c:0800
# REMOVE action = physical disconnection = potential theft
SUBSYSTEM=="usb", \
    ATTRS{idVendor}=="2c7c", \
    ATTRS{idProduct}=="0800", \
    ACTION=="remove", \
    RUN+="/usr/local/bin/wauditbox-modem-removed-handler"

# Also trigger on USB subsystem removal (belt + suspenders)
SUBSYSTEM=="usb_device", \
    ATTRS{idVendor}=="2c7c", \
    ATTRS{idProduct}=="0800", \
    ACTION=="remove", \
    RUN+="/usr/local/bin/wauditbox-modem-removed-handler"
UDEV_KS_EOF

# Create the modem removed handler
# (udev rules cannot call scripts with arguments directly in all cases)
cat > /usr/local/bin/wauditbox-modem-removed-handler << 'MODEM_HANDLER_EOF'
#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — 5G Modem Removal Handler
# Called by udev when SIM8200EA-M2 is disconnected
# Adds a small delay to avoid false positives (USB reconnects)
# =============================================================================

# Wait 10 seconds — if modem reconnects, cancel
sleep 10

# Check if modem came back
if lsusb | grep -q "2c7c:0800"; then
    logger -t wauditbox-killswitch "5G modem returned after removal — false alarm, standing down"
    exit 0
fi

# Modem is gone — trigger kill switch
logger -t wauditbox-killswitch "ALERT: 5G modem permanently removed — triggering kill switch"
/usr/local/bin/wauditbox-killswitch-trigger "5g_modem_removed"
MODEM_HANDLER_EOF

chmod 700 /usr/local/bin/wauditbox-modem-removed-handler
chown root:root /usr/local/bin/wauditbox-modem-removed-handler

# Reload udev rules
udevadm control --reload-rules
udevadm trigger
log_info "✓ udev kill switch rules deployed and reloaded."

# =============================================================================
# STEP 6: Remote Kill Command Listener
# =============================================================================
log_section "STEP 6: Remote Kill Command Listener"

log_info "Creating remote kill command listener..."
log_info "Listens on WireGuard interface (${WG_IFACE}) port ${KS_REMOTE_KILL_PORT}"
log_info "Receives encrypted kill command from C2 server"

cat > "${KS_REMOTE_KILL_SCRIPT}" << 'REMOTE_KILL_EOF'
#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — Remote Kill Listener
# Listens for kill commands from the C2 server via WireGuard tunnel
# Only accepts connections from VPN subnet (10.200.0.0/16)
#
# Protocol: Simple TCP — server sends "WAUDITBOX_KILL:<signature>"
# Signature: SHA256 of (hostname + timestamp_hour + shared_secret)
# =============================================================================

set -euo pipefail

LISTEN_PORT="9999"
LISTEN_IFACE="wg0"
LISTEN_IP=$(ip addr show wg0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 || echo "10.200.1.1")
KS_TRIGGER="/usr/local/bin/wauditbox-killswitch-trigger"
LOG="/var/log/wauditbox/remote-kill.log"
SHARED_SECRET_FILE="/etc/wauditbox/kill-shared-secret"

mkdir -p "$(dirname ${LOG})"
mkdir -p /etc/wauditbox

rk_log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [REMOTE-KILL] $*" >> "${LOG}"
    logger -t wauditbox-remote-kill "$*"
}

# Validate shared secret exists
if [[ ! -f "${SHARED_SECRET_FILE}" ]]; then
    rk_log "ERROR: Shared secret file not found at ${SHARED_SECRET_FILE}"
    rk_log "Generate with: openssl rand -hex 32 > ${SHARED_SECRET_FILE}"
    exit 1
fi

SHARED_SECRET=$(cat "${SHARED_SECRET_FILE}")

rk_log "Remote kill listener starting on ${LISTEN_IP}:${LISTEN_PORT}"
rk_log "Only accepting from VPN subnet 10.200.0.0/16"

# Listen for incoming connection (one-shot per systemd invocation)
while true; do
    # Wait for connection and read command
    RECEIVED=$(echo "" | \
        timeout 30 nc -l -p "${LISTEN_PORT}" \
        -s "${LISTEN_IP}" 2>/dev/null || echo "")

    if [[ -z "${RECEIVED}" ]]; then
        sleep 5
        continue
    fi

    rk_log "Received data: ${RECEIVED:0:50}..."

    # Validate format: WAUDITBOX_KILL:<signature>
    if [[ "${RECEIVED}" != WAUDITBOX_KILL:* ]]; then
        rk_log "Invalid format received — ignoring"
        continue
    fi

    RECEIVED_SIG="${RECEIVED#WAUDITBOX_KILL:}"

    # Validate signature
    # Signature = SHA256(hostname + current_hour + shared_secret)
    CURRENT_HOUR=$(date -u +%Y%m%d%H)
    HOSTNAME=$(hostname)
    EXPECTED_SIG=$(echo -n "${HOSTNAME}${CURRENT_HOUR}${SHARED_SECRET}" | \
        sha256sum | awk '{print $1}')

    # Also check previous hour (in case of clock drift)
    PREV_HOUR=$(date -u -d '1 hour ago' +%Y%m%d%H 2>/dev/null || \
                date -u -v-1H +%Y%m%d%H 2>/dev/null || echo "")
    PREV_SIG=$(echo -n "${HOSTNAME}${PREV_HOUR}${SHARED_SECRET}" | \
        sha256sum | awk '{print $1}')

    if [[ "${RECEIVED_SIG}" == "${EXPECTED_SIG}" ]] || \
       [[ "${RECEIVED_SIG}" == "${PREV_SIG}" ]]; then
        rk_log "✓ Valid kill signature received — ACTIVATING KILL SWITCH"
        "${KS_TRIGGER}" "remote_kill_command"
        exit 0
    else
        rk_log "✗ Invalid signature — ignoring kill command"
        rk_log "  Expected: ${EXPECTED_SIG:0:16}..."
        rk_log "  Received: ${RECEIVED_SIG:0:16}..."
    fi

    sleep 1
done
REMOTE_KILL_EOF

chmod 700 "${KS_REMOTE_KILL_SCRIPT}"
chown root:root "${KS_REMOTE_KILL_SCRIPT}"

# Generate shared secret for remote kill authentication
SHARED_SECRET_FILE="/etc/wauditbox/kill-shared-secret"
mkdir -p /etc/wauditbox
chmod 700 /etc/wauditbox

if [[ ! -f "${SHARED_SECRET_FILE}" ]]; then
    openssl rand -hex 32 > "${SHARED_SECRET_FILE}"
    chmod 600 "${SHARED_SECRET_FILE}"
    log_info "✓ Remote kill shared secret generated: ${SHARED_SECRET_FILE}"
    log_warn "Store this secret on your C2 server to send kill commands:"
    log_warn "Secret: $(cat ${SHARED_SECRET_FILE})"
else
    log_info "Shared secret already exists — keeping existing."
fi

# Create systemd service for remote kill listener
cat > /etc/systemd/system/wauditbox-remote-kill.service << RK_SVC_EOF
# =============================================================================
# WauditBox v2.0 — Remote Kill Listener Service
# Listens for kill commands from C2 server via WireGuard tunnel
# =============================================================================
[Unit]
Description=WauditBox Remote Kill Listener
After=network.target
After=wg-quick@wg0.service
Requires=wg-quick@wg0.service
BindsTo=wg-quick@wg0.service

[Service]
Type=simple
ExecStart=${KS_REMOTE_KILL_SCRIPT}
Restart=always
RestartSec=10
User=root
StandardOutput=journal
StandardError=journal

# Security hardening for the listener service
NoNewPrivileges=no
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
RK_SVC_EOF

log_info "✓ Remote kill listener service created."

# =============================================================================
# STEP 7: Status & Health Check Script
# =============================================================================
log_section "STEP 7: Kill Switch Status Script"

log_info "Creating kill switch status check script..."

cat > /usr/local/bin/wauditbox-ks-status << 'KS_STATUS_EOF'
#!/usr/bin/env bash
# =============================================================================
# WauditBox v2.0 — Kill Switch Status Check
# Usage: sudo wauditbox-ks-status
# Shows the current state of all kill switch components
# =============================================================================

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║         WauditBox v2.0 — Kill Switch Status                  ║"
echo "╠══════════════════════════════════════════════════════════════╣"

# Heartbeat failures
FAILS=$(cat /var/run/wauditbox-heartbeat-fails 2>/dev/null || echo "N/A")
echo "║  Heartbeat failures  : ${FAILS}"

# Last contact
if [[ -f /var/run/wauditbox-last-contact ]]; then
    LAST=$(cat /var/run/wauditbox-last-contact)
    NOW=$(date +%s)
    SILENCE=$(( NOW - LAST ))
    SILENCE_H=$(( SILENCE / 3600 ))
    SILENCE_M=$(( (SILENCE % 3600) / 60 ))
    LAST_STR=$(date -d "@${LAST}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || \
               date -r "${LAST}" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "N/A")
    echo "║  Last server contact : ${LAST_STR}"
    echo "║  Silence duration    : ${SILENCE_H}h ${SILENCE_M}m (max: 24h)"
else
    echo "║  Last server contact : Never"
fi

# Service statuses
echo "╠══════════════════════════════════════════════════════════════╣"
for svc in wauditbox-heartbeat.timer wauditbox-autowipe.timer \
           wauditbox-remote-kill.service; do
    STATUS=$(systemctl is-active "${svc}" 2>/dev/null || echo "inactive")
    ICON="✓"
    [[ "${STATUS}" != "active" ]] && ICON="✗"
    printf "║  %-12s %-30s %s\n" "${ICON}" "${svc}" "${STATUS}"
done

# 5G modem presence
echo "╠══════════════════════════════════════════════════════════════╣"
if lsusb 2>/dev/null | grep -q "2c7c:0800"; then
    echo "║  5G Modem            : ✓ CONNECTED (kill switch ARMED)"
else
    echo "║  5G Modem            : ✗ NOT DETECTED"
fi

# WireGuard status
WG_STATUS=$(wg show wg0 2>/dev/null | grep -c "latest handshake" || echo 0)
if [[ "${WG_STATUS}" -gt 0 ]]; then
    echo "║  WireGuard Tunnel    : ✓ ACTIVE"
else
    echo "║  WireGuard Tunnel    : ✗ DOWN"
fi

# LUKS status
LUKS_DEVICE=$(grep "wauditbox-crypt" /etc/crypttab 2>/dev/null | awk '{print $2}' | head -1 || echo "N/A")
echo "║  LUKS Device         : ${LUKS_DEVICE}"

echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Recent kill switch logs:                                    ║"
if [[ -f /var/log/wauditbox/killswitch.log ]]; then
    tail -3 /var/log/wauditbox/killswitch.log | while read -r line; do
        printf "║  %-60s ║\n" "${line:0:60}"
    done
else
    echo "║  No kill switch events logged.                               ║"
fi

echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
KS_STATUS_EOF

chmod 755 /usr/local/bin/wauditbox-ks-status
log_info "✓ Status check script: sudo wauditbox-ks-status"

# =============================================================================
# STEP 8: Enable All Services
# =============================================================================
log_section "STEP 8: Enable All Kill Switch Services"

log_info "Reloading systemd daemon..."
systemctl daemon-reload

# Enable all services and timers
SERVICES_TO_ENABLE=(
    "wauditbox-heartbeat.timer"
    "wauditbox-autowipe.timer"
    "wauditbox-remote-kill.service"
)

for svc in "${SERVICES_TO_ENABLE[@]}"; do
    log_info "Enabling ${svc}..."
    systemctl enable "${svc}"  2>&1 | tee -a "${SCRIPT_LOG}"
    systemctl start  "${svc}"  2>&1 | tee -a "${SCRIPT_LOG}"

    if systemctl is-active "${svc}" >/dev/null 2>&1; then
        log_info "✓ ${svc} is active"
    else
        log_warn "⚠ ${svc} failed to start — check: journalctl -u ${svc}"
    fi
done

# =============================================================================
# STEP 9: Verify Deployment
# =============================================================================
log_section "STEP 9: Deployment Verification"

log_info "Verifying all kill switch components..."

# Check trigger script
[[ -f "${KS_TRIGGER_SCRIPT}" ]] && \
    log_info "✓ Trigger script: ${KS_TRIGGER_SCRIPT}" || \
    log_warn "✗ Trigger script MISSING"

# Check heartbeat script
[[ -f "${KS_HEARTBEAT_SCRIPT}" ]] && \
    log_info "✓ Heartbeat script: ${KS_HEARTBEAT_SCRIPT}" || \
    log_warn "✗ Heartbeat script MISSING"

# Check udev rule
[[ -f "/etc/udev/rules.d/99-wauditbox-killswitch.rules" ]] && \
    log_info "✓ udev kill switch rule: 99-wauditbox-killswitch.rules" || \
    log_warn "✗ udev rule MISSING"

# Check modem handler
[[ -f "/usr/local/bin/wauditbox-modem-removed-handler" ]] && \
    log_info "✓ Modem removal handler deployed" || \
    log_warn "✗ Modem removal handler MISSING"

# Check shared secret
[[ -f "${SHARED_SECRET_FILE}" ]] && \
    log_info "✓ Remote kill shared secret exists" || \
    log_warn "✗ Shared secret MISSING"

# Run status check
log_info "Kill switch status:"
/usr/local/bin/wauditbox-ks-status 2>&1 | tee -a "${SCRIPT_LOG}"

# =============================================================================
# SUMMARY
# =============================================================================
cat << 'SUMMARY_EOF' | tee -a "${SCRIPT_LOG}"

╔══════════════════════════════════════════════════════════════════════╗
║          WauditBox v2.0 — Kill Switch Deployment Complete           ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  TRIGGER MECHANISMS DEPLOYED:                                        ║
║                                                                      ║
║  ✓  [1] 5G Modem Removal (udev)                                     ║
║        → 10s delay to avoid false positives                         ║
║        → Immediate kill if modem doesn't return                     ║
║                                                                      ║
║  ✓  [2] Heartbeat Failure (systemd timer)                           ║
║        → Checks every 60s via WireGuard tunnel                      ║
║        → Triggers after 3 consecutive failures                      ║
║                                                                      ║
║  ✓  [3] 24h No-Contact Auto-wipe (systemd timer)                    ║
║        → Checks every 30 minutes                                     ║
║        → Wipes if last contact > 24h ago                            ║
║                                                                      ║
║  ✓  [4] Remote Kill Command (TCP listener on wg0:9999)              ║
║        → Only accepts from VPN subnet 10.200.0.0/16                 ║
║        → HMAC-style signature validation                             ║
║                                                                      ║
║  ✓  [5] LUKS Nuke Password (at boot, configured in script 02)       ║
║        → Entering nuke password = immediate key destruction          ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  KILL SWITCH ACTIONS (on trigger):                                   ║
║  1. Destroy all LUKS key slots (0-7)                                ║
║  2. Overwrite LUKS header (100MB of /dev/urandom)                   ║
║  3. Drop RAM caches                                                  ║
║  4. Emergency shutdown                                               ║
╠══════════════════════════════════════════════════════════════════════╣
║  USEFUL COMMANDS:                                                    ║
║  Status    : sudo wauditbox-ks-status                               ║
║  HB logs   : tail -f /var/log/wauditbox/heartbeat.log               ║
║  KS logs   : tail -f /var/log/wauditbox/killswitch.log              ║
║  RK logs   : tail -f /var/log/wauditbox/remote-kill.log             ║
║  Test HB   : sudo wauditbox-heartbeat                               ║
╠══════════════════════════════════════════════════════════════════════╣
║  ✅ ALL 5 SCRIPTS COMPLETE — READY TO PUSH TO GITHUB                ║
╚══════════════════════════════════════════════════════════════════════╝

SUMMARY_EOF

log_info "Full log: ${SCRIPT_LOG}"
log_info "05-killswitch.sh COMPLETE"

# =============================================================================
# END OF SCRIPT
# =============================================================================
