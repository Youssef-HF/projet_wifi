#!/usr/bin/env python3
"""
WauditBox v2.0 — killswitch/watchdog.py
Heartbeat watchdog daemon:
- Pings HEARTBEAT_SERVER every HEARTBEAT_INTERVAL seconds
- After MAX_FAILURES consecutive failures → triggers kill switch
- Also monitors 5G modem USB presence
- Runs as systemd service (wauditbox-watchdog.service)
"""
# PLACEHOLDER — Full implementation in 05-killswitch.sh
import subprocess
import time
import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler("/var/log/wauditbox/watchdog.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("wauditbox.watchdog")

HEARTBEAT_SERVER  = os.getenv("HEARTBEAT_SERVER", "10.200.0.1")
HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", "60"))
MAX_FAILURES       = int(os.getenv("HEARTBEAT_MAX_FAILURES", "3"))
KILLSWITCH_SCRIPT  = "/usr/local/bin/wauditbox-killswitch-trigger"


def ping_server(host: str) -> bool:
    """Returns True if server is reachable."""
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "5", host],
        capture_output=True
    )
    return result.returncode == 0


def trigger_kill_switch(reason: str):
    """Execute the kill switch — IRREVERSIBLE."""
    logger.critical(f"KILL SWITCH TRIGGERED: {reason}")
    subprocess.run([KILLSWITCH_SCRIPT, reason])


def run():
    failures = 0
    logger.info(f"Watchdog started — target: {HEARTBEAT_SERVER} — interval: {HEARTBEAT_INTERVAL}s")

    while True:
        if ping_server(HEARTBEAT_SERVER):
            if failures > 0:
                logger.info(f"Server reachable — resetting failure counter (was {failures})")
            failures = 0
        else:
            failures += 1
            logger.warning(f"Heartbeat FAILED ({failures}/{MAX_FAILURES}): {HEARTBEAT_SERVER}")

            if failures >= MAX_FAILURES:
                trigger_kill_switch(f"heartbeat_failed_{failures}_times")
                break

        time.sleep(HEARTBEAT_INTERVAL)


if __name__ == "__main__":
    run()
