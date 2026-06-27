#!/usr/bin/env python3
"""
WauditBox v2.0 — harvesters/openwifimap_api.py
Phase Easy: Query OpenWiFiMap public API
"""
# PLACEHOLDER — Full implementation in Phase 2
import requests
import logging
from typing import Optional

logger = logging.getLogger("wauditbox.openwifimap")

OWM_BASE_URL = "https://openwifimap.net/api"


class OpenWiFiMapClient:
    def __init__(self):
        self.session = requests.Session()

    def search_by_bssid(self, bssid: str) -> dict:
        try:
            resp = self.session.get(
                f"{OWM_BASE_URL}/db/view/{bssid}",
                timeout=10
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            logger.error(f"OpenWiFiMap query failed: {e}")
            return {}
