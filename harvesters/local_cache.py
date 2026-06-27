#!/usr/bin/env python3
"""
WauditBox v2.0 — harvesters/local_cache.py
SQLite local cache for discovered credentials
Synchronized with central server via WireGuard tunnel
"""
# PLACEHOLDER — Full implementation in Phase 2
import sqlite3
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger("wauditbox.cache")

DB_PATH = "/opt/wauditbox/results/wauditbox_cache.db"


class LocalCache:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    bssid     TEXT NOT NULL,
                    ssid      TEXT,
                    password  TEXT,
                    source    TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(bssid, password)
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS handshakes (
                    id        INTEGER PRIMARY KEY AUTOINCREMENT,
                    bssid     TEXT NOT NULL,
                    ssid      TEXT,
                    file_path TEXT,
                    cracked   INTEGER DEFAULT 0,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)

    def lookup_bssid(self, bssid: str) -> Optional[str]:
        """Look up a password for a known BSSID."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT password FROM credentials WHERE bssid=? LIMIT 1",
                (bssid,)
            ).fetchone()
        return row[0] if row else None

    def store_credential(self, bssid: str, ssid: str, password: str, source: str):
        """Store a discovered credential."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO credentials (bssid, ssid, password, source) VALUES (?,?,?,?)",
                (bssid, ssid, password, source)
            )
        logger.info(f"Stored credential for {bssid} ({ssid}) from {source}")
