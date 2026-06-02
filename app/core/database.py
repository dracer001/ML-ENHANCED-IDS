"""
core/database.py
────────────────
SQLite event logger.
Stores every detected intrusion for reporting and audit.
"""

import sqlite3
import threading
import time
import os
import logging
from datetime import datetime
from typing import Optional, List, Dict

log = logging.getLogger("ids.database")


class EventDB:
    """Thread-safe SQLite-backed event log."""

    def __init__(self, db_path: str = "ids_events.db"):
        self.db_path = db_path
        self._lock   = threading.Lock()
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT    NOT NULL,
                    unix_ts     REAL    NOT NULL,
                    src_ip      TEXT    NOT NULL,
                    dst_ip      TEXT    NOT NULL,
                    src_port    INTEGER,
                    dst_port    INTEGER,
                    protocol    TEXT,
                    attack_type TEXT    NOT NULL,
                    confidence  REAL,
                    model_used  TEXT,
                    packets     INTEGER,
                    bytes_total INTEGER,
                    duration    REAL,
                    alerted     INTEGER DEFAULT 0,
                    app_mode    TEXT,
                    notes       TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_src_ip    ON events(src_ip);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_attack    ON events(attack_type);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_timestamp ON events(unix_ts);
            """)
            conn.commit()
        log.debug(f"Database ready: {self.db_path}")

    def log_event(
        self,
        src_ip:      str,
        dst_ip:      str,
        attack_type: str,
        confidence:  Optional[float] = None,
        model_used:  str = "",
        src_port:    int = 0,
        dst_port:    int = 0,
        protocol:    str = "",
        packets:     int = 0,
        bytes_total: int = 0,
        duration:    float = 0.0,
        alerted:     bool = False,
        app_mode:    str = "",
        notes:       str = "",
    ) -> int:
        now = time.time()
        ts  = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
        with self._lock:
            with self._connect() as conn:
                cur = conn.execute("""
                    INSERT INTO events (
                        timestamp, unix_ts, src_ip, dst_ip, src_port, dst_port,
                        protocol, attack_type, confidence, model_used,
                        packets, bytes_total, duration, alerted, app_mode, notes
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (ts, now, src_ip, dst_ip, src_port, dst_port,
                      protocol, attack_type, confidence, model_used,
                      packets, bytes_total, duration,
                      1 if alerted else 0, app_mode, notes))
                conn.commit()
                return cur.lastrowid

    def get_recent(self, limit: int = 20) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY unix_ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> Dict:
        with self._connect() as conn:
            total     = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            by_attack = conn.execute(
                "SELECT attack_type, COUNT(*) as cnt FROM events "
                "GROUP BY attack_type ORDER BY cnt DESC LIMIT 10"
            ).fetchall()
            by_src = conn.execute(
                "SELECT src_ip, COUNT(*) as cnt FROM events "
                "GROUP BY src_ip ORDER BY cnt DESC LIMIT 10"
            ).fetchall()
            alerted = conn.execute(
                "SELECT COUNT(*) FROM events WHERE alerted=1"
            ).fetchone()[0]
        return {
            "total":     total,
            "alerted":   alerted,
            "by_attack": [(r["attack_type"], r["cnt"]) for r in by_attack],
            "by_src":    [(r["src_ip"],      r["cnt"]) for r in by_src],
        }

    def export_csv(self, path: str, hours: int = 24) -> int:
        """Export events from the last N hours to CSV. Returns row count."""
        import csv
        cutoff = time.time() - hours * 3600
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE unix_ts >= ? ORDER BY unix_ts DESC",
                (cutoff,)
            ).fetchall()
        if not rows:
            return 0
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=dict(rows[0]).keys())
            writer.writeheader()
            for r in rows:
                writer.writerow(dict(r))
        return len(rows)
