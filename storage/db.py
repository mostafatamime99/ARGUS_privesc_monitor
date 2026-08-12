"""SQLite storage for baselines and alert history."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence


SCHEMA = """
CREATE TABLE IF NOT EXISTS baselines (
    detector_name TEXT NOT NULL,
    item_hash     TEXT NOT NULL,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    item_key      TEXT NOT NULL DEFAULT '',
    payload       TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (detector_name, item_hash)
);

CREATE TABLE IF NOT EXISTS alerts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL,
    detector_name TEXT NOT NULL,
    severity      TEXT NOT NULL,
    message       TEXT NOT NULL,
    acknowledged  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_baselines_detector
    ON baselines (detector_name);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
    ON alerts (timestamp);

CREATE TABLE IF NOT EXISTS lookup_cache (
    cache_key  TEXT PRIMARY KEY,
    payload    TEXT NOT NULL,
    fetched_at TEXT NOT NULL
);
"""


class Database:
    """Thin SQLite wrapper used by detectors and alert plumbing.

    Safe for use from the asyncio event loop and worker threads
    (``check_same_thread=False`` + a reentrant lock).
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.executescript(SCHEMA)
            self._migrate_baselines()
            self._conn.commit()

    def _migrate_baselines(self) -> None:
        """Add item_key/payload if upgrading an older Step-1 schema."""
        cols = {
            row["name"]
            for row in self._conn.execute("PRAGMA table_info(baselines)").fetchall()
        }
        if "item_key" not in cols:
            self._conn.execute(
                "ALTER TABLE baselines ADD COLUMN item_key TEXT NOT NULL DEFAULT ''"
            )
        if "payload" not in cols:
            self._conn.execute(
                "ALTER TABLE baselines ADD COLUMN payload TEXT NOT NULL DEFAULT ''"
            )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def get_baseline_hashes(self, detector_name: str) -> set[str]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT item_hash FROM baselines WHERE detector_name = ?",
                (detector_name,),
            )
            return {row["item_hash"] for row in cur.fetchall()}

    def get_baseline_entries(self, detector_name: str) -> list[sqlite3.Row]:
        """Full baseline rows (needed to describe REMOVED findings)."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT detector_name, item_hash, first_seen, last_seen, item_key, payload
                FROM baselines
                WHERE detector_name = ?
                """,
                (detector_name,),
            )
            return list(cur.fetchall())

    def replace_baselines(
        self, detector_name: str, rows: Sequence[tuple[str, str, str, str, str, str]]
    ) -> None:
        """
        Replace the baseline for one detector with the current inventory.

        rows: (detector_name, item_hash, first_seen, last_seen, item_key, payload)

        On conflict: keep original first_seen, refresh last_seen / key / payload.
        Rows absent from this set are deleted so reappearing items re-alert.
        """
        with self._lock:
            keep_hashes = {row[1] for row in rows}
            existing = {
                row["item_hash"]
                for row in self._conn.execute(
                    "SELECT item_hash FROM baselines WHERE detector_name = ?",
                    (detector_name,),
                ).fetchall()
            }
            stale = existing - keep_hashes
            if stale:
                self._conn.executemany(
                    "DELETE FROM baselines WHERE detector_name = ? AND item_hash = ?",
                    [(detector_name, h) for h in stale],
                )
            if rows:
                self._conn.executemany(
                    """
                    INSERT INTO baselines (
                        detector_name, item_hash, first_seen, last_seen, item_key, payload
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(detector_name, item_hash) DO UPDATE SET
                        last_seen = excluded.last_seen,
                        item_key = excluded.item_key,
                        payload = excluded.payload
                    """,
                    rows,
                )
            self._conn.commit()

    def upsert_baselines(
        self, rows: Sequence[tuple[str, str, str, str]]
    ) -> None:
        """
        rows: (detector_name, item_hash, first_seen, last_seen)

        Legacy upsert without prune. Prefer replace_baselines for detectors.
        """
        with self._lock:
            self._conn.executemany(
                """
                INSERT INTO baselines (detector_name, item_hash, first_seen, last_seen)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(detector_name, item_hash) DO UPDATE SET
                    last_seen = excluded.last_seen
                """,
                rows,
            )
            self._conn.commit()

    def upsert_baseline_entries(
        self, rows: Sequence[tuple[str, str, str, str, str, str]]
    ) -> None:
        """
        Merge baseline rows without pruning.

        rows: (detector_name, item_hash, first_seen, last_seen, item_key, payload)

        Used by event-driven detectors (sudoers/cron) where scan() yields
        change events rather than a full inventory.
        """
        if not rows:
            return
        with self._lock:
            self._conn.executemany(
                """
                INSERT INTO baselines (
                    detector_name, item_hash, first_seen, last_seen, item_key, payload
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(detector_name, item_hash) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    item_key = excluded.item_key,
                    payload = excluded.payload
                """,
                rows,
            )
            self._conn.commit()

    def insert_alert(
        self,
        timestamp: str,
        detector_name: str,
        severity: str,
        message: str,
        acknowledged: bool = False,
    ) -> int:
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO alerts (timestamp, detector_name, severity, message, acknowledged)
                VALUES (?, ?, ?, ?, ?)
                """,
                (timestamp, detector_name, severity, message, int(acknowledged)),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def acknowledge_alert(self, alert_id: int) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
                (alert_id,),
            )
            self._conn.commit()

    def get_lookup_cache(self, cache_key: str, ttl_seconds: float) -> str | None:
        """Return cached payload if present and younger than ``ttl_seconds``."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT payload, fetched_at FROM lookup_cache WHERE cache_key = ?",
                (cache_key,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        try:
            fetched = datetime.fromisoformat(row["fetched_at"])
            if fetched.tzinfo is None:
                fetched = fetched.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
        age = datetime.now(timezone.utc) - fetched
        if age > timedelta(seconds=ttl_seconds):
            return None
        return str(row["payload"])

    def put_lookup_cache(
        self, cache_key: str, payload: str, fetched_at: str | None = None
    ) -> None:
        """Insert or replace a lookup-cache row."""
        ts = fetched_at or datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO lookup_cache (cache_key, payload, fetched_at)
                VALUES (?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    payload = excluded.payload,
                    fetched_at = excluded.fetched_at
                """,
                (cache_key, payload, ts),
            )
            self._conn.commit()

    def recent_alerts(self, limit: int = 50) -> list[sqlite3.Row]:
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT id, timestamp, detector_name, severity, message, acknowledged
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
            return list(cur.fetchall())
