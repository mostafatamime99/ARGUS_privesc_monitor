"""SQLite storage for baselines, alert history, lookup cache, and integrity chain."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Sequence

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

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

CREATE TABLE IF NOT EXISTS integrity_chain (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    table_name TEXT NOT NULL,
    row_key    TEXT NOT NULL,
    row_digest TEXT NOT NULL,
    chain_hash TEXT NOT NULL,
    written_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chain_seq
    ON integrity_chain (seq);
"""

# ---------------------------------------------------------------------------
# Integrity-chain helpers (module-level so dashboard can import them too)
# ---------------------------------------------------------------------------

_GENESIS_HASH = "0" * 64  # initial prev_chain_hash before any entries


def _alert_row_digest(
    alert_id: int,
    timestamp: str,
    detector_name: str,
    severity: str,
    message: str,
) -> str:
    """Canonical digest of an alerts row.  Only immutable fields are hashed
    (acknowledged is intentionally excluded so ACKing doesn't break the chain).
    """
    payload = json.dumps(
        {
            "table": "alerts",
            "key": f"alerts:{alert_id}",
            "id": alert_id,
            "timestamp": timestamp,
            "detector_name": detector_name,
            "severity": severity,
            "message": message,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _compute_chain_hash(prev_hash: str, row_digest: str) -> str:
    return hashlib.sha256((prev_hash + row_digest).encode()).hexdigest()


def verify_chain_conn(conn: sqlite3.Connection) -> tuple[bool, str]:
    """
    Verify the integrity chain using an existing *open* SQLite connection.

    The connection may be read-only (e.g. from the dashboard) or read-write
    (from the Database class).  The function only runs SELECT statements.

    Returns (ok, human_readable_message).

    What this detects
    -----------------
    * Retroactive modification of any alerts row's core fields.
    * Deletion of rows from the alerts table.
    * Deletion or modification of integrity_chain rows.

    What this does NOT prevent
    --------------------------
    A determined root-level attacker who controls the SQLite file can always
    rewrite both tables and reconstruct a valid chain.  This is detection /
    audit-trail hardening, not cryptographic proof of integrity.
    """
    chain_rows = conn.execute(
        "SELECT seq, table_name, row_key, row_digest, chain_hash "
        "FROM integrity_chain ORDER BY seq"
    ).fetchall()

    if not chain_rows:
        alert_count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        if alert_count == 0:
            return True, "Integrity chain empty — new installation"
        # Existing DB created before chain feature was added; non-fatal.
        return True, (
            f"Integrity chain not yet seeded ({alert_count} pre-existing alert(s) "
            "not covered — chain will grow from next write)"
        )

    # Load all alerts in a single pass for O(n) verification.
    alerts_map: dict[int, sqlite3.Row] = {
        row["id"]: row
        for row in conn.execute(
            "SELECT id, timestamp, detector_name, severity, message FROM alerts"
        ).fetchall()
    }

    alert_count = len(alerts_map)
    chain_alert_count = sum(
        1 for r in chain_rows if r["table_name"] == "alerts"
    )
    if alert_count != chain_alert_count:
        return False, (
            f"Alert count mismatch: {alert_count} row(s) in alerts table "
            f"but {chain_alert_count} in integrity chain "
            "(row(s) deleted from alerts or chain entries removed)"
        )

    prev_hash = _GENESIS_HASH
    for row in chain_rows:
        seq = row["seq"]
        table_name = row["table_name"]
        row_key = row["row_key"]
        stored_row_digest: str = row["row_digest"]
        stored_chain_hash: str = row["chain_hash"]

        # Re-derive the row digest from the actual table data.
        if table_name == "alerts":
            try:
                alert_id = int(row_key.split(":")[-1])
            except (ValueError, IndexError):
                return False, f"seq={seq}: malformed row_key {row_key!r}"
            alert = alerts_map.get(alert_id)
            if alert is None:
                return False, (
                    f"seq={seq}: alert id={alert_id} referenced by chain "
                    "is missing from the alerts table (deleted?)"
                )
            actual_digest = _alert_row_digest(
                alert["id"],
                alert["timestamp"],
                alert["detector_name"],
                alert["severity"],
                alert["message"],
            )
        else:
            # Unknown table — trust stored digest; still verify chain link.
            actual_digest = stored_row_digest

        if actual_digest != stored_row_digest:
            return False, (
                f"seq={seq}: {table_name} row {row_key} data does not match "
                "the stored digest (row was modified after insertion)"
            )

        expected_chain = _compute_chain_hash(prev_hash, stored_row_digest)
        if expected_chain != stored_chain_hash:
            return False, (
                f"seq={seq}: chain hash mismatch — integrity_chain row(s) "
                "may have been modified or deleted"
            )

        prev_hash = stored_chain_hash

    return True, "Integrity chain verified OK"


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

    # ------------------------------------------------------------------
    # Integrity chain
    # ------------------------------------------------------------------

    def _append_chain_locked(
        self, table_name: str, row_key: str, row_digest: str
    ) -> None:
        """Append one entry to integrity_chain.  Caller must hold self._lock
        and must commit the enclosing transaction afterwards."""
        row = self._conn.execute(
            "SELECT chain_hash FROM integrity_chain ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev_hash = row["chain_hash"] if row else _GENESIS_HASH
        new_chain = _compute_chain_hash(prev_hash, row_digest)
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "INSERT INTO integrity_chain "
            "(table_name, row_key, row_digest, chain_hash, written_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (table_name, row_key, row_digest, new_chain, now),
        )

    def verify_chain(self) -> tuple[bool, str]:
        """Verify the integrity chain; see :func:`verify_chain_conn`."""
        with self._lock:
            return verify_chain_conn(self._conn)

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
            alert_id = int(cur.lastrowid)
            digest = _alert_row_digest(
                alert_id, timestamp, detector_name, severity, message
            )
            self._append_chain_locked("alerts", f"alerts:{alert_id}", digest)
            self._conn.commit()
            return alert_id

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

    def query_alerts(
        self,
        *,
        severity: str | None = None,
        detector: str | None = None,
        acknowledged: bool | None = None,
        limit: int = 50,
    ) -> list[sqlite3.Row]:
        """Filtered alert query used by the dashboard."""
        conditions: list[str] = []
        params: list[object] = []
        if severity:
            conditions.append("severity = ?")
            params.append(severity.lower())
        if detector:
            conditions.append("detector_name = ?")
            params.append(detector)
        if acknowledged is not None:
            conditions.append("acknowledged = ?")
            params.append(1 if acknowledged else 0)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(max(1, min(limit, 500)))
        with self._lock:
            return list(
                self._conn.execute(
                    f"SELECT id, timestamp, detector_name, severity, message, acknowledged "
                    f"FROM alerts {where} ORDER BY id DESC LIMIT ?",
                    params,
                ).fetchall()
            )

    def get_alert_by_id(self, alert_id: int) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT id, timestamp, detector_name, severity, message, acknowledged "
                "FROM alerts WHERE id = ?",
                (alert_id,),
            ).fetchone()

    def stats_summary(self) -> dict[str, object]:
        """Aggregate counts for the dashboard summary cards."""
        from datetime import datetime, timedelta, timezone  # already imported above

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            last_24h = self._conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE timestamp >= ?", (cutoff,)
            ).fetchone()[0]
            by_severity = {
                row[0]: row[1]
                for row in self._conn.execute(
                    "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
                ).fetchall()
            }
            by_detector = {
                row[0]: row[1]
                for row in self._conn.execute(
                    "SELECT detector_name, COUNT(*) FROM alerts GROUP BY detector_name"
                ).fetchall()
            }
        return {
            "total_alerts": total,
            "alerts_last_24h": last_24h,
            "by_severity": by_severity,
            "by_detector": by_detector,
        }

    def detector_baselines_summary(self) -> list[sqlite3.Row]:
        """Per-detector baseline counts and last-seen timestamps."""
        with self._lock:
            return list(
                self._conn.execute(
                    "SELECT detector_name, COUNT(*) AS baseline_count, "
                    "MAX(last_seen) AS last_seen "
                    "FROM baselines GROUP BY detector_name"
                ).fetchall()
            )
