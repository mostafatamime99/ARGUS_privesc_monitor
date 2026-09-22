"""Tests for the SQLite integrity chain in storage/db.py."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from storage.db import (
    Database,
    _GENESIS_HASH,
    _alert_row_digest,
    _compute_chain_hash,
    verify_chain_conn,
)


def _fresh_db(tmp: str) -> Database:
    return Database(Path(tmp) / "t.db")


class TestChainHelpers(unittest.TestCase):
    def test_alert_row_digest_is_deterministic(self) -> None:
        d1 = _alert_row_digest(1, "2026-01-01T00:00:00+00:00", "suid_check", "high", "msg")
        d2 = _alert_row_digest(1, "2026-01-01T00:00:00+00:00", "suid_check", "high", "msg")
        self.assertEqual(d1, d2)

    def test_alert_row_digest_changes_on_severity(self) -> None:
        d1 = _alert_row_digest(1, "2026-01-01", "suid_check", "high", "msg")
        d2 = _alert_row_digest(1, "2026-01-01", "suid_check", "critical", "msg")
        self.assertNotEqual(d1, d2)

    def test_compute_chain_hash_chained(self) -> None:
        h1 = _compute_chain_hash(_GENESIS_HASH, "digest_a")
        h2 = _compute_chain_hash(h1, "digest_b")
        # Different inputs → different outputs
        self.assertNotEqual(h1, h2)
        # Deterministic
        self.assertEqual(_compute_chain_hash(_GENESIS_HASH, "digest_a"), h1)


class TestChainAppend(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = _fresh_db(self._tmp.name)

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def test_first_alert_creates_one_chain_entry(self) -> None:
        self.db.insert_alert(
            timestamp="2026-01-01T00:00:00+00:00",
            detector_name="suid_check",
            severity="high",
            message="test alert",
        )
        rows = self.db._conn.execute("SELECT * FROM integrity_chain").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["table_name"], "alerts")
        self.assertEqual(rows[0]["row_key"], "alerts:1")

    def test_chain_hash_starts_from_genesis(self) -> None:
        self.db.insert_alert(
            timestamp="2026-01-01T00:00:00+00:00",
            detector_name="suid_check",
            severity="high",
            message="first",
        )
        row = self.db._conn.execute("SELECT * FROM integrity_chain").fetchone()
        expected = _compute_chain_hash(_GENESIS_HASH, row["row_digest"])
        self.assertEqual(row["chain_hash"], expected)

    def test_two_alerts_chain_links_correctly(self) -> None:
        self.db.insert_alert("2026-01-01", "d1", "high", "first")
        self.db.insert_alert("2026-01-01", "d2", "medium", "second")
        rows = self.db._conn.execute(
            "SELECT * FROM integrity_chain ORDER BY seq"
        ).fetchall()
        self.assertEqual(len(rows), 2)
        # Second entry uses first's chain_hash as prev
        expected = _compute_chain_hash(rows[0]["chain_hash"], rows[1]["row_digest"])
        self.assertEqual(rows[1]["chain_hash"], expected)

    def test_multiple_inserts_all_chained(self) -> None:
        for i in range(10):
            self.db.insert_alert(f"2026-01-{i+1:02d}", "det", "low", f"msg {i}")
        count = self.db._conn.execute("SELECT COUNT(*) FROM integrity_chain").fetchone()[0]
        self.assertEqual(count, 10)


class TestVerifyChainOk(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = _fresh_db(self._tmp.name)

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def test_empty_db_is_ok(self) -> None:
        ok, msg = self.db.verify_chain()
        self.assertTrue(ok)
        self.assertIn("empty", msg.lower())

    def test_single_alert_verifies(self) -> None:
        self.db.insert_alert("2026-01-01T00:00:00+00:00", "suid_check", "high", "msg")
        ok, msg = self.db.verify_chain()
        self.assertTrue(ok, msg)
        self.assertIn("OK", msg)

    def test_many_alerts_verify(self) -> None:
        for i in range(20):
            self.db.insert_alert(f"2026-01-01T{i:02d}:00:00+00:00", "suid", "low", f"m{i}")
        ok, msg = self.db.verify_chain()
        self.assertTrue(ok, msg)

    def test_acknowledge_does_not_break_chain(self) -> None:
        aid = self.db.insert_alert("2026-01-01", "suid_check", "high", "msg")
        self.db.acknowledge_alert(aid)
        ok, msg = self.db.verify_chain()
        self.assertTrue(ok, msg)

    def test_details_modification_breaks_chain(self) -> None:
        self.db.insert_alert(
            "2026-01-01",
            "sudoers_check",
            "high",
            "modified",
            hostname="web-01",
            details='{"path": "/etc/sudoers"}',
        )
        with self.db._lock:
            self.db._conn.execute(
                "UPDATE alerts SET details = '{\"path\": \"/tmp/nope\"}' WHERE id = 1"
            )
            self.db._conn.commit()
        ok, msg = self.db.verify_chain()
        self.assertFalse(ok)
        self.assertIn("modified", msg.lower())


class TestChainMigration(unittest.TestCase):
    def test_v1_rows_still_verify_after_column_migration(self) -> None:
        import sqlite3

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "legacy.db"
        conn = sqlite3.connect(path)
        conn.executescript(
            """
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                detector_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE integrity_chain (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                table_name TEXT NOT NULL,
                row_key TEXT NOT NULL,
                row_digest TEXT NOT NULL,
                chain_hash TEXT NOT NULL,
                written_at TEXT NOT NULL
            );
            """
        )
        timestamp = "2026-01-01T00:00:00+00:00"
        conn.execute(
            "INSERT INTO alerts (timestamp, detector_name, severity, message, acknowledged) "
            "VALUES (?, 'suid_check', 'high', 'legacy', 0)",
            (timestamp,),
        )
        digest = _alert_row_digest(1, timestamp, "suid_check", "high", "legacy")
        chain = _compute_chain_hash(_GENESIS_HASH, digest)
        conn.execute(
            "INSERT INTO integrity_chain "
            "(table_name, row_key, row_digest, chain_hash, written_at) "
            "VALUES ('alerts', 'alerts:1', ?, ?, '2026-01-01T00:00:00+00:00')",
            (digest, chain),
        )
        conn.commit()
        conn.close()

        db = Database(path)
        self.addCleanup(db.close)
        ok, msg = db.verify_chain()
        self.assertTrue(ok, msg)
        db.insert_alert(
            "2026-01-02T00:00:00+00:00",
            "suid_check",
            "high",
            "new",
            hostname="migrated",
            details='{"path": "/bin/new"}',
        )
        ok, msg = db.verify_chain()
        self.assertTrue(ok, msg)


class TestVerifyChainTamper(unittest.TestCase):
    """Simulate retroactive tampering and verify detection."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = _fresh_db(self._tmp.name)

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def _raw_write(self, sql: str, *params) -> None:
        """Bypass Database.insert_alert to simulate attacker-direct edits."""
        with self.db._lock:
            self.db._conn.execute(sql, params)
            self.db._conn.commit()

    def test_detects_alert_deletion(self) -> None:
        self.db.insert_alert("2026-01-01", "suid_check", "critical", "evil")
        self.db.insert_alert("2026-01-02", "suid_check", "high", "normal")
        # Attacker deletes the first alert to hide evidence
        self._raw_write("DELETE FROM alerts WHERE id = 1")
        ok, msg = self.db.verify_chain()
        self.assertFalse(ok)
        self.assertTrue(
            "deleted" in msg.lower()
            or "missing" in msg.lower()
            or "mismatch" in msg.lower(),
            msg,
        )

    def test_detects_severity_modification(self) -> None:
        self.db.insert_alert("2026-01-01", "suid_check", "high", "msg")
        # Attacker downgrades severity to hide severity
        self._raw_write("UPDATE alerts SET severity = 'low' WHERE id = 1")
        ok, msg = self.db.verify_chain()
        self.assertFalse(ok)
        self.assertIn("modified", msg.lower())

    def test_detects_message_modification(self) -> None:
        self.db.insert_alert("2026-01-01", "suid_check", "critical", "original message")
        self._raw_write("UPDATE alerts SET message = 'tampered message' WHERE id = 1")
        ok, msg = self.db.verify_chain()
        self.assertFalse(ok)
        self.assertIn("modified", msg.lower())

    def test_detects_chain_entry_modification(self) -> None:
        self.db.insert_alert("2026-01-01", "suid_check", "high", "msg")
        # Attacker also touches the chain entry hoping to cover tracks
        self._raw_write(
            "UPDATE integrity_chain SET row_digest = 'aaaa' WHERE seq = 1"
        )
        ok, msg = self.db.verify_chain()
        self.assertFalse(ok)
        # Either digest or chain-hash mismatch should be caught
        self.assertTrue("modified" in msg.lower() or "mismatch" in msg.lower(), msg)

    def test_existing_db_without_chain_is_not_flagged(self) -> None:
        """Pre-chain alerts (from before this feature) must not trigger false alarms."""
        # Insert alert bypassing chain (simulating legacy insert)
        with self.db._lock:
            self.db._conn.execute(
                "INSERT INTO alerts (timestamp, detector_name, severity, message, acknowledged) "
                "VALUES ('2026-01-01', 'suid_check', 'high', 'legacy', 0)"
            )
            self.db._conn.commit()
        # No chain entries yet
        ok, msg = self.db.verify_chain()
        self.assertTrue(ok, msg)
        self.assertIn("pre-existing", msg.lower())


class TestVerifyChainReadOnly(unittest.TestCase):
    """The module-level verify_chain_conn works with a read-only connection."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = _fresh_db(self._tmp.name)
        self.db.insert_alert("2026-01-01", "suid_check", "high", "test")

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def test_verify_via_readonly_conn(self) -> None:
        import sqlite3

        db_path = self.db.path
        conn = sqlite3.connect(
            f"file:{db_path}?mode=ro", uri=True, check_same_thread=False
        )
        conn.row_factory = sqlite3.Row
        try:
            ok, msg = verify_chain_conn(conn)
            self.assertTrue(ok, msg)
        finally:
            conn.close()

    def test_readonly_conn_cannot_write(self) -> None:
        import sqlite3

        db_path = self.db.path
        conn = sqlite3.connect(
            f"file:{db_path}?mode=ro", uri=True, check_same_thread=False
        )
        try:
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("DELETE FROM alerts WHERE 1=1")
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
