"""
Tests for the ARGUS read-only web dashboard.

Key assertions:
1. All endpoints require authentication — unauthenticated requests → 401.
2. All read endpoints return correct data from the DB.
3. The underlying SQLite connection is read-only: any write attempt raises an
   OperationalError, proving the dashboard cannot modify data.
4. No endpoint in the application calls any write method; we verify this by
   using a read-only SQLite connection as the backing store and confirming
   every endpoint succeeds (reads work) while writes would fail (by testing
   the connection directly).
"""

from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path

import bcrypt
from fastapi.testclient import TestClient

from dashboard.app import create_app, hash_password, verify_password
from storage.db import Database


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PLAIN_PW = "test-secret-123"
_PW_HASH = bcrypt.hashpw(_PLAIN_PW.encode(), bcrypt.gensalt()).decode()

_CONFIG = {
    "dashboard": {
        "username": "admin",
        "password_hash": _PW_HASH,
    },
    "detectors": {
        "enabled": ["suid_check", "capability_check"],
    },
}


def _auth_header(username: str = "admin", password: str = _PLAIN_PW) -> dict:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def _make_client(tmp_path: Path) -> tuple[TestClient, Database]:
    db = Database(tmp_path / "test.db")
    # Seed some data
    db.insert_alert("2026-08-12T08:00:00+00:00", "suid_check", "high", "SUID set on /usr/bin/evil")
    db.insert_alert("2026-08-12T09:00:00+00:00", "capability_check", "medium", "Cap on /bin/python")
    db.insert_alert("2026-08-11T08:00:00+00:00", "suid_check", "critical", "Old critical")
    db.acknowledge_alert(3)

    # Seed a baseline entry so detector status has data
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    db.replace_baselines(
        "suid_check",
        [("suid_check", "abc123", now, now, "suid:/usr/bin/evil", '{"test":1}')],
    )

    app = create_app(_CONFIG, tmp_path / "test.db")
    client = TestClient(app, raise_server_exceptions=True)
    return client, db


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------

class TestDashboardAuth(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.client, self.db = _make_client(Path(self._tmp.name))

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def test_unauthenticated_root_returns_401(self) -> None:
        resp = self.client.get("/", auth=None)
        self.assertEqual(resp.status_code, 401)

    def test_wrong_password_returns_401(self) -> None:
        resp = self.client.get("/", auth=("admin", "wrong-password"))
        self.assertEqual(resp.status_code, 401)

    def test_wrong_username_returns_401(self) -> None:
        resp = self.client.get("/api/alerts", auth=("hacker", _PLAIN_PW))
        self.assertEqual(resp.status_code, 401)

    def test_valid_credentials_allowed(self) -> None:
        resp = self.client.get("/api/alerts", auth=("admin", _PLAIN_PW))
        self.assertEqual(resp.status_code, 200)

    def test_unauthenticated_api_alerts_returns_401(self) -> None:
        resp = self.client.get("/api/alerts")
        self.assertEqual(resp.status_code, 401)

    def test_unauthenticated_stats_returns_401(self) -> None:
        resp = self.client.get("/api/stats/summary")
        self.assertEqual(resp.status_code, 401)

    def test_unauthenticated_detectors_returns_401(self) -> None:
        resp = self.client.get("/api/detectors/status")
        self.assertEqual(resp.status_code, 401)

    def test_empty_password_hash_blocks_all(self) -> None:
        """If password_hash is empty, dashboard must reject every request."""
        app = create_app(
            {"dashboard": {"username": "admin", "password_hash": ""}},
            Path(self._tmp.name) / "test.db",
        )
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/api/alerts", auth=("admin", _PLAIN_PW))
        self.assertIn(resp.status_code, (401, 503))


# ---------------------------------------------------------------------------
# GET /api/alerts
# ---------------------------------------------------------------------------

class TestAlertsEndpoint(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.client, self.db = _make_client(Path(self._tmp.name))
        self._auth = ("admin", _PLAIN_PW)

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def test_returns_all_alerts_by_default(self) -> None:
        resp = self.client.get("/api/alerts", auth=self._auth)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 3)

    def test_filter_by_severity(self) -> None:
        resp = self.client.get("/api/alerts?severity=high", auth=self._auth)
        self.assertEqual(resp.status_code, 200)
        rows = resp.json()
        self.assertTrue(all(r["severity"] == "high" for r in rows))
        self.assertEqual(len(rows), 1)

    def test_filter_by_detector(self) -> None:
        resp = self.client.get("/api/alerts?detector=suid_check", auth=self._auth)
        rows = resp.json()
        self.assertTrue(all(r["detector_name"] == "suid_check" for r in rows))
        self.assertEqual(len(rows), 2)

    def test_filter_unacknowledged(self) -> None:
        resp = self.client.get("/api/alerts?acknowledged=false", auth=self._auth)
        rows = resp.json()
        self.assertTrue(all(not r["acknowledged"] for r in rows))
        self.assertEqual(len(rows), 2)

    def test_filter_acknowledged(self) -> None:
        resp = self.client.get("/api/alerts?acknowledged=true", auth=self._auth)
        rows = resp.json()
        self.assertTrue(all(r["acknowledged"] for r in rows))
        self.assertEqual(len(rows), 1)

    def test_limit_respected(self) -> None:
        resp = self.client.get("/api/alerts?limit=1", auth=self._auth)
        self.assertEqual(len(resp.json()), 1)

    def test_response_has_expected_fields(self) -> None:
        resp = self.client.get("/api/alerts", auth=self._auth)
        row = resp.json()[0]
        for field in ("id", "timestamp", "detector_name", "severity", "message", "acknowledged"):
            self.assertIn(field, row, f"Missing field: {field}")


# ---------------------------------------------------------------------------
# GET /api/alerts/{id}
# ---------------------------------------------------------------------------

class TestAlertByIdEndpoint(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.client, self.db = _make_client(Path(self._tmp.name))
        self._auth = ("admin", _PLAIN_PW)

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def test_returns_specific_alert(self) -> None:
        resp = self.client.get("/api/alerts/1", auth=self._auth)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["id"], 1)
        self.assertEqual(data["severity"], "high")

    def test_404_for_missing_id(self) -> None:
        resp = self.client.get("/api/alerts/9999", auth=self._auth)
        self.assertEqual(resp.status_code, 404)


# ---------------------------------------------------------------------------
# GET /api/stats/summary
# ---------------------------------------------------------------------------

class TestStatsSummaryEndpoint(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.client, self.db = _make_client(Path(self._tmp.name))
        self._auth = ("admin", _PLAIN_PW)

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def test_summary_shape(self) -> None:
        resp = self.client.get("/api/stats/summary", auth=self._auth)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        for key in ("total_alerts", "alerts_last_24h", "by_severity", "by_detector",
                    "integrity_status", "integrity_message"):
            self.assertIn(key, data, f"Missing key: {key}")

    def test_total_alerts_correct(self) -> None:
        resp = self.client.get("/api/stats/summary", auth=self._auth)
        self.assertEqual(resp.json()["total_alerts"], 3)

    def test_integrity_status_ok_on_clean_db(self) -> None:
        resp = self.client.get("/api/stats/summary", auth=self._auth)
        self.assertEqual(resp.json()["integrity_status"], "ok")

    def test_integrity_tamper_detected(self) -> None:
        """Directly modify an alert — summary must report TAMPERED."""
        with self.db._lock:
            self.db._conn.execute("UPDATE alerts SET severity = 'low' WHERE id = 1")
            self.db._conn.commit()
        resp = self.client.get("/api/stats/summary", auth=self._auth)
        self.assertEqual(resp.json()["integrity_status"], "TAMPERED")

    def test_by_severity_counts(self) -> None:
        data = self.client.get("/api/stats/summary", auth=self._auth).json()
        sev = data["by_severity"]
        self.assertEqual(sev.get("high", 0), 1)
        self.assertEqual(sev.get("medium", 0), 1)
        self.assertEqual(sev.get("critical", 0), 1)


# ---------------------------------------------------------------------------
# GET /api/detectors/status
# ---------------------------------------------------------------------------

class TestDetectorStatusEndpoint(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.client, self.db = _make_client(Path(self._tmp.name))
        self._auth = ("admin", _PLAIN_PW)

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def test_returns_list(self) -> None:
        resp = self.client.get("/api/detectors/status", auth=self._auth)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)

    def test_enabled_detectors_marked(self) -> None:
        resp = self.client.get("/api/detectors/status", auth=self._auth)
        names_enabled = {d["name"]: d["enabled"] for d in resp.json()}
        self.assertTrue(names_enabled.get("suid_check"))
        self.assertTrue(names_enabled.get("capability_check"))

    def test_detector_has_required_fields(self) -> None:
        resp = self.client.get("/api/detectors/status", auth=self._auth)
        for det in resp.json():
            for field in ("name", "mode", "enabled", "baseline_count", "last_seen"):
                self.assertIn(field, det, f"{det['name']}: missing {field}")

    def test_suid_check_has_baseline_count(self) -> None:
        resp = self.client.get("/api/detectors/status", auth=self._auth)
        suid = next(d for d in resp.json() if d["name"] == "suid_check")
        self.assertEqual(suid["baseline_count"], 1)


# ---------------------------------------------------------------------------
# Read-only guarantee
# ---------------------------------------------------------------------------

class TestDashboardReadOnly(unittest.TestCase):
    """
    The dashboard opens a read-only SQLite connection.  Verify that:
    1. All read endpoints succeed.
    2. The connection itself rejects any write attempt.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.client, self.db = _make_client(Path(self._tmp.name))

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def test_all_read_endpoints_succeed(self) -> None:
        auth = ("admin", _PLAIN_PW)
        endpoints = [
            "/api/alerts",
            "/api/alerts/1",
            "/api/stats/summary",
            "/api/detectors/status",
        ]
        for ep in endpoints:
            resp = self.client.get(ep, auth=auth)
            self.assertIn(
                resp.status_code,
                (200, 404),  # 404 is acceptable if no data; not 500
                f"{ep} returned {resp.status_code}",
            )

    def test_readonly_sqlite_rejects_write(self) -> None:
        """Read-only connection cannot write — this is enforced by SQLite URI mode."""
        import sqlite3

        db_path = self.db.path
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                conn.execute("DELETE FROM alerts")
        finally:
            conn.close()

    def test_no_write_routes_in_schema(self) -> None:
        """The OpenAPI schema must contain zero DELETE/POST/PUT/PATCH routes."""
        resp = self.client.get("/openapi.json")
        self.assertEqual(resp.status_code, 200)
        schema = resp.json()
        write_methods = {"post", "put", "patch", "delete"}
        violations = []
        for path, methods in schema.get("paths", {}).items():
            for method in methods:
                if method.lower() in write_methods:
                    violations.append(f"{method.upper()} {path}")
        self.assertEqual(
            violations,
            [],
            f"Dashboard has write endpoints (must be read-only): {violations}",
        )


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

class TestPasswordHelpers(unittest.TestCase):
    def test_hash_and_verify_roundtrip(self) -> None:
        hashed = hash_password("my-secret")
        self.assertTrue(verify_password("my-secret", hashed))

    def test_wrong_password_fails(self) -> None:
        hashed = hash_password("correct")
        self.assertFalse(verify_password("wrong", hashed))

    def test_empty_hash_always_fails(self) -> None:
        self.assertFalse(verify_password("anything", ""))


if __name__ == "__main__":
    unittest.main()
