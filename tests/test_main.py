"""Tests for main daemon wiring (config, detectors, dry-run)."""

from __future__ import annotations

import asyncio
import logging
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import main as app
from detectors.base import Finding
from storage.db import Database


class TestParseArgs(unittest.TestCase):
    def test_ack_ids(self) -> None:
        args = app.parse_args(["ack", "4", "9", "-c", "config.yaml"])
        self.assertEqual(args.command, "ack")
        self.assertEqual(args.ids, [4, 9])

    def test_dry_run_flag(self) -> None:
        args = app.parse_args(["--dry-run", "-c", "config.yaml"])
        self.assertTrue(args.dry_run)
        self.assertEqual(args.config, Path("config.yaml"))

    def test_default_no_dry_run(self) -> None:
        args = app.parse_args([])
        self.assertFalse(args.dry_run)


class TestBuildDetectors(unittest.TestCase):
    def test_splits_poll_and_watch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "t.db")
            config = {
                "detectors": {
                    "enabled": ["suid_check", "sudoers_check", "cron_check"],
                    "suid_check": {"scan_paths": [tmp]},
                    "sudoers_check": {
                        "watch_files": [str(Path(tmp) / "sudoers")],
                        "watch_dirs": [str(Path(tmp) / "sudoers.d")],
                    },
                    "cron_check": {
                        "watch_files": [str(Path(tmp) / "crontab")],
                        "watch_dirs": [str(Path(tmp) / "cron.d")],
                    },
                }
            }
            Path(tmp, "sudoers.d").mkdir()
            Path(tmp, "cron.d").mkdir()
            poll, watch = app.build_detectors(config, db)
            self.assertEqual([d.name for d in poll], ["suid_check"])
            self.assertEqual(
                sorted(d.name for d in watch), ["cron_check", "sudoers_check"]
            )
            db.close()


class TestBuildDetectorsAuditParser(unittest.TestCase):
    """audit_parser is mode='watch' but NOT a ContentWatchDetector subclass.
    Enabling it must not crash build_detectors (regression for the dropped assert)."""

    def test_audit_parser_in_watch_list_no_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "t.db")
            log_file = Path(tmp) / "audit.log"
            log_file.write_text("", encoding="utf-8")
            config = {
                "detectors": {
                    "enabled": ["audit_parser"],
                    "audit_parser": {
                        "log_path": str(log_file),
                        "poll_interval_seconds": 60,
                    },
                }
            }
            poll, watch = app.build_detectors(config, db)
            self.assertEqual(poll, [])
            self.assertEqual(len(watch), 1)
            self.assertEqual(watch[0].name, "audit_parser")
            db.close()

    def test_all_six_detectors_build_without_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "t.db")
            log_file = Path(tmp) / "audit.log"
            log_file.write_text("", encoding="utf-8")
            Path(tmp, "sudoers.d").mkdir()
            Path(tmp, "cron.d").mkdir()
            config = {
                "detectors": {
                    "enabled": [
                        "suid_check",
                        "capability_check",
                        "version_scanner",
                        "sudoers_check",
                        "cron_check",
                        "audit_parser",
                    ],
                    "suid_check": {"scan_paths": [tmp]},
                    "capability_check": {"scan_roots": [tmp]},
                    "version_scanner": {
                        "engine": "searchsploit",
                        "scan_interval_seconds": 3600,
                    },
                    "sudoers_check": {
                        "watch_files": [str(Path(tmp) / "sudoers")],
                        "watch_dirs": [str(Path(tmp) / "sudoers.d")],
                    },
                    "cron_check": {
                        "watch_files": [str(Path(tmp) / "crontab")],
                        "watch_dirs": [str(Path(tmp) / "cron.d")],
                    },
                    "audit_parser": {
                        "log_path": str(log_file),
                        "poll_interval_seconds": 60,
                    },
                }
            }
            poll, watch = app.build_detectors(config, db)
            self.assertEqual(
                sorted(d.name for d in poll),
                ["capability_check", "suid_check", "version_scanner"],
            )
            self.assertEqual(
                sorted(d.name for d in watch),
                ["audit_parser", "cron_check", "sudoers_check"],
            )
            db.close()


class TestEmitFindingsDryRun(unittest.IsolatedAsyncioTestCase):
    async def test_dry_run_skips_telegram(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(Path(tmp.name) / "t.db")
        self.addCleanup(db.close)
        bot = mock.Mock()
        bot.notify = mock.Mock(return_value=1)
        finding = Finding(
            detector_name="suid_check",
            severity="high",
            message="test",
            item_key="k",
        )
        await app.emit_findings(
            [finding], db=db, bot=bot, dry_run=True, lock=asyncio.Lock()
        )
        bot.notify.assert_not_called()
        rows = db.recent_alerts(limit=5)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["detector_name"], "suid_check")

    async def test_live_calls_telegram(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(Path(tmp.name) / "t.db")
        self.addCleanup(db.close)
        bot = mock.Mock()
        bot.notify = mock.Mock(return_value=1)
        finding = Finding(
            detector_name="cron_check",
            severity="high",
            message="changed",
            item_key="k2",
        )
        await app.emit_findings(
            [finding], db=db, bot=bot, dry_run=False, lock=asyncio.Lock()
        )
        bot.notify.assert_called_once()

    async def test_notify_false_persists_but_skips_telegram(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(Path(tmp.name) / "t.db")
        self.addCleanup(db.close)
        bot = mock.Mock()
        bot.notify = mock.Mock(return_value=1)
        finding = Finding(
            detector_name="version_scanner",
            severity="medium",
            message="low confidence match",
            item_key="openssh:9.1:EDB-1",
            details={"confidence": "low"},
            notify=False,
        )
        await app.emit_findings(
            [finding], db=db, bot=bot, dry_run=False, lock=asyncio.Lock()
        )
        bot.notify.assert_not_called()
        rows = db.recent_alerts(limit=5)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["detector_name"], "version_scanner")

    async def test_persists_hostname_and_details(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(Path(tmp.name) / "t.db")
        self.addCleanup(db.close)
        bot = mock.Mock()
        bot.notify = mock.Mock(return_value=0)
        finding = Finding(
            detector_name="sudoers_check",
            severity="high",
            message="modified /etc/sudoers",
            item_key="modified:/etc/sudoers",
            details={"path": "/etc/sudoers", "diff": "+ ALL"},
        )
        await app.emit_findings(
            [finding],
            db=db,
            bot=bot,
            dry_run=True,
            lock=asyncio.Lock(),
            hostname="web-01",
        )
        row = db.recent_alerts(limit=1)[0]
        self.assertEqual(row["hostname"], "web-01")
        self.assertIn("/etc/sudoers", row["details"])
        self.assertIn("+ ALL", row["details"])
        ok, msg = db.verify_chain()
        self.assertTrue(ok, msg)


class TestSetupLogging(unittest.TestCase):
    def test_creates_rotating_log_file(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        log_path = Path(tmp.name) / "nested" / "app.log"
        app.setup_logging(
            {
                "logging": {
                    "level": "INFO",
                    "file": str(log_path),
                    "max_bytes": 1024,
                    "backup_count": 2,
                }
            }
        )
        logging.getLogger("privesc_monitor").info("hello-rotate")
        self.assertTrue(log_path.is_file())


class TestAcknowledgeCli(unittest.TestCase):
    def test_ack_marks_alert_without_breaking_chain(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        db_path = root / "alerts.db"
        cfg_path = root / "config.yaml"
        cfg_path.write_text(
            f"daemon:\n  db_path: {db_path.as_posix()}\n",
            encoding="utf-8",
        )
        db = Database(db_path)
        alert_id = db.insert_alert("2026-01-01", "suid_check", "high", "msg")
        db.close()

        code = app.main(["ack", str(alert_id), "-c", str(cfg_path)])
        self.assertEqual(code, 0)

        db = Database(db_path)
        self.addCleanup(db.close)
        row = db.get_alert_by_id(alert_id)
        assert row is not None
        self.assertEqual(row["acknowledged"], 1)
        ok, msg = db.verify_chain()
        self.assertTrue(ok, msg)

    def test_ack_missing_id_returns_error(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        db_path = root / "alerts.db"
        cfg_path = root / "config.yaml"
        cfg_path.write_text(
            f"daemon:\n  db_path: {db_path.as_posix()}\n",
            encoding="utf-8",
        )
        Database(db_path).close()
        code = app.main(["ack", "99", "-c", str(cfg_path)])
        self.assertEqual(code, 1)
        # Release file handles so temp cleanup succeeds on Windows
        root = logging.getLogger()
        for handler in list(root.handlers):
            handler.close()
            root.removeHandler(handler)


if __name__ == "__main__":
    unittest.main()
