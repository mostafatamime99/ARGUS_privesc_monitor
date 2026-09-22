"""Tests for baseline/diff behavior and the SUID/SGID detector."""

from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from detectors.base import BaseDetector, Finding
from detectors.suid_check import SuidCheckDetector
from storage.db import Database


class StubDetector(BaseDetector):
    name = "stub"

    def __init__(self, db: Database, findings: list[Finding] | None = None) -> None:
        super().__init__(db)
        self._findings = findings or []

    def scan(self) -> list[Finding]:
        return list(self._findings)


def _finding(key: str, message: str = "test") -> Finding:
    return Finding(
        detector_name="stub",
        severity="medium",
        message=message,
        item_key=key,
    )


def _reg_stat(*, suid: bool = False, sgid: bool = False) -> SimpleNamespace:
    mode = stat.S_IFREG | 0o755
    if suid:
        mode |= stat.S_ISUID
    if sgid:
        mode |= stat.S_ISGID
    return SimpleNamespace(st_mode=mode, st_uid=0, st_gid=0)


class TestBaselineDiff(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.db = Database(Path(self._tmp.name) / "test.db")

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def test_diff_returns_only_new_hashes(self) -> None:
        a, b, c = _finding("a"), _finding("b"), _finding("c")
        old = {a.item_hash(), b.item_hash()}
        novel = StubDetector(self.db).diff(old, [a, b, c])
        self.assertEqual([f.item_key for f in novel], ["c"])

    def test_run_once_does_not_realert_unchanged(self) -> None:
        findings = [_finding("suid-/usr/bin/pass"), _finding("writable-/etc")]
        det = StubDetector(self.db, findings)
        first = det.run_once()
        self.assertEqual(len(first), 2)

        second = det.run_once()
        self.assertEqual(second, [])

    def test_run_once_alerts_only_newly_appeared(self) -> None:
        det = StubDetector(self.db, [_finding("one")])
        self.assertEqual(len(det.run_once()), 1)

        det._findings = [_finding("one"), _finding("two")]
        novel = det.run_once()
        self.assertEqual([f.item_key for f in novel], ["two"])

    def test_allowlist_suppresses_known_good_and_still_baselines(self) -> None:
        det = StubDetector(self.db, [_finding("keep"), _finding("alert")])
        det.allowlist = ["keep"]
        first = det.run_once()
        self.assertEqual([f.item_key for f in first], ["alert"])
        self.assertEqual(det.run_once(), [])
        self.assertEqual(
            self.db.get_baseline_hashes("stub"),
            {_finding("keep").item_hash(), _finding("alert").item_hash()},
        )

    def test_allowlist_matches_path_and_prefix(self) -> None:
        path_finding = Finding(
            detector_name="stub",
            severity="high",
            message="suid",
            item_key="suid:/usr/bin/passwd",
            details={"path": "/usr/bin/passwd"},
        )
        other = Finding(
            detector_name="stub",
            severity="high",
            message="other",
            item_key="suid:/usr/local/bin/evil",
            details={"path": "/usr/local/bin/evil"},
        )
        det = StubDetector(self.db, [path_finding, other])
        det.allowlist = ["/usr/bin/passwd", "/usr/local/bin/*"]
        self.assertEqual(det.run_once(), [])

    def test_save_baseline_prunes_removed_hashes(self) -> None:
        det = StubDetector(self.db, [_finding("one"), _finding("two")])
        det.run_once()
        det._findings = [_finding("one")]
        det.run_once()
        self.assertEqual(self.db.get_baseline_hashes("stub"), {_finding("one").item_hash()})


class TestSuidCheckDetector(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.bin_dir = self.root / "usr_bin"
        self.bin_dir.mkdir()
        self.db = Database(self.root / "test.db")
        self.det = SuidCheckDetector(
            self.db, config={"scan_paths": [str(self.bin_dir)]}
        )
        # path -> fake lstat result (SUID bits are Linux-only; mock for CI/Windows)
        self._stat_map: dict[str, SimpleNamespace] = {}

    def tearDown(self) -> None:
        self.db.close()
        self._tmp.cleanup()

    def _add_binary(self, name: str, *, suid: bool = True, sgid: bool = False) -> Path:
        path = self.bin_dir / name
        path.write_bytes(b"\0")
        self._stat_map[str(path)] = _reg_stat(suid=suid, sgid=sgid)
        return path

    def _patch_lstat(self):
        stat_map = self._stat_map

        def fake_lstat(self_path: Path):
            key = str(self_path)
            if key in stat_map:
                return stat_map[key]
            return Path.lstat(self_path)

        return mock.patch.object(Path, "lstat", fake_lstat)

    def test_scan_finds_suid_files(self) -> None:
        path = self._add_binary("evil", suid=True)
        with self._patch_lstat():
            findings = self.det.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].details["path"], str(path))
        self.assertEqual(findings[0].details["bits"], "suid")

    def test_run_once_no_realert_on_unchanged(self) -> None:
        self._add_binary("passwd")
        with self._patch_lstat():
            first = self.det.run_once()
            second = self.det.run_once()
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0].severity, "high")
        self.assertEqual(second, [])

    def test_run_once_high_on_new_then_low_on_removed(self) -> None:
        path = self._add_binary("newbin")
        with self._patch_lstat():
            novel = self.det.run_once()
        self.assertEqual([f.severity for f in novel], ["high"])

        path.unlink()
        del self._stat_map[str(path)]
        with self._patch_lstat():
            delta = self.det.run_once()
        self.assertEqual(len(delta), 1)
        self.assertEqual(delta[0].severity, "low")
        self.assertTrue(delta[0].item_key.startswith("removed:"))

        with self._patch_lstat():
            self.assertEqual(self.det.run_once(), [])

    def test_uses_base_diff_for_new_detection(self) -> None:
        self._add_binary("a")
        with self._patch_lstat():
            self.det.run_once()
        self._add_binary("b")

        with self._patch_lstat(), mock.patch.object(
            SuidCheckDetector, "diff", wraps=self.det.diff
        ) as wrapped_diff:
            results = self.det.run_once()
            wrapped_diff.assert_called_once()
            highs = [f for f in results if f.severity == "high"]
            self.assertEqual(len(highs), 1)
            self.assertIn("b", highs[0].details["path"])


if __name__ == "__main__":
    unittest.main()
