"""Detect new/removed SUID and SGID binaries under common paths."""

from __future__ import annotations

import json
import logging
import os
import stat
from pathlib import Path
from typing import Any, Iterable

from detectors.base import BaseDetector, Finding
from storage.db import Database

logger = logging.getLogger(__name__)

DEFAULT_SCAN_PATHS = (
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
)

# st_mode bits we care about
_SUID = stat.S_ISUID
_SGID = stat.S_ISGID


class SuidCheckDetector(BaseDetector):
    """
    Inventory setuid/setgid files; alert on inventory deltas only.

    - NEW SUID/SGID file  → severity HIGH  (via BaseDetector.diff)
    - REMOVED / cleared   → severity LOW   (informational; once, then pruned)
    """

    name = "suid_check"

    def __init__(self, db: Database, config: dict[str, Any] | None = None) -> None:
        super().__init__(db, config)
        raw_paths = (self.config.get("scan_paths") if self.config else None) or DEFAULT_SCAN_PATHS
        self.scan_paths: list[Path] = [Path(p) for p in raw_paths]

    def scan(self) -> list[Finding]:
        """Return current SUID/SGID inventory (all severity=high for baseline identity)."""
        findings: list[Finding] = []
        seen: set[str] = set()

        for root in self.scan_paths:
            if not root.is_dir():
                logger.debug("Skipping missing scan path: %s", root)
                continue
            for path in self._iter_files(root):
                finding = self._finding_for_path(path)
                if finding is None:
                    continue
                if finding.item_key in seen:
                    continue
                seen.add(finding.item_key)
                findings.append(finding)

        findings.sort(key=lambda f: f.item_key)
        return findings

    def run_once(self) -> list[Finding]:
        """
        Scan → NEW via diff() → REMOVED as LOW → replace baseline.

        Removal findings are not written into the baseline (different item_key /
        severity); pruning the prior hash prevents re-alert every cycle.
        """
        current = self.scan()
        baseline_hashes = self.get_baseline()
        novel = self.diff(baseline_hashes, current)

        current_hashes = {f.item_hash() for f in current}
        removed = self._removed_findings(baseline_hashes - current_hashes)

        self.save_baseline(current)
        return self.suppress_allowlisted(novel + removed)

    def _removed_findings(self, removed_hashes: set[str]) -> list[Finding]:
        if not removed_hashes:
            return []

        out: list[Finding] = []
        for row in self.db.get_baseline_entries(self.name):
            if row["item_hash"] not in removed_hashes:
                continue
            out.append(self._removal_finding_from_payload(row["payload"], row["item_key"]))
        out.sort(key=lambda f: f.item_key)
        return out

    def _removal_finding_from_payload(self, payload: str, fallback_key: str) -> Finding:
        path = fallback_key
        bits = "suid/sgid"
        details: dict[str, Any] = {"change": "removed"}

        if payload:
            try:
                data = json.loads(payload)
                prev_details = data.get("details") or {}
                path = prev_details.get("path") or data.get("item_key") or fallback_key
                bits = prev_details.get("bits") or bits
                details = {
                    "change": "removed",
                    "path": path,
                    "previous_bits": bits,
                    "previous_mode": prev_details.get("mode"),
                }
            except json.JSONDecodeError:
                details = {"change": "removed", "path": path}

        # Strip inventory prefix from item_key if present (suid:/path → /path)
        display = path
        if isinstance(path, str) and ":" in path and not path.startswith("/"):
            display = path.split(":", 1)[-1]

        return Finding(
            detector_name=self.name,
            severity="low",
            message=f"SUID/SGID cleared or binary removed: {display} (was {bits})",
            item_key=f"removed:{display}",
            details=details,
        )

    def _finding_for_path(self, path: Path) -> Finding | None:
        try:
            st = path.lstat()
        except OSError as exc:
            logger.debug("stat failed for %s: %s", path, exc)
            return None

        if not stat.S_ISREG(st.st_mode):
            return None

        has_suid = bool(st.st_mode & _SUID)
        has_sgid = bool(st.st_mode & _SGID)
        if not (has_suid or has_sgid):
            return None

        if has_suid and has_sgid:
            bits = "suid+sgid"
        elif has_suid:
            bits = "suid"
        else:
            bits = "sgid"

        resolved = str(path)

        return Finding(
            detector_name=self.name,
            severity="high",
            # Stable wording — "newness" comes from diff(), not the message text
            message=f"{bits.upper()} bit set on {resolved}",
            item_key=f"{bits}:{resolved}",
            details={
                "path": resolved,
                "bits": bits,
                "mode": oct(st.st_mode & 0o7777),
                "uid": st.st_uid,
                "gid": st.st_gid,
                "change": "present",
            },
        )

    @staticmethod
    def _iter_files(root: Path) -> Iterable[Path]:
        """Non-recursive listing of entries under root (common bin dirs are flat)."""
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    try:
                        if entry.is_file(follow_symlinks=False):
                            yield Path(entry.path)
                    except OSError:
                        continue
        except OSError as exc:
            logger.warning("Cannot scan %s: %s", root, exc)
