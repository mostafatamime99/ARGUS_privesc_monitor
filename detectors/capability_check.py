"""Inventory Linux file capabilities; alert on new/removed entries."""

from __future__ import annotations

import json
import logging
import re
import subprocess
from typing import Any

from detectors.base import BaseDetector, Finding
from storage.db import Database

logger = logging.getLogger(__name__)

# Default: scan everything.  Restrict in config for speed (e.g. ["/usr", "/bin"])
DEFAULT_SCAN_ROOTS = ("/",)

# getcap output format:  /path/to/file = cap_net_raw+ep
# Some distros may omit the leading space around '='.
_GETCAP_LINE = re.compile(r"^(.+?)\s+=\s+(.+)$")

# Severity for new vs removed capability entries
_SEV_NEW = "high"
_SEV_REMOVED = "low"


class CapabilityCheckDetector(BaseDetector):
    """
    Run ``getcap -r <root>`` and diff the capability inventory.

    Alert fatigue strategy (same as suid_check):
    - New entry (path + caps)   → HIGH   (via BaseDetector.diff)
    - Cap removed / binary gone → LOW    (once, then pruned from baseline)
    - Changed caps on same path → NEW entry hash → treated as HIGH new finding
    """

    name = "capability_check"

    def __init__(self, db: Database, config: dict[str, Any] | None = None) -> None:
        super().__init__(db, config)
        raw_roots = self.config.get("scan_roots") or list(DEFAULT_SCAN_ROOTS)
        self.scan_roots: list[str] = [str(r) for r in raw_roots]
        # Timeout guard: getcap -r / on a busy system can take a while
        self.timeout: int = int(self.config.get("timeout_seconds", 60))

    # ------------------------------------------------------------------
    # BaseDetector interface
    # ------------------------------------------------------------------

    def scan(self) -> list[Finding]:
        """Return current capability inventory as HIGH findings."""
        findings: list[Finding] = []
        seen: set[str] = set()

        for root in self.scan_roots:
            for path, caps in self._run_getcap(root):
                item_key = f"cap:{path}:{caps}"
                if item_key in seen:
                    continue
                seen.add(item_key)
                findings.append(
                    Finding(
                        detector_name=self.name,
                        severity=_SEV_NEW,
                        message=f"Capability set on {path}: {caps}",
                        item_key=item_key,
                        details={"path": path, "caps": caps, "change": "present"},
                    )
                )

        findings.sort(key=lambda f: f.item_key)
        return findings

    def run_once(self) -> list[Finding]:
        """
        Scan → diff NEW (HIGH) → detect REMOVED (LOW) → replace baseline.

        Mirrors suid_check.run_once so removals alert exactly once.
        """
        current = self.scan()
        baseline_hashes = self.get_baseline()
        novel = self.diff(baseline_hashes, current)

        current_hashes = {f.item_hash() for f in current}
        removed = self._removed_findings(baseline_hashes - current_hashes)

        self.save_baseline(current)
        return self.suppress_allowlisted(novel + removed)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_getcap(self, root: str) -> list[tuple[str, str]]:
        """
        Execute ``getcap -r <root>`` and return (path, caps) pairs.

        Returns [] on any error (tool absent, permission denied, timeout).
        getcap exits non-zero only on hard errors; partial output is still
        useful so we parse whatever we got before checking returncode.
        """
        try:
            result = subprocess.run(
                ["getcap", "-r", root],
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except FileNotFoundError:
            logger.warning(
                "capability_check: 'getcap' not found — "
                "install libcap2-bin (Debian/Ubuntu) or libcap (RHEL/Arch)"
            )
            return []
        except subprocess.TimeoutExpired:
            logger.error("capability_check: getcap timed out after %ds", self.timeout)
            return []
        except OSError as exc:
            logger.error("capability_check: error running getcap: %s", exc)
            return []

        if result.returncode not in (0, 1):
            # Return code 1 commonly means "some paths not accessible" — benign
            logger.warning(
                "capability_check: getcap returned %d: %s",
                result.returncode,
                result.stderr.strip()[:300],
            )

        pairs: list[tuple[str, str]] = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            m = _GETCAP_LINE.match(line)
            if m:
                pairs.append((m.group(1).strip(), m.group(2).strip()))
            else:
                logger.debug("capability_check: unrecognised getcap line: %r", line)
        return pairs

    def _removed_findings(self, removed_hashes: set[str]) -> list[Finding]:
        if not removed_hashes:
            return []
        out: list[Finding] = []
        for row in self.db.get_baseline_entries(self.name):
            if row["item_hash"] not in removed_hashes:
                continue
            out.append(self._removal_finding(row["payload"], row["item_key"]))
        out.sort(key=lambda f: f.item_key)
        return out

    def _removal_finding(self, payload: str, fallback_key: str) -> Finding:
        path = fallback_key
        caps = "unknown"
        details: dict[str, Any] = {"change": "removed"}

        if payload:
            try:
                data = json.loads(payload)
                prev = data.get("details") or {}
                path = prev.get("path") or fallback_key
                caps = prev.get("caps") or caps
                details = {
                    "change": "removed",
                    "path": path,
                    "previous_caps": caps,
                }
            except json.JSONDecodeError:
                pass

        return Finding(
            detector_name=self.name,
            severity=_SEV_REMOVED,
            message=f"Capability removed from {path} (was {caps})",
            item_key=f"removed:{path}",
            details=details,
        )
