"""Abstract base detector with SQLite-backed baseline diffing."""

from __future__ import annotations

import hashlib
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from storage.db import Database

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Finding:
    """A single actionable finding from a detector scan."""

    detector_name: str
    severity: str  # critical | high | medium | low | info
    message: str
    # Stable identity for baseline/diff — must be unique within a detector
    item_key: str
    # Optional structured metadata (paths, PIDs, etc.)
    details: dict[str, Any] = field(default_factory=dict)
    # If False, persist/log the finding but skip Telegram (low-confidence, etc.)
    notify: bool = True

    def item_hash(self) -> str:
        """Hash used as the baseline identity for this finding."""
        payload = json.dumps(
            {
                "detector": self.detector_name,
                "item_key": self.item_key,
                "severity": self.severity,
                "message": self.message,
                "details": self.details,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def baseline_payload(self) -> str:
        """JSON stored alongside the baseline hash (for REMOVED reconstructions)."""
        return json.dumps(self.to_dict(), sort_keys=True, default=str)


class BaseDetector(ABC):
    """
    Abstract detector.

    Diff strategy (alert-fatigue prevention):
      1. scan() produces the current set of findings.
      2. Each finding gets a stable item_hash (content identity).
      3. get_baseline() loads known hashes for this detector from SQLite.
      4. diff(old, new) returns only findings whose hash is NOT in the baseline.
      5. save_baseline() replaces the baseline with the current inventory
         (prunes removed hashes so a later reappearance re-alerts).
      6. Alerts fire only for the diff set — unchanged state is silent.
         Detectors that care about removals (e.g. suid_check) emit LOW
         findings separately before pruning.
    """

    name: str = "base"

    def __init__(self, db: Database, config: dict[str, Any] | None = None) -> None:
        self.db = db
        self.config = config or {}
        raw_allow = self.config.get("allowlist") or []
        if isinstance(raw_allow, str):
            raw_allow = [raw_allow]
        self.allowlist: list[str] = [
            str(item).strip() for item in raw_allow if str(item).strip()
        ]

    @abstractmethod
    def scan(self) -> list[Finding]:
        """Inspect the system and return current findings. No I/O to alerts here."""

    def get_baseline(self) -> set[str]:
        """Return set of item_hash values last known for this detector."""
        return self.db.get_baseline_hashes(self.name)

    def save_baseline(self, findings: list[Finding]) -> None:
        """Replace this detector's baseline with the current inventory."""
        now = datetime.now(timezone.utc).isoformat()
        rows = [
            (
                self.name,
                f.item_hash(),
                now,
                now,
                f.item_key,
                f.baseline_payload(),
            )
            for f in findings
        ]
        self.db.replace_baselines(self.name, rows)

    def diff(self, old: set[str], new: list[Finding]) -> list[Finding]:
        """
        Return only NEW findings.

        A finding is new when its item_hash is not in the previous baseline.
        """
        return [f for f in new if f.item_hash() not in old]

    def is_allowlisted(self, finding: Finding) -> bool:
        """True when config marks this finding as known-good.

        An entry matches the item_key, the details path, a ``bits:path`` key
        via a bare path, or a prefix when the entry ends with ``*``.
        """
        if not self.allowlist:
            return False
        path = str(finding.details.get("path") or "")
        for entry in self.allowlist:
            if entry.endswith("*"):
                prefix = entry[:-1]
                if finding.item_key.startswith(prefix) or (
                    path and path.startswith(prefix)
                ):
                    return True
                continue
            if finding.item_key == entry or (path and path == entry):
                return True
            if finding.item_key.endswith(":" + entry):
                return True
        return False

    def suppress_allowlisted(self, findings: list[Finding]) -> list[Finding]:
        """Drop known-good findings after they have been written to the baseline."""
        if not self.allowlist:
            return findings
        kept: list[Finding] = []
        for finding in findings:
            if self.is_allowlisted(finding):
                logger.info(
                    "Allowlist suppressed %s finding %s",
                    self.name,
                    finding.item_key,
                )
                continue
            kept.append(finding)
        return kept

    def run_once(self) -> list[Finding]:
        """Scan → diff against baseline → persist baseline → return new findings only."""
        current = self.scan()
        baseline = self.get_baseline()
        novel = self.diff(baseline, current)
        self.save_baseline(current)
        return self.suppress_allowlisted(novel)
