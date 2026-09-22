"""Telegram alert backend with severity formatting and rate-limited batching."""

from __future__ import annotations

import json
import logging
import time
from collections import deque
from typing import Any, Callable, Deque, Iterable, Protocol, Sequence

from detectors.base import Finding

logger = logging.getLogger(__name__)

SEVERITY_EMOJI: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "🟢",
}

SEVERITY_LABEL: dict[str, str] = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
}

# Telegram hard limit ~4096; leave headroom for UTF-8 / markup
_MAX_MESSAGE_CHARS = 4000

# A deferred item is (finding, outbox row id or None when no database is attached).
_Pending = tuple[Finding, int | None]


class _SessionLike(Protocol):
    def post(self, url: str, **kwargs: Any) -> Any: ...


def _default_session() -> _SessionLike:
    import requests

    return requests.Session()


class TelegramBot:
    """
    Sends findings to a Telegram chat.

    Credentials come only from config (bot_token / chat_id) — never hardcoded.
    Rate limit: at most ``max_alerts_per_minute`` API messages per rolling
    60s window. Anything beyond that is coalesced into one summary message
    (using one of the remaining slots when possible).
    """

    def __init__(
        self,
        config: dict[str, Any],
        *,
        session: _SessionLike | None = None,
        time_fn: Callable[[], float] | None = None,
        db: Any | None = None,
        hostname: str | None = None,
    ) -> None:
        telegram = config.get("telegram", config)
        self.enabled: bool = bool(telegram.get("enabled", False))
        self.bot_token: str = str(telegram.get("bot_token") or "").strip()
        self.chat_id: str = str(telegram.get("chat_id") or "").strip()
        self.max_alerts_per_minute: int = int(
            telegram.get("max_alerts_per_minute", 10)
        )
        if self.max_alerts_per_minute < 1:
            raise ValueError("telegram.max_alerts_per_minute must be >= 1")

        if hostname is None:
            daemon_cfg = config.get("daemon") or {}
            hostname = str(daemon_cfg.get("hostname") or "")
        self.hostname: str = str(hostname or "").strip()

        self._db = db
        self._session: _SessionLike | None = session
        self._time = time_fn or time.monotonic
        self._send_times: Deque[float] = deque()
        self._deferred: list[_Pending] = []

        if self.enabled and (not self.bot_token or not self.chat_id):
            logger.warning(
                "telegram.enabled is true but bot_token/chat_id are missing; "
                "alerts will be skipped"
            )

    @property
    def api_url(self) -> str:
        return f"https://api.telegram.org/bot{self.bot_token}/sendMessage"

    def format_alert(self, finding: Finding) -> str:
        """Single-finding message with severity emoji."""
        sev = finding.severity.lower()
        emoji = SEVERITY_EMOJI.get(sev, "🟡")
        label = SEVERITY_LABEL.get(sev, finding.severity.upper())
        lines = [f"{emoji} {label} | {finding.detector_name}"]
        if self.hostname:
            lines.append(f"host: {self.hostname}")
        lines.extend(
            [
                finding.message,
                f"key: `{finding.item_key}`",
            ]
        )
        if finding.details:
            # Keep details compact — path/bits are the usual signal
            for key in (
                "path",
                "bits",
                "change",
                "mode",
                "event",
                "package",
                "installed_version",
                "vuln_id",
                "confidence",
                "reference",
            ):
                if key in finding.details:
                    lines.append(f"{key}: {finding.details[key]}")
            diff = finding.details.get("diff")
            if diff:
                text = str(diff)
                if len(text) > 1500:
                    text = text[:1500] + "\n…(diff truncated)"
                lines.append("diff:")
                lines.append(text)
        return "\n".join(lines)

    def format_summary(self, findings: Sequence[Finding]) -> str:
        """Batched overflow message when rate limit would be exceeded."""
        if not findings:
            return ""

        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity.lower()] = counts.get(f.severity.lower(), 0) + 1

        count_bits = ", ".join(
            f"{SEVERITY_EMOJI.get(sev, '🟡')} {SEVERITY_LABEL.get(sev, sev.upper())}×{n}"
            for sev, n in sorted(counts.items(), key=lambda kv: kv[0])
        )
        host_bit = f" — {self.hostname}" if self.hostname else ""
        header = (
            f"📦 Batched summary — {len(findings)} alert(s) rate-limited "
            f"({count_bits}){host_bit}"
        )
        body_lines = [header, ""]
        for f in findings:
            sev = f.severity.lower()
            emoji = SEVERITY_EMOJI.get(sev, "🟡")
            label = SEVERITY_LABEL.get(sev, f.severity.upper())
            body_lines.append(
                f"• {emoji} {label} [{f.detector_name}] {f.message}"
            )

        text = "\n".join(body_lines)
        if len(text) > _MAX_MESSAGE_CHARS:
            truncated = text[: _MAX_MESSAGE_CHARS - 80]
            omitted = len(findings) - truncated.count("\n• ")
            text = (
                f"{truncated}\n\n… truncated; {max(omitted, 0)} more finding(s) "
                "omitted (see local SQLite alerts)."
            )
        return text

    def notify(self, findings: Finding | Iterable[Finding]) -> int:
        """
        Send findings to Telegram, respecting the per-minute cap.

        When a database is attached, each finding is written to the outbox
        before the send attempt. A restart can retry anything still unsent.

        Returns the number of Telegram API messages actually sent.
        """
        items = [findings] if isinstance(findings, Finding) else list(findings)
        if not items:
            return self.flush_deferred()

        if not self._can_send():
            logger.debug(
                "Telegram disabled or misconfigured; dropping %d finding(s)",
                len(items),
            )
            return 0

        staged = [(finding, self._stage(finding)) for finding in items]
        # Retry anything deferred once capacity returns
        queue = self._deferred + staged
        self._deferred = []
        return self._dispatch(queue)

    def flush_deferred(self) -> int:
        """Attempt to send findings held while the rate window was full."""
        if not self._deferred:
            return 0
        if not self._can_send():
            return 0
        queue = self._deferred
        self._deferred = []
        return self._dispatch(queue)

    def recover_unsent(self) -> int:
        """Load outbox rows that never got a successful send into the defer queue."""
        if self._db is None:
            return 0
        rows = self._db.unsent_outbox()
        recovered: list[_Pending] = []
        for row in rows:
            finding = self._finding_from_payload(str(row["payload"]))
            if finding is None:
                logger.warning("Skipping unreadable Telegram outbox row id=%s", row["id"])
                continue
            recovered.append((finding, int(row["id"])))
        self._deferred = recovered
        return len(recovered)

    def _stage(self, finding: Finding) -> int | None:
        if self._db is None:
            return None
        return int(self._db.enqueue_outbox(self._payload(finding)))

    def _mark_sent(self, outbox_id: int | None) -> None:
        if self._db is None or outbox_id is None:
            return
        self._db.mark_outbox_sent(outbox_id)

    @staticmethod
    def _payload(finding: Finding) -> str:
        return json.dumps(
            {
                "detector_name": finding.detector_name,
                "severity": finding.severity,
                "message": finding.message,
                "item_key": finding.item_key,
                "details": finding.details,
                "notify": finding.notify,
            },
            sort_keys=True,
            default=str,
        )

    @staticmethod
    def _finding_from_payload(payload: str) -> Finding | None:
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        details = data.get("details") or {}
        if not isinstance(details, dict):
            details = {}
        try:
            return Finding(
                detector_name=str(data.get("detector_name") or "unknown"),
                severity=str(data.get("severity") or "info"),
                message=str(data.get("message") or ""),
                item_key=str(data.get("item_key") or ""),
                details=details,
                notify=bool(data.get("notify", True)),
            )
        except (TypeError, ValueError):
            return None

    def _dispatch(self, pending: list[_Pending]) -> int:
        sent = 0
        remaining = self._slots_remaining()

        if remaining <= 0:
            self._deferred.extend(pending)
            logger.info(
                "Rate limit reached (%d/min); deferring %d finding(s)",
                self.max_alerts_per_minute,
                len(pending),
            )
            return 0

        if len(pending) <= remaining:
            failed: list[_Pending] = []
            for finding, outbox_id in pending:
                if self._send_text(self.format_alert(finding)):
                    sent += 1
                    self._mark_sent(outbox_id)
                else:
                    failed.append((finding, outbox_id))
            self._deferred.extend(failed)
            return sent

        # Need one slot for the summary of the overflow.
        individual_slots = max(0, remaining - 1)
        failed = []
        for finding, outbox_id in pending[:individual_slots]:
            if self._send_text(self.format_alert(finding)):
                sent += 1
                self._mark_sent(outbox_id)
            else:
                failed.append((finding, outbox_id))

        overflow = pending[individual_slots:]
        if overflow:
            if self._slots_remaining() > 0:
                summary = self.format_summary([item[0] for item in overflow])
                if self._send_text(summary):
                    sent += 1
                    for _, outbox_id in overflow:
                        self._mark_sent(outbox_id)
                else:
                    failed.extend(overflow)
            else:
                failed.extend(overflow)
                logger.info(
                    "Deferred %d finding(s) after filling rate window",
                    len(overflow),
                )
        self._deferred.extend(failed)
        return sent

    def _can_send(self) -> bool:
        return bool(self.enabled and self.bot_token and self.chat_id)

    def _prune_window(self) -> None:
        cutoff = self._time() - 60.0
        while self._send_times and self._send_times[0] < cutoff:
            self._send_times.popleft()

    def _slots_remaining(self) -> int:
        self._prune_window()
        return max(0, self.max_alerts_per_minute - len(self._send_times))

    def _session_or_default(self) -> _SessionLike:
        if self._session is None:
            self._session = _default_session()
        return self._session

    def _send_text(self, text: str) -> bool:
        if not text:
            return False
        try:
            resp = self._session_or_default().post(
                self.api_url,
                json={
                    "chat_id": self.chat_id,
                    "text": text,
                    "disable_web_page_preview": True,
                },
                timeout=15,
            )
        except Exception as exc:
            logger.error("Telegram send error: %s", exc)
            return False

        if getattr(resp, "status_code", 0) != 200:
            body = getattr(resp, "text", "")[:300]
            logger.error(
                "Telegram sendMessage failed: HTTP %s %s",
                getattr(resp, "status_code", "?"),
                body,
            )
            return False
        self._send_times.append(self._time())
        return True
