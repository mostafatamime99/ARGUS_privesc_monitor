"""Tests for Telegram alert formatting and rate-limited batching."""

from __future__ import annotations

import unittest
from unittest import mock

import tempfile
from pathlib import Path

from alerts.telegram_bot import TelegramBot
from detectors.base import Finding
from storage.db import Database


def _finding(
    key: str,
    *,
    severity: str = "high",
    detector: str = "suid_check",
    message: str | None = None,
) -> Finding:
    return Finding(
        detector_name=detector,
        severity=severity,
        message=message or f"finding {key}",
        item_key=key,
        details={"path": f"/tmp/{key}"},
    )


class _FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class TestTelegramFormatting(unittest.TestCase):
    def setUp(self) -> None:
        self.bot = TelegramBot(
            {
                "enabled": True,
                "bot_token": "TEST_TOKEN",
                "chat_id": "12345",
                "max_alerts_per_minute": 10,
            }
        )

    def test_severity_emoji_mapping(self) -> None:
        cases = {
            "critical": "🔴 CRITICAL",
            "high": "🟠 HIGH",
            "medium": "🟡 MEDIUM",
            "low": "🟢 LOW",
        }
        for severity, expected in cases.items():
            text = self.bot.format_alert(_finding(severity, severity=severity))
            self.assertIn(expected, text)
            self.assertIn("suid_check", text)

    def test_summary_batches_and_counts(self) -> None:
        findings = [
            _finding("a", severity="high"),
            _finding("b", severity="high"),
            _finding("c", severity="low"),
        ]
        text = self.bot.format_summary(findings)
        self.assertIn("Batched summary", text)
        self.assertIn("3 alert(s)", text)
        self.assertIn("🟠 HIGH×2", text)
        self.assertIn("🟢 LOW×1", text)


class TestTelegramRateLimit(unittest.TestCase):
    def setUp(self) -> None:
        self.clock = _FakeClock()
        self.session = mock.Mock()
        self.session.post.return_value = mock.Mock(status_code=200, text='{"ok":true}')
        self.bot = TelegramBot(
            {
                "enabled": True,
                "bot_token": "TEST_TOKEN",
                "chat_id": "12345",
                "max_alerts_per_minute": 3,
            },
            session=self.session,
            time_fn=self.clock,
        )

    def _sent_texts(self) -> list[str]:
        return [call.kwargs["json"]["text"] for call in self.session.post.call_args_list]

    def test_under_limit_sends_individually(self) -> None:
        sent = self.bot.notify([_finding("a"), _finding("b")])
        self.assertEqual(sent, 2)
        texts = self._sent_texts()
        self.assertEqual(len(texts), 2)
        self.assertTrue(all("Batched summary" not in t for t in texts))

    def test_overflow_batched_into_summary(self) -> None:
        findings = [_finding(str(i), severity="high") for i in range(5)]
        sent = self.bot.notify(findings)
        # 2 individual + 1 summary (max 3/min)
        self.assertEqual(sent, 3)
        texts = self._sent_texts()
        self.assertEqual(len(texts), 3)
        self.assertNotIn("Batched summary", texts[0])
        self.assertNotIn("Batched summary", texts[1])
        self.assertIn("Batched summary", texts[2])
        self.assertIn("3 alert(s)", texts[2])

    def test_full_window_defers_then_flushes(self) -> None:
        self.bot.notify([_finding("1"), _finding("2"), _finding("3")])
        self.session.post.reset_mock()

        sent = self.bot.notify([_finding("4"), _finding("5")])
        self.assertEqual(sent, 0)
        self.assertEqual(self.session.post.call_count, 0)
        self.assertEqual(len(self.bot._deferred), 2)

        self.clock.advance(61)
        flushed = self.bot.flush_deferred()
        self.assertEqual(flushed, 2)
        self.assertEqual(self.session.post.call_count, 2)

    def test_disabled_sends_nothing(self) -> None:
        bot = TelegramBot(
            {"enabled": False, "bot_token": "X", "chat_id": "1"},
            session=self.session,
            time_fn=self.clock,
        )
        self.assertEqual(bot.notify([_finding("x")]), 0)
        self.session.post.assert_not_called()

    def test_reads_nested_telegram_config(self) -> None:
        bot = TelegramBot(
            {
                "telegram": {
                    "enabled": True,
                    "bot_token": "NESTED",
                    "chat_id": "99",
                    "max_alerts_per_minute": 5,
                }
            }
        )
        self.assertEqual(bot.bot_token, "NESTED")
        self.assertEqual(bot.chat_id, "99")
        self.assertEqual(bot.max_alerts_per_minute, 5)
        self.assertIn("NESTED", bot.api_url)

    def test_hostname_is_included_when_set(self) -> None:
        bot = TelegramBot(
            {
                "enabled": True,
                "bot_token": "TEST_TOKEN",
                "chat_id": "12345",
                "max_alerts_per_minute": 3,
            },
            session=self.session,
            time_fn=self.clock,
            hostname="web-01",
        )
        text = bot.format_alert(_finding("host"))
        self.assertIn("host: web-01", text)

    def test_failed_send_is_retried_from_outbox(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = Database(Path(tmp.name) / "t.db")
        self.addCleanup(db.close)

        failing = mock.Mock()
        failing.post.side_effect = OSError("telegram down")
        bot = TelegramBot(
            {
                "enabled": True,
                "bot_token": "TEST_TOKEN",
                "chat_id": "12345",
                "max_alerts_per_minute": 5,
            },
            session=failing,
            time_fn=self.clock,
            db=db,
            hostname="web-01",
        )
        self.assertEqual(bot.notify([_finding("queued")]), 0)
        self.assertEqual(len(db.unsent_outbox()), 1)

        recovered = TelegramBot(
            {
                "enabled": True,
                "bot_token": "TEST_TOKEN",
                "chat_id": "12345",
                "max_alerts_per_minute": 5,
            },
            session=self.session,
            time_fn=self.clock,
            db=db,
            hostname="web-01",
        )
        self.assertEqual(recovered.recover_unsent(), 1)
        self.assertEqual(recovered.flush_deferred(), 1)
        self.assertEqual(db.unsent_outbox(), [])
        self.assertIn("host: web-01", self._sent_texts()[-1])

    def test_no_hardcoded_secrets_in_module(self) -> None:
        import alerts.telegram_bot as mod
        import inspect

        src = inspect.getsource(mod)
        self.assertNotIn("123456:ABC", src)
        self.assertNotRegex(src, r'bot_token\s*=\s*"[^"]{20,}"')


if __name__ == "__main__":
    unittest.main()
