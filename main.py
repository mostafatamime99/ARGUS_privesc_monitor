"""PrivescMonitor — continuous privilege-escalation vector & anomaly daemon."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Sequence

import yaml

from banner import print_banner
from alerts.telegram_bot import TelegramBot
from detectors.audit_parser import AuditParserDetector
from detectors.base import BaseDetector, Finding
from detectors.capability_check import CapabilityCheckDetector
from detectors.content_watch import ContentWatchDetector
from detectors.cron_check import CronCheckDetector
from detectors.sudoers_check import SudoersCheckDetector
from detectors.suid_check import SuidCheckDetector
from detectors.version_scanner import VersionScannerDetector
from storage.db import Database

logger = logging.getLogger("privesc_monitor")

# name -> (factory, mode)
# "poll"  → run_once() called every scan_interval_seconds
# "watch" → run_once() called every WATCH_DRAIN_INTERVAL_SECONDS (1 s)
#            (includes both watchdog and custom-tail detectors)
DETECTOR_REGISTRY: dict[str, tuple[type[BaseDetector], str]] = {
    "suid_check":       (SuidCheckDetector,       "poll"),
    "capability_check": (CapabilityCheckDetector, "poll"),
    "version_scanner":  (VersionScannerDetector,  "poll"),
    "sudoers_check":    (SudoersCheckDetector,    "watch"),
    "cron_check":       (CronCheckDetector,       "watch"),
    "audit_parser":     (AuditParserDetector,     "watch"),
}

WATCH_DRAIN_INTERVAL_SECONDS = 1.0
DEFERRED_FLUSH_INTERVAL_SECONDS = 15.0


def load_config(path: Path) -> dict[str, Any]:
    """Load YAML config from disk."""
    with path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config root must be a mapping: {path}")
    return data


def setup_logging(config: dict[str, Any], *, verbose: bool = False) -> None:
    """Configure console + rotating file logging."""
    log_cfg = config.get("logging") or {}
    level_name = str(log_cfg.get("level", "INFO")).upper()
    if verbose:
        level_name = "DEBUG"
    level = getattr(logging, level_name, logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(fmt)
    console.setLevel(level)
    root.addHandler(console)

    log_file = Path(log_cfg.get("file", "logs/privesc_monitor.log"))
    if not log_file.is_absolute():
        log_file = Path(__file__).resolve().parent / log_file
    log_file.parent.mkdir(parents=True, exist_ok=True)

    max_bytes = int(log_cfg.get("max_bytes", 1_048_576))
    backup_count = int(log_cfg.get("backup_count", 5))
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    file_handler.setLevel(level)
    root.addHandler(file_handler)

    logger.info("Logging to %s (level=%s)", log_file, level_name)


def build_detectors(
    config: dict[str, Any], db: Database
) -> tuple[list[BaseDetector], list[BaseDetector]]:
    """
    Instantiate enabled detectors.

    Returns (poll_detectors, watch_detectors).

    Watch detectors are any detector registered with mode="watch".  They
    are not required to be ContentWatchDetector subclasses — AuditParserDetector
    uses its own background thread rather than watchdog, but is still drained
    by watch_drain_loop every second.
    """
    det_cfg = config.get("detectors") or {}
    enabled = list(det_cfg.get("enabled") or [])
    poll: list[BaseDetector] = []
    watch: list[BaseDetector] = []

    for name in enabled:
        if name not in DETECTOR_REGISTRY:
            logger.warning("Unknown detector in config.enabled: %s — skipping", name)
            continue
        cls, mode = DETECTOR_REGISTRY[name]
        instance_cfg = dict(det_cfg.get(name) or {})
        detector = cls(db, instance_cfg)
        if mode == "watch":
            watch.append(detector)
            logger.info("Registered watch detector: %s", name)
        else:
            poll.append(detector)
            logger.info("Registered poll detector: %s", name)

    if not poll and not watch:
        logger.warning("No detectors enabled — daemon will idle")
    return poll, watch


def persist_findings(db: Database, findings: Sequence[Finding]) -> None:
    """Write findings to the alerts table."""
    now = datetime.now(timezone.utc).isoformat()
    for finding in findings:
        db.insert_alert(
            timestamp=now,
            detector_name=finding.detector_name,
            severity=finding.severity,
            message=finding.message,
        )


def log_finding(finding: Finding, *, dry_run: bool) -> None:
    prefix = "[dry-run] " if dry_run else ""
    extra = ""
    if finding.details.get("diff"):
        diff = str(finding.details["diff"])
        extra = f"\n{diff}" if len(diff) < 2000 else f"\n{diff[:2000]}\n…(diff truncated in log)"
    logger.warning(
        "%sFinding %s/%s: %s%s",
        prefix,
        finding.severity.upper(),
        finding.detector_name,
        finding.message,
        extra,
    )


async def emit_findings(
    findings: list[Finding],
    *,
    db: Database,
    bot: TelegramBot,
    dry_run: bool,
    lock: asyncio.Lock,
) -> None:
    """Log, persist, and optionally Telegram-notify findings."""
    if not findings:
        return

    for finding in findings:
        log_finding(finding, dry_run=dry_run)

    async with lock:
        await asyncio.to_thread(persist_findings, db, findings)

    if dry_run:
        logger.info(
            "[dry-run] Skipping Telegram for %d finding(s)", len(findings)
        )
        return

    to_notify = [f for f in findings if getattr(f, "notify", True)]
    skipped = len(findings) - len(to_notify)
    if skipped:
        logger.info(
            "Skipping Telegram for %d finding(s) (low confidence or below min_severity_alert)",
            skipped,
        )
    if not to_notify:
        return

    sent = await asyncio.to_thread(bot.notify, to_notify)
    logger.info("Telegram: sent %d message(s) for %d finding(s)", sent, len(to_notify))


async def poll_loop(
    detectors: list[BaseDetector],
    interval: float,
    *,
    db: Database,
    bot: TelegramBot,
    dry_run: bool,
    lock: asyncio.Lock,
    stop: asyncio.Event,
) -> None:
    """Run poll-based detectors every ``interval`` seconds."""
    if not detectors:
        await stop.wait()
        return

    logger.info(
        "Poll loop started (%s) interval=%.1fs",
        ", ".join(d.name for d in detectors),
        interval,
    )
    while not stop.is_set():
        for detector in detectors:
            try:
                findings = await asyncio.to_thread(detector.run_once)
            except Exception:
                logger.exception("Poll detector %s failed", detector.name)
                continue
            await emit_findings(
                findings, db=db, bot=bot, dry_run=dry_run, lock=lock
            )
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


async def watch_drain_loop(
    detectors: list[BaseDetector],
    *,
    db: Database,
    bot: TelegramBot,
    dry_run: bool,
    lock: asyncio.Lock,
    stop: asyncio.Event,
    interval: float = WATCH_DRAIN_INTERVAL_SECONDS,
) -> None:
    """
    Drain watchdog detectors frequently.

    Observers run in background threads; this loop pulls pending findings.
    """
    if not detectors:
        await stop.wait()
        return

    logger.info(
        "Watch drain loop started (%s) interval=%.1fs",
        ", ".join(d.name for d in detectors),
        interval,
    )
    while not stop.is_set():
        for detector in detectors:
            try:
                findings = await asyncio.to_thread(detector.run_once)
            except Exception:
                logger.exception("Watch detector %s failed", detector.name)
                continue
            await emit_findings(
                findings, db=db, bot=bot, dry_run=dry_run, lock=lock
            )
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


async def deferred_flush_loop(
    bot: TelegramBot,
    *,
    dry_run: bool,
    stop: asyncio.Event,
    interval: float = DEFERRED_FLUSH_INTERVAL_SECONDS,
) -> None:
    """Periodically flush rate-limited Telegram backlog."""
    if dry_run:
        await stop.wait()
        return
    while not stop.is_set():
        try:
            sent = await asyncio.to_thread(bot.flush_deferred)
            if sent:
                logger.info("Telegram: flushed %d deferred message(s)", sent)
        except Exception:
            logger.exception("Telegram deferred flush failed")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


async def run_daemon(config: dict[str, Any], *, dry_run: bool = False) -> None:
    """Initialize detectors and run poll + watch loops until cancelled."""
    daemon_cfg = config.get("daemon") or {}
    interval = float(daemon_cfg.get("scan_interval_seconds", 60))
    db_path = Path(daemon_cfg.get("db_path", "privesc_monitor.db"))
    if not db_path.is_absolute():
        db_path = Path(__file__).resolve().parent / db_path

    db = Database(db_path)
    bot = TelegramBot(config)
    poll_detectors, watch_detectors = build_detectors(config, db)

    if dry_run:
        logger.info("Dry-run mode: findings will be logged, Telegram disabled")

    # start() is defined on ContentWatchDetector and AuditParserDetector
    for detector in watch_detectors:
        start = getattr(detector, "start", None)
        if callable(start):
            try:
                start()
            except Exception:
                logger.exception("Failed to start watch detector %s", detector.name)

    stop = asyncio.Event()
    lock = asyncio.Lock()

    logger.info(
        "PrivescMonitor running (poll=%d, watch=%d, interval=%.1fs, dry_run=%s)",
        len(poll_detectors),
        len(watch_detectors),
        interval,
        dry_run,
    )

    tasks = [
        asyncio.create_task(
            poll_loop(
                poll_detectors,
                interval,
                db=db,
                bot=bot,
                dry_run=dry_run,
                lock=lock,
                stop=stop,
            ),
            name="poll_loop",
        ),
        asyncio.create_task(
            watch_drain_loop(
                watch_detectors,
                db=db,
                bot=bot,
                dry_run=dry_run,
                lock=lock,
                stop=stop,
            ),
            name="watch_drain_loop",
        ),
        asyncio.create_task(
            deferred_flush_loop(bot, dry_run=dry_run, stop=stop),
            name="deferred_flush_loop",
        ),
    ]

    try:
        # Block until cancelled (Ctrl+C / task cancel); worker loops run aside.
        await asyncio.Future()
    except asyncio.CancelledError:
        logger.info("Shutdown requested")
        raise
    finally:
        stop.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for detector in watch_detectors:
            stop_fn = getattr(detector, "stop", None)
            if callable(stop_fn):
                try:
                    stop_fn()
                except Exception:
                    logger.exception("Error stopping %s", detector.name)
        db.close()
        logger.info("PrivescMonitor stopped")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PrivescMonitor — real-time Linux priv-esc vector detection"
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=Path(__file__).resolve().parent / "config.yaml",
        help="Path to config.yaml",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Log findings without sending Telegram alerts",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable DEBUG logging",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    print_banner()
    args = parse_args(argv)

    if not args.config.is_file():
        # logging may not be configured yet
        print(f"Config not found: {args.config}", file=sys.stderr)
        return 1

    try:
        config = load_config(args.config)
    except Exception as exc:
        print(f"Failed to load config: {exc}", file=sys.stderr)
        return 1

    setup_logging(config, verbose=args.verbose)

    try:
        asyncio.run(run_daemon(config, dry_run=args.dry_run))
    except KeyboardInterrupt:
        logger.info("Interrupted — shutting down")
    return 0


if __name__ == "__main__":
    sys.exit(main())
