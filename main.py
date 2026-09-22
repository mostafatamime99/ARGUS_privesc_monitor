"""PrivescMonitor — continuous privilege-escalation vector & anomaly daemon."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import socket
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
from logging_channels import log_db_event, log_finding_to_channel, setup_channel_logging
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
    """Configure console + rotating main log + themed channel logs."""
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

    channel_paths = setup_channel_logging(
        config,
        level=level,
        project_root=Path(__file__).resolve().parent,
    )
    logger.info("Logging to %s (level=%s)", log_file, level_name)
    for channel, path in channel_paths.items():
        logger.info("Channel log [%s] → %s", channel, path)


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


def resolve_hostname(config: dict[str, Any]) -> str:
    """Hostname stamped on every alert. Config wins; otherwise the machine name."""
    daemon_cfg = config.get("daemon") or {}
    configured = str(daemon_cfg.get("hostname") or "").strip()
    if configured:
        return configured
    return socket.gethostname()


def persist_findings(
    db: Database, findings: Sequence[Finding], *, hostname: str = ""
) -> None:
    """Write findings to the alerts table, including structured details."""
    now = datetime.now(timezone.utc).isoformat()
    for finding in findings:
        details = json.dumps(finding.details, sort_keys=True, default=str)
        db.insert_alert(
            timestamp=now,
            detector_name=finding.detector_name,
            severity=finding.severity,
            message=finding.message,
            hostname=hostname,
            details=details,
        )


def log_finding(finding: Finding, *, dry_run: bool) -> None:
    """Short line on the main log; full themed detail on the channel log."""
    prefix = "[dry-run] " if dry_run else ""
    channel = log_finding_to_channel(finding, dry_run=dry_run)
    logger.warning(
        "%sFinding %s/%s [%s]: %s",
        prefix,
        finding.severity.upper(),
        finding.detector_name,
        channel,
        finding.message,
    )


async def emit_findings(
    findings: list[Finding],
    *,
    db: Database,
    bot: TelegramBot,
    dry_run: bool,
    lock: asyncio.Lock,
    hostname: str = "",
) -> None:
    """Log, persist, and optionally Telegram-notify findings."""
    if not findings:
        return

    for finding in findings:
        log_finding(finding, dry_run=dry_run)

    async with lock:
        await asyncio.to_thread(persist_findings, db, findings, hostname=hostname)

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
    hostname: str = "",
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
                findings,
                db=db,
                bot=bot,
                dry_run=dry_run,
                lock=lock,
                hostname=hostname,
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
    hostname: str = "",
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
                findings,
                db=db,
                bot=bot,
                dry_run=dry_run,
                lock=lock,
                hostname=hostname,
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


async def startup_checks(
    db: Database,
    bot: TelegramBot,
    *,
    dry_run: bool,
    lock: asyncio.Lock,
    hostname: str = "",
) -> bool:
    """
    Run at every daemon (re)start:
    1. Verify the SQLite integrity chain.  Emit a CRITICAL alert if broken.
    2. Announce the (re)start via log + Telegram so restarts leave a visible trail.

    A root-level attacker who has tampered with the DB *and then* killed/restarted
    ARGUS will trigger both alerts.  An attacker who also kills the Telegram
    delivery cannot suppress the SQLite alert record for (2).
    """
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # --- Integrity chain verification ---
    ok, chain_msg = await asyncio.to_thread(db.verify_chain)
    if ok:
        logger.info("DB integrity chain: %s", chain_msg)
        log_db_event(f"Integrity chain OK: {chain_msg}")
    else:
        logger.critical("DB INTEGRITY CHECK FAILED: %s", chain_msg)
        log_db_event(
            f"Integrity chain FAILED: {chain_msg}",
            level=logging.CRITICAL,
        )
        tamper_finding = Finding(
            detector_name="argus_integrity",
            severity="critical",
            message=f"Database tampering detected: {chain_msg}",
            item_key=f"integrity:tamper",
        )
        await emit_findings(
            [tamper_finding],
            db=db,
            bot=bot,
            dry_run=dry_run,
            lock=lock,
            hostname=hostname,
        )

    # --- Startup announcement ---
    restart_msg = f"ARGUS daemon (re)started at {ts}"
    logger.info(restart_msg)
    restart_finding = Finding(
        detector_name="argus_daemon",
        severity="info",
        message=restart_msg,
        item_key=f"restart:{ts}",
    )
    # Always persist the restart event so the dashboard shows it; notify Telegram too.
    await emit_findings(
        [restart_finding],
        db=db,
        bot=bot,
        dry_run=dry_run,
        lock=lock,
        hostname=hostname,
    )
    return ok


async def integrity_loop(
    db: Database,
    bot: TelegramBot,
    *,
    interval: float,
    dry_run: bool,
    lock: asyncio.Lock,
    stop: asyncio.Event,
    hostname: str,
    already_broken: bool,
) -> None:
    """Re-check the hash chain while the daemon is up.

    A failure is announced once. Recovery clears that latch so a later break
    alerts again. ``interval`` <= 0 disables the loop.
    """
    if interval <= 0:
        await stop.wait()
        return

    announced = already_broken
    logger.info("Integrity recheck every %.0fs", interval)
    while not stop.is_set():
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
            return
        except asyncio.TimeoutError:
            pass
        try:
            ok, chain_msg = await asyncio.to_thread(db.verify_chain)
        except Exception:
            logger.exception("Integrity recheck failed")
            continue
        if ok:
            if announced:
                logger.info("DB integrity chain recovered: %s", chain_msg)
                log_db_event(f"Integrity chain recovered: {chain_msg}")
            announced = False
            continue
        logger.critical("DB INTEGRITY CHECK FAILED: %s", chain_msg)
        log_db_event(
            f"Integrity chain FAILED (periodic): {chain_msg}",
            level=logging.CRITICAL,
        )
        if announced:
            continue
        announced = True
        tamper_finding = Finding(
            detector_name="argus_integrity",
            severity="critical",
            message=f"Database tampering detected: {chain_msg}",
            item_key="integrity:tamper",
        )
        await emit_findings(
            [tamper_finding],
            db=db,
            bot=bot,
            dry_run=dry_run,
            lock=lock,
            hostname=hostname,
        )


async def run_daemon(config: dict[str, Any], *, dry_run: bool = False) -> None:
    """Initialize detectors and run poll + watch loops until cancelled."""
    daemon_cfg = config.get("daemon") or {}
    interval = float(daemon_cfg.get("scan_interval_seconds", 60))
    integrity_interval = float(daemon_cfg.get("integrity_check_seconds", 300))
    db_path = resolve_db_path(config)
    hostname = resolve_hostname(config)

    db = Database(db_path)
    bot = TelegramBot(config, db=db, hostname=hostname)
    recovered = bot.recover_unsent()
    if recovered:
        logger.info(
            "Telegram outbox: %d unsent message(s) queued for retry", recovered
        )
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

    # Startup integrity check + restart announcement (before detection loops).
    chain_ok = await startup_checks(
        db, bot, dry_run=dry_run, lock=lock, hostname=hostname
    )

    logger.info(
        "PrivescMonitor running (poll=%d, watch=%d, interval=%.1fs, dry_run=%s)",
        len(poll_detectors),
        len(watch_detectors),
        interval,
        dry_run,
    )

    # --- Optional dashboard ---
    dashboard_server = None
    dashboard_cfg = config.get("dashboard") or {}
    if dashboard_cfg.get("enabled"):
        try:
            from dashboard.app import DashboardServer, create_app  # lazy import

            dash_app = create_app(config, db_path)
            dashboard_server = DashboardServer(
                app=dash_app,
                host=str(dashboard_cfg.get("bind_host", "127.0.0.1")),
                port=int(dashboard_cfg.get("port", 8420)),
            )
            dashboard_server.start()
            logger.info(
                "Dashboard listening on http://%s:%d/",
                dashboard_server.host,
                dashboard_server.port,
            )
        except ImportError as exc:
            logger.warning(
                "Dashboard disabled — missing dependency: %s  "
                "(pip install fastapi uvicorn bcrypt)",
                exc,
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
                hostname=hostname,
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
                hostname=hostname,
            ),
            name="watch_drain_loop",
        ),
        asyncio.create_task(
            deferred_flush_loop(bot, dry_run=dry_run, stop=stop),
            name="deferred_flush_loop",
        ),
        asyncio.create_task(
            integrity_loop(
                db,
                bot,
                interval=integrity_interval,
                dry_run=dry_run,
                lock=lock,
                stop=stop,
                hostname=hostname,
                already_broken=not chain_ok,
            ),
            name="integrity_loop",
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
        if dashboard_server is not None:
            dashboard_server.stop()
        for detector in watch_detectors:
            stop_fn = getattr(detector, "stop", None)
            if callable(stop_fn):
                try:
                    stop_fn()
                except Exception:
                    logger.exception("Error stopping %s", detector.name)
        db.close()
        logger.info("PrivescMonitor stopped")


def resolve_db_path(config: dict[str, Any]) -> Path:
    """SQLite path from config, relative paths anchored at the project root."""
    daemon_cfg = config.get("daemon") or {}
    db_path = Path(daemon_cfg.get("db_path", "privesc_monitor.db"))
    if not db_path.is_absolute():
        db_path = Path(__file__).resolve().parent / db_path
    return db_path


def acknowledge_cli(config: dict[str, Any], alert_ids: Sequence[int]) -> int:
    """Mark alerts acknowledged without breaking the integrity chain."""
    if not alert_ids:
        print("Usage: python main.py ack <id> [<id> ...]", file=sys.stderr)
        return 1
    db = Database(resolve_db_path(config))
    try:
        newly, missing = db.acknowledge_alerts(alert_ids)
    finally:
        db.close()
    print(f"Acknowledged {newly} alert(s)")
    if missing:
        print(
            "Not found: " + ", ".join(str(alert_id) for alert_id in missing),
            file=sys.stderr,
        )
        return 1
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PrivescMonitor — real-time Linux priv-esc vector detection"
    )
    parser.add_argument(
        "command",
        nargs="?",
        default="run",
        choices=["run", "ack"],
        help="Omit or pass 'run' to start the daemon. 'ack' marks alert ids acknowledged.",
    )
    parser.add_argument(
        "ids",
        nargs="*",
        type=int,
        help="Alert ids to acknowledge when command is ack",
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

    if args.command == "ack":
        return acknowledge_cli(config, args.ids)

    print_banner()
    setup_logging(config, verbose=args.verbose)

    try:
        asyncio.run(run_daemon(config, dry_run=args.dry_run))
    except KeyboardInterrupt:
        logger.info("Interrupted — shutting down")
    return 0


if __name__ == "__main__":
    sys.exit(main())
