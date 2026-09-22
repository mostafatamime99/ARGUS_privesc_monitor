"""Themed, channel-separated rotating logs for ARGUS.

Channels
--------
* ``detectors`` — privilege-escalation detectors (SUID, sudoers, cron, …)
* ``exploit``   — CVE / advisory scanner (``version_scanner``)
* ``db``        — SQLite integrity chain and storage events

Each channel writes to its own file with a distinct theme label so operators
can open one stream without noise from the others. The main daemon log
(``logging.file``) still receives a short summary line for every finding.
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from detectors.base import Finding

# Detector names that belong on the exploit channel (CVE / EDB references).
EXPLOIT_DETECTORS = frozenset({"version_scanner"})

# Detector / synthetic names that belong on the DB channel.
DB_DETECTORS = frozenset({"argus_integrity"})

CHANNEL_THEME: dict[str, str] = {
    "detectors": "DETECTOR",
    "exploit": "EXPLOIT",
    "db": "DB",
}

_CHANNEL_LOGGERS: dict[str, logging.Logger] = {}


def channel_for_finding(finding: Finding) -> str:
    """Return the log channel name for a finding."""
    name = finding.detector_name
    if name in EXPLOIT_DETECTORS:
        return "exploit"
    if name in DB_DETECTORS:
        return "db"
    return "detectors"


def get_channel_logger(channel: str) -> logging.Logger:
    """Return the dedicated logger for *channel* (falls back to detectors)."""
    return _CHANNEL_LOGGERS.get(channel) or _CHANNEL_LOGGERS.get(
        "detectors", logging.getLogger("argus.detectors")
    )


def _resolve_path(raw: str | Path, *, project_root: Path) -> Path:
    path = Path(raw)
    if not path.is_absolute():
        path = project_root / path
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _theme_formatter(theme: str) -> logging.Formatter:
    # Fixed-width theme so columns line up across channels.
    label = f"{theme:<8}"
    return logging.Formatter(
        f"%(asctime)s │ {label} │ [%(levelname)s] %(name)s: %(message)s"
    )


def _attach_rotating(
    logger: logging.Logger,
    *,
    path: Path,
    theme: str,
    level: int,
    max_bytes: int,
    backup_count: int,
    also_console: bool,
) -> None:
    logger.handlers.clear()
    logger.setLevel(level)
    logger.propagate = False

    fmt = _theme_formatter(theme)
    file_handler = RotatingFileHandler(
        path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    file_handler.setLevel(level)
    logger.addHandler(file_handler)

    if also_console:
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(fmt)
        console.setLevel(level)
        logger.addHandler(console)


def setup_channel_logging(
    config: dict[str, Any],
    *,
    level: int,
    project_root: Path | None = None,
) -> dict[str, Path]:
    """
    Create themed channel loggers.

    Returns a map of channel name → log file path.
    """
    global _CHANNEL_LOGGERS

    log_cfg = config.get("logging") or {}
    channels_cfg = dict(log_cfg.get("channels") or {})
    max_bytes = int(log_cfg.get("max_bytes", 1_048_576))
    backup_count = int(log_cfg.get("backup_count", 5))
    also_console = bool(log_cfg.get("channels_to_console", True))
    root = project_root or Path(__file__).resolve().parent

    defaults = {
        "detectors": "logs/detectors.log",
        "exploit": "logs/exploit.log",
        "db": "logs/db.log",
    }

    paths: dict[str, Path] = {}
    _CHANNEL_LOGGERS = {}
    for channel, default_file in defaults.items():
        ch_cfg = channels_cfg.get(channel) or {}
        if isinstance(ch_cfg, str):
            file_raw = ch_cfg
        else:
            file_raw = str(ch_cfg.get("file") or default_file)
        path = _resolve_path(file_raw, project_root=root)
        theme = str(ch_cfg.get("theme") if isinstance(ch_cfg, dict) else "") or CHANNEL_THEME[channel]
        logger_name = f"argus.{channel}"
        lg = logging.getLogger(logger_name)
        _attach_rotating(
            lg,
            path=path,
            theme=theme,
            level=level,
            max_bytes=max_bytes,
            backup_count=backup_count,
            also_console=also_console,
        )
        _CHANNEL_LOGGERS[channel] = lg
        paths[channel] = path

    return paths


def log_finding_to_channel(finding: Finding, *, dry_run: bool = False) -> str:
    """
    Write a finding to its themed channel log.

    Returns the channel name used.
    """
    channel = channel_for_finding(finding)
    lg = get_channel_logger(channel)
    prefix = "[dry-run] " if dry_run else ""
    theme = CHANNEL_THEME.get(channel, channel.upper())

    lines = [
        f"{prefix}{finding.severity.upper()} | {finding.detector_name}",
        f"message: {finding.message}",
        f"key: {finding.item_key}",
    ]
    if finding.details:
        for key, value in sorted(finding.details.items()):
            text = str(value)
            if key == "diff" and len(text) > 2000:
                text = text[:2000] + "\n…(diff truncated in log)"
            lines.append(f"{key}: {text}")

    body = "\n".join(lines)
    level = logging.CRITICAL if finding.severity.lower() == "critical" else logging.WARNING
    lg.log(level, "%s\n%s", theme, body)
    return channel


def log_db_event(message: str, *, level: int = logging.INFO) -> None:
    """Write a storage / integrity event to the DB channel."""
    get_channel_logger("db").log(level, message)
