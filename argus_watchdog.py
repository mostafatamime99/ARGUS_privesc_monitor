#!/usr/bin/env python3
"""
ARGUS Watchdog — independent monitor for the main ARGUS daemon.

This script intentionally has NO imports from the main ARGUS codebase.
It is designed to survive even if main.py is broken, updated, or missing,
and to run as a completely separate systemd unit.

What it does
------------
* Checks every CHECK_INTERVAL seconds whether the ARGUS service is alive
  (via ``systemctl is-active``, falling back to a pidfile if systemd is
  unavailable).
* Sends a single Telegram alert when it detects ARGUS is down, then stays
  quiet until the service recovers, at which point it sends a recovery notice.
* Uses only the Python standard library (urllib, json, subprocess, os) —
  zero external dependencies.

LIMITATION (documented honestly)
---------------------------------
A root-level attacker who kills the main ARGUS daemon can also kill this
watchdog.  If both processes are stopped before the Telegram alert is
delivered, the alert may never be sent.  This script provides *best-effort*
detection and self-alerting, not true unkillability.  For stronger assurance,
pair with an out-of-band monitoring channel (e.g., a separate host or cloud
health-check service).

Configuration
-------------
Create /etc/argus/watchdog.json (see deploy/watchdog-config.example.json):

    {
        "bot_token": "YOUR_BOT_TOKEN",
        "chat_id":   "YOUR_CHAT_ID",
        "service_name": "argus",
        "pidfile": null,
        "check_interval": 30
    }

Override config path with the ARGUS_WATCHDOG_CONFIG environment variable.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_CHECK_INTERVAL = 30  # seconds
DEFAULT_SERVICE_NAME = "argus"
DEFAULT_CONFIG_PATH = "/etc/argus/watchdog.json"

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] argus-watchdog: %(message)s",
    level=logging.INFO,
    stream=sys.stderr,
)
logger = logging.getLogger("argus_watchdog")


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_config(path: str | None = None) -> dict:
    config_path = Path(
        path
        or os.environ.get("ARGUS_WATCHDOG_CONFIG", DEFAULT_CONFIG_PATH)
    )
    if not config_path.is_file():
        logger.error(
            "Watchdog config not found: %s  "
            "(set ARGUS_WATCHDOG_CONFIG or create %s)",
            config_path,
            DEFAULT_CONFIG_PATH,
        )
        sys.exit(1)
    try:
        with config_path.open() as fh:
            cfg = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Cannot read watchdog config %s: %s", config_path, exc)
        sys.exit(1)
    if not cfg.get("bot_token") or not cfg.get("chat_id"):
        logger.error(
            "watchdog config must have non-empty 'bot_token' and 'chat_id'"
        )
        sys.exit(1)
    return cfg


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

def is_argus_alive(
    service_name: str = DEFAULT_SERVICE_NAME,
    pidfile: str | None = None,
) -> bool:
    """Return True if the ARGUS daemon appears to be running."""
    # Primary: ask systemd
    try:
        result = subprocess.run(
            ["systemctl", "is-active", "--quiet", service_name],
            timeout=5,
        )
        return result.returncode == 0
    except FileNotFoundError:
        pass  # systemd not available; fall through to pidfile
    except subprocess.TimeoutExpired:
        logger.warning("systemctl is-active timed out — assuming down")
        return False

    # Fallback: pidfile
    if pidfile:
        pid_path = Path(pidfile)
        if not pid_path.is_file():
            return False
        try:
            pid = int(pid_path.read_text().strip())
            os.kill(pid, 0)  # signal 0 = existence check
            return True
        except (ValueError, ProcessLookupError):
            return False
        except PermissionError:
            return True  # process exists but we can't signal it; assume alive

    logger.warning(
        "systemctl not found and no pidfile configured — cannot determine ARGUS status"
    )
    return True  # safe default: don't false-alarm when we genuinely don't know


# ---------------------------------------------------------------------------
# Telegram delivery (pure stdlib)
# ---------------------------------------------------------------------------

def send_telegram(bot_token: str, chat_id: str, message: str) -> bool:
    """Send a Telegram message using urllib only (no third-party dependencies)."""
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    body = json.dumps({"chat_id": chat_id, "text": message}).encode()
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status == 200
    except urllib.error.HTTPError as exc:
        logger.error("Telegram HTTP error %s: %s", exc.code, exc.reason)
        return False
    except urllib.error.URLError as exc:
        logger.error("Telegram network error: %s", exc.reason)
        return False
    except OSError as exc:
        logger.error("Telegram send failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main(config_path: str | None = None) -> None:
    cfg = load_config(config_path)

    bot_token: str = cfg["bot_token"]
    chat_id: str = cfg["chat_id"]
    service_name: str = cfg.get("service_name", DEFAULT_SERVICE_NAME)
    pidfile: str | None = cfg.get("pidfile")
    interval: float = float(cfg.get("check_interval", DEFAULT_CHECK_INTERVAL))

    logger.info(
        "ARGUS watchdog started — monitoring '%s' every %.0fs",
        service_name,
        interval,
    )

    # Assume alive at startup to avoid spurious alert if the watchdog is
    # started before/during a normal ARGUS restart.
    was_alive = True

    while True:
        alive = is_argus_alive(service_name=service_name, pidfile=pidfile)

        if not alive and was_alive:
            msg = (
                "\U0001f534 ARGUS WATCHDOG ALERT\n"
                f"ARGUS main process ({service_name!r}) is DOWN.\n"
                "Privilege escalation monitoring is inactive.\n"
                "systemd will attempt auto-restart (Restart=always)."
            )
            logger.warning("ARGUS is DOWN — sending Telegram alert")
            send_telegram(bot_token, chat_id, msg)

        elif alive and not was_alive:
            msg = (
                "\U0001f7e2 ARGUS WATCHDOG: RECOVERED\n"
                f"ARGUS main process ({service_name!r}) is back UP."
            )
            logger.info("ARGUS recovered — sending recovery notice")
            send_telegram(bot_token, chat_id, msg)

        was_alive = alive
        time.sleep(interval)


if __name__ == "__main__":
    main()
