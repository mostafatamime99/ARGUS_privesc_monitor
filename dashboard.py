#!/usr/bin/env python3
"""
ARGUS Dashboard — standalone launcher.

Run independently of the main ARGUS daemon (reads the same SQLite file):

    python dashboard.py                         # uses config.yaml
    python dashboard.py -c /etc/argus/config.yaml

The dashboard is strictly read-only.  It cannot modify the database,
kill detectors, or execute any system commands.

Auth: HTTP Basic Auth.  Set dashboard.username and dashboard.password_hash
in config.yaml.  Generate a hash:

    python -c "from dashboard.app import hash_password; print(hash_password('pw'))"
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="ARGUS read-only web dashboard (standalone)"
    )
    parser.add_argument(
        "-c",
        "--config",
        type=Path,
        default=Path(__file__).resolve().parent / "config.yaml",
        help="Path to config.yaml",
    )
    args = parser.parse_args(argv)

    if not args.config.is_file():
        print(f"Config not found: {args.config}", file=sys.stderr)
        return 1

    try:
        with args.config.open(encoding="utf-8") as fh:
            config = yaml.safe_load(fh) or {}
    except Exception as exc:
        print(f"Cannot load config: {exc}", file=sys.stderr)
        return 1

    daemon_cfg = config.get("daemon") or {}
    db_path = Path(daemon_cfg.get("db_path", "privesc_monitor.db"))
    if not db_path.is_absolute():
        db_path = args.config.parent / db_path

    dashboard_cfg = config.get("dashboard") or {}
    host = str(dashboard_cfg.get("bind_host", "127.0.0.1"))
    port = int(dashboard_cfg.get("port", 8420))

    try:
        from dashboard.app import DashboardServer, create_app
    except ImportError as exc:
        print(
            f"Dashboard dependencies not installed ({exc}).\n"
            "Install with:  pip install fastapi uvicorn bcrypt",
            file=sys.stderr,
        )
        return 1

    app = create_app(config, db_path)
    server = DashboardServer(app=app, host=host, port=port)
    print(f"ARGUS Dashboard: http://{host}:{port}/  (Ctrl+C to stop)")
    server.start()
    try:
        server._thread.join()
    except KeyboardInterrupt:
        print("\nShutting down dashboard…")
        server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
