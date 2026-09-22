"""
ARGUS read-only web dashboard — FastAPI backend.

Design constraints
------------------
* Every API endpoint is strictly read-only.  No endpoint modifies the SQLite
  database, kills detectors, or executes system commands.
* Each request opens its own short-lived read-only SQLite connection (WAL mode
  supports unlimited concurrent readers).
* HTTP Basic Auth with a bcrypt-hashed password stored in config.yaml.
  An empty password_hash means the dashboard rejects all requests — there is
  no anonymous mode even for localhost-only use.
* Bound to 127.0.0.1 by default; never 0.0.0.0 unless the operator explicitly
  sets dashboard.bind_host.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Optional dependency guard — import errors produce a clear message
# ---------------------------------------------------------------------------
try:
    import bcrypt as _bcrypt
    import uvicorn
    from fastapi import Depends, FastAPI, HTTPException, Query, status
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.security import HTTPBasic, HTTPBasicCredentials
    from fastapi.staticfiles import StaticFiles
except ImportError as _imp_err:
    raise ImportError(
        f"Dashboard dependencies missing ({_imp_err}).  "
        "Install with: pip install fastapi uvicorn bcrypt"
    ) from _imp_err

from storage.db import alert_select_columns, verify_chain_conn

_STATIC_DIR = Path(__file__).parent / "static"
_DETECTOR_MODES = {
    "suid_check": "poll",
    "capability_check": "poll",
    "version_scanner": "poll",
    "sudoers_check": "watch",
    "cron_check": "watch",
    "audit_parser": "watch",
}

# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches the bcrypt *hashed* string."""
    if not hashed:
        return False
    try:
        return _bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def hash_password(plain: str) -> str:
    """Generate a bcrypt hash suitable for storage in config.yaml."""
    return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt()).decode()


def _public_alert(row: sqlite3.Row) -> dict[str, Any]:
    """JSON-ready alert. ``details`` is an object; empty when the column is blank."""
    data = dict(row)
    raw = data.get("details") or ""
    if isinstance(raw, str):
        if not raw:
            data["details"] = {}
        else:
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = {"raw": raw}
            data["details"] = parsed if isinstance(parsed, dict) else {"raw": raw}
    data.setdefault("hostname", "")
    return data


# ---------------------------------------------------------------------------
# Database dependency (read-only connection per request)
# ---------------------------------------------------------------------------


def _make_db_dep(db_path: Path):
    """Return a FastAPI dependency that yields a read-only sqlite3 connection."""

    def _get_db():
        try:
            conn = sqlite3.connect(
                f"file:{db_path}?mode=ro", uri=True, check_same_thread=False
            )
        except sqlite3.OperationalError:
            # DB does not yet exist (first run before any alerts).
            conn = sqlite3.connect(":memory:", check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    return _get_db


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------


def _make_auth_dep(dashboard_cfg: dict[str, Any]):
    security = HTTPBasic()
    username = str(dashboard_cfg.get("username") or "")
    password_hash = str(dashboard_cfg.get("password_hash") or "")

    def _check_auth(credentials: HTTPBasicCredentials = Depends(security)):
        if not username or not password_hash:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=(
                    "Dashboard auth not configured. "
                    "Set dashboard.username and dashboard.password_hash in config.yaml. "
                    "Generate a hash: python -c \"from dashboard.app import hash_password; "
                    "print(hash_password('yourpassword'))\""
                ),
            )
        ok_user = secrets.compare_digest(credentials.username, username)
        ok_pass = verify_password(credentials.password, password_hash)
        if not (ok_user and ok_pass):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
                headers={"WWW-Authenticate": "Basic"},
            )

    return _check_auth


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(
    config: dict[str, Any],
    db_path: Path,
) -> FastAPI:
    """Build and return the FastAPI application instance."""
    dashboard_cfg: dict[str, Any] = config.get("dashboard") or {}
    detector_registry: dict[str, Any] = config.get("detectors") or {}
    enabled_detectors: list[str] = list(detector_registry.get("enabled") or [])

    app = FastAPI(
        title="ARGUS Dashboard",
        description="Read-only privilege escalation alert viewer.",
        version="1.0",
        docs_url=None,  # Disable Swagger UI (read-only tool, no need)
        redoc_url=None,
    )

    get_db = _make_db_dep(db_path)
    check_auth = _make_auth_dep(dashboard_cfg)

    # ------------------------------------------------------------------
    # Static frontend
    # ------------------------------------------------------------------

    if _STATIC_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def _root(auth=Depends(check_auth)):  # noqa: ARG001
        index = _STATIC_DIR / "index.html"
        if index.is_file():
            return HTMLResponse(index.read_text(encoding="utf-8"))
        return HTMLResponse("<h1>ARGUS Dashboard</h1><p>index.html not found.</p>")

    # ------------------------------------------------------------------
    # GET /api/alerts
    # ------------------------------------------------------------------

    @app.get("/api/alerts")
    def get_alerts(
        severity: str | None = Query(None),
        detector: str | None = Query(None),
        acknowledged: bool | None = Query(None),
        limit: int = Query(50, ge=1, le=500),
        auth=Depends(check_auth),
        db: sqlite3.Connection = Depends(get_db),
    ):
        conditions: list[str] = []
        params: list[object] = []
        if severity:
            conditions.append("severity = ?")
            params.append(severity.lower())
        if detector:
            conditions.append("detector_name = ?")
            params.append(detector)
        if acknowledged is not None:
            conditions.append("acknowledged = ?")
            params.append(1 if acknowledged else 0)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        columns = alert_select_columns(db)
        rows = db.execute(
            f"SELECT {columns} FROM alerts {where} ORDER BY id DESC LIMIT ?",
            params,
        ).fetchall()
        return JSONResponse([_public_alert(r) for r in rows])

    # ------------------------------------------------------------------
    # GET /api/alerts/{id}
    # ------------------------------------------------------------------

    @app.get("/api/alerts/{alert_id}")
    def get_alert(
        alert_id: int,
        auth=Depends(check_auth),
        db: sqlite3.Connection = Depends(get_db),
    ):
        columns = alert_select_columns(db)
        row = db.execute(
            f"SELECT {columns} FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Alert not found")
        return JSONResponse(_public_alert(row))

    # ------------------------------------------------------------------
    # GET /api/stats/summary
    # ------------------------------------------------------------------

    @app.get("/api/stats/summary")
    def get_summary(
        auth=Depends(check_auth),
        db: sqlite3.Connection = Depends(get_db),
    ):
        from datetime import datetime, timedelta, timezone

        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        total = db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        last_24h = db.execute(
            "SELECT COUNT(*) FROM alerts WHERE timestamp >= ?", (cutoff,)
        ).fetchone()[0]
        by_severity = {
            r[0]: r[1]
            for r in db.execute(
                "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
            ).fetchall()
        }
        by_detector = {
            r[0]: r[1]
            for r in db.execute(
                "SELECT detector_name, COUNT(*) FROM alerts GROUP BY detector_name"
            ).fetchall()
        }
        # Integrity chain status (read-only verification).
        chain_ok, chain_msg = verify_chain_conn(db)

        return JSONResponse(
            {
                "total_alerts": total,
                "alerts_last_24h": last_24h,
                "by_severity": by_severity,
                "by_detector": by_detector,
                "integrity_status": "ok" if chain_ok else "TAMPERED",
                "integrity_message": chain_msg,
            }
        )

    # ------------------------------------------------------------------
    # GET /api/detectors/status
    # ------------------------------------------------------------------

    @app.get("/api/detectors/status")
    def get_detector_status(
        auth=Depends(check_auth),
        db: sqlite3.Connection = Depends(get_db),
    ):
        baseline_rows = db.execute(
            "SELECT detector_name, COUNT(*) AS baseline_count, MAX(last_seen) AS last_seen "
            "FROM baselines GROUP BY detector_name"
        ).fetchall()
        baseline_map = {r["detector_name"]: r for r in baseline_rows}

        result = []
        all_known = set(enabled_detectors) | set(baseline_map.keys())
        for name in sorted(all_known):
            b = baseline_map.get(name)
            result.append(
                {
                    "name": name,
                    "mode": _DETECTOR_MODES.get(name, "poll"),
                    "enabled": name in enabled_detectors,
                    "baseline_count": b["baseline_count"] if b else 0,
                    "last_seen": b["last_seen"] if b else None,
                }
            )
        return JSONResponse(result)

    return app


# ---------------------------------------------------------------------------
# Server wrapper (background thread for in-process launch)
# ---------------------------------------------------------------------------


class DashboardServer:
    """Run a uvicorn server in a daemon thread."""

    def __init__(self, app: FastAPI, host: str = "127.0.0.1", port: int = 8420) -> None:
        self.host = host
        self.port = port
        cfg = uvicorn.Config(
            app,
            host=host,
            port=port,
            log_level="warning",
            access_log=False,
        )
        self._server = uvicorn.Server(cfg)
        self._thread = threading.Thread(
            target=self._server.run,
            name="argus-dashboard",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.should_exit = True
        self._thread.join(timeout=5)
