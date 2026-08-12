"""
Fingerprint installed package/service versions and report matching CVE /
exploit-db *references* for a human operator to review.

Informational only: never fetches, generates, or executes exploit code.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import socket
import ssl
import subprocess
import time
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any, Callable
from urllib.parse import quote_plus

from detectors.base import BaseDetector, Finding
from storage.db import Database

logger = logging.getLogger(__name__)

try:
    from packaging.version import InvalidVersion, Version as Pep440Version
except ImportError:  # pragma: no cover - packaging is in requirements.txt
    Pep440Version = None  # type: ignore[misc, assignment]
    InvalidVersion = ValueError  # type: ignore[misc, assignment]


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_ENGINE = "searchsploit"
DEFAULT_SCAN_INTERVAL = 3600
DEFAULT_CACHE_TTL_HOURS = 24
DEFAULT_MIN_SEVERITY = "medium"
DEFAULT_BANNER_TIMEOUT = 2.0
DEFAULT_SUBPROCESS_TIMEOUT = 30
DEFAULT_SEARCHSPLOIT_TIMEOUT = 15
DEFAULT_NVD_TIMEOUT = 20
DEFAULT_MAX_LOOKUPS = 50
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_NO_KEY = (5, 30.0)   # 5 requests / 30 s
NVD_RATE_WITH_KEY = (50, 30.0)

# High-value targets for priv-esc / remotely reachable services.
# Lookup is intersected with whatever is actually installed (plus kernel + banners).
DEFAULT_WATCH_PACKAGES = frozenset({
    "sudo", "openssh", "openssh-server", "openssh-client", "openssl",
    "nginx", "apache2", "apache", "httpd", "mysql-server", "mysql",
    "mariadb-server", "mariadb", "postgresql", "polkit", "policykit-1",
    "dbus", "systemd", "docker", "docker.io", "docker-ce", "containerd",
    "bash", "libc6", "glibc", "linux-image", "kernel", "linux",
    "php", "python3", "perl", "redis", "redis-server", "bind9", "postfix",
    "snapd", "cron", "cronie", "util-linux", "pam", "libpam-modules",
    "shadow", "passwd", "xz-utils", "liblzma5", "liblzma", "curl", "wget",
    "git", "vim", "nano", "tar", "gzip", "login", "coreutils",
})

# Distro package name → searchsploit / NVD query term
PACKAGE_QUERY_ALIASES: dict[str, str] = {
    "openssh-server": "openssh",
    "openssh-client": "openssh",
    "apache2": "apache",
    "httpd": "apache",
    "mysql-server": "mysql",
    "mariadb-server": "mysql",
    "mariadb": "mysql",
    "linux-image": "linux kernel",
    "kernel": "linux kernel",
    "linux": "linux kernel",
    "policykit-1": "polkit",
    "libc6": "glibc",
    "liblzma5": "xz",
    "xz-utils": "xz",
    "docker.io": "docker",
    "docker-ce": "docker",
    "redis-server": "redis",
    "libpam-modules": "pam",
}

DEFAULT_BANNER_TARGETS: tuple[dict[str, Any], ...] = (
    {"host": "127.0.0.1", "port": 22, "service": "ssh"},
    {"host": "127.0.0.1", "port": 80, "service": "http"},
    {"host": "127.0.0.1", "port": 443, "service": "https"},
    {"host": "127.0.0.1", "port": 3306, "service": "mysql"},
)

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Distro packaging suffixes stripped before version comparison.
_DISTRO_SUFFIX_RE = re.compile(
    r"(?:\+deb\d+u\d+|\+dfsg\d*|\+ds\d*|\+git[\w.]*|"
    r"-\d+ubuntu[\d.]*|-\d+\.fc\d+|-\d+\.el\d+[\w._]*|"
    r"-\d+debian\d*|~\w+)",
    re.IGNORECASE,
)
_EPOCH_RE = re.compile(r"^\d+:")
_OPENSSH_P_RE = re.compile(r"(\d+(?:\.\d+)*)p(\d+)", re.IGNORECASE)
_KERNEL_VER_RE = re.compile(r"^(\d+\.\d+(?:\.\d+)?)")

# Advisory range patterns (applied to exploit-db titles / CVE descriptions).
# Two-sided dash: "Apache 2.4.49-2.4.50" or "2.4.49 - 2.4.50"
_RANGE_DASH = re.compile(
    r"(?P<lo>\d[\w.]*)\s*[-–]\s*(?P<hi>\d[\w.]*)"
)
# Two-sided operator: "OpenSSH 2.3 < 7.7" / "2.3 <= 7.7"
_RANGE_TWO_SIDED = re.compile(
    r"(?P<lo>\d[\w.]*)\s*(?P<op><=|<)\s*(?P<hi>\d[\w.]*)"
)
# One-sided: "< 9.3", "<= 9.3", ">= 2.0", "before 9.3", "through 9.3"
_RANGE_ONE_SIDED = re.compile(
    r"(?:(?P<op><=|>=|<|>)\s*|(?P<before>before|prior\s+to)\s+|(?P<through>through|up\s+to)\s+)"
    r"(?P<ver>\d[\w.+]*)",
    re.IGNORECASE,
)

_DPKG_LINE = re.compile(
    r"^(?P<status>[a-zA-Z]{2,3})\s+(?P<name>\S+)\s+(?P<version>\S+)"
)

ConnectFn = Callable[..., bytes]
RunFn = Callable[..., Any]
HttpGetFn = Callable[..., str]


# ---------------------------------------------------------------------------
# Version objects
# ---------------------------------------------------------------------------

class _TupleVersion:
    """Fallback comparable version when packaging is missing or parse fails."""

    __slots__ = ("parts", "raw")

    def __init__(self, raw: str) -> None:
        self.raw = raw
        nums = [int(p) for p in re.split(r"\D+", raw) if p.isdigit()]
        self.parts = tuple(nums) if nums else (0,)

    def __lt__(self, other: Any) -> bool:
        return self._cmp(other) < 0

    def __le__(self, other: Any) -> bool:
        return self._cmp(other) <= 0

    def __gt__(self, other: Any) -> bool:
        return self._cmp(other) > 0

    def __ge__(self, other: Any) -> bool:
        return self._cmp(other) >= 0

    def __eq__(self, other: Any) -> bool:
        return self._cmp(other) == 0

    def _cmp(self, other: Any) -> int:
        oparts = other.parts if isinstance(other, _TupleVersion) else _TupleVersion(str(other)).parts
        n = max(len(self.parts), len(oparts))
        a = self.parts + (0,) * (n - len(self.parts))
        b = oparts + (0,) * (n - len(oparts))
        return (a > b) - (a < b)

    def __repr__(self) -> str:
        return f"_TupleVersion({self.raw!r})"


def normalize_version(raw: str, *, kernel: bool = False) -> str:
    """Strip distro suffixes / epochs into a comparable upstream-like string."""
    text = (raw or "").strip()
    if not text:
        return ""
    if kernel:
        m = _KERNEL_VER_RE.match(text)
        if m:
            return m.group(1)
    text = _EPOCH_RE.sub("", text)
    # Repeatedly strip known distro suffixes
    prev = None
    while prev != text:
        prev = text
        text = _DISTRO_SUFFIX_RE.sub("", text)
    # Trailing Debian revision with no distro tag (e.g. 7.9p1-10)
    text = re.sub(r"-\d+$", "", text)
    text = text.strip("-~+")
    # OpenSSH 9.3p1 → 9.3.post1 (PEP 440; p-patch is newer than the base)
    text = _OPENSSH_P_RE.sub(r"\1.post\2", text)
    return text


def parse_version(raw: str, *, kernel: bool = False) -> Any | None:
    """Return a comparable version object, or None if ``raw`` is empty."""
    norm = normalize_version(raw, kernel=kernel)
    if not norm:
        return None
    if Pep440Version is not None:
        try:
            return Pep440Version(norm)
        except InvalidVersion:
            pass
    return _TupleVersion(norm)


@dataclass(frozen=True)
class VersionRange:
    """Inclusive/exclusive bounds. ``None`` on a side means unbounded."""

    min_version: Any | None = None
    min_inclusive: bool = True
    max_version: Any | None = None
    max_inclusive: bool = False

    def contains(self, ver: Any) -> bool:
        if ver is None:
            return False
        if self.min_version is not None:
            if self.min_inclusive:
                if ver < self.min_version:
                    return False
            elif ver <= self.min_version:
                return False
        if self.max_version is not None:
            if self.max_inclusive:
                if ver > self.max_version:
                    return False
            elif ver >= self.max_version:
                return False
        return True


def _looks_like_version(token: str) -> bool:
    return bool(re.match(r"^\d+(\.\d+)*([a-zA-Z]\w*)?$", token or ""))


def parse_affected_range(text: str) -> VersionRange | None:
    """
    Extract a version range from an advisory title/description.

    Returns None when no clear version boundary is present (caller should
    fall back to substring matching with confidence=low).
    """
    if not text:
        return None

    # Prefer two-sided dash ranges whose both ends parse as versions and lo < hi.
    for m in _RANGE_DASH.finditer(text):
        lo_s, hi_s = m.group("lo"), m.group("hi")
        if not (_looks_like_version(lo_s) and _looks_like_version(hi_s)):
            continue
        lo, hi = parse_version(lo_s), parse_version(hi_s)
        if lo is None or hi is None or not (lo < hi or lo == hi):
            continue
        if lo == hi:
            return VersionRange(min_version=lo, min_inclusive=True,
                                max_version=hi, max_inclusive=True)
        return VersionRange(min_version=lo, min_inclusive=True,
                            max_version=hi, max_inclusive=True)

    for m in _RANGE_TWO_SIDED.finditer(text):
        lo_s, hi_s, op = m.group("lo"), m.group("hi"), m.group("op")
        if not (_looks_like_version(lo_s) and _looks_like_version(hi_s)):
            continue
        lo, hi = parse_version(lo_s), parse_version(hi_s)
        if lo is None or hi is None or not (lo < hi):
            continue
        return VersionRange(
            min_version=lo,
            min_inclusive=True,
            max_version=hi,
            max_inclusive=(op == "<="),
        )

    # One-sided: take the first operator that is actually bound to a version.
    for m in _RANGE_ONE_SIDED.finditer(text):
        ver_s = m.group("ver")
        if not _looks_like_version(ver_s.split("+")[0]) and not _looks_like_version(ver_s):
            # Allow 9.3p1 via normalize
            if parse_version(ver_s) is None:
                continue
        bound = parse_version(ver_s)
        if bound is None:
            continue
        if m.group("before"):
            return VersionRange(max_version=bound, max_inclusive=False)
        if m.group("through"):
            return VersionRange(max_version=bound, max_inclusive=True)
        op = (m.group("op") or "").strip()
        if op == "<":
            return VersionRange(max_version=bound, max_inclusive=False)
        if op == "<=":
            return VersionRange(max_version=bound, max_inclusive=True)
        if op == ">":
            return VersionRange(min_version=bound, min_inclusive=False)
        if op == ">=":
            return VersionRange(min_version=bound, min_inclusive=True)
    return None


def version_in_advisory(installed: str, advisory_text: str, *, kernel: bool = False) -> tuple[bool, str]:
    """
    Compare ``installed`` against a range parsed from ``advisory_text``.

    Returns (matched, confidence) where confidence is "high" if a real range
    was parsed and compared, "low" if we fell back to substring matching.
    """
    inst = parse_version(installed, kernel=kernel)
    rng = parse_affected_range(advisory_text)
    if rng is not None and inst is not None:
        return rng.contains(inst), "high"

    # Substring fallback — no clear boundary.
    norm = normalize_version(installed, kernel=kernel)
    hay = advisory_text.lower()
    if norm and norm.lower() in hay:
        return True, "low"
    # Bare numeric form without .postN
    bare = re.sub(r"\.post\d+", "", norm, flags=re.IGNORECASE)
    if bare and bare.lower() in hay:
        return True, "low"
    return False, "low"


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def severity_from_title(title: str, confidence: str) -> str:
    """
    searchsploit-only severity. Default MEDIUM.

    Title keywords may bump to HIGH only when confidence is high.
    Low-confidence findings never exceed MEDIUM.
    """
    if confidence != "high":
        return "medium"
    t = (title or "").lower()
    if "remote" in t or "privilege escalation" in t:
        return "high"
    return "medium"


def query_term_for(package_name: str) -> str:
    name = package_name.lower()
    if name in PACKAGE_QUERY_ALIASES:
        return PACKAGE_QUERY_ALIASES[name]
    for prefix, alias in PACKAGE_QUERY_ALIASES.items():
        if name.startswith(prefix):
            return alias
    return package_name


# ---------------------------------------------------------------------------
# Package-list parsers (pure; unit-testable)
# ---------------------------------------------------------------------------

def parse_dpkg_output(text: str) -> list[dict[str, str]]:
    """Parse ``dpkg -l`` stdout into {name, version} dicts (installed only)."""
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        m = _DPKG_LINE.match(line.strip())
        if not m:
            continue
        status = m.group("status")
        # Second character 'i' means installed (ii, hi, ...)
        if len(status) < 2 or status[1].lower() != "i":
            continue
        out.append({"name": m.group("name"), "version": m.group("version")})
    return out


def parse_rpm_output(text: str) -> list[dict[str, str]]:
    """Parse ``rpm -qa --queryformat`` or raw ``rpm -qa`` stdout."""
    out: list[dict[str, str]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if "\t" in line:
            name, version = line.split("\t", 1)
            out.append({"name": name.strip(), "version": version.strip()})
            continue
        # name-ver-rel.arch → split on last two hyphens (RPM NEVRA)
        m = re.match(r"^(.+)-([^-]+)-([^-]+)\.[^.]+$", line)
        if m:
            out.append({"name": m.group(1), "version": m.group(2)})
            continue
        m = re.match(r"^(.+)-([^-]+)-([^-]+)$", line)
        if m:
            out.append({"name": m.group(1), "version": m.group(2)})
    return out


# ---------------------------------------------------------------------------
# Banner parsers (pure)
# ---------------------------------------------------------------------------

def parse_ssh_banner(data: bytes | str) -> dict[str, str] | None:
    text = data.decode("latin-1", errors="replace") if isinstance(data, bytes) else data
    # SSH-2.0-OpenSSH_9.2p1 Ubuntu-3
    m = re.search(r"OpenSSH[_\s-]([\w.]+)", text, re.IGNORECASE)
    if m:
        return {"name": "openssh", "version": m.group(1)}
    m = re.search(r"^SSH-[\d.]+-(\S+)", text, re.MULTILINE)
    if m:
        return {"name": "ssh", "version": m.group(1)}
    return None


def parse_http_server_header(data: bytes | str) -> dict[str, str] | None:
    text = data.decode("latin-1", errors="replace") if isinstance(data, bytes) else data
    m = re.search(r"(?im)^server:\s*(.+)$", text)
    if not m:
        return None
    server = m.group(1).strip()
    nginx = re.search(r"nginx/([\w.]+)", server, re.IGNORECASE)
    if nginx:
        return {"name": "nginx", "version": nginx.group(1)}
    apache = re.search(r"Apache/([\w.]+)", server, re.IGNORECASE)
    if apache:
        return {"name": "apache", "version": apache.group(1)}
    return None


def parse_mysql_handshake(data: bytes) -> dict[str, str] | None:
    """Extract the null-terminated version string from a MySQL greeting."""
    if len(data) < 6:
        return None
    # 4-byte packet header, 1-byte protocol version, then version\0
    body = data[4:] if data[0] < 32 else data
    if not body:
        return None
    rest = body[1:]  # skip protocol byte
    end = rest.find(b"\x00")
    if end <= 0:
        return None
    ver = rest[:end].decode("ascii", errors="replace")
    if not re.match(r"\d+\.\d+", ver):
        return None
    return {"name": "mysql", "version": ver}


# ---------------------------------------------------------------------------
# Vulnerability record
# ---------------------------------------------------------------------------

@dataclass
class VulnRecord:
    vuln_id: str
    title: str
    reference: str
    confidence: str  # high | low
    severity: str
    cvss: float | None = None
    engine: str = "searchsploit"


class _RateLimiter:
    """Simple sliding-window limiter (NVD: 5/30s without key, 50/30s with)."""

    def __init__(self, max_requests: int, window_seconds: float) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._times: deque[float] = deque()

    def wait(self) -> None:
        if self.max_requests <= 0:
            return
        now = time.monotonic()
        while self._times and now - self._times[0] >= self.window_seconds:
            self._times.popleft()
        if len(self._times) >= self.max_requests:
            sleep_for = self.window_seconds - (now - self._times[0])
            if sleep_for > 0:
                time.sleep(sleep_for)
            now = time.monotonic()
            while self._times and now - self._times[0] >= self.window_seconds:
                self._times.popleft()
        self._times.append(time.monotonic())


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class VersionScannerDetector(BaseDetector):
    """
    Inventory package/kernel/service versions; match CVE / exploit-db
    references with real version-range comparison; alert only on new hashes.
    """

    name = "version_scanner"

    def __init__(
        self,
        db: Database,
        config: dict[str, Any] | None = None,
        *,
        run: RunFn | None = None,
        connect: ConnectFn | None = None,
        http_get: HttpGetFn | None = None,
        monotonic: Callable[[], float] | None = None,
    ) -> None:
        super().__init__(db, config)
        cfg = self.config
        self.engine: str = str(cfg.get("engine") or DEFAULT_ENGINE).strip().lower()
        if self.engine not in ("searchsploit", "nvd_api"):
            logger.warning(
                "version_scanner: unknown engine %r — falling back to searchsploit",
                self.engine,
            )
            self.engine = DEFAULT_ENGINE
        self.scan_interval: float = float(
            cfg.get("scan_interval_seconds", DEFAULT_SCAN_INTERVAL)
        )
        self.nvd_api_key: str = str(cfg.get("nvd_api_key") or "").strip()
        self.cache_ttl_seconds: float = float(cfg.get("cache_ttl_hours", DEFAULT_CACHE_TTL_HOURS)) * 3600.0
        self.min_severity_alert: str = str(
            cfg.get("min_severity_alert", DEFAULT_MIN_SEVERITY)
        ).strip().lower()
        self.alert_on_low_confidence: bool = bool(cfg.get("alert_on_low_confidence", False))
        self.banner_timeout: float = float(
            cfg.get("banner_timeout_seconds", DEFAULT_BANNER_TIMEOUT)
        )
        self.max_lookups: int = int(cfg.get("max_lookups", DEFAULT_MAX_LOOKUPS))
        raw_watch = cfg.get("watch_packages")
        if raw_watch is None:
            self.watch_packages: list[str] | None = None  # default high-value set
        else:
            self.watch_packages = [str(p) for p in raw_watch]
        self.banner_targets: list[dict[str, Any]] = list(
            cfg.get("banner_targets") or DEFAULT_BANNER_TARGETS
        )

        self._run: RunFn = run or subprocess.run
        self._connect: ConnectFn | None = connect
        self._http_get: HttpGetFn | None = http_get
        self._monotonic = monotonic or time.monotonic
        self._last_run: float | None = None
        self._searchsploit_warned = False
        max_req, window = NVD_RATE_WITH_KEY if self.nvd_api_key else NVD_RATE_NO_KEY
        self._nvd_limiter = _RateLimiter(max_req, window)

    # ------------------------------------------------------------------
    # BaseDetector
    # ------------------------------------------------------------------

    def run_once(self) -> list[Finding]:
        """Throttle to scan_interval_seconds; otherwise scan → diff → save."""
        now = self._monotonic()
        if (
            self._last_run is not None
            and self.scan_interval > 0
            and (now - self._last_run) < self.scan_interval
        ):
            return []
        self._last_run = now
        return super().run_once()

    def scan(self) -> list[Finding]:
        packages = self.collect_installed_packages()
        kernel = self.collect_kernel_version()
        if kernel:
            packages.append(kernel)
        packages.extend(self.collect_service_banners())

        targets = self._select_lookup_targets(packages)
        findings: list[Finding] = []
        seen: set[str] = set()
        for pkg in targets:
            is_kernel = pkg.get("source") == "kernel" or pkg["name"] in (
                "linux-kernel",
                "kernel",
                "linux",
            )
            vulns = self.lookup_vulnerabilities(
                pkg["name"], pkg["version"], kernel=is_kernel
            )
            for rec in vulns:
                finding = self._finding_from(pkg, rec)
                if finding.item_key in seen:
                    continue
                seen.add(finding.item_key)
                findings.append(finding)
        findings.sort(key=lambda f: f.item_key)
        return findings

    # ------------------------------------------------------------------
    # Fingerprinting
    # ------------------------------------------------------------------

    def collect_installed_packages(
        self,
        *,
        run: RunFn | None = None,
        which: Callable[[str], str | None] | None = None,
    ) -> list[dict[str, str]]:
        """Detect dpkg vs rpm and return [{name, version}, ...]."""
        run = run or self._run
        which = which or shutil.which
        if which("dpkg"):
            return self._collect_dpkg(run)
        if which("rpm"):
            return self._collect_rpm(run)
        logger.debug("version_scanner: neither dpkg nor rpm found on PATH")
        return []

    def _collect_dpkg(self, run: RunFn) -> list[dict[str, str]]:
        try:
            result = run(
                ["dpkg", "-l"],
                capture_output=True,
                text=True,
                timeout=DEFAULT_SUBPROCESS_TIMEOUT,
            )
        except FileNotFoundError:
            return []
        except subprocess.TimeoutExpired:
            logger.error("version_scanner: dpkg -l timed out")
            return []
        except OSError as exc:
            logger.error("version_scanner: dpkg -l failed: %s", exc)
            return []
        return parse_dpkg_output(result.stdout or "")

    def _collect_rpm(self, run: RunFn) -> list[dict[str, str]]:
        try:
            result = run(
                ["rpm", "-qa", "--queryformat", "%{NAME}\\t%{VERSION}\\n"],
                capture_output=True,
                text=True,
                timeout=DEFAULT_SUBPROCESS_TIMEOUT,
            )
        except FileNotFoundError:
            return []
        except subprocess.TimeoutExpired:
            logger.error("version_scanner: rpm -qa timed out")
            return []
        except OSError as exc:
            logger.error("version_scanner: rpm -qa failed: %s", exc)
            return []
        return parse_rpm_output(result.stdout or "")

    def collect_kernel_version(
        self, *, run: RunFn | None = None
    ) -> dict[str, str] | None:
        run = run or self._run
        try:
            result = run(
                ["uname", "-r"],
                capture_output=True,
                text=True,
                timeout=DEFAULT_SUBPROCESS_TIMEOUT,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
            logger.debug("version_scanner: uname -r failed: %s", exc)
            return None
        ver = (result.stdout or "").strip()
        if not ver:
            return None
        return {"name": "linux-kernel", "version": ver, "source": "kernel"}

    def collect_service_banners(
        self, *, connect: ConnectFn | None = None
    ) -> list[dict[str, str]]:
        """Minimal banner grab for SSH, nginx, Apache, MySQL (2s timeout)."""
        grab = connect or self._connect or _default_banner_connect
        found: list[dict[str, str]] = []
        for target in self.banner_targets:
            host = str(target.get("host", "127.0.0.1"))
            port = int(target.get("port", 0))
            service = str(target.get("service", "")).lower()
            if not port:
                continue
            try:
                data = grab(
                    host,
                    port,
                    probe=_probe_for(service),
                    use_ssl=(service == "https"),
                    timeout=self.banner_timeout,
                )
            except (OSError, TimeoutError, socket.timeout, ssl.SSLError) as exc:
                logger.debug(
                    "version_scanner: banner %s:%s (%s) failed: %s",
                    host, port, service, exc,
                )
                continue
            parsed = _parse_banner(service, data)
            if parsed:
                parsed = dict(parsed)
                parsed["source"] = "banner"
                found.append(parsed)
        return found

    # ------------------------------------------------------------------
    # CVE / exploit-db matching
    # ------------------------------------------------------------------

    def lookup_vulnerabilities(
        self,
        package_name: str,
        version: str,
        *,
        kernel: bool = False,
    ) -> list[VulnRecord]:
        """Pluggable lookup with SQLite TTL cache keyed by (engine, name, version)."""
        cache_key = f"{self.engine}:{package_name}:{version}"
        cached = self.db.get_lookup_cache(cache_key, self.cache_ttl_seconds)
        if cached is not None:
            return _vulns_from_json(cached)

        if self.engine == "nvd_api":
            records = self._lookup_nvd(package_name, version, kernel=kernel)
        else:
            records = self._lookup_searchsploit(package_name, version, kernel=kernel)

        self.db.put_lookup_cache(
            cache_key,
            json.dumps([asdict(r) for r in records], default=str),
        )
        return records

    def _lookup_searchsploit(
        self, package_name: str, version: str, *, kernel: bool
    ) -> list[VulnRecord]:
        term = query_term_for(package_name)
        try:
            result = self._run(
                ["searchsploit", "--json", term],
                capture_output=True,
                text=True,
                timeout=DEFAULT_SEARCHSPLOIT_TIMEOUT,
            )
        except FileNotFoundError:
            if not self._searchsploit_warned:
                logger.warning(
                    "version_scanner: searchsploit not installed — "
                    "install exploitdb (Debian: apt install exploitdb) or "
                    "switch engine to nvd_api; detector will keep fingerprinting"
                )
                self._searchsploit_warned = True
            return []
        except subprocess.TimeoutExpired:
            logger.warning("version_scanner: searchsploit timed out for %s", term)
            return []
        except OSError as exc:
            logger.error("version_scanner: searchsploit error: %s", exc)
            return []

        stdout = result.stdout or ""
        return parse_searchsploit_json(stdout, package_name, version, kernel=kernel)

    def _lookup_nvd(
        self, package_name: str, version: str, *, kernel: bool
    ) -> list[VulnRecord]:
        term = query_term_for(package_name)
        url = (
            f"{NVD_CVE_API}?keywordSearch={quote_plus(term)}"
            f"&resultsPerPage=20"
        )
        headers = {
            "User-Agent": "ARGUS-privesc-monitor (defensive version fingerprinting)",
        }
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        try:
            self._nvd_limiter.wait()
            body = self._http_get_json(url, headers)
        except Exception as exc:
            logger.warning("version_scanner: NVD lookup failed for %s: %s", term, exc)
            return []
        return parse_nvd_response(body, package_name, version, kernel=kernel)

    def _http_get_json(self, url: str, headers: dict[str, str]) -> str:
        if self._http_get is not None:
            return self._http_get(url, headers=headers, timeout=DEFAULT_NVD_TIMEOUT)
        import requests

        resp = requests.get(url, headers=headers, timeout=DEFAULT_NVD_TIMEOUT)
        resp.raise_for_status()
        return resp.text

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _select_lookup_targets(
        self, packages: list[dict[str, str]]
    ) -> list[dict[str, str]]:
        """Always include kernel + banners; intersect the rest with the watchlist."""
        watch = self.watch_packages
        lookup_all = watch is not None and any(p.strip() == "*" for p in watch)
        watch_set = (
            {p.lower() for p in watch if p.strip() != "*"}
            if watch is not None
            else set(DEFAULT_WATCH_PACKAGES)
        )

        selected: list[dict[str, str]] = []
        seen_names: set[str] = set()
        for pkg in packages:
            name = pkg["name"]
            key = name.lower()
            source = pkg.get("source", "package")
            if source in ("kernel", "banner"):
                pass  # always include
            elif lookup_all:
                pass
            elif not _name_is_watched(key, watch_set):
                continue
            # Dedupe by lowercase name, prefer banner/kernel over package
            if key in seen_names:
                continue
            seen_names.add(key)
            selected.append(pkg)
            if len(selected) >= self.max_lookups:
                logger.warning(
                    "version_scanner: lookup cap (%d) reached; remaining packages skipped",
                    self.max_lookups,
                )
                break
        return selected

    def _finding_from(self, pkg: dict[str, str], rec: VulnRecord) -> Finding:
        name = pkg["name"]
        version = pkg["version"]
        item_key = f"{name}:{normalize_version(version)}:{rec.vuln_id}"
        message = (
            f"{name} {version} matches {rec.vuln_id} [{rec.confidence}]: "
            f"{rec.title} | ref: {rec.reference}"
        )
        notify = self._should_notify(rec.confidence, rec.severity)
        return Finding(
            detector_name=self.name,
            severity=rec.severity,
            message=message,
            item_key=item_key,
            details={
                "package": name,
                "installed_version": version,
                "vuln_id": rec.vuln_id,
                "title": rec.title,
                "confidence": rec.confidence,
                "reference": rec.reference,
                "cvss": rec.cvss,
                "engine": rec.engine,
                "source": pkg.get("source", "package"),
            },
            notify=notify,
        )

    def _should_notify(self, confidence: str, severity: str) -> bool:
        if confidence == "low" and not self.alert_on_low_confidence:
            return False
        return _SEV_RANK.get(severity, 0) >= _SEV_RANK.get(self.min_severity_alert, 2)


def _name_is_watched(name: str, watch_set: set[str]) -> bool:
    if name in watch_set:
        return True
    for w in watch_set:
        if name.startswith(w) or w.startswith(name):
            return True
    return False


def _probe_for(service: str) -> bytes | None:
    if service in ("http", "https"):
        return b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n"
    return None  # SSH / MySQL: server speaks first


def _parse_banner(service: str, data: bytes) -> dict[str, str] | None:
    if not data:
        return None
    if service == "ssh":
        return parse_ssh_banner(data)
    if service in ("http", "https"):
        return parse_http_server_header(data)
    if service == "mysql":
        return parse_mysql_handshake(data)
    # Try all parsers
    return (
        parse_ssh_banner(data)
        or parse_http_server_header(data)
        or parse_mysql_handshake(data)
    )


def _default_banner_connect(
    host: str,
    port: int,
    *,
    probe: bytes | None = None,
    use_ssl: bool = False,
    timeout: float = DEFAULT_BANNER_TIMEOUT,
) -> bytes:
    sock: socket.socket | ssl.SSLSocket = socket.create_connection(
        (host, port), timeout=timeout
    )
    try:
        sock.settimeout(timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        if probe:
            sock.sendall(probe)
        return sock.recv(2048)
    finally:
        try:
            sock.close()
        except OSError:
            pass


def parse_searchsploit_json(
    text: str,
    package_name: str,
    installed_version: str,
    *,
    kernel: bool = False,
) -> list[VulnRecord]:
    """Turn searchsploit --json stdout into VulnRecords (titles/IDs only)."""
    payload = _extract_json_object(text)
    if not payload:
        return []
    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        logger.debug("version_scanner: searchsploit JSON parse failed")
        return []

    rows = data.get("RESULTS_EXPLOIT") or []
    records: list[VulnRecord] = []
    pkg_l = package_name.lower()
    query_l = query_term_for(package_name).lower()
    for row in rows:
        if not isinstance(row, dict):
            continue
        title = str(row.get("Title") or row.get("title") or "").strip()
        edb_id = str(row.get("EDB-ID") or row.get("edb_id") or "").strip()
        if not title or not edb_id:
            continue
        matched, confidence = version_in_advisory(
            installed_version, title, kernel=kernel
        )
        if confidence == "high" and not matched:
            # A real range was parsed and this install is outside it — skip.
            continue
        if not matched:
            # No parseable range: low-confidence product-name mention only.
            hay = title.lower()
            if pkg_l not in hay and query_l not in hay:
                continue
            confidence = "low"
        severity = severity_from_title(title, confidence)
        records.append(
            VulnRecord(
                vuln_id=f"EDB-{edb_id}" if not edb_id.upper().startswith("EDB") else edb_id,
                title=title,
                reference=f"https://www.exploit-db.com/exploits/{edb_id}",
                confidence=confidence,
                severity=severity,
                cvss=None,
                engine="searchsploit",
            )
        )
    return records


def parse_nvd_response(
    text: str,
    package_name: str,
    installed_version: str,
    *,
    kernel: bool = False,
) -> list[VulnRecord]:
    """Extract CVEs whose CPE/description range contains the installed version."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    inst = parse_version(installed_version, kernel=kernel)
    records: list[VulnRecord] = []
    for item in data.get("vulnerabilities") or []:
        cve = (item or {}).get("cve") or {}
        cve_id = str(cve.get("id") or "").strip()
        if not cve_id:
            continue
        title = _nvd_english_description(cve)
        cvss = _nvd_cvss(cve)
        rng, confidence = _nvd_range_for_cve(cve, title)
        if rng is None or inst is None:
            continue
        if not rng.contains(inst):
            continue
        severity = severity_from_cvss(cvss) if cvss is not None else severity_from_title(title, confidence)
        if confidence != "high" and _SEV_RANK[severity] > _SEV_RANK["medium"]:
            severity = "medium"
        records.append(
            VulnRecord(
                vuln_id=cve_id,
                title=title[:200] or cve_id,
                reference=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                confidence=confidence,
                severity=severity,
                cvss=cvss,
                engine="nvd_api",
            )
        )
    return records


def _nvd_english_description(cve: dict[str, Any]) -> str:
    for d in cve.get("descriptions") or []:
        if str(d.get("lang", "")).lower() == "en":
            return str(d.get("value") or "").strip()
    if cve.get("descriptions"):
        return str(cve["descriptions"][0].get("value") or "").strip()
    return ""


def _nvd_cvss(cve: dict[str, Any]) -> float | None:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if not arr:
            continue
        data = (arr[0] or {}).get("cvssData") or {}
        score = data.get("baseScore")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                return None
    return None


def _nvd_range_for_cve(
    cve: dict[str, Any], description: str
) -> tuple[VersionRange | None, str]:
    """Prefer CPE versionStart/End fields; fall back to description text."""
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable", True):
                    continue
                rng = _range_from_cpe_match(match)
                if rng is not None:
                    return rng, "high"
    rng = parse_affected_range(description)
    if rng is not None:
        return rng, "high"
    return None, "low"


def _range_from_cpe_match(match: dict[str, Any]) -> VersionRange | None:
    lo = match.get("versionStartIncluding") or match.get("versionStartExcluding")
    hi = match.get("versionEndIncluding") or match.get("versionEndExcluding")
    lo_inc = "versionStartIncluding" in match
    hi_inc = "versionEndIncluding" in match
    min_v = parse_version(str(lo)) if lo else None
    max_v = parse_version(str(hi)) if hi else None
    if min_v is not None or max_v is not None:
        return VersionRange(
            min_version=min_v,
            min_inclusive=lo_inc if lo else True,
            max_version=max_v,
            max_inclusive=hi_inc if hi else False,
        )
    # Exact version in the CPE URI (part 5, 0-indexed split)
    criteria = str(match.get("criteria") or "")
    parts = criteria.split(":")
    if len(parts) >= 6:
        cpe_ver = parts[5]
        if cpe_ver and cpe_ver not in ("*", "-"):
            v = parse_version(cpe_ver)
            if v is not None:
                return VersionRange(
                    min_version=v, min_inclusive=True,
                    max_version=v, max_inclusive=True,
                )
    return None


def _extract_json_object(text: str) -> str:
    """searchsploit may print a banner before the JSON object."""
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return ""
    return text[start : end + 1]


def _vulns_from_json(payload: str) -> list[VulnRecord]:
    try:
        rows = json.loads(payload)
    except json.JSONDecodeError:
        return []
    out: list[VulnRecord] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        out.append(
            VulnRecord(
                vuln_id=str(row.get("vuln_id") or ""),
                title=str(row.get("title") or ""),
                reference=str(row.get("reference") or ""),
                confidence=str(row.get("confidence") or "low"),
                severity=str(row.get("severity") or "medium"),
                cvss=row.get("cvss"),
                engine=str(row.get("engine") or "searchsploit"),
            )
        )
    return [r for r in out if r.vuln_id]
