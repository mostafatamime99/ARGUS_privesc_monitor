# ARGUS

> **The watcher that never sleeps.**
> Real-time Linux privilege escalation detection and alerting.

**Author:** Mostafa Tamime

[![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)](#)

---

## Table of Contents

- [The Problem](#the-problem)
- [Why ARGUS is not linPEAS](#why-argus-is-not-linpeas)
- [Features](#features)
- [Architecture](#architecture)
- [Screenshots](#screenshots)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Telegram Setup](#telegram-setup)
  - [Configuration Reference](#configuration-reference)
- [Usage](#usage)
- [Detectors](#detectors)
- [Recommended auditd Rules](#recommended-auditd-rules)
- [Resilience & Hardening](#resilience--hardening)
  - [Systemd Auto-Restart](#systemd-auto-restart)
  - [Startup Announcement](#startup-announcement)
  - [SQLite Integrity Chain](#sqlite-integrity-chain)
  - [Systemd Unit Hardening](#systemd-unit-hardening)
- [Web Dashboard](#web-dashboard)
  - [Enable](#enable)
  - [Standalone Mode](#standalone-mode)
  - [Design Constraints](#design-constraints)
- [Deployment Guide](#deployment-guide)
  - [Production Checklist](#production-checklist)
  - [First 24 Hours](#first-24-hours)
  - [Log Rotation and Disk Usage](#log-rotation-and-disk-usage)
- [Operations / Runbook](#operations--runbook)
  - [Handling a CRITICAL Alert](#handling-a-critical-alert)
  - [Database Tampering Detected](#database-tampering-detected)
  - [Watchdog DOWN Alert](#watchdog-down-alert)
  - [Upgrading ARGUS Safely](#upgrading-argus-safely)
- [FAQ](#faq)
- [Glossary](#glossary)
- [Contributing / Extending](#contributing--extending)
  - [Adding a New Detector](#adding-a-new-detector)
  - [Code Style and Testing](#code-style-and-testing)
- [Threat Model & Limitations](#threat-model--limitations)
- [Roadmap](#roadmap)
- [License](#license)

---

## The Problem

Privilege escalation vectors on Linux servers — misconfigured SUID binaries,
injected cron jobs, tampered sudoers policies, capability grants — often sit
undetected for hours or days after they appear. Manual enumeration tools like
linPEAS require an operator to deliberately run them; by the time they do, an
attacker may already have moved laterally or established persistence. ARGUS
watches continuously and alerts the moment system state changes.

---

## Why ARGUS is not linPEAS

|  | linPEAS | ARGUS |
|---|---|---|
| **Mode** | One-shot, run manually | Continuous background daemon |
| **Trigger** | Operator initiates | Always-on, automatic |
| **Alerting** | None — prints to terminal | Real-time Telegram messages |
| **Noise / dedup** | Re-reports everything on every run | SQLite baseline; alerts only on *new* state |
| **Purpose** | Offensive enumeration aid | Blue team defensive monitor |

---

## Features

- **SUID/SGID binary detection** — inventories setuid/setgid files across
  configured paths every N seconds; alerts HIGH on new entries, LOW when an
  entry disappears (cleared or binary removed)
- **Sudoers real-time monitoring** — inotify-driven; detects `/etc/sudoers`
  and `/etc/sudoers.d/` changes the moment they are written, with a unified
  content diff in the alert body
- **Cron job monitoring** — same mechanism for `/etc/crontab`, `/etc/cron.d/`,
  and `/var/spool/cron/` (recursive)
- **Telegram alerting** with per-severity emoji (🔴 CRITICAL / 🟠 HIGH /
  🟡 MEDIUM / 🟢 LOW), configurable per-minute rate limit, and automatic
  overflow batching into summary messages when the cap is hit
- **SQLite baseline + diff deduplication** — each finding is hashed; only
  genuinely new state fires an alert; the same binary or file change never
  spams twice
- **Version / CVE reference scanner** (`version_scanner`, opt-in) —
  fingerprints dpkg/rpm packages, kernel (`uname -r`), and local SSH/nginx/
  Apache/MySQL banners; compares installed versions against exploit-db /
  NVD *advisory ranges* (not substring guesses) and reports CVE or EDB IDs
  with a confidence level; informational only — no exploit code or PoCs
- **SQLite integrity chain** — every alert inserted gets a SHA-256 hash chained
  to the previous row; ARGUS verifies the chain on every (re)start and on a
  configurable interval while running, and fires a CRITICAL Telegram alert if
  retroactive deletions or edits are detected; informational detection, not
  cryptographic proof
- **Structured alert storage** — each alert row stores hostname plus the
  finding's JSON `details` (path, diff, CVE ids); the dashboard renders them
  alongside the message
- **Per-detector allowlist** — known-good paths or item keys (exact match or
  trailing `*`) are baselined but never Telegram-alerted, so legitimate
  package SUID binaries stop paging you
- **Durable Telegram outbox** — rate-limited or failed sends are written to
  SQLite and retried after a restart; the finding itself is always in `alerts`
- **`python main.py ack <id>`** — acknowledge alerts without writing raw SQL;
  the `acknowledged` column is outside the hash digest so ACK does not look
  like tampering
- **Startup announcement** — every daemon start (including auto-restarts after
  a kill) logs and Telegram-alerts `ARGUS daemon (re)started at <timestamp>`,
  creating a visible restart trail
- **Systemd hardening** (`deploy/argus.service`) — `Restart=always`, strict
  filesystem isolation, `PrivateTmp`, `NoNewPrivileges`, capability bounding
  set limited to `CAP_DAC_READ_SEARCH`
- **Companion watchdog** (`deploy/argus-watchdog.service`, `argus_watchdog.py`)
  — independent systemd unit with zero ARGUS code imports; alerts Telegram if
  the main daemon goes down; recovers alert once the service comes back
- **Read-only web dashboard** (`dashboard/app.py`, opt-in) — FastAPI backend,
  dark-themed vanilla JS frontend, HTTP Basic Auth with bcrypt-hashed password;
  zero write endpoints; runs in-process alongside the daemon or standalone
- **`--dry-run` mode** — full detection pipeline and SQLite logging, zero
  outbound Telegram calls; safe for initial testing on production hosts
- **Rotating log file** — configurable size and backup count; always-on,
  independent of Telegram availability
- **Themed channel logs** — detectors write to `logs/detectors.log`, the CVE /
  exploit scanner (`version_scanner`) to `logs/exploit.log`, and SQLite
  integrity events to `logs/db.log`, each with a distinct log theme label

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         main.py                             │
│                                                             │
│  asyncio.run(run_daemon)                                    │
│  ├── startup_checks()  (chain verify + restart announcement)│
│  ├── integrity_loop  (periodic chain recheck)               │
│  │                                                          │
│  ├── poll_loop  (every scan_interval_seconds)               │
│  │    ├── SuidCheckDetector.run_once()                      │
│  │    ├── CapabilityCheckDetector.run_once()                │
│  │    └── VersionScannerDetector.run_once()                 │
│  │                                                          │
│  ├── watch_drain_loop  (every 1 s, drains pending queue)    │
│  │    ├── SudoersCheckDetector.run_once()                   │
│  │    └── CronCheckDetector.run_once()                      │
│  │                                                          │
│  ├── deferred_flush_loop  (every 15 s)                      │
│  │    └── TelegramBot.flush_deferred()                      │
│  │                                                          │
│  └── DashboardServer  (background thread, if enabled)       │
│       └── uvicorn → dashboard/app.py (read-only FastAPI)    │
└──────────────────┬──────────────────────────────────────────┘
                   │ detector.run_once()
                   ▼
┌──────────────────────────┐    ┌─────────────────────────────┐
│  BaseDetector            │    │  storage/db.py              │
│  scan()                  │    │                             │
│  diff(baseline, current) │◄───│  baselines table            │
│  allowlist filter        │───►│  (detector_name, item_hash, │
│  save_baseline(current)  │    │   first_seen, last_seen)    │
└──────────────┬───────────┘    └─────────────────────────────┘
               │ novel findings
               ▼
┌──────────────────────────┐    ┌─────────────────────────────┐
│  emit_findings()         │───►│  alerts table               │
│  log_finding()           │    │  (id, timestamp, detector,  │
│  persist_findings()      │    │   severity, message, host,  │
│  bot.notify()            │    │   details, acknowledged)    │
└──────────────┬───────────┘    └──────────┬──────────────────┘
               │                           │ every insert
               │                           ▼
               │               ┌─────────────────────────────┐
               │               │  integrity_chain table      │
               │               │  (seq, row_digest,          │
               │               │   chain_hash, written_at)   │
               │               └─────────────────────────────┘
               │
               ├──► logs/detectors.log  (DETECTOR theme)
               ├──► logs/exploit.log    (EXPLOIT theme — version_scanner)
               └──► logs/db.log         (DB theme — integrity events)
               ▼
┌──────────────────────────┐    ┌─────────────────────────────┐
│  alerts/telegram_bot.py  │───►│  telegram_outbox table      │
│  format_alert()          │    │  (durable unsent payloads)  │
│  rate-limit window       │    └─────────────────────────────┘
│  POST /sendMessage API   │
└──────────────────────────┘
```

Separately, `argus-watchdog.service` runs `argus_watchdog.py` as an
independent process. It has **no imports from ARGUS source code** and
communicates with Telegram directly via `urllib.request`.

---

## Screenshots

**Daemon startup — ARGUS banner and detector registration**

![ARGUS daemon startup](image/لقطة%20شاشة%202026-07-14%20020732.png)

**Log output — detection events, Telegram dispatch, and graceful shutdown**

![ARGUS log output](image/لقطة%20شاشة%202026-07-14%20021458.png)

**Telegram alert — batched rate-limited HIGH findings**

![Telegram alert](image/Screenshot_2026-07-14-02-08-06-97_948cd9899890cbd5c2798760b2b95377.jpg)

**Web dashboard — alert table with severity filtering**

![Dashboard alert table](image/لقطة%20شاشة%202026-08-12%20105538.png)

**Web dashboard — summary cards and detector status panel**

![Dashboard summary and detectors](image/لقطة%20شاشة%202026-08-12%20105554.png)

---

## Installation

```bash
git clone https://github.com/your-handle/argus.git
cd argus
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

**Requirements:**

| Requirement | Notes |
|---|---|
| Python 3.11+ | Required |
| Linux host | inotify-based watch detectors require Linux |
| `libcap2-bin` (Debian/Ubuntu) or `libcap` (RHEL/Fedora) | For `capability_check` (`getcap`) |
| auditd + rules | For `audit_parser`; see [Recommended auditd Rules](#recommended-auditd-rules) |
| `searchsploit` or NVD API key | For `version_scanner`; see [Detectors](#detectors) |
| `fastapi`, `uvicorn`, `bcrypt` | For the optional web dashboard; already in `requirements.txt` |

---

## Configuration

Copy the example config and fill in your values:

```bash
cp config.example.yaml config.yaml
```

> **Never commit `config.yaml`** — it holds your Telegram bot token.
> The file is listed in `.gitignore`. Only `config.example.yaml` is tracked.

### Telegram Setup

1. Message [@BotFather](https://t.me/BotFather) on Telegram → `/newbot` →
   copy the token it gives you.
2. Start a conversation with your new bot (send it any message), or add it
   to a private channel.
3. Retrieve your `chat_id`:
   ```bash
   curl "https://api.telegram.org/bot<TOKEN>/getUpdates"
   ```
   Look for `"chat":{"id": <number>}` in the JSON response.
4. In `config.yaml`, set `telegram.enabled: true` and paste both values.

### Configuration Reference

| Key | Default | Description |
|---|---|---|
| `daemon.scan_interval_seconds` | `60` | Polling interval for SUID/capability scans |
| `daemon.db_path` | `privesc_monitor.db` | SQLite file location |
| `daemon.hostname` | `""` | Stamped on every alert and Telegram message; empty uses the machine hostname |
| `daemon.integrity_check_seconds` | `300` | Re-verify the hash chain while running; `0` disables |
| `telegram.enabled` | `false` | Set `true` to activate Telegram alerts |
| `telegram.bot_token` | `""` | Token from BotFather |
| `telegram.chat_id` | `""` | Target chat or channel ID |
| `telegram.max_alerts_per_minute` | `10` | Rate-limit cap; overflow is batched into a summary |
| `detectors.enabled` | list | Which detectors to activate (see [Detectors](#detectors)) |
| `detectors.suid_check.scan_paths` | common bin dirs | Paths searched for SUID/SGID bits |
| `detectors.<name>.allowlist` | `[]` | Known-good item keys, paths, or prefixes ending in `*` |
| `detectors.version_scanner.engine` | `searchsploit` | `searchsploit` or `nvd_api` |
| `detectors.version_scanner.alert_on_low_confidence` | `false` | If false, low-confidence matches are logged but not sent to Telegram |
| `detectors.version_scanner.min_severity_alert` | `medium` | Minimum severity to Telegram-alert for version matches |
| `detectors.audit_parser.watch_keys` | see example | auditd rule keys to monitor |
| `dashboard.enabled` | `false` | Enable the read-only web dashboard |
| `dashboard.bind_host` | `127.0.0.1` | Dashboard listen address |
| `dashboard.port` | `8420` | Dashboard listen port |
| `dashboard.username` | `admin` | HTTP Basic Auth username |
| `dashboard.password_hash` | `""` | bcrypt hash of dashboard password (see [Enable](#enable)) |
| `logging.file` | `logs/privesc_monitor.log` | Main rotating daemon log |
| `logging.max_bytes` | `1048576` | Max log file size before rotation (1 MB default) |
| `logging.backup_count` | `5` | Number of rotated log files to keep |
| `logging.channels.detectors.file` | `logs/detectors.log` | Themed log for SUID/sudoers/cron/capability/audit findings |
| `logging.channels.exploit.file` | `logs/exploit.log` | Themed log for `version_scanner` CVE/EDB matches |
| `logging.channels.db.file` | `logs/db.log` | Themed log for integrity-chain / storage events |

---

## Usage

```bash
# Full daemon — detection + SQLite logging + Telegram alerts
python main.py -c config.yaml

# Dry-run — detection and SQLite logging only, no Telegram messages sent
python main.py --dry-run -c config.yaml

# Verbose DEBUG output to console and log file
python main.py -v -c config.yaml

# Acknowledge one or more alerts (does not break the integrity chain)
python main.py ack 12 15 -c config.yaml
```

Always run `--dry-run` first on a new host before enabling live Telegram alerts
— it lets you review findings and tune `scan_paths`/`watch_dirs` without noise.
See [First 24 Hours](#first-24-hours) for a recommended commissioning workflow.

To silence a known-good SUID binary without narrowing `scan_paths`:

```yaml
detectors:
  suid_check:
    allowlist:
      - /usr/bin/passwd
      - suid:/usr/bin/*
```

Allowlisted items are still written to the baseline so they do not re-alert;
they are simply never sent to Telegram or shown as new findings.

---

## Detectors

| Detector | Mode | Default | What it watches |
|---|---|---|---|
| `suid_check` | poll | enabled | SUID/SGID bits under configured bin paths |
| `sudoers_check` | watch | enabled | `/etc/sudoers` and `/etc/sudoers.d/` |
| `cron_check` | watch | enabled | `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/` |
| `capability_check` | poll | opt-in | File capabilities via `getcap -r` |
| `audit_parser` | watch | opt-in | auditd log keys (see [auditd Rules](#recommended-auditd-rules)) |
| `version_scanner` | poll | opt-in | Package/kernel/service versions vs CVE/EDB references (self-throttled, default 1 h) |

**`version_scanner` notes:**

- Uses real version-range comparison (e.g. OpenSSH 9.4 does **not** match an
  advisory of `< 9.3`).
- Matches with a parseable version range → `confidence: high`; these may
  Telegram-alert subject to `min_severity_alert`.
- Advisory titles with no extractable version boundary → `confidence: low`;
  these are stored in SQLite and visible on the dashboard but not sent to
  Telegram unless `alert_on_low_confidence: true`.
- Does **not** download or execute exploit code.

**Poll vs watch modes** — see [Glossary](#glossary) for definitions.

---

## Recommended auditd Rules

Add to `/etc/audit/rules.d/argus.rules` and reload with `augenrules --load`:

```
# Privilege escalation to root
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -k priv_esc_root

# Sudoers changes
-w /etc/sudoers -p wa -k sudoers_change
-w /etc/sudoers.d/ -p wa -k sudoers_change

# Cron changes
-w /etc/crontab -p wa -k cron_change
-w /etc/cron.d/ -p wa -k cron_change
-w /var/spool/cron/ -p wa -k cron_change

# SUID/SGID bit changes
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k suid_change

# Capability grants
-a always,exit -F arch=b64 -S capset -k capset_usage

# UID changes
-a always,exit -F arch=b64 -S setuid -S setreuid -S setresuid -k uid_change

# Kernel module insertion
-a always,exit -F arch=b64 -S init_module -S finit_module -k module_insertion
```

Verify the rules are loaded:

```bash
auditctl -l | grep -E "argus|priv_esc|sudoers_change|cron_change"
```

---

## Resilience & Hardening

### Systemd Auto-Restart

`deploy/argus.service` sets `Restart=always, RestartSec=5`. Any crash or
`SIGKILL` causes systemd to restart ARGUS within 5 seconds.

The companion `deploy/argus-watchdog.service` runs `argus_watchdog.py` as a
completely independent process with **no imports from ARGUS source code**. It
checks every 30 s whether the main service is alive (via `systemctl is-active`
or pidfile) and sends one Telegram alert when the service is down, and a
recovery alert when it returns.

> **Limitation:** A root-level attacker can kill both units and disable ARGUS
> entirely. Systemd auto-restart and the watchdog raise the detection bar —
> they do not prevent a determined attacker who already has root access. For
> stronger guarantees, pair with an out-of-band health-check from a separate
> host.

### Startup Announcement

On every start (including auto-restarts), ARGUS logs and Telegram-alerts
`ARGUS daemon (re)started at <timestamp>`. This creates a visible trail: if
someone kills and immediately restarts ARGUS, the restart event appears in both
SQLite and Telegram, making kill-restart cycles detectable.

### SQLite Integrity Chain

Every row written to the `alerts` table is appended to a SHA-256 hash chain in
the `integrity_chain` table:

```
chain_hash[n] = SHA-256( chain_hash[n-1] + row_digest[n] )
```

On every start (including auto-restarts), and again every
`daemon.integrity_check_seconds` (default 300), ARGUS re-derives the full chain.
If any row has been deleted or modified, the chain breaks and ARGUS fires a
CRITICAL Telegram alert. A failure while the daemon is up is announced once;
recovery clears that latch so a later break can alert again.

> **Limitation:** This is *detection*, not prevention. A root attacker with
> direct SQLite file access can rewrite both `alerts` and `integrity_chain` and
> reconstruct a valid chain. The feature makes *casual* or *automated*
> tampering immediately visible; it does not protect against a forensically
> capable adversary. Pair with filesystem-level integrity tools (Linux IMA/EVM,
> read-only bind mounts) for stronger guarantees.

### Systemd Unit Hardening

`argus.service` enables the following protections:

| Option | Effect |
|---|---|
| `ProtectSystem=strict` | Mounts `/`, `/usr`, `/boot` read-only for the unit |
| `ReadOnlyPaths=/opt/argus` | ARGUS code directory is read-only |
| `PrivateTmp=true` | Private `/tmp` namespace |
| `NoNewPrivileges=true` | `execve()` cannot gain privileges |
| `CapabilityBoundingSet=CAP_DAC_READ_SEARCH` | Only capability needed to read audit log and `/proc` paths |
| `RestrictSUIDSGID=true` | Cannot create SUID/SGID files |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` | Network restricted to required families |
| `SystemCallFilter=@system-service` | Syscall allowlist |

The daemon runs as the dedicated non-root `argus` user (created during
deployment — see [Production Checklist](#production-checklist)).

---

## Web Dashboard

The optional read-only web dashboard lets you browse alerts, view detector
status, and check integrity health without SSH access to the host.

![Dashboard alert table](image/لقطة%20شاشة%202026-08-12%20105538.png)

### Enable

1. Dependencies are already in `requirements.txt` (`fastapi`, `uvicorn`,
   `bcrypt`). If running from a bare venv, install them:
   ```bash
   pip install fastapi uvicorn bcrypt
   ```
2. Generate a bcrypt password hash:
   ```bash
   python -c "from dashboard.app import hash_password; print(hash_password('yourpassword'))"
   ```
3. Add to `config.yaml`:
   ```yaml
   dashboard:
     enabled: true
     bind_host: 127.0.0.1
     port: 8420
     username: admin
     password_hash: "$2b$12$..."   # paste the hash here
   ```
4. The dashboard starts automatically with the main daemon and logs its URL.
5. Access via an SSH tunnel if the host is remote:
   ```bash
   ssh -L 8420:127.0.0.1:8420 user@host
   # then open http://127.0.0.1:8420/ locally
   ```

### Standalone Mode

Run without the main daemon (reads the same SQLite file in read-only mode):

```bash
python dashboard.py -c config.yaml
# → Serving at http://127.0.0.1:8420/
```

This is useful for inspecting a database on another host without starting
detection loops.

### Design Constraints

| Property | Detail |
|---|---|
| **Read-only** | Every API endpoint is a `GET`. No endpoint writes to the DB, kills detectors, or executes commands. |
| **Auth required** | HTTP Basic Auth + bcrypt. An empty `password_hash` blocks all requests — there is no anonymous mode. |
| **Localhost-only default** | `bind_host: 127.0.0.1` — never `0.0.0.0` unless explicitly overridden and firewalled. |
| **SQLite isolation** | Dashboard opens its own read-only SQLite URI connection (`?mode=ro`); SQLite rejects any write attempt at the driver level. |

The dashboard **cannot** acknowledge alerts, modify detectors, or execute
anything — by deliberate design. Use the SQLite CLI or a future management API
for administrative actions.

---

## Deployment Guide

### Production Checklist

Run these steps on the host that ARGUS will monitor. Assumes Ubuntu/Debian;
adapt package names for RHEL/Fedora.

```bash
# 1. Create a dedicated non-root user (no login shell, no home directory)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin argus

# 2. Install ARGUS into a fixed path
sudo git clone https://github.com/your-handle/argus.git /opt/argus
cd /opt/argus
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt

# 3. Configure
sudo cp config.example.yaml config.yaml
sudo nano config.yaml          # fill in telegram.bot_token, chat_id, scan_paths

# 4. Set ownership — argus user reads code, cannot write
sudo chown -R root:argus /opt/argus
sudo chmod -R o-rwx /opt/argus
sudo chmod g+rX /opt/argus

# 5. Install systemd units
sudo cp deploy/argus.service /etc/systemd/system/
sudo cp deploy/argus-watchdog.service /etc/systemd/system/

# 6. Edit unit files to match your install path if it differs from /opt/argus
sudo nano /etc/systemd/system/argus.service

# 7. Configure the watchdog credentials
sudo cp deploy/watchdog-config.example.json /etc/argus-watchdog.json
sudo nano /etc/argus-watchdog.json            # fill in bot_token, chat_id

# 8. Enable and start both units
sudo systemctl daemon-reload
sudo systemctl enable --now argus.service
sudo systemctl enable --now argus-watchdog.service

# 9. Verify
sudo systemctl status argus.service
sudo systemctl status argus-watchdog.service
sudo journalctl -u argus.service -f
```

Expected output from `systemctl status argus.service` on a healthy deployment:

```
● argus.service - ARGUS Privilege Escalation Monitor
     Loaded: loaded (/etc/systemd/system/argus.service; enabled)
     Active: active (running) since ...
```

The Telegram channel should receive an `ARGUS daemon (re)started at ...` message
within a few seconds of the first start.

### First 24 Hours

Follow this workflow to commission ARGUS on a new host without alert fatigue:

1. **Dry-run first** — run the daemon with `--dry-run` for at least one full
   scan cycle. Inspect the SQLite database (`privesc_monitor.db`) and log file
   to understand the existing state of the host:
   ```bash
   python main.py --dry-run -c config.yaml -v
   sqlite3 privesc_monitor.db "SELECT detector_name, count(*) FROM baselines GROUP BY 1;"
   ```

2. **Review baseline findings** — check the `alerts` table for any detections
   from dry-run. Each finding represents existing state that ARGUS has
   baselined; future changes to these will trigger alerts.

3. **Tune `scan_paths` and `watch_dirs`** — if ARGUS is discovering SUID
   binaries or cron entries you know are legitimate, exclude those paths in
   `config.yaml` rather than suppressing alert severity globally.

4. **Enable live alerts** — set `telegram.enabled: true` and restart the daemon.
   The first live run will not re-alert on already-baselined state.

5. **Tune `version_scanner` separately** — if enabled, watch for
   `confidence: low` hits in the first 24 hours. Adjust
   `alert_on_low_confidence` and `min_severity_alert` once you understand the
   volume for your package set.

6. **Enable the dashboard** — once the daemon is stable, enable the web
   dashboard and verify the integrity chain shows `ok` in the summary card.

### Channel Logs (detectors / exploit / db)

Findings are written to **three themed rotating files** in addition to the
main daemon log. Each line is tagged with a fixed theme label so you can
`tail` one stream without noise from the others:

| Channel | Default file | Theme | Contents |
|---|---|---|---|
| `detectors` | `logs/detectors.log` | `DETECTOR` | SUID, sudoers, cron, capability, audit findings |
| `exploit` | `logs/exploit.log` | `EXPLOIT` | `version_scanner` CVE / EDB advisory matches |
| `db` | `logs/db.log` | `DB` | Integrity-chain OK / FAILED / recovered |

Example lines:

```text
2026-09-22 14:00:01,234 │ DETECTOR │ [WARNING] argus.detectors: …
2026-09-22 14:00:01,235 │ EXPLOIT  │ [WARNING] argus.exploit: …
2026-09-22 14:00:01,236 │ DB       │ [CRITICAL] argus.db: …
```

Paths and theme labels are configurable under `logging.channels` in
`config.yaml` (see `config.example.yaml`). Set `logging.channels_to_console:
false` if you only want channel detail in the files (the main log still gets
a one-line summary per finding).

### Log Rotation and Disk Usage

**Log files** — ARGUS uses Python's `RotatingFileHandler` for the main log and
each channel log. With the defaults (`max_bytes: 1048576`, `backup_count: 5`),
each file's maximum footprint is 6 MB (one active file + five backups). On a
busy host generating 50–100 alerts/day, the active log rotates roughly every
1–3 days. Increase `max_bytes` if you need longer single-file retention, or
reduce `backup_count` to cap total size.

**SQLite database** — on a typical single-host deployment:

| Table | Typical growth |
|---|---|
| `baselines` | Largely static after initial scan; grows only when new binaries are installed. Expect < 1 MB for a standard server. |
| `alerts` | 0.5–2 KB per alert row. 10,000 alerts ≈ 10–20 MB. Version scanner findings are the most voluminous. |
| `integrity_chain` | One row per alert; roughly the same size as `alerts`. |

For long-running deployments, consider periodically archiving and truncating the
`alerts` and `integrity_chain` tables. Truncating `integrity_chain` resets the
chain — restart the daemon to rebuild from the new baseline:

```bash
sqlite3 privesc_monitor.db "DELETE FROM integrity_chain; DELETE FROM alerts WHERE timestamp < date('now','-90 days');"
sudo systemctl restart argus.service   # rebuilds chain from scratch on start
```

> **Note:** Truncating resets detection continuity. Keep archives for forensic
> use before deleting rows.

---

## Operations / Runbook

### Handling a CRITICAL Alert

When ARGUS sends a CRITICAL Telegram alert for a detection finding (not a
tampering or restart alert):

1. **Identify the subject** — the alert message includes the detector name,
   severity, and description (e.g. `[suid_check] New SUID binary: /usr/local/bin/foo`).

2. **Check when it appeared** — query the alerts table:
   ```bash
   sqlite3 privesc_monitor.db \
     "SELECT timestamp, message FROM alerts WHERE severity='CRITICAL' ORDER BY id DESC LIMIT 10;"
   ```

3. **Cross-reference with auditd** (if `audit_parser` is enabled or auditd is
   running independently):
   ```bash
   ausearch -k suid_change --start recent | aureport -f
   ausearch -k priv_esc_root --start recent
   ```
   This shows *which process* set the SUID bit or escalated privileges and
   *under which user context*.

4. **Correlate with package manager activity** — a common false-positive is a
   package update that legitimately sets SUID bits:
   ```bash
   grep "$(date +%Y-%m-%d)" /var/log/dpkg.log | grep -i install
   ```

5. **Remediate or document** — if the finding is legitimate (planned package
   install), no action needed; the baseline updates automatically on the next
   scan. If unexpected, treat as a potential incident and follow your IR
   playbook.

6. **Acknowledge the alert** — from the host:

   ```bash
   python main.py ack <id> -c config.yaml
   ```

   The dashboard is read-only and shows the acknowledgement status after the
   next refresh. Direct SQL (`UPDATE alerts SET acknowledged=1`) also works and
   does not break the integrity chain.

### Database Tampering Detected

If ARGUS sends `Database tampering detected` at startup or during a periodic
recheck, the SHA-256 integrity chain over the `alerts` table is broken. This
means one or more rows have been deleted, modified, or inserted outside of
ARGUS.

**First three checks:**

1. **Verify file modification time** — check when `privesc_monitor.db` was
   last written:
   ```bash
   stat privesc_monitor.db
   ls -lah privesc_monitor.db
   ```
   An unexpected modification timestamp during a period when ARGUS was not
   running is a strong indicator of external editing.

2. **Check for deleted rows** — compare the alert count with `integrity_chain`
   row count; they should match:
   ```bash
   sqlite3 privesc_monitor.db \
     "SELECT (SELECT count(*) FROM alerts) AS alerts,
             (SELECT count(*) FROM integrity_chain) AS chain_rows;"
   ```
   A discrepancy means rows were deleted from `alerts` without updating the
   chain, or vice versa.

3. **Check for concurrent writes** — confirm no other process has the database
   open for writing:
   ```bash
   lsof privesc_monitor.db
   fuser privesc_monitor.db
   ```

If tampering is confirmed, treat the database as potentially compromised,
preserve a forensic copy, and consider the full contents of `alerts` after the
chain-break point as unverified.

### Watchdog DOWN Alert

If `argus-watchdog.service` sends `ARGUS main process is DOWN`, the main daemon
is not responding to systemd's `is-active` check.

**Diagnosis steps:**

```bash
# Check current unit state
sudo systemctl status argus.service

# Review recent journal entries for the crash reason
sudo journalctl -u argus.service -n 100 --no-pager

# Check if systemd is attempting a restart (look for "start request repeated")
sudo journalctl -u argus.service --since "10 minutes ago"

# If the unit is in a failed state with no auto-restart (e.g. hit StartLimitBurst)
sudo systemctl reset-failed argus.service
sudo systemctl start argus.service
```

Common causes:

| Symptom in journal | Likely cause |
|---|---|
| `ModuleNotFoundError` | Dependency missing from venv after a code update |
| `PermissionError` on `audit.log` | `argus` user lost `CAP_DAC_READ_SEARCH` |
| `sqlite3.OperationalError: database is locked` | Another process has the DB open exclusively |
| `Killed` with no Python traceback | OOM killer terminated the process |

### Upgrading ARGUS Safely

```bash
# 1. Stop the daemon (watchdog will alert — that is expected)
sudo systemctl stop argus.service

# 2. Back up the database
sudo cp /opt/argus/privesc_monitor.db /opt/argus/privesc_monitor.db.bak-$(date +%Y%m%d)

# 3. Pull the new version
cd /opt/argus
sudo git pull origin main

# 4. Update dependencies
sudo .venv/bin/pip install -r requirements.txt

# 5. Review config changes
diff config.example.yaml config.yaml
# Add any new keys introduced in config.example.yaml to config.yaml

# 6. Restart
sudo systemctl start argus.service

# 7. Verify — expect a restart announcement in Telegram within seconds
sudo systemctl status argus.service
sudo journalctl -u argus.service -n 30 --no-pager
```

> Always review `config.example.yaml` diffs between releases. New detectors or
> hardening options often require new keys in `config.yaml` to take effect.

---

## FAQ

**Why did ARGUS alert on a package my package manager just updated?**

Package managers (apt, dnf, pip) routinely set SUID bits on binaries, modify
crontab entries, and install files in monitored paths. ARGUS detects these as
legitimate state changes — because they *are* state changes. Cross-reference
the alert timestamp with your package manager log (`/var/log/dpkg.log`,
`/var/log/dnf.log`) to confirm the source. If the package is expected and
approved, no action is needed; the new state becomes the baseline on the next
scan cycle. To reduce noise, scope `detectors.suid_check.scan_paths` to only
the paths you actually care about.

---

**Can I run ARGUS on more than one host?**

The current design is **single-host**. Each ARGUS instance writes to a local
SQLite file and alerts to a single Telegram channel. To monitor multiple hosts
today, run a separate ARGUS instance per host, each with its own `config.yaml`
pointing to the same Telegram `chat_id` (or different channels per host).

Central alert aggregation, fleet management, and a shared dashboard across
hosts are not currently implemented. These are noted as roadmap items.

---

**Does ARGUS replace auditd or a SIEM?**

No. ARGUS *complements* auditd and a SIEM; it does not replace either. auditd
provides kernel-level syscall visibility that ARGUS does not have; a SIEM
aggregates events across hosts and supports long-term retention and correlation.
ARGUS fills a specific gap: continuous, automated privilege escalation *baseline
diffing* with immediate Telegram alerting, with a low operational overhead. See
[Threat Model & Limitations](#threat-model--limitations) for the full scope.

---

**Why is the dashboard read-only? Can I acknowledge alerts from it?**

By deliberate design. A monitoring interface that can also modify state (stop
detectors, clear alerts, change configuration) is a higher-value target: if an
attacker compromises the dashboard credentials, they can suppress detections.
Read-only means a compromised dashboard session gives an attacker no more
capability than read access to the log file.

Alert acknowledgement is done with `python main.py ack <id>` (or a direct
`UPDATE` on the `acknowledged` column). A dedicated management API with
separate, stricter authentication remains a potential future addition.

---

**What happens to alerts if Telegram is down?**

Telegram notifications are best-effort. If the Telegram API is unreachable,
`TelegramBot.notify()` logs the failure and the alert is still written to
SQLite and the log file. Payloads that were not accepted by Telegram are kept
in the `telegram_outbox` table and retried by `deferred_flush_loop` (every
15 seconds) and again after a daemon restart via `recover_unsent()`.

For environments where Telegram downtime is a concern, monitor `privesc_monitor.db`
and the log file directly, or add an out-of-band health-check on a separate
host. Slack/webhook alert backends are on the roadmap.

---

**The version scanner found a CVE for a package — is the system exploitable?**

Not necessarily. `version_scanner` reports *advisory references*: it checks
whether your installed version falls within the affected range published by
exploit-db or NVD. Whether the vulnerability is actually exploitable depends on
your system configuration, whether the affected code path is reachable, and
whether mitigating controls (SELinux, AppArmor, seccomp) are in place. Treat
version scanner findings as starting points for manual verification, not
confirmed exploitability.

---

**The integrity chain alert fired after I manually edited the database — is that expected?**

Yes. Any direct SQLite write that bypasses ARGUS's `insert_alert()` path will
break the chain. The `acknowledged` column is intentionally excluded from the
row digest, so `python main.py ack <id>` or
`UPDATE alerts SET acknowledged=1` does *not* break it. Other manual
modifications (deleting rows, editing `message`, `severity`, `hostname`, or
`details`) will.

---

**Can ARGUS detect memory-only attacks or rootkits?**

No. ARGUS monitors filesystem state (SUID bits, file contents, capability
attributes) and auditd log events. It cannot detect in-memory modifications,
`memfd_create`-based payloads, eBPF-based rootkits, or attacks that do not
touch the filesystem or produce auditd events. eBPF-based syscall monitoring
is planned as a future detector.

---

## Glossary

**SUID / SGID** — Set-User-ID and Set-Group-ID permission bits on a file
executable; when set, the process runs with the file owner's (or group's)
privileges rather than the caller's, making misconfigured SUID root binaries a
common privilege escalation vector.

**Baseline diffing** — ARGUS stores a hash of every discovered item (binary,
sudoers entry, cron job) in SQLite; on each scan, it computes the current
state and alerts only on items that are *new* relative to the stored baseline,
avoiding repeat alerts for unchanged state.

**Watch vs poll detector** — a *watch* detector registers an inotify kernel
event on a file or directory and is notified instantly when it changes; a
*poll* detector runs on a configurable timer (e.g. every 60 seconds) and
re-scans the relevant paths on each cycle.

**Confidence level** — used by `version_scanner`; `high` means the advisory
contained a parseable version range and the installed version falls within it;
`low` means the advisory title matched by name but contained no extractable
version boundary, so the match may be a false positive.

**Integrity chain** — an append-only SHA-256 hash chain stored in the
`integrity_chain` table; each entry's `chain_hash` is derived from the
previous hash plus a digest of the alert row, so any retroactive deletion or
modification breaks the chain and is detectable on the next daemon start.

**`CAP_DAC_READ_SEARCH`** — a Linux capability that allows a process to bypass
discretionary access control for read operations and directory searches; ARGUS
requests only this capability (not full root) so it can read `/proc` paths and
the auditd log without running as uid 0.

---

## Contributing / Extending

### Adding a New Detector

All detectors follow the same pattern. Here is the minimal structure:

```python
# detectors/my_detector.py
from detectors.base import BaseDetector, Finding, Severity

class MyDetector(BaseDetector):
    name = "my_detector"

    def scan(self) -> list[dict]:
        """
        Return a list of dicts representing the current observed state.
        Each dict must be JSON-serialisable and deterministic for the same
        underlying state (used as the baseline hash input).
        """
        results = []
        # ... collect findings ...
        return results

    def run_once(self) -> list[Finding]:
        current = self.scan()
        new_items, removed_items = self.diff(self.load_baseline(), current)
        findings = []
        for item in new_items:
            findings.append(Finding(
                severity=Severity.HIGH,
                message=f"New item detected: {item}",
                detector=self.name,
            ))
        self.save_baseline(current)
        return findings
```

**Registration** — add the detector to `DETECTOR_REGISTRY` in `main.py`:

```python
from detectors.my_detector import MyDetector

DETECTOR_REGISTRY = {
    ...
    "my_detector": {"cls": MyDetector, "mode": "poll"},  # or "watch"
}
```

**Config keys** — add a corresponding section to `config.example.yaml`:

```yaml
detectors:
  enabled:
    - my_detector
  my_detector:
    some_option: default_value
```

**Unit tests** — add `tests/test_my_detector.py` following the pattern in
`tests/test_suid_check.py`:

- Mock all subprocess calls and filesystem access.
- Test the "new item" path, the "removed item" path, and the "no change" path.
- Assert no live network or filesystem access occurs during tests.

### Code Style and Testing

| Expectation | Detail |
|---|---|
| **Test runner** | `pytest` — run `pytest tests/` from the project root |
| **Subprocess calls** | Always mock with `unittest.mock.patch`; no real subprocess calls in tests |
| **Network calls** | Never make live network calls in tests; mock `urllib.request` or `httpx` |
| **Filesystem access** | Use `tmp_path` (pytest fixture) for any test that needs real files |
| **Type hints** | New code should include type hints for public function signatures |
| **No magic numbers** | Constants belong in the config or as named module-level values |
| **No print statements** | Use `logging.getLogger(__name__)` for all output |

Run the full test suite before submitting changes:

```bash
pytest tests/ -v
```

All existing tests must pass. New detectors and features must include tests
covering at least the happy path and the no-change path.

---

## Threat Model & Limitations

ARGUS is a host-level blue team monitoring tool. It is deliberately scoped
and honest about its boundaries:

| Limitation | What it means | Mitigation in ARGUS |
|---|---|---|
| **Host-only visibility** | Cannot detect lateral movement to other hosts, container escapes, or network-level attacks | Pair with a SIEM or network IDS |
| **Root can kill ARGUS** | A process with root privileges can `kill -9` the daemon and its watchdog | Systemd `Restart=always`; companion watchdog alerts on downtime; startup announcement creates a restart trail |
| **SQLite can be tampered** | Root can edit the database file directly | Integrity chain detects retroactive modifications; CRITICAL alert on startup if broken; filesystem-level immutability (IMA/EVM) for stronger protection |
| **Telegram is a single point of failure** | If the API is unreachable, notifications queue in the SQLite outbox and retry after restart | SQLite always stores the alert; out-of-band monitoring on a separate host is still recommended |
| **auditd dependency for `audit_parser`** | No auditd rules → no findings, silently | Check `systemctl is-active auditd` and loaded rule keys |
| **Root-required paths** | `/var/log/audit/audit.log` and `/proc` paths need elevated access | Run as `argus` user with `CAP_DAC_READ_SEARCH`; see `deploy/argus.service` |
| **Filesystem events only** | Memory-only attacks (`memfd_create`, in-memory rootkits) are invisible | Combine with eBPF-based monitoring (planned) |
| **Alert ≠ compromise** | Package managers set SUID bits, cron entries are modified by installers | Tune `scan_paths`, `allowlist`, `watch_keys`, and `version_scanner.watch_packages` |
| **Dashboard is read-only** | Cannot acknowledge alerts or modify configuration via the UI | Use `python main.py ack <id>`; design prevents a compromised dashboard session from suppressing detections |
| **Single-host design** | No fleet aggregation, no central dashboard across hosts | Run one instance per host; set `daemon.hostname` so shared Telegram chats stay readable; central aggregation is a roadmap item |

---

## Roadmap

### Implemented and enabled by default

- [x] SUID/SGID binary detection (`suid_check`) — poll-based inventory diff
- [x] Sudoers real-time file monitoring (`sudoers_check`) — inotify + unified diff
- [x] Cron job monitoring (`cron_check`) — inotify + unified diff
- [x] Telegram alerting with rate limiting and overflow batching
- [x] SQLite baseline and diff-based deduplication
- [x] `--dry-run` mode
- [x] Rotating log file
- [x] Themed channel logs — detectors / exploit / db streams

### Implemented — enable in `config.yaml` to activate

- [x] File capability detection (`capability_check`) — `getcap -r` inventory diff
- [x] auditd log parser (`audit_parser`) — tails `audit.log`, parses seven rule keys
- [x] Version / CVE reference scanner (`version_scanner`) — package/kernel/service version ranges vs exploit-db/NVD
- [x] SQLite integrity chain — SHA-256 hash chain; CRITICAL alert on startup and periodic recheck if broken
- [x] Startup announcement — Telegram + log entry on every (re)start
- [x] Systemd hardening (`deploy/argus.service`, `deploy/argus-watchdog.service`)
- [x] Read-only web dashboard (`dashboard/`) — FastAPI + dark-themed frontend, HTTP Basic Auth
- [x] Structured alert storage — hostname + JSON details on every alert row
- [x] Per-detector allowlist — known-good paths/keys suppressed after baseline write
- [x] Durable Telegram outbox — unsent payloads survive daemon restart
- [x] Alert acknowledgement CLI — `python main.py ack <id>`

### Planned

- [ ] eBPF-based syscall hooks — eliminate polling latency, detect memory-only attacks
- [ ] `/proc` anomaly scanner — hidden processes, namespace escape detection
- [ ] World-writable path and `$PATH` hijack monitoring
- [ ] Slack / generic webhook alert backends
- [ ] Fleet mode — central alert aggregation across multiple hosts
- [ ] Alert acknowledgement API — dedicated management endpoint with separate authentication

---

## License

MIT © Mostafa Tamime
