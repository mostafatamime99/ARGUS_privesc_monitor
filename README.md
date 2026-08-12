# ARGUS

> **The watcher that never sleeps.**
> Real-time Linux privilege escalation detection and alerting.

**Author:** Mostafa Tamime

[![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen)](#)

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
  common binary paths every N seconds; alerts HIGH on new entries, LOW when
  one disappears (cleared or binary removed)
- **Sudoers real-time monitoring** — watchdog-driven; detects `/etc/sudoers`
  and `/etc/sudoers.d/` changes the moment they are written, with a unified
  content diff in the alert body
- **Cron job monitoring** — same mechanism for `/etc/crontab`, `/etc/cron.d/`,
  and `/var/spool/cron/` (recursive)
- **Telegram alerting** with per-severity emoji (🔴 CRITICAL / 🟠 HIGH /
  🟡 MEDIUM / 🟢 LOW), configurable per-minute rate limit, and automatic
  overflow batching into summary messages when the cap is hit
- **SQLite baseline + diff deduplication** — each finding is hashed; only
  genuinely new state fires an alert; the same binary or file change never
  spams you twice
- **Version / CVE reference scanner** (`version_scanner`, opt-in) —
  fingerprints dpkg/rpm packages, kernel (`uname -r`), and local SSH/nginx/
  Apache/MySQL banners; compares installed versions against exploit-db /
  NVD *advisory ranges* (not substring guesses) and reports CVE or EDB IDs
  with a confidence level. Informational only — no exploit code or PoCs
- **SQLite integrity chain** — every alert inserted gets a SHA-256 hash chained
  to the previous row; on every daemon (re)start ARGUS verifies the full chain
  and fires a CRITICAL Telegram alert if retroactive deletions or edits are
  detected. Informational detection, not cryptographic proof — an attacker with
  raw file access can rewrite both tables
- **Startup announcement** — every daemon start (including auto-restarts after
  a kill) logs and Telegram-alerts "ARGUS daemon (re)started at \<timestamp\>",
  creating a visible restart trail
- **Systemd hardening** (`deploy/argus.service`) — `Restart=always`, strict
  filesystem isolation, `PrivateTmp`, `NoNewPrivileges`, capability bounding
  set limited to `CAP_DAC_READ_SEARCH`
- **Companion watchdog** (`deploy/argus-watchdog.service`, `argus_watchdog.py`)
  — independent systemd unit with zero ARGUS code imports; alerts Telegram if
  the main daemon goes down; recovers alert once the service comes back
- **Read-only web dashboard** (`dashboard.py` / `dashboard/app.py`, opt-in) —
  FastAPI backend, dark-themed vanilla JS frontend, HTTP Basic Auth with
  bcrypt-hashed password; zero write endpoints; can run in-process or standalone
- **`--dry-run` mode** — full detection pipeline and SQLite logging, zero
  outbound Telegram calls; safe for testing on production hosts
- **Rotating log file** — configurable size and backup count; always-on,
  independent of Telegram availability

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         main.py                             │
│                                                             │
│  asyncio.run(run_daemon)                                    │
│  ├── poll_loop  (every scan_interval_seconds)               │
│  │    ├── SuidCheckDetector.run_once()                      │
│  │    ├── CapabilityCheckDetector.run_once()                │
│  │    └── VersionScannerDetector.run_once()                 │
│  │                                                          │
│  ├── watch_drain_loop  (every 1 s, drains pending queue)    │
│  │    ├── SudoersCheckDetector.run_once()                   │
│  │    └── CronCheckDetector.run_once()                      │
│  │                                                          │
│  └── deferred_flush_loop  (every 15 s)                      │
│       └── TelegramBot.flush_deferred()                      │
└──────────────────┬──────────────────────────────────────────┘
                   │ detector.run_once()
                   ▼
┌──────────────────────────┐    ┌─────────────────────────────┐
│  BaseDetector            │    │  storage/db.py              │
│  scan()                  │    │                             │
│  diff(baseline, current) │◄───│  baselines table            │
│  save_baseline(current)  │───►│  (detector_name, item_hash, │
└──────────────┬───────────┘    │   first_seen, last_seen)    │
               │ novel findings  └─────────────────────────────┘
               ▼
┌──────────────────────────┐    ┌─────────────────────────────┐
│  emit_findings()         │───►│  alerts table               │
│  log_finding()           │    │  (id, timestamp, detector,  │
│  persist_findings()      │    │   severity, message,        │
│  bot.notify()            │    │   acknowledged)             │
└──────────────┬───────────┘    └─────────────────────────────┘
               │
               ▼
┌──────────────────────────┐
│  alerts/telegram_bot.py  │
│  format_alert()          │
│  rate-limit window       │
│  POST /sendMessage API   │
└──────────────────────────┘
```

---

## Screenshots

**Daemon startup — ARGUS banner and detector registration**

![ARGUS daemon startup](image/لقطة%20شاشة%202026-07-14%20020732.png)

**Log output — detection events, Telegram dispatch, and graceful shutdown**

![ARGUS log output](image/لقطة%20شاشة%202026-07-14%20021458.png)

**Telegram alert — batched rate-limited HIGH findings**

![Telegram alert](image/Screenshot_2026-07-14-02-08-06-97_948cd9899890cbd5c2798760b2b95377.jpg)

---

## Installation

```bash
git clone https://github.com/your-handle/argus.git
cd argus
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

> **Requirements:** Python 3.11+, Linux target host.
> For capability scanning: `apt install libcap2-bin` (Debian/Ubuntu) or
> `dnf install libcap` (RHEL/Fedora).
> For auditd event parsing: auditd must be running and loaded with the
> rule keys listed in the [Recommended auditd Rules](#recommended-auditd-rules)
> section below.
> For `version_scanner` (optional): `searchsploit` from the exploitdb package,
> **or** an NVD API key (`engine: nvd_api`). The detector fingerprints versions
> and reports advisory *references* only; it does not download or run exploits.

---

## Configuration

Copy the example config and fill in your values:

```bash
cp config.example.yaml config.yaml
```

> **⚠️ Never commit `config.yaml`** — it holds your Telegram bot token.
> The file is listed in `.gitignore`. Only `config.example.yaml` is tracked.

### Telegram setup

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

### Key config options

| Key | Default | Description |
|---|---|---|
| `daemon.scan_interval_seconds` | `60` | Polling interval for SUID/capability scans |
| `daemon.db_path` | `privesc_monitor.db` | SQLite file location |
| `telegram.enabled` | `false` | Set `true` to activate Telegram alerts |
| `telegram.max_alerts_per_minute` | `10` | Rate-limit cap; overflow is batched into a summary |
| `detectors.enabled` | list | Which detectors to activate (see `config.example.yaml`) |
| `detectors.version_scanner.engine` | `searchsploit` | `searchsploit` or `nvd_api` |
| `detectors.version_scanner.alert_on_low_confidence` | `false` | If false, low-confidence matches are logged but not sent to Telegram |
| `dashboard.enabled` | `false` | Enable the read-only web dashboard |
| `dashboard.bind_host` | `127.0.0.1` | Dashboard listen address |
| `dashboard.port` | `8420` | Dashboard listen port |
| `dashboard.username` | `admin` | HTTP Basic Auth username |
| `dashboard.password_hash` | `""` | bcrypt hash of dashboard password |
| `logging.file` | `logs/privesc_monitor.log` | Rotating log file path |
| `logging.max_bytes` | `1048576` | Max log file size before rotation (1 MB) |
| `logging.backup_count` | `5` | Number of rotated log files to keep |

---

## Usage

```bash
# Full daemon — detection + SQLite logging + Telegram alerts
python main.py -c config.yaml

# Dry-run — detection and SQLite logging only, no Telegram messages sent
python main.py --dry-run -c config.yaml

# Verbose DEBUG output to console and log file
python main.py -v -c config.yaml
```

---

## Detectors

| Detector | Mode | Default | What it watches |
|---|---|---|---|
| `suid_check` | poll | enabled | SUID/SGID bits under common bin paths |
| `sudoers_check` | watch | enabled | `/etc/sudoers` and `/etc/sudoers.d/` |
| `cron_check` | watch | enabled | crontab, `/etc/cron.d/`, `/var/spool/cron/` |
| `capability_check` | poll | opt-in | file capabilities via `getcap -r` |
| `audit_parser` | watch | opt-in | auditd log keys (see rules below) |
| `version_scanner` | poll | opt-in | package/kernel/service versions vs CVE/EDB *references* (self-throttled, default 1h). Does **not** use auditd. |

`version_scanner` uses real version-range comparison (e.g. OpenSSH 9.4 does **not** match an advisory of `< 9.3`). Matches with a parseable range are `confidence: high` and may Telegram-alert (subject to `min_severity_alert`). Titles with no version boundary are stored as `confidence: low` for the dashboard and are not sent to Telegram unless `alert_on_low_confidence: true`.

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

---

## Roadmap

### Implemented and enabled by default

- [x] SUID/SGID binary detection (`suid_check`) — poll-based inventory diff
- [x] Sudoers real-time file monitoring (`sudoers_check`) — watchdog + unified diff
- [x] Cron job monitoring (`cron_check`) — watchdog + unified diff
- [x] Telegram alerting with rate limiting and overflow batching
- [x] SQLite baseline and diff-based deduplication
- [x] `--dry-run` mode
- [x] Rotating log file

### Implemented — enable in `config.yaml` to activate

- [x] File capability detection (`capability_check`) — `getcap -r` inventory
      diff; add `capability_check` to `detectors.enabled` to activate
- [x] auditd log parser (`audit_parser`) — tails `audit.log`, parses seven
      rule keys with configurable severities; add `audit_parser` to
      `detectors.enabled` and load the auditd rules above to activate
- [x] Version / CVE reference scanner (`version_scanner`) — fingerprints
      installed packages, kernel, and local service banners; matches
      searchsploit / NVD advisory version ranges; add `version_scanner` to
      `detectors.enabled` to activate (disabled by default)
- [x] SQLite integrity chain — SHA-256 hash chain over all alert rows;
      verified on every daemon start; CRITICAL alert if chain is broken
- [x] Startup announcement — Telegram + log entry on every (re)start,
      creating an auditable restart trail
- [x] Systemd hardening (`deploy/argus.service`, `deploy/argus-watchdog.service`) —
      `Restart=always`, strict FS isolation, companion watchdog with zero ARGUS
      code imports; see `deploy/` for unit files and `INSTALL.md`
- [x] Read-only web dashboard (`dashboard/`) — FastAPI + dark-themed frontend,
      HTTP Basic Auth, zero write endpoints; enable via `dashboard.enabled: true`

### Planned

- [ ] eBPF-based syscall hooks — eliminate polling latency, detect
      memory-only attacks
- [ ] `/proc` anomaly scanner — hidden processes, namespace escape detection
- [ ] World-writable path and `$PATH` hijack monitoring
- [ ] Slack / generic webhook alert backends

---

## Resilience & Hardening

### Systemd auto-restart

`deploy/argus.service` sets `Restart=always, RestartSec=5`.  Any crash or
`SIGKILL` causes systemd to restart ARGUS automatically within 5 seconds.
The companion `deploy/argus-watchdog.service` is an independent unit running
`argus_watchdog.py` (no ARGUS code imports); it checks every 30 s whether
the main service is alive and sends a Telegram alert when it is not.

> **Limitation:** A root-level attacker can kill both units and disable
> ARGUS entirely.  These services raise the bar — they do not prevent a
> determined attacker who already has root access.  For stronger guarantees,
> pair ARGUS with an out-of-band monitoring channel (e.g., a cloud health-check
> service on a separate host).

### Startup announcement

On every start (including auto-restarts), ARGUS logs and Telegram-alerts
`"ARGUS daemon (re)started at <timestamp>"`.  This creates a visible trail:
if someone kills and restarts ARGUS, the restart event appears in both SQLite
and Telegram.

### SQLite integrity chain

Every row written to the `alerts` table is appended to a SHA-256 hash chain
in the `integrity_chain` table (each `chain_hash` = SHA-256(prev_hash +
row_digest)).  On every daemon start, ARGUS re-derives the full chain and
fires a CRITICAL alert if any row was deleted or modified.

> **Limitation:** This is *detection*, not prevention.  A root attacker with
> direct SQLite file access can rewrite both `alerts` and `integrity_chain`
> and reconstruct a valid chain.  The feature makes *casual* or *automated*
> tampering immediately visible; it does not protect against a forensically
> capable adversary.  Pair with filesystem-level integrity tools (Linux IMA/EVM,
> read-only mounts) for stronger guarantees.

### Systemd unit hardening

`argus.service` enables: `ProtectSystem=strict`, `ReadOnlyPaths=/opt/argus`,
`PrivateTmp=true`, `NoNewPrivileges=true`,
`CapabilityBoundingSet=CAP_DAC_READ_SEARCH`, `RestrictSUIDSGID=true`.
The daemon runs as a dedicated non-root `argus` user.

---

## Web Dashboard

The optional read-only web dashboard lets you browse alerts, view detector
status, and check integrity health without SSH access to the host.

### Enable

1. Install dependencies: `pip install fastapi uvicorn bcrypt`
2. Generate a password hash:
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

### Standalone mode

Run without the main daemon (reads the same SQLite file in read-only mode):

```bash
python dashboard.py -c config.yaml
# → http://127.0.0.1:8420/
```

### Design constraints

| Property | Detail |
|---|---|
| **Read-only** | Every API endpoint is a GET.  No endpoint writes to the DB, kills detectors, or executes commands. |
| **Auth required** | HTTP Basic Auth + bcrypt.  Empty `password_hash` blocks all requests — no anonymous mode. |
| **Localhost-only default** | `bind_host: 127.0.0.1` — never `0.0.0.0` unless explicitly overridden. |
| **SQLite isolation** | Dashboard opens its own read-only SQLite URI connection (`?mode=ro`); SQLite itself rejects any write attempt. |

The dashboard **cannot** acknowledge alerts, modify detectors, or execute
anything — by deliberate design.

---

## Threat Model & Limitations

ARGUS is a host-level blue team monitoring tool. It is deliberately scoped
and honest about its boundaries:

| Limitation | What it means | Mitigation in ARGUS |
|---|---|---|
| **Host-only visibility** | Cannot detect lateral movement to other hosts, container escapes, or network-level attacks | Pair with a SIEM or network IDS |
| **Root can kill ARGUS** | A process with root privileges can `kill -9` the daemon and its watchdog | Systemd `Restart=always`; companion watchdog alerts on downtime; startup announcement creates a restart trail |
| **SQLite can be tampered** | Root can edit the database file directly | Integrity chain detects retroactive modifications; CRITICAL alert on startup if broken; immutable mounts (IMA/EVM) for stronger protection |
| **Telegram is a single point of failure** | If the API is unreachable, alerts queue in memory and are lost on restart | SQLite is always written; out-of-band monitoring (separate host) recommended |
| **auditd dependency for `audit_parser`** | No auditd rules → no findings, silently | Check `systemctl is-active auditd` and loaded rule keys |
| **Root-required paths** | `/var/log/audit/audit.log` and `/proc` paths need elevated access | Run as `argus` user with `CAP_DAC_READ_SEARCH`; see `deploy/argus.service` |
| **Filesystem events only** | Memory-only attacks (`memfd_create`, in-memory rootkits) are invisible | Combine with eBPF-based monitoring (planned) |
| **Alert ≠ compromise** | Package managers set SUID bits, cron entries are modified by installers | Tune `scan_paths`, `watch_keys`, and `version_scanner.watch_packages` |
| **Dashboard is detection-only** | Cannot acknowledge alerts or modify configuration via the UI | By design — use CLI/SQLite for administrative actions |

---

## License

MIT © Mostafa Tamime
