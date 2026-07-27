# HyperionIDS

A lightweight, modular host + network intrusion detection system for Linux, built from four independent monitoring modules that can run standalone or together under a single master process.

Made by [Harsh Raj Singhania](https://github.com/HarshRajSinghania)

## Modules

| Module | File | What it does |
|---|---|---|
| File Integrity Monitoring (FIM) | `file_integrity_monitoring.py` | Hashes files under configured paths, baselines them, and alerts on modification/deletion |
| Process Behaviour Analysis (PBA) | `process_behaviour_analysis.py` | Watches running processes for high CPU/memory, restricted-file access, suspicious parent-child chains, execution from `/tmp`, and root processes running from non-standard locations |
| Syslog Monitoring | `syslog_monitoring.py` | Tails `/var/log/syslog` and `/var/log/auth.log`, pattern-matching for failed logins, privilege escalation, user add/delete, service restarts |
| Network Traffic Monitoring | `network_traffic_monitoring.py` | Sniffs live traffic with `scapy` and flags port scans, SYN floods, ICMP floods, and connections to historically risky ports (telnet, ftp, rdp, smb...) |

`master.py` starts all four as daemon threads and keeps the process alive until `Ctrl+C`.

## What changed in this pass

The original repo had three modules that, run together, would flag each other as malicious and spam desktop notifications continuously. This version fixes both, refactors all three original modules onto shared infrastructure, and adds the network module.

**Fixed:**
- `master.py` imported `fim_module` / `pba_module` / `syslog_module`, none of which existed in the repo — it couldn't actually run. Now imports the real files.
- PBA's "process running as root" check fired on *any* root-owned process, so once all three modules were running as root (needed to read `/etc/shadow`, `/var/log/auth.log`, etc.) they alerted on each other's `python3` process, plus basically every legitimate root service on the box. It now only flags root processes executing from outside standard system binary directories, and every module explicitly recognizes its siblings (`common.is_hyperion_process`) so they're never flagged.
- Every alert re-fired on every single poll with no deduplication — a process sitting above the CPU threshold, or a brute-force attempt hitting the log, would spam one notification per cycle. All three modules (and the new fourth) now route alerts through a shared `AlertManager` that deduplicates identical alerts within a cooldown window (default 5 minutes, configurable).
- FIM's exclusion list compared bare filenames against a mix of filenames and full paths, so entries like `/etc/mtab` never actually matched and constantly-changing files spammed "file modified" alerts.
- FIM now also auto-excludes every module's own log/baseline files so writing an alert doesn't itself trigger a FIM alert.

**Added:**
- `network_traffic_monitoring.py` — the fourth module.
- `config.py` — every path, threshold, and filename in one place instead of duplicated across four files.
- `common.py` — the shared `AlertManager` and `is_hyperion_process` helper.
- `requirements.txt`, `.gitignore`.

## Installation

```bash
git clone https://github.com/HarshRajSinghania/HyperionIDS.git
cd HyperionIDS
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

Network sniffing needs `libpcap`:

```bash
sudo apt install libpcap-dev   # Debian/Ubuntu/Kali
```

## Usage

Run everything together:

```bash
sudo python3 master.py
```

Root is required for reading `/etc/shadow`-class files (FIM), `/var/log/auth.log` (syslog), and opening raw sockets (network). Each module can also be run on its own, e.g.:

```bash
sudo python3 process_behaviour_analysis.py
```

Desktop notifications are sent via `plyer`; on a headless box or one without a running notification daemon, modules log a warning and keep going rather than crash.

## Configuration

Everything tunable lives in `config.py`: monitored paths, CPU/memory thresholds, syslog patterns, network thresholds/window sizes, watched ports, and `ALERT_COOLDOWN_SECONDS` (also overridable via the `HYPERION_ALERT_COOLDOWN` environment variable).

## Logs

Each module writes its own log next to the source (all covered by `.gitignore`, so they won't get committed):

- `fim_notifications.log`, `fim_baseline.json`
- `pba_notifications.log`
- `syslog_alerts.log`
- `network_notifications.log`

## Disclaimer

For authorized use on systems and networks you own or have explicit permission to monitor. Network sniffing and process/log monitoring can be misused for surveillance — don't.
