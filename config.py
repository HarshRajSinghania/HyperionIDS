"""
Central configuration for HyperionIDS.

Every module reads its defaults from here so there is a single place to
tune paths, thresholds, and behavior instead of hunting through four files.
Any module can still be run standalone with these defaults, or imported
and constructed with overrides (see master.py).
"""

import os

# ---------------------------------------------------------------------------
# General
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# How long (seconds) to suppress a repeat of the *same* alert before it is
# allowed to log/notify again. This is what stops the notification spam --
# without it, a condition that stays true (high CPU, a brute-force attempt,
# an oversized baseline diff) re-fires every single poll.
ALERT_COOLDOWN_SECONDS = int(os.environ.get("HYPERION_ALERT_COOLDOWN", "300"))

# Filenames that belong to HyperionIDS itself. Used by every module to make
# sure it never treats its own (or a sibling module's) process, log file, or
# state file as something to alert on.
HYPERION_SCRIPT_NAMES = [
    "master.py",
    "file_integrity_monitoring.py",
    "process_behaviour_analysis.py",
    "syslog_monitoring.py",
    "network_traffic_monitoring.py",
]

HYPERION_DATA_FILES = [
    "security_monitor.log",
    "fim_baseline.json",
    "fim_notifications.log",
    "pba_notifications.log",
    "syslog_alerts.log",
    "network_notifications.log",
]

# ---------------------------------------------------------------------------
# File Integrity Monitoring (FIM)
# ---------------------------------------------------------------------------
FIM_MONITORED_PATHS = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/boot"]
FIM_EXCLUDE_FILES = [".DS_Store", "Thumbs.db", "mtab", "adjtime"]
FIM_HASH_ALGORITHM = "sha256"
FIM_BASELINE_FILE = os.path.join(PROJECT_ROOT, "fim_baseline.json")
FIM_LOG_FILE = os.path.join(PROJECT_ROOT, "fim_notifications.log")
FIM_SCAN_INTERVAL = 10

# ---------------------------------------------------------------------------
# Process Behaviour Analysis (PBA)
# ---------------------------------------------------------------------------
PBA_CPU_THRESHOLD = 80
PBA_MEMORY_THRESHOLD = 80
PBA_RESTRICTED_FILES = ["/etc/shadow", "/etc/passwd", "/var/log/auth.log", "/etc/hosts"]
PBA_SUSPICIOUS_RELATIONSHIPS = [
    {"parent": "bash", "child": "nc"},
    {"parent": "ssh", "child": "bash"},
    {"parent": "python3", "child": "bash"},
]
PBA_EXCLUDED_PROCESSES = [
    "kworker", "kthreadd", "systemd", "rcu_tasks_kthread", "systemd-journald",
    "systemd-udevd", "dbus-daemon", "lightdm", "Xorg", "NetworkManager",
    "accounts-daemon", "wpa_supplicant", "cron", "gvfsd", "gvfsd-fuse",
    "modemmanager", "udisksd", "upowerd", "irq", "ksmd", "kcompactd0",
    "rcu_sched", "rcu_preempt", "rcu_bh", "ksoftirqd", "migration",
    "idle_inject", "cpuhp", "irqbalance", "snapd", "smartd",
    "pool_workqueue_release", "rcu_tasks_rude_kthread", "rcu_tasks_trace_kthread",
    "rcu_exp_par_gp_kthread_worker", "rcu_exp_gp_kthread_worker", "kdevtmpfs",
    "kauditd", "khungtaskd", "oom_reaper", "khugepaged", "kswapd0", "scsi_eh_0",
    "scsi_eh_1", "spi0", "scsi_eh_2", "usb-storage", "scsi_eh_3", "card0-crtc0",
    "card0-crtc1", "card0-crtc2", "jbd2/sda6-8", "psimon", "watchdogd", "hwrng",
    "haveged", "ModemManager", "agetty", "openvpn", "xfconfd", "dbus-launch",
    "xfce4-notifyd",
]
PBA_SUSPICIOUS_DIRECTORIES = ["/tmp", "/var/tmp"]
# Standard install locations. A process running as root FROM one of these is
# not, by itself, suspicious. Root processes running from anywhere else are
# what actually deserve a flag (see process_behaviour_analysis.py).
PBA_TRUSTED_ROOT_DIRECTORIES = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/lib", "/lib"]
PBA_LOG_FILE = os.path.join(PROJECT_ROOT, "pba_notifications.log")
PBA_SCAN_INTERVAL = 5

# ---------------------------------------------------------------------------
# Syslog Monitoring
# ---------------------------------------------------------------------------
SYSLOG_FILES = ["/var/log/syslog", "/var/log/auth.log"]
SYSLOG_PATTERNS = {
    "Failed SSH Login": r"Failed password for (invalid user )?\S+ from \S+ port \d+",
    "Successful Root Login": r"session opened for user root",
    "Privilege Escalation": r"(sudo:|su:|pam_unix\(sudo:session\)): session",
    "User Added or Deleted": r"useradd|userdel",
    "Service Restarted": r"systemd.*(restarting|failed|stopped)",
    "Unauthorized File Access": r"avc:  denied",
}
SYSLOG_LOG_FILE = os.path.join(PROJECT_ROOT, "syslog_alerts.log")

# ---------------------------------------------------------------------------
# Network Traffic Monitoring (new 4th module)
# ---------------------------------------------------------------------------
NETWORK_INTERFACE = os.environ.get("HYPERION_NET_IFACE")  # None -> scapy default
NETWORK_LOG_FILE = os.path.join(PROJECT_ROOT, "network_notifications.log")
# Port-scan heuristic: N distinct destination ports from one source within window
NETWORK_PORT_SCAN_THRESHOLD = 15
NETWORK_PORT_SCAN_WINDOW = 10  # seconds
# SYN-flood heuristic: N SYN packets from one source within window
NETWORK_SYN_FLOOD_THRESHOLD = 100
NETWORK_SYN_FLOOD_WINDOW = 5  # seconds
# ICMP flood heuristic: N ICMP echo requests from one source within window
NETWORK_ICMP_FLOOD_THRESHOLD = 50
NETWORK_ICMP_FLOOD_WINDOW = 5  # seconds
NETWORK_WATCHED_PORTS = {
    23: "Telnet (unencrypted, commonly exploited)",
    21: "FTP (unencrypted)",
    3389: "RDP",
    445: "SMB",
    135: "MSRPC",
}
