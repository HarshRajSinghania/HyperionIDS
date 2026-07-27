"""
Shared utilities for HyperionIDS modules.

This is what fixes the two headline bugs:

1. Modules flagging each other as malicious -- ``is_hyperion_process`` lets
   every module recognize the other three (and itself) by script name so a
   root-owned ``python3`` process running ``process_behaviour_analysis.py``
   never gets reported as a suspicious root process by a sibling module.

2. Notifications spamming continuously -- ``AlertManager`` deduplicates
   alerts by key and only lets an identical alert through once per
   ``cooldown_seconds``. Everything still gets written to the log for audit
   purposes on first occurrence and on a summarized re-occurrence, but the
   desktop notification (and the log write) is throttled.
"""

import os
import threading
import time

try:
    from plyer import notification as _plyer_notification
except Exception:  # pragma: no cover - plyer is an optional runtime dep
    _plyer_notification = None

from config import HYPERION_SCRIPT_NAMES, ALERT_COOLDOWN_SECONDS


def is_hyperion_process(process) -> bool:
    """Return True if a psutil.Process belongs to HyperionIDS itself.

    Matches on the process's command line containing one of our own script
    names, rather than on process name or UID, so this works whether the
    modules are run as threads inside master.py (one shared PID) or as four
    independent ``python3 <script>.py`` processes (four different PIDs, all
    plausibly running as root).
    """
    try:
        cmdline = process.cmdline()
    except Exception:
        return False
    cmdline_str = " ".join(cmdline)
    return any(script in cmdline_str for script in HYPERION_SCRIPT_NAMES)


class AlertManager:
    """Handles logging + desktop notifications with per-key rate limiting."""

    def __init__(self, log_file, app_name, title=None,
                 cooldown_seconds=ALERT_COOLDOWN_SECONDS):
        self.log_file = log_file
        self.app_name = app_name
        self.title = title or app_name
        self.cooldown_seconds = cooldown_seconds
        self._last_seen = {}
        self._suppressed_since = {}
        self._lock = threading.Lock()

    def raise_alert(self, key, message, notify=True):
        """Log/notify for `message`, deduplicated on `key`.

        Returns True if the alert was actually emitted, False if it was
        suppressed because an identical alert already fired within the
        cooldown window.
        """
        now = time.time()
        with self._lock:
            last = self._last_seen.get(key)
            if last is not None and (now - last) < self.cooldown_seconds:
                self._suppressed_since[key] = self._suppressed_since.get(key, 0) + 1
                return False

            suppressed_count = self._suppressed_since.pop(key, 0)
            self._last_seen[key] = now

        if suppressed_count:
            message = f"{message} (+{suppressed_count} repeats suppressed)"

        self._write_log(message)
        print(message)
        if notify:
            self._send_notification(message)
        return True

    def info(self, message):
        """Unthrottled informational log line (startup/shutdown messages)."""
        self._write_log(message)
        print(message)

    def _write_log(self, message):
        try:
            with open(self.log_file, "a") as log:
                log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
        except OSError as e:
            print(f"[ERROR] Could not write to log file {self.log_file}: {e}")

    def _send_notification(self, message):
        if _plyer_notification is None:
            return
        try:
            _plyer_notification.notify(
                title=self.title,
                message=message[:250],
                app_name=self.app_name,
                timeout=5,
            )
        except Exception as e:
            # Headless boxes / missing notification backends shouldn't kill
            # a monitoring thread -- degrade to log-only instead.
            print(f"[WARN] Notification backend unavailable ({self.app_name}): {e}")


def ensure_directory_for(path):
    directory = os.path.dirname(os.path.abspath(path))
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
