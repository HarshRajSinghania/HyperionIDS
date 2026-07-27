import os
import time
import re
import threading

import config
from common import AlertManager

print(
    """
 __    __                                          __                      ______  _______    ______  
|  \\  |  \\                                        |  \\                    |      \\|       \\  /      \\ 
| $$  | $$ __    __   ______    ______    ______   \\$$  ______   _______   \\$$$$$$| $$$$$$$\\|  $$$$$$\\
| $$__| $$|  \\  |  \\ /      \\  /      \\  /      \\ |  \\ /      \\ |       \\   | $$  | $$  | $$| $$___\\$$
| $$    $$| $$  | $$|  $$$$$$\\|  $$$$$$\\|  $$$$$$\\| $$|  $$$$$$\\| $$$$$$$\\  | $$  | $$  | $$ \\$$    \\ 
| $$$$$$$$| $$  | $$| $$  | $$| $$    $$| $$   \\$$| $$| $$  | $$| $$  | $$  | $$  | $$  | $$ _\\$$$$$$\\
| $$  | $$| $$__/ $$| $$__/ $$| $$$$$$$$| $$      | $$| $$__/ $$| $$  | $$ _| $$_ | $$__/ $$|  \\__| $$
| $$  | $$ \\$$    $$| $$    $$ \\$$     \\| $$      | $$ \\$$    $$| $$  | $$|   $$ \\| $$    $$ \\$$    $$
 \\$$   \\$$ _\\$$$$$$$| $$$$$$$   \\$$$$$$$ \\$$       \\$$  \\$$$$$$  \\$$   \\$$ \\$$$$$$ \\$$$$$$$   \\$$$$$$ 
          |  \\__| $$| $$                                                                              
           \\$$    $$| $$                                                                              
            \\$$$$$$  \\$$                                                                              

===================================================> System Logs Analysis
Made by: Harsh Raj Singhania 
Github: https://github.com/HarshRajSinghania
"""
)

# Pulls a source IP out of a matched line when present, so repeated hits
# from *different* sources (e.g. two hosts both brute-forcing SSH) are
# tracked -- and alerted on -- separately, while repeats from the *same*
# source get deduplicated instead of spamming one notification per line.
_IP_PATTERN = re.compile(r"\bfrom (\d{1,3}(?:\.\d{1,3}){3})\b")


class SyslogMonitor:
    def __init__(self, log_files, log_alerts_file,
                 patterns=None, alert_manager=None):
        self.log_files = log_files
        self.patterns = patterns or config.SYSLOG_PATTERNS

        self.alerts = alert_manager or AlertManager(
            log_file=log_alerts_file, app_name="Syslog Monitor",
            title="Syslog Monitoring Alert",
        )

    def monitor_logs(self, log_file):
        """Continuously monitor a log file for suspicious activity."""
        try:
            with open(log_file, "r") as f:
                f.seek(0, os.SEEK_END)  # Move to end of file
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(1)
                        continue

                    for alert_name, pattern in self.patterns.items():
                        if re.search(pattern, line):
                            ip_match = _IP_PATTERN.search(line)
                            key_suffix = ip_match.group(1) if ip_match else log_file
                            self.alerts.raise_alert(
                                f"{alert_name}:{key_suffix}",
                                f"[ALERT] {alert_name}: {line.strip()}",
                            )

        except FileNotFoundError:
            self.alerts.info(f"[ERROR] Log file not found: {log_file}")
        except PermissionError:
            self.alerts.info(
                f"[ERROR] Permission denied reading {log_file} "
                f"(syslog monitoring typically needs to run as root)."
            )

    def run(self):
        """Run the Syslog Monitoring module in separate threads."""
        self.alerts.info("[INFO] Syslog Monitoring module is running...")
        for log_file in self.log_files:
            thread = threading.Thread(target=self.monitor_logs, args=(log_file,), daemon=True)
            thread.start()


# Main Execution
if __name__ == "__main__":
    syslog_monitor = SyslogMonitor(config.SYSLOG_FILES, config.SYSLOG_LOG_FILE)
    syslog_monitor.run()

    print("Syslog Monitoring is running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped.")
