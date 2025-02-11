import os
import time
import re
import threading
from plyer import notification

print(
    """
 __    __                                          __                      ______  _______    ______  
|  \  |  \                                        |  \                    |      \|       \  /      \ 
| $$  | $$ __    __   ______    ______    ______   \$$  ______   _______   \$$$$$$| $$$$$$$\|  $$$$$$\
| $$__| $$|  \  |  \ /      \  /      \  /      \ |  \ /      \ |       \   | $$  | $$  | $$| $$___\$$
| $$    $$| $$  | $$|  $$$$$$\|  $$$$$$\|  $$$$$$\| $$|  $$$$$$\| $$$$$$$\  | $$  | $$  | $$ \$$    \ 
| $$$$$$$$| $$  | $$| $$  | $$| $$    $$| $$   \$$| $$| $$  | $$| $$  | $$  | $$  | $$  | $$ _\$$$$$$\
| $$  | $$| $$__/ $$| $$__/ $$| $$$$$$$$| $$      | $$| $$__/ $$| $$  | $$ _| $$_ | $$__/ $$|  \__| $$
| $$  | $$ \$$    $$| $$    $$ \$$     \| $$      | $$ \$$    $$| $$  | $$|   $$ \| $$    $$ \$$    $$
 \$$   \$$ _\$$$$$$$| $$$$$$$   \$$$$$$$ \$$       \$$  \$$$$$$  \$$   \$$ \$$$$$$ \$$$$$$$   \$$$$$$ 
          |  \__| $$| $$                                                                              
           \$$    $$| $$                                                                              
            \$$$$$$  \$$                                                                              

===================================================> System Logs Analysis
Made by: Harsh Raj Singhania 
Github: https://github.com/HarshRajSinghania
"""
)

# Configuration
LOG_FILES = ["/var/log/syslog", "/var/log/auth.log"]  # Logs to monitor
LOG_ALERTS_FILE = "syslog_alerts.log"

# Patterns for suspicious activity
SUSPICIOUS_PATTERNS = {
    "Failed SSH Login": r"Failed password for (invalid user )?\S+ from \S+ port \d+",
    "Successful Root Login": r"session opened for user root",
    "Privilege Escalation": r"(sudo:|su:|pam_unix\(sudo:session\)): session",
    "User Added or Deleted": r"useradd|userdel",
    "Service Restarted": r"systemd.*(restarting|failed|stopped)",
    "Unauthorized File Access": r"avc:  denied"
}

class SyslogMonitor:
    def __init__(self, log_files, log_alerts_file):
        self.log_files = log_files
        self.log_alerts_file = log_alerts_file

    def log_event(self, event):
        """Log detected events to a file and send a system notification."""
        with open(self.log_alerts_file, "a") as log:
            log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {event}\n")
        print(event)
        self.send_notification(event)

    def send_notification(self, message):
        """Display a system notification."""
        notification.notify(
            title="Syslog Monitoring Alert",
            message=message,
            app_name="Syslog Monitor",
            timeout=5
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
                    
                    for alert_name, pattern in SUSPICIOUS_PATTERNS.items():
                        if re.search(pattern, line):
                            self.log_event(f"[ALERT] {alert_name}: {line.strip()}")

        except FileNotFoundError:
            print(f"[ERROR] Log file not found: {log_file}")

    def run(self):
        """Run the Syslog Monitoring module in separate threads."""
        self.log_event("[INFO] Syslog Monitoring module is running...")
        for log_file in self.log_files:
            thread = threading.Thread(target=self.monitor_logs, args=(log_file,), daemon=True)
            thread.start()


# Main Execution
if __name__ == "__main__":
    syslog_monitor = SyslogMonitor(LOG_FILES, LOG_ALERTS_FILE)
    syslog_monitor.run()

    print("Syslog Monitoring is running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped.")
