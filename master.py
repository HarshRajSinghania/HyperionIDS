import threading
import time
from fim_module import FIMModule  # Import File Integrity Monitoring
from pba_module import PBAModule  # Import Process Behavior Analysis
from syslog_module import SyslogMonitor  # Import Syslog Monitoring

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

===================================================> Master Script
Made by: Harsh Raj Singhania 
Github: https://github.com/HarshRajSinghania
"""
)

# Configuration
SECURITY_LOG_FILE = "security_monitor.log"

# Define monitored paths for FIM
MONITORED_PATHS = ["/etc", "/var/www/html"]
FIM_BASELINE_FILE = "fim_baseline.json"

# Define process monitoring parameters
CPU_THRESHOLD = 80  # High CPU usage alert threshold
MEMORY_THRESHOLD = 80  # High memory usage alert threshold

# Define syslog files to monitor
SYSLOG_FILES = ["/var/log/syslog", "/var/log/auth.log"]


def run_fim():
    """Start the File Integrity Monitoring module."""
    fim = FIMModule(
        monitored_paths=MONITORED_PATHS,
        baseline_file=FIM_BASELINE_FILE,
        log_file=SECURITY_LOG_FILE
    )
    fim.run()


def run_pba():
    """Start the Process Behavior Analysis module."""
    pba = PBAModule(
        log_file=SECURITY_LOG_FILE,
        cpu_threshold=CPU_THRESHOLD,
        memory_threshold=MEMORY_THRESHOLD
    )
    pba.run()


def run_syslog():
    """Start the Syslog Monitoring module."""
    syslog_monitor = SyslogMonitor(
        log_files=SYSLOG_FILES,
        log_alerts_file=SECURITY_LOG_FILE
    )
    syslog_monitor.run()


if __name__ == "__main__":
    print("[INFO] Starting Security Monitoring System...")

    # Start modules in separate threads
    fim_thread = threading.Thread(target=run_fim, daemon=True)
    pba_thread = threading.Thread(target=run_pba, daemon=True)
    syslog_thread = threading.Thread(target=run_syslog, daemon=True)

    fim_thread.start()
    pba_thread.start()
    syslog_thread.start()

    print("[INFO] All modules are running. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Security Monitoring System stopped.")
