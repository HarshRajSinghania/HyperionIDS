import psutil
import time
import threading

import config
from common import AlertManager, is_hyperion_process

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

===================================================> Process Behaviour Analysis
Made by: Harsh Raj Singhania 
Github: https://github.com/HarshRajSinghania
"""
)


class PBAModule:
    def __init__(self, log_file,
                 cpu_threshold=config.PBA_CPU_THRESHOLD,
                 memory_threshold=config.PBA_MEMORY_THRESHOLD,
                 scan_interval=config.PBA_SCAN_INTERVAL,
                 alert_manager=None):
        self.log_file = log_file
        self.cpu_threshold = cpu_threshold
        self.memory_threshold = memory_threshold
        self.scan_interval = scan_interval

        self.alerts = alert_manager or AlertManager(
            log_file=log_file, app_name="PBA System",
            title="Process Behavior Analysis Alert",
        )

    def is_excluded_process(self, process_name):
        """Check if a process is in the exclusion list."""
        for excluded in config.PBA_EXCLUDED_PROCESSES:
            if process_name.startswith(excluded):
                return True
        return False

    def _is_suspicious_root_process(self, process, process_name):
        """A process running as root is normal (most of the OS does). What
        is actually worth an alert is a root process running from outside
        the standard system binary directories -- e.g. something dropped
        in /tmp or a user's home dir and executed as root. This replaces
        the previous blanket 'UID == 0' check, which flagged literally
        every root process on the box, including HyperionIDS's own
        modules and each other."""
        exe = process.info.get("exe")
        if not exe:
            return False
        if any(exe.startswith(trusted) for trusted in config.PBA_TRUSTED_ROOT_DIRECTORIES):
            return False
        return True

    def monitor_processes(self):
        """Monitor active processes for suspicious behavior."""
        self.alerts.info("[INFO] Starting Process Behavior Analysis...")

        # Prime psutil's internal CPU-percent tracking. Without a first,
        # throwaway call, cpu_percent() has nothing to compare against and
        # every process reports 0.0% on the first real reading.
        for process in psutil.process_iter():
            try:
                process.cpu_percent(interval=None)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        while True:
            for process in psutil.process_iter(
                ['pid', 'name', 'memory_percent', 'exe', 'ppid', 'uids']
            ):
                try:
                    process_name = process.info['name']
                    pid = process.info['pid']

                    if self.is_excluded_process(process_name):
                        continue

                    # Never let HyperionIDS's own modules -- or each other
                    # -- get flagged as malicious.
                    if is_hyperion_process(process):
                        continue

                    cpu_percent = process.cpu_percent(interval=None)
                    if cpu_percent > self.cpu_threshold:
                        self.alerts.raise_alert(
                            f"cpu:{pid}",
                            f"[ALERT] High CPU usage: {process_name} (PID: {pid}), CPU: {cpu_percent}%",
                        )
                    if process.info['memory_percent'] and process.info['memory_percent'] > self.memory_threshold:
                        self.alerts.raise_alert(
                            f"mem:{pid}",
                            f"[ALERT] High Memory usage: {process_name} (PID: {pid}), Memory: {process.info['memory_percent']:.1f}%",
                        )

                    if process.info['exe'] and any(
                        restricted_file in process.info['exe'] for restricted_file in config.PBA_RESTRICTED_FILES
                    ):
                        self.alerts.raise_alert(
                            f"restricted:{pid}",
                            f"[ALERT] Restricted file accessed by {process_name} (PID: {pid})",
                        )

                    parent_process = (
                        psutil.Process(process.info['ppid']).name()
                        if process.info['ppid'] and psutil.pid_exists(process.info['ppid'])
                        else None
                    )
                    for rule in config.PBA_SUSPICIOUS_RELATIONSHIPS:
                        if parent_process == rule["parent"] and process_name == rule["child"]:
                            self.alerts.raise_alert(
                                f"relationship:{pid}",
                                f"[ALERT] Suspicious parent-child relationship: {parent_process} -> {process_name} (PID: {pid})",
                            )

                    if process.info['exe'] and any(
                        process.info['exe'].startswith(d) for d in config.PBA_SUSPICIOUS_DIRECTORIES
                    ):
                        self.alerts.raise_alert(
                            f"suspdir:{pid}",
                            f"[ALERT] Suspicious directory execution: {process.info['exe']} (PID: {pid})",
                        )

                    if process.info['uids'] and process.info['uids'].real == 0:
                        if self._is_suspicious_root_process(process, process_name):
                            self.alerts.raise_alert(
                                f"root:{pid}",
                                f"[ALERT] Suspicious process running as root from non-standard path: "
                                f"{process_name} (PID: {pid}, exe: {process.info['exe']})",
                            )

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            time.sleep(self.scan_interval)

    def run(self):
        """Run the PBA module."""
        monitor_thread = threading.Thread(target=self.monitor_processes, daemon=True)
        monitor_thread.start()
        self.alerts.info("[INFO] PBA module is running in the background.")


# Main Execution
if __name__ == "__main__":
    pba = PBAModule(
        log_file=config.PBA_LOG_FILE,
        cpu_threshold=config.PBA_CPU_THRESHOLD,
        memory_threshold=config.PBA_MEMORY_THRESHOLD,
    )
    pba.run()

    print("Process Behavior Analysis is running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped.")
