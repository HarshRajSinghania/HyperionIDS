import psutil
import time
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

===================================================> Process Behaviour Analysis
Made by: Harsh Raj Singhania 
Github: https://github.com/HarshRajSinghania
"""
)

# Configuration
CPU_THRESHOLD = 80  # Percentage
MEMORY_THRESHOLD = 80  # Percentage
RESTRICTED_FILES = ["/etc/shadow", "/etc/passwd", "/var/log/auth.log", "/etc/hosts"]  # Critical Linux files
LOG_FILE = "pba_notifications.log"

# Suspicious parent-child relationships (Linux)
SUSPICIOUS_RELATIONSHIPS = [
    {"parent": "bash", "child": "nc"},  # bash -> netcat (common in reverse shells)
    {"parent": "ssh", "child": "bash"},  # ssh -> bash (can indicate unauthorized activity)
    {"parent": "python3", "child": "bash"}  # python -> bash (unusual process chain)
]

# Exception list for common system processes in Kali Linux
EXCLUDED_PROCESSES = [
    "kworker", "kthreadd", "systemd", "rcu_tasks_kthread", "systemd-journald",
    "systemd-udevd", "dbus-daemon", "lightdm", "Xorg", "NetworkManager",
    "accounts-daemon", "wpa_supplicant", "cron", "gvfsd", "gvfsd-fuse",
    "modemmanager", "udisksd", "upowerd", "irq", "ksmd", "kcompactd0",
    "rcu_sched", "rcu_preempt", "rcu_bh", "ksoftirqd", "migration",
    "idle_inject", "cpuhp", "irqbalance", "snapd", "smartd", "pool_workqueue_release", "rcu_tasks_rude_kthread", "rcu_tasks_trace_kthread", "rcu_exp_par_gp_kthread_worker", "rcu_exp_gp_kthread_worker", "kdevtmpfs", "kauditd", "khungtaskd", "oom_reaper", "khugepaged", "kswapd0", "scsi_eh_0", "scsi_eh_1", "spi0", "scsi_eh_2", "usb-storage", "scsi_eh_3", "card0-crtc0", "card0-crtc1", "card0-crtc2", "jbd2/sda6-8", "psimon", "watchdogd", "hwrng", "haveged", "ModemManager", "agetty", "psimon", "openvpn", "xfconfd", "dbus-launch", "xfce4-notifyd"
]

# Suspicious directories for process execution
SUSPICIOUS_DIRECTORIES = ["/tmp", "/var/tmp"]


class PBAModule:
    def __init__(self, log_file, cpu_threshold=80, memory_threshold=80):
        self.log_file = log_file
        self.cpu_threshold = cpu_threshold
        self.memory_threshold = memory_threshold

    def log_event(self, event):
        """Log events to a file and display system notifications."""
        with open(self.log_file, "a") as log:
            log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {event}\n")
        print(event)
        self.send_notification(event)

    def send_notification(self, message):
        """Display a system notification."""
        notification.notify(
            title="Process Behavior Analysis Alert",
            message=message,
            app_name="PBA System",
            timeout=5
        )

    def is_excluded_process(self, process_name):
        """Check if a process is in the exclusion list."""
        for excluded in EXCLUDED_PROCESSES:
            if process_name.startswith(excluded):
                return True
        return False

    def monitor_processes(self):
        """Monitor active processes for suspicious behavior."""
        self.log_event("[INFO] Starting Process Behavior Analysis...")
        while True:
            for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'exe', 'ppid', 'uids']):
                try:
                    process_name = process.info['name']

                    # Skip excluded processes
                    if self.is_excluded_process(process_name):
                        continue

                    # Monitor high CPU or memory usage
                    if process.info['cpu_percent'] > self.cpu_threshold:
                        self.log_event(f"[ALERT] High CPU usage: {process_name} (PID: {process.info['pid']}), CPU: {process.info['cpu_percent']}%")
                    if process.info['memory_percent'] > self.memory_threshold:
                        self.log_event(f"[ALERT] High Memory usage: {process_name} (PID: {process.info['pid']}), Memory: {process.info['memory_percent']}%")

                    # Monitor access to restricted files
                    if process.info['exe'] and any(restricted_file in process.info['exe'] for restricted_file in RESTRICTED_FILES):
                        self.log_event(f"[ALERT] Restricted file accessed by {process_name} (PID: {process.info['pid']})")

                    # Detect unusual parent-child relationships
                    parent_process = psutil.Process(process.info['ppid']).name() if psutil.pid_exists(process.info['ppid']) else None
                    for rule in SUSPICIOUS_RELATIONSHIPS:
                        if parent_process == rule["parent"] and process_name == rule["child"]:
                            self.log_event(f"[ALERT] Suspicious parent-child relationship: {parent_process} -> {process_name} (PID: {process.info['pid']})")

                    # Detect processes running from suspicious directories
                    if process.info['exe'] and any(process.info['exe'].startswith(dir) for dir in SUSPICIOUS_DIRECTORIES):
                        self.log_event(f"[ALERT] Suspicious directory execution: {process.info['exe']} (PID: {process.info['pid']})")

                    # Detect processes running as root (UID=0) that are not typical system processes
                    if process.info['uids'] and process.info['uids'].real == 0:
                        self.log_event(f"[ALERT] Suspicious process running as root: {process_name} (PID: {process.info['pid']})")

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            time.sleep(5)  # Adjust the monitoring interval

    def run(self):
        """Run the PBA module."""
        monitor_thread = threading.Thread(target=self.monitor_processes, daemon=True)
        monitor_thread.start()
        self.log_event("[INFO] PBA module is running in the background.")


# Main Execution
if __name__ == "__main__":
    pba = PBAModule(
        log_file=LOG_FILE,
        cpu_threshold=CPU_THRESHOLD,
        memory_threshold=MEMORY_THRESHOLD
    )
    pba.run()

    print("Process Behavior Analysis is running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped.")
