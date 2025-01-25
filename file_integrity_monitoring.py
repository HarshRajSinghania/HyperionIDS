import os
import hashlib
import json
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

===================================================> File Intergrity Monitoring
Made by: Harsh Raj Singhania 
Github: https://github.com/HarshRajSinghania
"""
)

# Configuration
MONITORED_PATHS = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/boot", "/tmp", "/root", "/srv"]  # Replace with actual paths
EXCLUDE_FILES = [".DS_Store", "Thumbs.db", "/root/.dbus/session-bus/7817bd73d9b94d65a33bb5a802eee272-0", "/etc/mtab"]  # Add exclusions
HASH_ALGORITHM = "sha256"  # Options: md5, sha1, sha256, sha512
BASELINE_FILE = "fim_baseline.json"
LOG_FILE = "fim_notifications.log"

# FIM Module
class FIMModule:
    def __init__(self, monitored_paths, baseline_file, log_file, exclude_files=None, hash_algorithm="sha256"):
        self.monitored_paths = monitored_paths
        self.baseline_file = baseline_file
        self.log_file = log_file
        self.exclude_files = exclude_files or []
        self.hash_algorithm = hash_algorithm
        self.baseline = {}

    def compute_hash(self, filepath):
        """Compute the hash of a file."""
        hash_func = getattr(hashlib, self.hash_algorithm)()
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                hash_func.update(chunk)
        return hash_func.hexdigest()

    def generate_baseline(self):
        """Generate a baseline of monitored files."""
        baseline = {}
        for path in self.monitored_paths:
            for root, _, files in os.walk(path):
                for file in files:
                    if file in self.exclude_files:
                        continue
                    full_path = os.path.join(root, file)
                    try:
                        file_hash = self.compute_hash(full_path)
                        file_timestamp = os.path.getmtime(full_path)
                        baseline[full_path] = {
                            "hash": file_hash,
                            "timestamp": file_timestamp
                        }
                    except Exception as e:
                        self.log_event(f"[ERROR] Error processing {full_path}: {e}")
        with open(self.baseline_file, "w") as f:
            json.dump(baseline, f, indent=4)
        self.log_event("[INFO] Baseline generated successfully.")
        self.baseline = baseline

    def load_baseline(self):
        """Load the baseline file."""
        if not os.path.exists(self.baseline_file):
            self.log_event("[INFO] Baseline file not found. Generating a new baseline.")
            self.generate_baseline()
        else:
            with open(self.baseline_file, "r") as f:
                self.baseline = json.load(f)
            self.log_event("[INFO] Baseline loaded successfully.")

    def log_event(self, event):
        """Log events to a file and display system notifications."""
        with open(self.log_file, "a") as log:
            log.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {event}\n")
        print(event)
        self.send_notification(event)

    def send_notification(self, message):
        """Display a system notification."""
        notification.notify(
            title="File Integrity Monitoring Alert",
            message=message,
            app_name="FIM System",
            timeout=5
        )

    def monitor_files(self):
        """Monitor files for changes."""
        if not self.baseline:
            self.load_baseline()

        self.log_event("[INFO] Starting file monitoring...")
        while True:
            for file, data in self.baseline.items():
                try:
                    if not os.path.exists(file):
                        self.log_event(f"[ALERT] File deleted: {file}")
                        continue

                    current_hash = self.compute_hash(file)
                    current_timestamp = os.path.getmtime(file)

                    if current_hash != data["hash"]:
                        self.log_event(f"[ALERT] File modified: {file}")

                    if current_timestamp != data["timestamp"]:
                        self.log_event(f"[INFO] File timestamp changed: {file}")

                except Exception as e:
                    self.log_event(f"[ERROR] Error processing {file}: {e}")

            time.sleep(10)  # Adjust monitoring interval

    def run(self):
        """Run the FIM module."""
        monitor_thread = threading.Thread(target=self.monitor_files, daemon=True)
        monitor_thread.start()
        self.log_event("[INFO] FIM module is running in the background.")


# Main Execution
if __name__ == "__main__":
    fim = FIMModule(
        monitored_paths=MONITORED_PATHS,
        baseline_file=BASELINE_FILE,
        log_file=LOG_FILE,
        exclude_files=EXCLUDE_FILES,
        hash_algorithm=HASH_ALGORITHM
    )
    fim.run()

    print("File Integrity Monitoring is running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped.")

