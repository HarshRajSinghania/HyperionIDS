import os
import hashlib
import json
import time
import threading

import config
from common import AlertManager, ensure_directory_for

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

===================================================> File Integrity Monitoring
Made by: Harsh Raj Singhania 
Github: https://github.com/HarshRajSinghania
"""
)


class FIMModule:
    def __init__(self, monitored_paths, baseline_file, log_file,
                 exclude_files=None, hash_algorithm="sha256",
                 scan_interval=config.FIM_SCAN_INTERVAL,
                 alert_manager=None):
        self.monitored_paths = monitored_paths
        self.baseline_file = baseline_file
        self.exclude_files = set(exclude_files or [])
        self.hash_algorithm = hash_algorithm
        self.scan_interval = scan_interval
        self.baseline = {}

        # HyperionIDS's own state/log files must never be treated as part
        # of the monitored surface -- otherwise FIM alerts every time a
        # sibling module (or itself) writes a log line, i.e. the modules
        # "flag each other" bug.
        self._own_paths = {
            os.path.abspath(os.path.join(config.PROJECT_ROOT, name))
            for name in config.HYPERION_DATA_FILES
        }
        self._own_paths.add(os.path.abspath(baseline_file))
        self._own_paths.add(os.path.abspath(log_file))

        self.alerts = alert_manager or AlertManager(
            log_file=log_file, app_name="FIM System",
            title="File Integrity Monitoring Alert",
        )

    def _is_excluded(self, full_path, filename):
        """Filenames AND full paths are both honored (the original code
        only ever compared bare filenames against a list that mixed in
        full paths, so entries like '/etc/mtab' never actually matched)."""
        if filename in self.exclude_files:
            return True
        if full_path in self.exclude_files:
            return True
        if os.path.abspath(full_path) in self._own_paths:
            return True
        return False

    def compute_hash(self, filepath):
        """Compute the hash of a file."""
        hash_func = getattr(hashlib, self.hash_algorithm)()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                hash_func.update(chunk)
        return hash_func.hexdigest()

    def generate_baseline(self):
        """Generate a baseline of monitored files."""
        baseline = {}
        for path in self.monitored_paths:
            if not os.path.exists(path):
                continue
            for root, _, files in os.walk(path):
                for file in files:
                    full_path = os.path.join(root, file)
                    if self._is_excluded(full_path, file):
                        continue
                    try:
                        file_hash = self.compute_hash(full_path)
                        file_timestamp = os.path.getmtime(full_path)
                        baseline[full_path] = {
                            "hash": file_hash,
                            "timestamp": file_timestamp,
                        }
                    except (PermissionError, FileNotFoundError, OSError):
                        # Unreadable/vanished files are common (sockets,
                        # permission-restricted files) and not an alert-
                        # worthy event on their own.
                        continue
        ensure_directory_for(self.baseline_file)
        with open(self.baseline_file, "w") as f:
            json.dump(baseline, f, indent=4)
        self.alerts.info(f"[INFO] Baseline generated successfully ({len(baseline)} files tracked).")
        self.baseline = baseline

    def load_baseline(self):
        """Load the baseline file."""
        if not os.path.exists(self.baseline_file):
            self.alerts.info("[INFO] Baseline file not found. Generating a new baseline.")
            self.generate_baseline()
        else:
            with open(self.baseline_file, "r") as f:
                self.baseline = json.load(f)
            self.alerts.info("[INFO] Baseline loaded successfully.")

    def monitor_files(self):
        """Monitor files for changes."""
        if not self.baseline:
            self.load_baseline()

        self.alerts.info("[INFO] Starting file monitoring...")
        while True:
            for file, data in list(self.baseline.items()):
                try:
                    if self._is_excluded(file, os.path.basename(file)):
                        continue

                    if not os.path.exists(file):
                        self.alerts.raise_alert(f"deleted:{file}", f"[ALERT] File deleted: {file}")
                        continue

                    current_hash = self.compute_hash(file)
                    current_timestamp = os.path.getmtime(file)

                    if current_hash != data["hash"]:
                        self.alerts.raise_alert(f"modified:{file}", f"[ALERT] File modified: {file}")
                        # Update baseline so a single change doesn't keep
                        # re-alerting forever once the cooldown expires.
                        data["hash"] = current_hash
                        data["timestamp"] = current_timestamp
                    elif current_timestamp != data["timestamp"]:
                        self.alerts.raise_alert(
                            f"touched:{file}",
                            f"[INFO] File timestamp changed: {file}",
                            notify=False,
                        )
                        data["timestamp"] = current_timestamp

                except (PermissionError, FileNotFoundError, OSError) as e:
                    self.alerts.raise_alert(f"error:{file}", f"[ERROR] Error processing {file}: {e}", notify=False)

            time.sleep(self.scan_interval)

    def run(self):
        """Run the FIM module."""
        monitor_thread = threading.Thread(target=self.monitor_files, daemon=True)
        monitor_thread.start()
        self.alerts.info("[INFO] FIM module is running in the background.")


# Main Execution
if __name__ == "__main__":
    fim = FIMModule(
        monitored_paths=config.FIM_MONITORED_PATHS,
        baseline_file=config.FIM_BASELINE_FILE,
        log_file=config.FIM_LOG_FILE,
        exclude_files=config.FIM_EXCLUDE_FILES,
        hash_algorithm=config.FIM_HASH_ALGORITHM,
    )
    fim.run()

    print("File Integrity Monitoring is running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped.")
