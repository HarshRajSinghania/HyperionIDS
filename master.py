import threading
import time

import config
from file_integrity_monitoring import FIMModule
from process_behaviour_analysis import PBAModule
from syslog_monitoring import SyslogMonitor
from network_traffic_monitoring import NetworkModule

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

===================================================> Master Script
Made by: Harsh Raj Singhania 
Github: https://github.com/HarshRajSinghania
"""
)


def run_fim():
    """Start the File Integrity Monitoring module."""
    fim = FIMModule(
        monitored_paths=config.FIM_MONITORED_PATHS,
        baseline_file=config.FIM_BASELINE_FILE,
        log_file=config.FIM_LOG_FILE,
        exclude_files=config.FIM_EXCLUDE_FILES,
        hash_algorithm=config.FIM_HASH_ALGORITHM,
    )
    fim.run()


def run_pba():
    """Start the Process Behavior Analysis module."""
    pba = PBAModule(
        log_file=config.PBA_LOG_FILE,
        cpu_threshold=config.PBA_CPU_THRESHOLD,
        memory_threshold=config.PBA_MEMORY_THRESHOLD,
    )
    pba.run()


def run_syslog():
    """Start the Syslog Monitoring module."""
    syslog_monitor = SyslogMonitor(
        log_files=config.SYSLOG_FILES,
        log_alerts_file=config.SYSLOG_LOG_FILE,
    )
    syslog_monitor.run()


def run_network():
    """Start the Network Traffic Monitoring module."""
    net = NetworkModule(
        log_file=config.NETWORK_LOG_FILE,
        interface=config.NETWORK_INTERFACE,
    )
    net.run()


if __name__ == "__main__":
    print("[INFO] Starting Security Monitoring System...")

    # Each run_* function spins up its module's own daemon thread(s), so
    # these outer threads just need to get each module started.
    fim_thread = threading.Thread(target=run_fim, daemon=True)
    pba_thread = threading.Thread(target=run_pba, daemon=True)
    syslog_thread = threading.Thread(target=run_syslog, daemon=True)
    network_thread = threading.Thread(target=run_network, daemon=True)

    fim_thread.start()
    pba_thread.start()
    syslog_thread.start()
    network_thread.start()

    print("[INFO] All 4 modules are running. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Security Monitoring System stopped.")
