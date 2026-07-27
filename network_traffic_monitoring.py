import threading
import time
from collections import defaultdict, deque

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

===================================================> Network Traffic Monitoring
Made by: Harsh Raj Singhania 
Github: https://github.com/HarshRajSinghania
"""
)


class _SlidingWindowCounter:
    """Tracks distinct-or-total events per key over a rolling time window."""

    def __init__(self, window_seconds):
        self.window_seconds = window_seconds
        self._events = defaultdict(deque)
        self._lock = threading.Lock()

    def add(self, key, value=None):
        """Record an event for `key` (optionally tagged with `value`, e.g.
        a destination port, so callers can count distinct values). Returns
        (count, distinct_values) for events still inside the window."""
        now = time.time()
        with self._lock:
            dq = self._events[key]
            dq.append((now, value))
            cutoff = now - self.window_seconds
            while dq and dq[0][0] < cutoff:
                dq.popleft()
            count = len(dq)
            distinct = {v for _, v in dq if v is not None}
            return count, distinct


class NetworkModule:
    """Sniffs live traffic and flags port scans, SYN/ICMP floods, and
    connections to historically risky ports (telnet, ftp, rdp, smb...).

    Requires the `scapy` package and raw-socket capability (root, or
    CAP_NET_RAW/CAP_NET_ADMIN on the interpreter). If scapy isn't
    installed or sniffing can't be started (no permission, no interface),
    the module logs a clear error and exits its thread instead of
    crashing the whole IDS.
    """

    def __init__(self, log_file, interface=config.NETWORK_INTERFACE,
                 alert_manager=None):
        self.log_file = log_file
        self.interface = interface

        self.alerts = alert_manager or AlertManager(
            log_file=log_file, app_name="Network Monitor",
            title="Network Traffic Monitoring Alert",
        )

        self._port_scan_tracker = _SlidingWindowCounter(config.NETWORK_PORT_SCAN_WINDOW)
        self._syn_tracker = _SlidingWindowCounter(config.NETWORK_SYN_FLOOD_WINDOW)
        self._icmp_tracker = _SlidingWindowCounter(config.NETWORK_ICMP_FLOOD_WINDOW)

    def _handle_packet(self, packet):
        try:
            from scapy.layers.inet import IP, TCP, ICMP
        except ImportError:
            return

        if not packet.haslayer(IP):
            return

        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            dport = tcp.dport
            flags = tcp.flags

            # Port scan heuristic: many distinct destination ports hit by
            # the same source in a short window.
            count, distinct_ports = self._port_scan_tracker.add(src, dport)
            if len(distinct_ports) >= config.NETWORK_PORT_SCAN_THRESHOLD:
                self.alerts.raise_alert(
                    f"portscan:{src}",
                    f"[ALERT] Possible port scan from {src}: "
                    f"{len(distinct_ports)} distinct ports hit on {dst} "
                    f"within {config.NETWORK_PORT_SCAN_WINDOW}s",
                )

            # SYN flood heuristic: SYN set, ACK not set.
            if flags & 0x02 and not flags & 0x10:
                syn_count, _ = self._syn_tracker.add(src)
                if syn_count >= config.NETWORK_SYN_FLOOD_THRESHOLD:
                    self.alerts.raise_alert(
                        f"synflood:{src}",
                        f"[ALERT] Possible SYN flood from {src}: "
                        f"{syn_count} SYN packets within {config.NETWORK_SYN_FLOOD_WINDOW}s",
                    )

            if dport in config.NETWORK_WATCHED_PORTS:
                self.alerts.raise_alert(
                    f"watchedport:{src}:{dport}",
                    f"[ALERT] Connection to sensitive port {dport} "
                    f"({config.NETWORK_WATCHED_PORTS[dport]}) from {src} to {dst}",
                )

        elif packet.haslayer(ICMP) and packet[ICMP].type == 8:  # echo-request
            icmp_count, _ = self._icmp_tracker.add(src)
            if icmp_count >= config.NETWORK_ICMP_FLOOD_THRESHOLD:
                self.alerts.raise_alert(
                    f"icmpflood:{src}",
                    f"[ALERT] Possible ICMP flood from {src}: "
                    f"{icmp_count} echo requests within {config.NETWORK_ICMP_FLOOD_WINDOW}s",
                )

    def sniff_traffic(self):
        try:
            from scapy.all import sniff
        except ImportError:
            self.alerts.info(
                "[ERROR] scapy is not installed. Install it with "
                "'pip install scapy' to enable network traffic monitoring."
            )
            return

        self.alerts.info(
            f"[INFO] Starting network traffic monitoring"
            f"{f' on {self.interface}' if self.interface else ''}..."
        )

        # sniff() can fail right at startup if the interface exists but
        # isn't fully up yet (e.g. wifi still associating -- DORMANT, not
        # LOWER_UP -- at the exact moment this thread starts), or drop out
        # later if the link bounces. Without a retry loop, one ENETDOWN
        # permanently ends this thread with no further error and the
        # module goes dark for the rest of the run. Retry with backoff
        # instead, and surface (deduplicated, via AlertManager) that it's
        # still down rather than failing silently.
        backoff = 1
        max_backoff = 30
        while True:
            try:
                sniff(iface=self.interface, prn=self._handle_packet, store=False)
                # sniff() only returns if the capture loop itself ends
                # (e.g. socket closed underneath us) -- that's not an
                # expected outcome for an unbounded capture, so treat it
                # the same as a failure and retry.
                self.alerts.raise_alert(
                    "network_capture_stopped",
                    "[WARN] Packet capture stopped unexpectedly; restarting...",
                    notify=False,
                )
            except PermissionError:
                self.alerts.info(
                    "[ERROR] Permission denied opening a raw socket. Network "
                    "traffic monitoring needs to run as root (or with "
                    "CAP_NET_RAW/CAP_NET_ADMIN)."
                )
                return  # won't fix itself -- no point retrying
            except OSError as e:
                self.alerts.raise_alert(
                    "network_capture_error",
                    f"[ERROR] Packet capture failed ({e}); retrying in {backoff}s...",
                    notify=False,
                )

            time.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)

    def run(self):
        """Run the Network Monitoring module."""
        sniff_thread = threading.Thread(target=self.sniff_traffic, daemon=True)
        sniff_thread.start()
        self.alerts.info("[INFO] Network module is running in the background.")


# Main Execution
if __name__ == "__main__":
    net = NetworkModule(
        log_file=config.NETWORK_LOG_FILE,
        interface=config.NETWORK_INTERFACE,
    )
    net.run()

    print("Network Traffic Monitoring is running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[INFO] Monitoring stopped.")
