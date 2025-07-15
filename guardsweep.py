from jsonargparse import ArgumentParser, ActionConfigFile
import psutil
import time
import os
import sys
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
from datetime import datetime, timedelta
import collections

# Set up logging to a file with timestamp and severity formatting
def setup_logging(log_file):
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


# Custom alert function that prints and logs messages with severity
def alert(message, severity="ALERT"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted_msg = f"[{timestamp}] [{severity}] {message}"
    print(formatted_msg)
    if severity == "ALERT":
        logging.info(formatted_msg)
    elif severity == "WARNING":
        logging.warning(formatted_msg)
    else:
        logging.info(formatted_msg)


# -------------------------
class FileMonitor(FileSystemEventHandler):
    """
    Custom watchdog event handler to monitor file creation events,
    ignoring noisy paths and filtering by suspicious file extensions.
    """

    def __init__(self, ignored_paths, suspicious_extensions):
        self.ignored_paths = ignored_paths
        self.suspicious_extensions = suspicious_extensions

    def on_created(self, event):
        # Ignore directory creations
        if event.is_directory:
            return
        path_lower = event.src_path.lower()
        # Skip files in ignored paths
        if any(ignored.lower() in path_lower for ignored in self.ignored_paths):
            return
        # Check if file extension matches suspicious list
        _, ext = os.path.splitext(event.src_path)
        if ext.lower() not in self.suspicious_extensions:
            return
        alert(f"Suspicious file created: {event.src_path}")


# -------------------------
def start_file_monitor(monitor_dir, ignored_paths, suspicious_extensions):
    """
    Start watchdog observer to monitor file system events recursively.
    """
    event_handler = FileMonitor(ignored_paths, suspicious_extensions)
    observer = Observer()
    observer.schedule(event_handler, path=monitor_dir, recursive=True)
    observer.start()
    return observer


# -------------------------
def monitor_processes(auto_respond, suspicious_process_names):
    """
    Monitor for new processes starting on the system.
    Alerts when a new process PID is detected.
    Implements behavioral analytic detection of rapid process creation.
    Optionally terminates suspicious processes automatically.
    """
    known_pids = set(psutil.pids())
    process_events = collections.deque(maxlen=100)  # track recent process start times

    while True:
        current_pids = set(psutil.pids())
        new_pids = current_pids - known_pids
        now = datetime.now()

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                alert(f"New process started: {proc_name} (PID {pid})")
                process_events.append(now)

                # Behavioral check: if >10 processes in 10 seconds, alert warning
                recent_events = [t for t in process_events if now - t < timedelta(seconds=10)]
                if len(recent_events) > 10:
                    alert("High process creation rate detected!", severity="WARNING")

                # Automated response: terminate suspicious process(es)
                if auto_respond and proc_name.lower() in suspicious_process_names:
                    proc.terminate()
                    alert(f"Automatically terminated suspicious process PID {pid}", severity="WARNING")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        known_pids = current_pids
        time.sleep(3)


# -------------------------
def monitor_network(blacklisted_ips):
    """
    Monitor network connections and alert on connections to blacklisted IPs.
    """
    while True:
        for conn in psutil.net_connections(kind="inet"):
            if conn.raddr and conn.raddr.ip in blacklisted_ips:
                alert(f"Connection to blacklisted IP: {conn.raddr.ip}")
        time.sleep(10)


# -------------------------
def main():
    parser = ArgumentParser(
        description="GuardSweep - Cross-platform EDR tool",
        default_config_files=["config.yaml"],
    )
    parser.add_argument(
        "--config",
        action=ActionConfigFile,
        help="Path to config YAML/JSON file",
    )
    parser.add_argument(
        "--blacklisted_ips",
        nargs="*",
        default=None,
        help="Blacklisted IP addresses (overrides config file)",
    )
    parser.add_argument(
        "--monitor_dir",
        default=None,
        help="Directory to monitor for file changes (overrides config file)",
    )
    parser.add_argument(
        "--ignored_paths",
        nargs="*",
        default=None,
        help="Paths to ignore for file monitoring (overrides config file)",
    )
    parser.add_argument(
        "--suspicious_extensions",
        nargs="*",
        default=None,
        help="File extensions to alert on (overrides config file)",
    )
    parser.add_argument(
        "--log_file",
        default=None,
        help="Log file path (overrides config file)",
    )
    parser.add_argument(
        "--auto_respond",
        action="store_true",
        help="Automatically respond to suspicious process detections (kill process)",
    )
    parser.add_argument(
        "--suspicious_process_names",
        nargs="*",
        default=None,
        help="List of suspicious process names to auto-terminate (case-insensitive)",
    )

    args = parser.parse_args()

    blacklisted_ips = args.blacklisted_ips or ["1.2.3.4", "8.8.8.8"]
    monitor_dir = args.monitor_dir or os.path.expanduser("~")
    ignored_paths = args.ignored_paths or []
    suspicious_extensions = args.suspicious_extensions or [
        ".exe",
        ".dll",
        ".bat",
        ".ps1",
        ".js",
        ".vbs",
        ".scr",
    ]
    log_file = args.log_file or "guardsweep.log"
    auto_respond = args.auto_respond
    suspicious_process_names = {name.lower() for name in (args.suspicious_process_names or [])}

    setup_logging(log_file)
    alert(f"GuardSweep started. Monitoring directory: {monitor_dir}", severity="INFO")

    observer = start_file_monitor(monitor_dir, ignored_paths, suspicious_extensions)
    file_thread = threading.Thread(target=observer.join, daemon=True)
    file_thread.start()

    proc_thread = threading.Thread(
        target=monitor_processes, args=(auto_respond, suspicious_process_names), daemon=True
    )
    proc_thread.start()

    net_thread = threading.Thread(target=monitor_network, args=(blacklisted_ips,), daemon=True)
    net_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        alert("GuardSweep stopped.", severity="INFO")
        sys.exit(0)


if __name__ == "__main__":
    main()
