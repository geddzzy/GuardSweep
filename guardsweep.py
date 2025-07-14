from jsonargparse import ArgumentParser, ActionConfigFile
import psutil
import time
import os
import sys
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
from datetime import datetime

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
def monitor_processes():
    """
    Monitor for new processes starting on the system.
    Alerts when a new process PID is detected.
    """
    known_pids = set(psutil.pids())
    while True:
        current_pids = set(psutil.pids())
        new_pids = current_pids - known_pids
        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                alert(f"New process started: {proc.name()} (PID {pid})")
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
    # Set up logging to a file with timestamp and severity formatting
    parser = ArgumentParser(
        description="GuardSweep - Cross-platform EDR tool",
        default_config_files=["config.yaml"],
    )
    # Allow specifying config file (YAML/JSON) from CLI
    parser.add_argument(
        "--config",
        action=ActionConfigFile,
        help="Path to config YAML/JSON file",
    )
    # Define command-line arguments that override config file values
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
        "--log_file", default=None, help="Log file path (overrides config file)"
    )

    # Parse args from CLI or config file
    args = parser.parse_args()

    # Fallback default values if not provided by user
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

    # Initialize logging and notify user
    setup_logging(log_file)
    alert(f"GuardSweep started. Monitoring directory: {monitor_dir}", severity="INFO")

    # Start file monitoring in a separate thread
    observer = start_file_monitor(monitor_dir, ignored_paths, suspicious_extensions)
    file_thread = threading.Thread(target=observer.join, daemon=True)
    file_thread.start()

    # Start process monitoring in a separate thread
    proc_thread = threading.Thread(target=monitor_processes, daemon=True)
    proc_thread.start()

    # Start network monitoring in a separate thread
    net_thread = threading.Thread(
        target=monitor_network, args=(blacklisted_ips,), daemon=True
    )
    net_thread.start()

    # Keep main thread alive; clean exit on Ctrl+C
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        alert("GuardSweep stopped.", severity="INFO")
        sys.exit(0)

# Entry point to run the GuardSweep EDR
if __name__ == "__main__":
    main()
