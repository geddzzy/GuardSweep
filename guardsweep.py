import psutil
import time
import os
import sys
import logging
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
from datetime import datetime

# --- Configuration ---
BLACKLISTED_IPS = {"1.2.3.4", "8.8.8.8"}  # Example IPs to flag
MONITOR_DIR = os.path.expanduser("~")  # Directory to watch for new files
LOG_FILE = "guardsweep.log"

# Ignore Paths
IGNORED_PATHS = [
    r"AppData\Roaming\Mozilla\Firefox",
    r"AppData\Local\Temp",
    r"AppData\Roaming\Microsoft\Windows\Recent",
    r"AppData\Local\Mozilla\Firefox",
    r"AppData\Roaming\Code\User\globalStorage",
    # Add more as needed
]

# Suspicious file extensions to alert on
SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".bat", ".ps1", ".js", ".vbs", ".scr"}

# --- Setup logging ---
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


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


# --- File Monitoring Handler ---
class FileMonitor(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        # Ignore files in ignored paths
        if any(ignored in event.src_path for ignored in IGNORED_PATHS):
            return
        # Check if file extension is suspicious
        _, ext = os.path.splitext(event.src_path)
        if ext.lower() not in SUSPICIOUS_EXTENSIONS:
            return
        alert(f"Suspicious file created: {event.src_path}")


def start_file_monitor():
    event_handler = FileMonitor()
    observer = Observer()
    observer.schedule(event_handler, path=MONITOR_DIR, recursive=True)
    observer.start()
    return observer


# --- Process Monitoring Function ---
def monitor_processes():
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
        time.sleep(3)  # Poll every 3 seconds to reduce CPU usage


# --- Network Monitoring Function ---
def monitor_network():
    while True:
        for conn in psutil.net_connections(kind="inet"):
            if conn.raddr and conn.raddr.ip in BLACKLISTED_IPS:
                alert(f"Connection to blacklisted IP: {conn.raddr.ip}")
        time.sleep(10)  # Check every 10 seconds


def main():
    parser = argparse.ArgumentParser(description="GuardSweep - Cross-platform EDR tool")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )
    parser.add_argument(
        "-d",
        "--directory",
        default=os.path.expanduser("~"),
        help="Directory to monitor for file changes (default: user home)",
    )
    parser.add_argument("--version", action="version", version="GuardSweep 1.0")

    args = parser.parse_args()

    # Use args.verbose to control logging verbosity
    if args.verbose:
        alert("Verbose mode enabled", severity="INFO")

    global MONITOR_DIR
    MONITOR_DIR = args.directory

    alert(f"GuardSweep started. Monitoring directory: {MONITOR_DIR}", severity="INFO")

    # Start your monitoring threads as before
    observer = start_file_monitor()
    file_thread = threading.Thread(target=observer.join)
    file_thread.daemon = True
    file_thread.start()

    proc_thread = threading.Thread(target=monitor_processes)
    proc_thread.daemon = True
    proc_thread.start()

    net_thread = threading.Thread(target=monitor_network)
    net_thread.daemon = True
    net_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        alert("GuardSweep stopped.", severity="INFO")
        sys.exit(0)

# --- Main Program ---
if __name__ == "__main__":
    main()