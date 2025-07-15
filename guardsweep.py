import ipaddress # Added for ipaddress handling
from jsonargparse import ArgumentParser, ActionConfigFile
import psutil
import time
import os
import sys
import logging
import hashlib
import requests
import threading
import collections
import yara
# Removed 'csv' as Spamhaus DROP is not CSV format
from datetime import datetime, timedelta
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import platform # For network blocking subprocess
import subprocess # For network blocking subprocess

# -------------- Configuration Constants --------------
SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"
YARA_RULES_DIR = "./yara_rules"
QUARANTINE_DIR = "quarantine"
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# Global list of malicious networks from Spamhaus DROP
malicious_networks = []

# -------------- Setup Logging --------------
def setup_logging(log_file):
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

# -------------- Alert Helper --------------
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

# -------------- Spamhaus DROP Feed Updater --------------
def update_spamhaus_drop_list():
    global malicious_networks
    while True:
        try:
            r = requests.get(SPAMHAUS_DROP_URL, timeout=15)
            r.raise_for_status()
            nets = []
            for line in r.text.splitlines():
                line = line.strip()
                # Spamhaus DROP lines are like: CIDR ; date ; description
                # Skip comments (starting with ';') and empty lines
                if not line or line.startswith(";"):
                    continue
                
                parts = line.split(";")
                cidr_str = parts[0].strip()
                try:
                    net = ipaddress.ip_network(cidr_str, strict=False) # strict=False to handle /32 without error
                    nets.append(net)
                except ValueError:
                    alert(f"Invalid network format encountered in Spamhaus DROP: {cidr_str}", severity="WARNING")
                    continue
            malicious_networks = nets
            alert(f"Spamhaus DROP: Loaded {len(nets)} malicious networks", severity="INFO")
        except Exception as e:
            alert(f"Spamhaus DROP feed update failed: {e}", severity="WARNING")

        time.sleep(86400)  # Update every 24 hours

# -------------- Load YARA Rules --------------
def compile_yara_rules():
    rules = {}
    if not os.path.exists(YARA_RULES_DIR):
        alert(f"YARA rules directory {YARA_RULES_DIR} does not exist; no rules loaded.", severity="WARNING")
        return rules

    for root, _, files in os.walk(YARA_RULES_DIR):
        for file in files:
            if file.endswith((".yar", ".yara")):
                path = os.path.join(root, file)
                try:
                    rules[file] = yara.compile(filepath=path)
                    alert(f"Loaded YARA rule: {file}", severity="INFO")
                except yara.SyntaxError as e:
                    alert(f"YARA syntax error in {file}: {e}", severity="WARNING")
    return rules

# -------------- File Hash Helper --------------
def get_file_sha256(file_path):
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        alert(f"Error hashing file {file_path}: {e}", severity="WARNING")
        return None

# -------------- File Quarantine Helper --------------
def quarantine_file(file_path):
    try:
        basename = os.path.basename(file_path)
        quarantine_path = os.path.join(QUARANTINE_DIR, basename)
        os.rename(file_path, quarantine_path)
        alert(f"File quarantined: {quarantine_path}", severity="WARNING")
    except Exception as e:
        alert(f"Failed to quarantine file {file_path}: {e}", severity="WARNING")

# -------------- Scan file with YARA --------------
def scan_file_with_yara(yara_rules, file_path):
    matches = []
    for name, rule in yara_rules.items():
        try:
            # Need to open the file each time to ensure it's not locked by another process
            with open(file_path, 'rb') as f:
                if rule.match(data=f.read()): # Use 'data' instead of 'filepath' for reliability
                    matches.append(name)
        except yara.Error as e: # Catch yara specific errors (e.g. file too big)
            alert(f"YARA scan error with rule '{name}' on {file_path}: {e}", severity="WARNING")
        except Exception as e:
            alert(f"Error scanning {file_path} with {name}: {e}", severity="WARNING")
    return matches

# -------------- File System Monitor --------------
class FileMonitor(FileSystemEventHandler):
    def __init__(self, ignored_paths, suspicious_extensions, enable_quarantine, yara_rules):
        self.ignored_paths = ignored_paths
        self.suspicious_extensions = suspicious_extensions
        self.enable_quarantine = enable_quarantine
        self.yara_rules = yara_rules

    def on_created(self, event):
        if event.is_directory:
            return
        path_lower = event.src_path.lower()
        if any(ignored.lower() in path_lower for ignored in self.ignored_paths):
            return
        # Ensure file exists before trying to scan or hash it, as it might be ephemeral
        if not os.path.exists(event.src_path):
            alert(f"File {event.src_path} was created but no longer exists.", severity="INFO")
            return

        _, ext = os.path.splitext(event.src_path)
        if ext.lower() not in self.suspicious_extensions:
            return

        alert(f"Suspicious file created: {event.src_path}")

        # YARA Scan
        matches = scan_file_with_yara(self.yara_rules, event.src_path)
        if matches:
            alert(f"YARA matched: {','.join(matches)} on file {event.src_path}", severity="WARNING")
            if self.enable_quarantine:
                quarantine_file(event.src_path)
        else:
            alert(f"No YARA matches for {event.src_path}")

# -------------- File Monitor Start Helper --------------
def start_file_monitor(monitor_dir, ignored_paths, suspicious_extensions, enable_quarantine, yara_rules):
    event_handler = FileMonitor(ignored_paths, suspicious_extensions, enable_quarantine, yara_rules)
    observer = Observer()
    observer.schedule(event_handler, path=monitor_dir, recursive=True)
    observer.start()
    return observer

# -------------- Process Monitor --------------
def monitor_processes(auto_respond, suspicious_process_names):
    known_pids = set(psutil.pids())
    process_events = collections.deque(maxlen=100)

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

                recent_events = [t for t in process_events if now - t < timedelta(seconds=10)]
                if len(recent_events) > 10:
                    alert("High process creation rate detected!", severity="WARNING")

                if auto_respond and proc_name.lower() in suspicious_process_names:
                    proc.terminate()
                    alert(f"Auto-terminated suspicious process PID {pid}", severity="WARNING")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        known_pids = current_pids
        time.sleep(3)

# -------------- Network Monitor Helper (for Spamhaus) --------------
def ip_in_malicious_networks(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        for net in malicious_networks:
            if ip_obj in net:
                return True
        return False
    except ValueError: # If ip_str is not a valid IP address
        return False

# -------------- Network Monitor with Spamhaus DROP Integration --------------
def monitor_network(blacklisted_ips, enable_network_blocking):
    known_blocked = set() # Track IPs we've already tried to block

    while True:
        for conn in psutil.net_connections(kind="inet"):
            if conn.raddr:
                remote_ip = conn.raddr.ip
                # Check against user-defined blacklisted_ips OR Spamhaus DROP list
                if remote_ip in blacklisted_ips or ip_in_malicious_networks(remote_ip):
                    alert(f"Connection to blacklisted/malicious IP or subnet: {remote_ip}", severity="ALERT")
                    if enable_network_blocking and remote_ip not in known_blocked:
                        block_network_ip(remote_ip)
                        known_blocked.add(remote_ip)
        time.sleep(10)

# -------------- Network Blocking --------------
NETWORK_BLOCK_COMMANDS = {
    "Windows": 'netsh advfirewall firewall add rule name="GuardSweepBlock_{ip}" dir=out action=block remoteip={ip}',
    "Linux": "iptables -I OUTPUT -d {ip} -j DROP",
}

def block_network_ip(ip):
    system = platform.system()
    cmd_template = NETWORK_BLOCK_COMMANDS.get(system)
    if not cmd_template:
        alert(f"Network block not supported on {system}", severity="WARNING")
        return
    cmd = cmd_template.format(ip=ip)
    try:
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        alert(f"Blocked network IP: {ip}", severity="WARNING")
    except subprocess.CalledProcessError as e:
        alert(f"Failed to block IP {ip}: {e.stderr.decode().strip()}", severity="WARNING") # Decode stderr for better message
    except Exception as e:
        alert(f"Error executing block command for IP {ip}: {e}", severity="WARNING")


# -------------- Main --------------
def main():
    parser = ArgumentParser(
        description="GuardSweep - Cross-platform EDR tool",
        default_config_files=["config.yaml"],
    )
    parser.add_argument("--config", action=ActionConfigFile, help="Path to config YAML/JSON file")
    parser.add_argument("--blacklisted_ips", nargs="*", default=None, help="Blacklisted IP addresses (overrides config file)")
    parser.add_argument("--monitor_dir", default=None, help="Directory to monitor for file changes (overrides config file)")
    parser.add_argument("--ignored_paths", nargs="*", default=None, help="Paths to ignore for file monitoring (overrides config file)")
    parser.add_argument("--suspicious_extensions", nargs="*", default=None, help="File extensions to alert on (overrides config file)")
    parser.add_argument("--log_file", default=None, help="Log file path (overrides config file)")
    parser.add_argument("--auto_respond", action="store_true", help="Automatically terminate suspicious processes")
    parser.add_argument("--suspicious_process_names", nargs="*", default=None, help="List of suspicious process names for auto termination")
    parser.add_argument("--enable_quarantine", action="store_true", help="Enable file quarantine for suspicious YARA matches")
    parser.add_argument("--enable_network_blocking", action="store_true", help="Enable automatic blocking of malicious network IPs")

    args = parser.parse_args()

    blacklisted_ips = args.blacklisted_ips or ["1.2.3.4", "8.8.8.8"]
    monitor_dir = args.monitor_dir or os.path.expanduser("~")
    ignored_paths = args.ignored_paths or []
    suspicious_extensions = args.suspicious_extensions or [
        ".exe", ".dll", ".bat", ".ps1", ".js", ".vbs", ".scr"
    ]
    log_file = args.log_file or "guardsweep.log"
    auto_respond = args.auto_respond
    suspicious_process_names = {name.lower() for name in (args.suspicious_process_names or [])}
    enable_quarantine = args.enable_quarantine
    enable_network_blocking = args.enable_network_blocking

    setup_logging(log_file)
    alert(f"GuardSweep started. Monitoring directory: {monitor_dir}", severity="INFO")

    # Start Spamhaus DROP update thread
    threading.Thread(target=update_spamhaus_drop_list, daemon=True).start()

    # Compile YARA rules
    yara_rules = compile_yara_rules()

    observer = start_file_monitor(monitor_dir, ignored_paths, suspicious_extensions, enable_quarantine, yara_rules)
    file_thread = threading.Thread(target=observer.join, daemon=True)
    file_thread.start()

    proc_thread = threading.Thread(target=monitor_processes, args=(auto_respond, suspicious_process_names), daemon=True)
    proc_thread.start()

    net_thread = threading.Thread(target=monitor_network, args=(blacklisted_ips, enable_network_blocking), daemon=True)
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
