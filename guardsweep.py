import threading
import time
import sys
import platform
from config.config import parse_args, setup_logging
from core.alerts import alert
from detection.yara_scanner import compile_yara_rules
from detection.file_monitor import start_file_monitor
from detection.process_monitor import monitor_processes
# --- MODIFIED: Import the new persistence monitor entrypoint ---
from detection.persistence_monitor import start_persistence_monitor
from intel.spamhaus_feed import start_spamhaus_thread
from intel.network_monitor import monitor_network

def main():
    args = parse_args()

    setup_logging(args.log_file)
    alert(f"GuardSweep started. Monitoring directory: {args.monitor_dir}", severity="INFO")

    # Start threat intelligence feed
    start_spamhaus_thread()

    # Compile YARA rules
    yara_rules = compile_yara_rules()

    # --- Start Monitoring Threads ---

    # 1. File Monitor
    observer = start_file_monitor(
        args.monitor_dir,
        args.ignored_paths,
        args.suspicious_extensions,
        args.enable_quarantine,
        yara_rules,
        args.virustotal_api_key,
    )
    # The observer runs in its own thread, so we just need to start it.
    # We will call observer.join() later if needed.

    # 2. Process Monitor
    threading.Thread(
        target=monitor_processes,
        args=(args.auto_respond, args.suspicious_process_names),
        daemon=True,
    ).start()

    # 3. Network Monitor
    threading.Thread(
        target=monitor_network,
        args=(args.blacklisted_ips, args.enable_network_blocking),
        daemon=True,
    ).start()

    # 4. --- NEW: Start all persistence monitors ---
    # This single function call will handle starting the correct threads if on Windows.
    start_persistence_monitor()


    # Keep the main thread alive to allow daemon threads to run
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        if 'observer' in locals() and observer.is_alive():
            observer.stop()
            observer.join()
        alert("GuardSweep stopped by user.", severity="INFO")
        sys.exit(0)


if __name__ == "__main__":
    # Ensure script is run with admin/root privileges for full functionality
    if platform.system() == "Windows":
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            alert("Warning: GuardSweep not running as Administrator. Some features like network blocking and full process analysis may fail.", severity="WARNING")
    else: # For Linux/macOS
        import os
        if os.geteuid() != 0:
            alert("Warning: GuardSweep not running as root. Some features like network blocking may fail.", severity="WARNING")

    main()