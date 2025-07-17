from config.config import parse_args, setup_logging
from core.alerts import alert
from detection.yara_scanner import compile_yara_rules
from detection.file_monitor import start_file_monitor
from detection.process_monitor import monitor_processes
from intel.spamhaus_feed import start_spamhaus_thread
from intel.network_monitor import monitor_network

import threading
import time 
import sys

def main():
    args = parse_args()

    setup_logging(args.log_file)
    alert(f"GuardSweep started. Monitoring directory: {args.monitor_dir}", severity="INFO")

    start_spamhaus_thread()

    yara_rules = compile_yara_rules()

    observer = start_file_monitor(
        args.monitor_dir,
        args.ignored_paths,
        args.suspicious_extensions,
        args.enable_quarantine,
        yara_rules,
        args.virustotal_api_key
    )
    threading.Thread(target=observer.join, daemon=True).start()

    threading.Thread(
        target=monitor_processes,
        args=(args.auto_respond, {name.lower() for name in args.suspicious_process_names}),
        daemon=True,
    ).start()

    threading.Thread(
        target=monitor_network,
        args=(args.blacklisted_ips, args.enable_network_blocking),
        daemon=True,
    ).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        alert("GuardSweep stopped.", severity="INFO")
        sys.exit(0)


if __name__ == "__main__":
    main()
