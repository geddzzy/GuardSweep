from jsonargparse import ArgumentParser, ActionConfigFile
import os

def parse_args():
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
    parser.add_argument("--suspicious_process_names", nargs="*", default=[], help="List of suspicious process names for auto termination")
    parser.add_argument("--enable_quarantine", action="store_true", help="Enable file quarantine for suspicious YARA matches")
    parser.add_argument("--enable_network_blocking", action="store_true", help="Enable automatic blocking of malicious network IPs")

    args = parser.parse_args()

    args.blacklisted_ips = args.blacklisted_ips or ["1.2.3.4", "8.8.8.8"]
    args.monitor_dir = args.monitor_dir or os.path.expanduser("~")
    args.ignored_paths = args.ignored_paths or []
    args.suspicious_extensions = args.suspicious_extensions or [
        ".exe", ".dll", ".bat", ".ps1", ".js", ".vbs", ".scr"
    ]

    return args

import logging

def setup_logging(log_file):
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
