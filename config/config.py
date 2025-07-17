# In config/config.py

from jsonargparse import ArgumentParser, ActionConfigFile
import os
import logging
import sys
import colorama

class ColorFormatter(logging.Formatter):
    level_colors = {
        logging.DEBUG: colorama.Fore.CYAN,
        logging.INFO: colorama.Fore.GREEN,
        logging.WARNING: colorama.Fore.YELLOW,
        logging.ERROR: colorama.Fore.RED,
        logging.CRITICAL: colorama.Fore.MAGENTA + colorama.Style.BRIGHT,
    }

    def format(self, record):
        color = self.level_colors.get(record.levelno)
        record.levelname = f"{color}{record.levelname:<8}{colorama.Style.RESET_ALL}"
        return super().format(record)

def parse_args():
    parser = ArgumentParser(
        description="GuardSweep - Cross-platform EDR tool",
        default_config_files=["config.yaml"], 
    )
    parser.add_argument("--config", action=ActionConfigFile, help="Path to a custom config YAML/JSON file.")
    parser.add_argument("--log_file", type=str, default="guardsweep.log", help="Log file path.") 
    parser.add_argument("--monitor_dir", type=str, default=os.path.expanduser("~"), help="Directory to monitor for file changes.")
    parser.add_argument("--ignored_paths", nargs="*", default=[], help="Paths to ignore for file monitoring.")
    parser.add_argument("--suspicious_extensions", nargs="*", default=[".exe", ".dll", ".bat", ".ps1", ".js", ".vbs", ".scr"], help="File extensions to alert on.")
    parser.add_argument("--suspicious_process_names", nargs="*", default=[], help="List of suspicious process names for auto termination.")
    parser.add_argument("--blacklisted_ips", nargs="*", default=[], help="Manually blacklisted IP addresses.")
    parser.add_argument("--virustotal_api_key", type=str, default=None, help="Your VirusTotal API Key for file hash checking.")
    parser.add_argument("--auto_respond", action="store_true", default=False, help="Automatically terminate suspicious processes.")
    parser.add_argument("--enable_quarantine", action="store_true", default=False, help="Enable file quarantine for suspicious YARA matches.")
    parser.add_argument("--enable_network_blocking", action="store_true", default=False, help="Enable automatic blocking of malicious network IPs.")
    args = parser.parse_args()
    return args

def setup_logging(log_file):
    """
    Configures logging to output to a file and to the console with colors.
    """
    # Initialize colorama
    colorama.init()

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Clear existing handlers
    if logger.hasHandlers():
        logger.handlers.clear()

    # Console handler with color
    console_formatter = ColorFormatter(
        f"[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(console_formatter)
    logger.addHandler(stream_handler)

    # File handler without color
    if log_file:
        file_formatter = logging.Formatter(
            "[%(asctime)s] [%(levelname)-8s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)