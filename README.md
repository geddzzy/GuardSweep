# GuardSweep – Cross-Platform Endpoint Detection and Response (EDR)

```
  ____                     _ ____
 / ___|_   _  __ _ _ __ __| / ___|_      _____  ___ _ __
| |  _| | | |/ _` | '__/ _` \___ \ \ /\ / / _ \/ _ \ '_ \
| |_| | |_| | (_| | | | (_| |___) \ V  V /  __/  __/ |_) |
 \____|\__,_|\__,_|_|  \__,_|____/ \_/\_/ \___|\___| .__/
                                                   |_|
```

GuardSweep is a lightweight, Python-based EDR (Endpoint Detection and Response) tool that monitors system processes, file creations, and network connections in real-time across Windows and Linux. It detects suspicious activity and alerts users, serving as a foundation for building automated endpoint security defenses.

## Project Structure

```
guardsweep/
├── guardsweep.py               # Main entrypoint and CLI orchestration

├── config/
│   └── config.py               # CLI argument parsing and logging setup

├── core/
│   ├── alerts.py               # Alert and logging helper functions
│   ├── quarantine.py           # File quarantine helpers
│   └── utils.py                # (Optional) Utility helpers

├── detection/
│   ├── yara_scanner.py         # YARA rule loading, file scanning, quarantine integration
│   ├── file_monitor.py         # Filesystem monitoring using watchdog
    ├── persistence_monitor.py  # Windows Registry persistence monitoring
│   └── process_monitor.py      # Process monitoring and behavioral analytics

├── intel/
│   ├── network_monitor.py      # Network connections monitoring and blocking
│   ├── spamhaus_feed.py        # Spamhaus DROP feed downloading and parsing
    └── threat_intel.py         # File hashing and VirusTotal API integration
    
├── yara_rules/                 # Directory containing YARA rules (e.g. upx_packed.yar)
    └── upx_packed.yar          # Sample YARA rule

├── config.yaml                 # Default configuration file
├── requirements.txt            # Python dependencies
├── README.md                   # This file
└── LICENSE                     # License file
```

## Installation

1. Clone the repository:

```bash
git clone https://github.com/geddzzy/guardsweep.git
cd guardsweep
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run GuardSweep from an **administrator/root terminal** to ensure it has full visibility into system processes.

---

Run using a YAML configuration (default: config.yaml) or override values via CLI:

```bash
python guardsweep.py --config config.yaml
```

Override any setting via the command line:

```bash
python guardsweep.py --monitor_dir "C:/Users/Admin/Downloads" --suspicious_process_names "mimikatz.exe"
```

---

Enable automatic process termination for suspicious process names:

```bash
python guardsweep.py --auto_respond --suspicious_process_names notepad.exe cmd.exe
```

This will automatically terminate any process whose name matches one in the list.

The behavioral analytics feature alerts if a high rate of process creation is detected.

---

Enable YARA scanning with automatic quarantine of suspicious files:

```bash
python guardsweep.py --enable_quarantine
```

Place your YARA rules files (e.g., `upx_packed.yar`) in the `yara_rules` directory. GuardSweep will scan new files with these rules and quarantine matches.

---

Enable automatic blocking of malicious network IPs detected via Spamhaus DROP feed:

```bash
python guardsweep.py --enable_network_blocking
```

---

Enable VirusTotal for Enhanced File Scanning:

GuardSweep automatically checks suspicious files against VirusTotal if an API key is present in the configuration.
To enable this, add your key to config.yaml:

```yaml
virustotal_api_key: "YOUR_API_KEY_HERE"
```

---

GuardSweep will continuously monitor and print alerts to the console.

## Configuration

GuardSweep provides configurable options directly in the guardsweep.py script to tailor monitoring to your environment:

- **monitor_dir**: Directory root to watch for new files.
- **ignored_paths**: Paths to exclude from file monitoring.
- **suspicious_extensions**: File extensions (e.g., .exe, .dll) to trigger alerts.
- **blacklisted_ips**: IP addresses blacklisted explicitly (alongside Spamhaus feed).
- **log_file**: Location of log file.
- **auto_respond**: Automatically terminate suspicious processes.
- **suspicious_process_names**: List of process executable names triggering termination.
- **enable_quarantine**: Quarantine files matched by YARA rules.
- **enable_network_blocking**: Block connections to malicious IPs from Spamhaus feed.

## YARA Rules

Sample YARA rules are loaded from the yara_rules/ directory. An example rule included:

- upx_packed.yar: Detects executables packed with the UPX packer, frequently used by malware to obfuscate payloads.

You can add your own .yar or .yara files to extend detection capabilities.

## Features

- Real-time process creation monitoring with behavioral analytics
- File system monitoring with YARA-based scanning and quarantine
- Network connection monitoring with integration of Spamhaus DROP threat intelligence
- Automated response capabilities including process termination and network blocking
- Modular design for easy extension and maintenance
- Cross-platform support: Windows and Linux

## Notes

- The behavioral analytics feature raises warnings if many new processes start in a short time, helping detect suspicious activity patterns.
- Use `auto_respond` carefully: automatic termination can interrupt legitimate processes if misconfigured.
- Extend `suspicious_process_names` with process names you want to detect and optionally kill automatically.
- The included YARA rule `upx_packed.yar` detects files packed with UPX — a common packer often used by malware.  
- You can customize or add further YARA rules inside the `yara_rules` directory to extend detection capabilities.  
- Quarantine moves suspicious files to the `quarantine` folder to safely isolate them.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.

**Author:** geddzzy

**Copyright ©** 2025 geddzzy

All rights reserved.
