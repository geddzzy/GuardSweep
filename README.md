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
│   └── quarantine.py           # File quarantine helpers

├── detection/
│   ├── yara_scanner.py         # YARA rule loading, file scanning, quarantine integration
│   ├── file_monitor.py         # Filesystem monitoring using watchdog
    ├── persistence_monitor.py  # Windows persistence monitoring (Registry, Tasks)
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

GuardSweep is configured using the config.yaml file, which allows for easy management of all settings.
Any option in this file can also be overridden at runtime using command-line arguments.

- monitor_dir: The root directory to monitor for new files.
- ignored_paths: A list of path substrings to exclude from file monitoring (e.g., temp folders).
- suspicious_extensions: File extensions (e.g., .exe, .dll) that will trigger a specific warning when created.
- suspicious_process_names: A list of process names that will trigger a CRITICAL alert and be terminated if auto_respond is enabled.
- blacklisted_ips: A list of IP addresses to block manually, in addition to the Spamhaus feed.
- log_file: The path for the output log file.
- virustotal_api_key: Your free API key from VirusTotal, which enables file hash scanning against its database.
- auto_respond: A boolean (true or false) to automatically terminate suspicious processes.
- enable_quarantine: A boolean (true or false) to move files that match a YARA rule to the quarantine folder.
- enable_network_blocking: A boolean (true or false) to automatically create firewall rules to block malicious IPs. (Requires admin privileges).

## YARA Rules

Sample YARA rules are loaded from the yara_rules/ directory. An example rule included:

- upx_packed.yar: Detects executables packed with the UPX packer, frequently used by malware to obfuscate payloads.

You can add your own .yar or .yara files to extend detection capabilities.

## Features

- Deep Process Analysis: Monitors new processes and their full command-line arguments to uncover malware masquerading as legitimate system tools. Includes behavioral analytics to detect suspicious, rapid process creation.
- Threat-Intelligence Driven File Scanning: Scans every new file with YARA for signature-based threats and automatically checks file hashes against the VirusTotal API to leverage community intelligence.
- Network Connection Monitoring: Integrates the Spamhaus DROP feed to detect and block connections to known malicious subnets and command-and-control servers.
- Windows Persistence Detection: Monitors critical areas like Registry autorun keys and new Scheduled Tasks to detect common persistence techniques.
- Automated Response: Capable of automatically terminating suspicious processes, quarantining malicious files, and blocking malicious network IPs via the system firewall.
- Cross-Platform & Modular: Built with a modular design for easy extension and supports both Windows and Linux environments.

## Notes

- Command-Line Analysis: GuardSweep logs the command-line arguments of new processes, which is crucial for detecting legitimate tools like powershell.exe being used for malicious purposes.
- VirusTotal Integration: By adding a free API key to your config.yaml, you enable GuardSweep to get a second opinion on new files from over 70 antivirus engines.
- Run as Administrator: For full visibility into system processes and to enable network blocking, you must run GuardSweep with administrator or root privileges.
- Persistence Alerts: The registry monitoring feature provides an early warning if a program tries to configure itself to start automatically on the next system boot.
- YARA Rules: Extend GuardSweep's detection capabilities by adding your own .yar or .yara rules to the yara_rules/ directory.
- Safe Response: The auto_respond, enable_quarantine, and enable_network_blocking features are powerful but should be configured carefully to avoid disrupting legitimate system activity.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.

**Author:** geddzzy

**Copyright ©** 2025 geddzzy

All rights reserved.
