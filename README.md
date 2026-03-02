# GuardSweep - Cross-Platform Endpoint Detection and Response (EDR)

```
  ____                     _ ____
 / ___|_   _  __ _ _ __ __| / ___|_      _____  ___ _ __
| |  _| | | |/ _` | '__/ _` \___ \ \ /\ / / _ \/ _ \ '_ \
| |_| | |_| | (_| | | | (_| |___) \ V  V /  __/  __/ |_) |
 \____|\__,_|\__,_|_|  \__,_|____/ \_/\_/ \___|\___| .__/
                                                   |_|
```

GuardSweep is a lightweight Python-based EDR prototype for Windows and Linux.  
It monitors file activity, process behavior, network connections, and (on Windows) basic persistence mechanisms.

## Project Structure

```text
guardsweep/
|-- guardsweep.py
|-- config/
|   `-- config.py
|-- core/
|   |-- alerts.py
|   `-- quarantine.py
|-- detection/
|   |-- file_monitor.py
|   |-- persistence_monitor.py
|   |-- process_monitor.py
|   `-- yara_scanner.py
|-- intel/
|   |-- network_monitor.py
|   |-- spamhaus_feed.py
|   `-- threat_intel.py
|-- yara_rules/
|   `-- upx_packed.yar
|-- config.yaml
|-- requirements.txt
|-- pyproject.toml
`-- tests/
```

## Installation

```bash
git clone https://github.com/geddzzy/guardsweep.git
cd guardsweep
pip install -r requirements.txt
```

## Usage

Run from an administrator/root shell for full visibility and response capability.

```bash
python guardsweep.py --config config.yaml
```

Example overrides:

```bash
python guardsweep.py --monitor_dir "C:/Users/Admin/Downloads" --suspicious_process_names mimikatz.exe
python guardsweep.py --auto_respond --suspicious_process_names notepad.exe cmd.exe
python guardsweep.py --enable_quarantine
python guardsweep.py --enable_network_blocking
```

VirusTotal (optional):

```yaml
virustotal_api_key: "YOUR_API_KEY_HERE"
```

## Features

- Real-time process monitoring with parent-child anomaly checks.
- Real-time file monitoring, SHA-256 hashing, YARA matching, optional quarantine.
- Spamhaus DROP feed integration for malicious network detection.
- Optional firewall-based IP blocking on supported platforms.
- Windows persistence monitoring (autorun registry keys and scheduled tasks).
- Modular code layout for extension.

## Configuration

Main options are configured in `config.yaml` and can be overridden via CLI:

- `monitor_dir`
- `ignored_paths`
- `suspicious_extensions`
- `suspicious_process_names`
- `blacklisted_ips`
- `log_file`
- `virustotal_api_key`
- `auto_respond`
- `enable_quarantine`
- `enable_network_blocking`

## Development

Run checks locally:

```bash
pip install pytest ruff
ruff check .
pytest
python guardsweep.py --help
```

CI runs on both `ubuntu-latest` and `windows-latest` using GitHub Actions.

## License

This project is licensed under the MIT License.

Author: geddzzy  
Copyright (c) 2025 geddzzy
