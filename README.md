# GuardSweep – Cross-Platform Endpoint Detection and Response (EDR)

```
  ____                     _ ____
 / ___|_   _  __ _ _ __ __| / ___|_      _____  ___ _ __
| |  _| | | |/ _` | '__/ _` \___ \ \ /\ / / _ \/ _ \ '_ \
| |_| | |_| | (_| | | | (_| |___) \ V  V /  __/  __/ |_) |
 \____|\__,_|\__,_|_|  \__,_|____/ \_/\_/ \___|\___| .__/
                                                   |_|
```

GuardSweep is a lightweight, Python-based EDR (Endpoint Detection and Response) tool that monitors system processes, file creations, and network connections in real-time across Windows and Linux. It helps detect suspicious activity and alert users, serving as a foundation for building automated endpoint security defenses.

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/guardsweep.git
cd guardsweep
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Run using a YAML configuration (default: config.yaml) or override values via CLI:

```bash
python guardsweep.py --config config.yaml
```

Or override any field from the config file directly via CLI:

```bash
python guardsweep.py \
  --monitor_dir "C:/Users/Admin/Documents" \
  --ignored_paths "C:/Windows/Temp" "C:/Windows/Logs" \
  --suspicious_extensions .exe .dll .bat \
  --blacklisted_ips 8.8.8.8 1.2.3.4
```

You can enable automated response to suspicious process creations by using:

```bash
python guardsweep.py --auto_respond --suspicious_process_names notepad.exe cmd.exe
```

This will automatically terminate any process whose name matches one in the list.

The behavioral analytics feature alerts if a high rate of process creation is detected.

GuardSweep will continuously monitor and print alerts to the console.

## Configuration

GuardSweep provides configurable options directly in the guardsweep.py script to tailor monitoring to your environment:

- monitor_dir: The root directory to watch for file creation events (default: user’s home directory).
- ignored_paths: List of paths to exclude from file monitoring. Helps reduce noise from temp or browser cache folders.
- blacklisted_ips: List of IPs to flag if network connections are made to them.
- suspicious_extensions: File extensions that trigger alerts when new files are created (e.g., .exe, .dll, .bat).
- log_file: Path to write logs.
- auto_respond: Boolean flag to enable automatic termination of suspicious processes.
- suspicious_process_names: List of process executable names that trigger automatic termination (case-insensitive).

To customize, edit config.yaml or pass arguments via CLI.

## Project Structure

```
guardsweep/
├── guardsweep.py         # Main logic
├── config.yaml           # Config file
├── requirements.txt      # Dependencies
├── LICENSE
└── README.md
```

- guardsweep.py – Main monitoring script
- requirements.txt – Python dependencies (psutil, watchdog)
- LICENSE – License file
- README.md – This file!
- .gitignore – Files and folders to exclude from git

## Example config.yaml

```yaml
monitor_dir: C:/Users/Admin/Documents
ignored_paths:
  - C:/Windows/Temp
  - \AppData\Local\Temp
  - \AppData\Roaming\Code\Cache
suspicious_extensions:
  - .exe
  - .dll
  - .bat
blacklisted_ips:
  - 1.2.3.4
  - 8.8.8.8
log_file: guardsweep.log
auto_respond: false
suspicious_process_names:
  - notepad.exe
  - cmd.exe
```

## Features

- Real-time monitoring of new processes
- File creation detection in specified directories
- Network connection tracking with blacklisted IP alerts
- Modular and extensible design for adding new detection rules
- Behavioral analytics detecting rapid process creation spikes
- Automated response to suspicious processes (optional automatic termination)
- Cross-platform support (Windows and Linux)

## Notes

- The behavioral analytics feature raises warnings if many new processes start in a short time, helping detect suspicious activity patterns.
- Use `auto_respond` carefully: automatic termination can interrupt legitimate processes if misconfigured.
- Extend `suspicious_process_names` with process names you want to detect and optionally kill automatically.

## About

GuardSweep is developed by a security engineer with a passion for building practical, open-source tools that strengthen endpoint visibility and defense. This project reflects a focused effort to deliver a reliable, real-time EDR solution built entirely in Python, with cross-platform support and modular design at its core.

Whether you're a blue teamer, threat hunter, or cybersecurity enthusiast, you're welcome to use, contribute to, or extend GuardSweep to fit your environment. Collaboration and innovation are always encouraged.

## Dependencies

GuardSweep relies on a few powerful Python libraries:

- psutil for process and network monitoring
- watchdog for file system event monitoring
- jsonargparse for YAML/JSON CLI config parsing

Install all with:

```bash
pip install -r requirements.txt
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.

**Author:** geddzzy

**Copyright ©** 2025 geddzzy

All rights reserved.
