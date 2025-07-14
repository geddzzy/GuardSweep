# GuardSweep – Cross-Platform Endpoint Detection and Response (EDR)

```
  ____                     _ ____                         
 / ___|_   _  __ _ _ __ __| / ___|_      _____  ___ _ __  
| |  _| | | |/ _` | '__/ _` \___ \ \ /\ / / _ \/ _ \ '_ \ 
| |_| | |_| | (_| | | | (_| |___) \ V  V /  __/  __/ |_) |
 \____|\__,_|\__,_|_|  \__,_|____/ \_/\_/ \___|\___| .__/ 
                                                   |_|    
```


GuardSweep is a Python-based EDR tool that monitors system processes, file creations, and network connections in real-time across Windows and Linux systems. It helps detect suspicious activities and alerts users, providing a foundation for automated endpoint security.

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

Run the main script to start monitoring:

```bash
python guardsweep.py
```

You can optionally specify a directory to monitor using the -d or --directory option:

```bash
python guardsweep.py --directory "C:\Path\To\Monitor"
```

GuardSweep will continuously monitor and print alerts to the console.

## Configuration
GuardSweep provides configurable options directly in the guardsweep.py script to tailor monitoring to your environment:

- MONITOR_DIR: The root directory to watch for file creation events. Defaults to the user’s home directory.
- IGNORED_PATHS: List of path substrings to exclude from file monitoring. Useful to filter out noisy system or application folders (e.g., browser caches, temp folders).
- BLACKLISTED_IPS: Set of IP addresses to flag if network connections are detected.
- SUSPICIOUS_EXTENSIONS: File extensions that trigger alerts when new files are created (e.g., .exe, .dll, .bat).

To customize, open guardsweep.py and edit these variables near the top of the file before running.

## Project Structure
```
guardsweep/
├── guardsweep.py
├── requirements.txt
├── LICENSE
├── README.md
└── .gitignore
```
- guardsweep.py – Main monitoring script
- requirements.txt – Python dependencies (psutil, watchdog)
- LICENSE – License file
- README.md – This file!
- .gitignore – Files and folders to exclude from git

## Features

- Real-time monitoring of new processes
- File creation detection in specified directories
- Network connection tracking with blacklisted IP alerts
- Modular and extensible design for adding new detection rules
- Cross-platform support (Windows and Linux)

## About

Created by a security engineer to explore real-time endpoint security monitoring using Python.
Feel free to use, contribute, or fork to build your own EDR solutions.


## Acknowledgments

- Uses psutil for process and network monitoring
- Uses watchdog for file system event monitoring


## Contributing

Contributions are welcome! Please open an issue or submit a pull request.


## License

This project is licensed under the MIT License.

**Author:** geddzzy 

**Copyright ©** 2025 geddzzy

All rights reserved.
