# GuardSweep - Cross-Platform Endpoint Detection and Response (EDR)

```
  ____                     _ ____
 / ___|_   _  __ _ _ __ __| / ___|_      _____  ___ _ __
| |  _| | | |/ _` | '__/ _` \___ \ \ /\ / / _ \/ _ \ '_ \
| |_| | |_| | (_| | | | (_| |___) \ V  V /  __/  __/ |_) |
 \____|\__,_|\__,_|_|  \__,_|____/ \_/\_/ \___|\___| .__/
                                                   |_|
```

GuardSweep is a lightweight, modular Python EDR prototype for Windows and Linux.  
It continuously monitors endpoints for suspicious file creation, process behavior, network activity, and (on Windows) common persistence techniques.

This project is designed as:
- A practical learning project for endpoint detection and response engineering.
- A base framework you can extend with additional telemetry and detections.
- A local-first security monitor with optional response actions.

## Table of Contents

1. Overview
2. Core Capabilities
3. Architecture
4. Detection and Response Pipeline
5. Project Structure
6. Installation
7. Privilege Requirements
8. Quick Start
9. Configuration Reference
10. Command-Line Usage
11. Detection Modules Deep Dive
12. Threat Intelligence Integrations
13. Quarantine Behavior
14. Logging and Alert Semantics
15. Platform-Specific Notes
16. Performance and Scalability Notes
17. False Positives and Tuning
18. Security and Operational Caveats
19. Development Workflow
20. Testing and CI
21. Troubleshooting
22. Suggested Roadmap
23. Contributing
24. License

## Overview

GuardSweep monitors multiple host telemetry sources and correlates them into human-readable alerts:

- File events from the monitored directory tree.
- Process creation events and command-line context.
- Outbound network connections and known-bad IP intelligence.
- Windows autorun registry keys and scheduled tasks (persistence checks).

It can optionally take action:

- Terminate suspicious processes.
- Quarantine suspicious files.
- Block malicious IPs at the firewall layer.

GuardSweep is not a replacement for enterprise EDR products. It is a compact, transparent baseline system that prioritizes readability and extension over full enterprise coverage.

## Core Capabilities

- Real-time file monitoring using `watchdog`.
- SHA-256 file hashing for suspicious files.
- YARA-based signature scanning with rule directory support.
- Optional asynchronous VirusTotal hash reputation checks.
- Process telemetry and anomaly heuristics:
  - suspicious process names
  - suspicious parent-child relationships
  - burst process creation warnings
- Network connection monitoring with:
  - static blacklist support
  - Spamhaus DROP feed integration
  - optional host firewall blocking
- Windows persistence monitoring:
  - registry autorun keys
  - scheduled task creation
- Unified alert/log interface with normalized severity handling.

## Architecture

GuardSweep follows a modular, thread-based architecture.

1. `guardsweep.py` loads config and starts monitoring workers.
2. Long-running monitors execute in background daemon threads.
3. Modules emit alerts through `core.alerts.alert`.
4. Logging output is emitted to both console and file.
5. Optional response actions execute inline in module context.

### High-Level Flow

1. Load config and CLI overrides.
2. Initialize logging.
3. Start Spamhaus feed updater thread.
4. Compile YARA rules.
5. Start monitoring threads:
   - file monitor
   - process monitor
   - network monitor
   - persistence monitor (Windows only)
6. Main thread remains alive until interrupted.

## Detection and Response Pipeline

### File Pipeline

1. File create event appears in monitored path.
2. Ignore filter is applied by path substring matching.
3. Extension filter is applied against `suspicious_extensions`.
4. SHA-256 hash is computed.
5. Hash reputation check is queued for VirusTotal (if API key configured).
6. YARA scan executes against loaded rule set.
7. On YARA match:
   - alert emitted
   - optional quarantine action

### Process Pipeline

1. Monitor polls active PIDs and identifies newly started processes.
2. Captures:
   - process name
   - command-line arguments (if accessible)
   - parent process context (if accessible)
3. Applies heuristics:
   - suspicious process name list
   - suspicious parent-child map
   - high process creation rate warning
4. On configured suspicious names with `auto_respond=true`, process termination is attempted.

### Network Pipeline

1. Monitor inspects active `inet` connections from `psutil`.
2. Extracts remote IP and owning PID.
3. Matches IP against:
   - static `blacklisted_ips`
   - cached Spamhaus DROP CIDR networks
4. Emits high-severity alert with process/user context.
5. If `enable_network_blocking=true`, adds firewall rule for remote IP.

### Persistence Pipeline (Windows)

1. Registry monitor snapshots key-value entries in common autorun locations.
2. On interval, computes delta and alerts on newly added entries.
3. Scheduled task monitor snapshots task list and alerts on newly observed tasks.

## Project Structure

```text
guardsweep/
|-- guardsweep.py                    # Entrypoint and thread orchestration
|-- config/
|   `-- config.py                    # CLI + config parsing, logging setup
|-- core/
|   |-- alerts.py                    # Severity normalization and logging interface
|   `-- quarantine.py                # File quarantine helper
|-- detection/
|   |-- file_monitor.py              # Watchdog event handler + file detection pipeline
|   |-- process_monitor.py           # Process telemetry + behavior heuristics
|   |-- persistence_monitor.py       # Windows persistence checks
|   `-- yara_scanner.py              # YARA loading + scan helpers
|-- intel/
|   |-- network_monitor.py           # Connection monitoring + IP blocking
|   |-- spamhaus_feed.py             # Spamhaus DROP updater thread
|   `-- threat_intel.py              # SHA256 + VirusTotal queue worker
|-- yara_rules/
|   `-- upx_packed.yar               # Example YARA rule
|-- config.yaml                      # Default runtime config
|-- requirements.txt                 # Runtime dependencies
|-- pyproject.toml                   # Project/test/lint metadata
|-- tests/                           # Unit tests
`-- .github/workflows/ci.yml         # CI for lint/tests/smoke checks
```

## Installation

### 1. Clone

```bash
git clone https://github.com/geddzzy/guardsweep.git
cd guardsweep
```

### 2. Create Virtual Environment (recommended)

Windows PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

Optional dev tooling:

```bash
pip install pytest ruff
```

## Privilege Requirements

Run GuardSweep with elevated privileges for best coverage:

- Windows: Administrator shell
- Linux: root (or capabilities that permit full process/network visibility)

Without elevation:

- Some process metadata may return `AccessDenied`.
- Firewall-based blocking may fail.
- Certain system-level telemetry may be incomplete.

## Quick Start

Run with default `config.yaml`:

```bash
python guardsweep.py --config config.yaml
```

Minimal custom run:

```bash
python guardsweep.py --monitor_dir "C:/Users/Admin/Downloads"
```

Enable key response controls:

```bash
python guardsweep.py --enable_quarantine --enable_network_blocking
```

Enable auto process response:

```bash
python guardsweep.py --auto_respond --suspicious_process_names cmd.exe powershell.exe
```

## Configuration Reference

GuardSweep supports YAML config and CLI overrides.  
`jsonargparse` merges settings, and CLI flags take precedence.

### Complete Option Reference

- `monitor_dir` (`str`)
  - Root directory for recursive file monitoring.
  - Example: `C:/Users/Admin/Documents`

- `ignored_paths` (`list[str]`)
  - Substring-based filters for file events.
  - Any event path containing one of these values is skipped.
  - Keep this tuned to noisy/cached/temp paths.

- `suspicious_extensions` (`list[str]`)
  - File extensions that trigger the file analysis pipeline.
  - Defaults include executable/script-oriented extensions.

- `suspicious_process_names` (`list[str]`)
  - Process names flagged as suspicious.
  - Compared case-insensitively.

- `blacklisted_ips` (`list[str]`)
  - Manual IPs to alert/block regardless of feed data.

- `log_file` (`str`)
  - Output log destination.
  - Example: `guardsweep.log`

- `virustotal_api_key` (`str | null`)
  - Enables hash reputation checks.
  - If absent, VT checks are skipped.

- `auto_respond` (`bool`)
  - If true, suspicious process names can be terminated.

- `enable_quarantine` (`bool`)
  - If true, files with YARA matches are moved to quarantine.

- `enable_network_blocking` (`bool`)
  - If true, matched malicious IPs are blocked via firewall rule command.

## Command-Line Usage

General help:

```bash
python guardsweep.py --help
```

Print merged config:

```bash
python guardsweep.py --print_config
```

Use alternate config file:

```bash
python guardsweep.py --config ./my_config.yaml
```

Override specific values:

```bash
python guardsweep.py \
  --monitor_dir "/home/analyst/sandbox" \
  --suspicious_extensions .exe .dll .js .bat \
  --blacklisted_ips 1.2.3.4 5.6.7.8
```

## Detection Modules Deep Dive

### `detection/file_monitor.py`

Purpose:
- Handle file creation events and run suspicious file analysis.

Key behavior:
- Sleeps briefly to allow write completion.
- Skips directories.
- Applies `ignored_paths` and extension filters.
- Hashes candidate files.
- Queues VT hash checks asynchronously.
- Runs YARA scan and triggers quarantine on match.

### `detection/process_monitor.py`

Purpose:
- Monitor new processes and inspect process context.

Key behavior:
- Tracks known PID set and polls every few seconds.
- Logs command-line arguments when available.
- Flags suspicious parent-child relationships (e.g., Office -> shell execution).
- Detects burst process creation in short time windows.
- Can terminate configured suspicious processes.

### `detection/persistence_monitor.py` (Windows only)

Purpose:
- Identify likely persistence changes.

Key behavior:
- Autorun registry snapshot + delta detection.
- Scheduled task snapshot + delta detection.
- Runs in dedicated threads.

### `detection/yara_scanner.py`

Purpose:
- Compile YARA rules and execute scans.

Key behavior:
- Loads `.yar` / `.yara` files from rules directory.
- Gracefully handles rule syntax errors and scan exceptions.

## Threat Intelligence Integrations

### Spamhaus DROP

- Source: `https://www.spamhaus.org/drop/drop.txt`
- Refreshed every 24 hours in background thread.
- Parsed into `ipaddress.ip_network` objects for efficient containment checks.

### VirusTotal Hash Reputation

- Uses VT v3 file hash lookup endpoint.
- Enforced rate limiting in worker to support free-tier constraints.
- Check execution is queued so file monitoring remains responsive.

## Quarantine Behavior

When enabled:

1. YARA match triggers quarantine helper.
2. File is moved into `quarantine/`.
3. If filename collision occurs, a timestamp-based suffix is added.

Operational note:
- Quarantine uses file move semantics (`os.rename`), so source and target location behavior may differ across filesystems.

## Logging and Alert Semantics

All modules use `core.alerts.alert(message, severity=...)`.

Normalized severities:
- `DEBUG`
- `INFO`
- `WARNING`
- `ERROR`
- `CRITICAL`
- `ALERT` (mapped to `CRITICAL` for compatibility)

Logging output:
- Colored console output (via `colorama`).
- File output with standard timestamped format.

## Platform-Specific Notes

### Windows

- Supported:
  - process monitoring
  - file monitoring
  - network monitoring/blocking via `netsh`
  - persistence monitor (registry + scheduled tasks)

### Linux

- Supported:
  - process monitoring
  - file monitoring
  - network monitoring/blocking via `iptables` command

- Persistence module logs informational notice (Windows-only implementation).

## Performance and Scalability Notes

Current implementation is intentionally simple and polling/thread based.  
For larger-scale production-like workloads:

- Process/network loops may need adaptive polling or event-driven backends.
- YARA scanning can be expensive for large or high-volume files.
- VirusTotal queue can grow during burst events.
- Logging verbosity can become I/O-bound on noisy systems.

Tuning guidance:

- Narrow `monitor_dir`.
- Expand `ignored_paths` to suppress cache/temp churn.
- Tighten `suspicious_extensions`.
- Disable expensive response actions where not required.

## False Positives and Tuning

Expected false-positive zones:

- Admin tooling (`powershell.exe`, `cmd.exe`) from legitimate automation.
- Installer/updater behavior creating executable files.
- Enterprise software that dynamically creates scheduled tasks.

Tuning strategies:

- Keep `suspicious_process_names` focused and environment-specific.
- Add noisy trusted paths to `ignored_paths`.
- Build targeted YARA rules with high-confidence signatures.
- Start in alert-only mode before enabling auto responses.

## Security and Operational Caveats

- GuardSweep executes firewall commands and process termination when enabled.
- Misconfiguration can disrupt legitimate processes or network traffic.
- VT/API lookups send file hashes externally; account for privacy policies.
- This tool does not currently implement signed update channels, RBAC, or secure remote management.

Recommended operational approach:

1. Start in monitor-only mode.
2. Validate alert quality.
3. Enable quarantine/network blocking in stages.
4. Enable process auto-termination only after explicit allow/deny design.

## Development Workflow

### Local Checks

```bash
ruff check .
pytest
python guardsweep.py --help
```

### Running Tests

```bash
pytest
```

Current tests validate:
- alert severity normalization
- CLI override behavior
- cross-platform import safety for persistence module

## Testing and CI

CI workflow:
- GitHub Actions: `.github/workflows/ci.yml`
- OS matrix:
  - `ubuntu-latest`
  - `windows-latest`
- Steps:
  - install dependencies
  - lint (`ruff`)
  - run tests (`pytest`)
  - smoke check (`python guardsweep.py --help`)

## Troubleshooting

### `Not running as Administrator/root` warnings

Cause:
- Process started with insufficient privilege.

Fix:
- Relaunch elevated shell.

### No YARA detections

Cause:
- Rule path is empty, rules did not compile, or event extensions are filtered out.

Fix:
- Verify `yara_rules/` contains valid `.yar` files.
- Check logs for syntax warnings.
- Ensure target extension is in `suspicious_extensions`.

### Network blocking fails

Cause:
- Missing privilege or firewall command differences.

Fix:
- Run elevated.
- Validate `netsh` (Windows) or `iptables` (Linux) availability.

### Too many alerts

Cause:
- Noisy paths/processes.

Fix:
- Expand `ignored_paths`.
- Tighten suspicious lists.
- Reduce monitored scope.

### VirusTotal checks seem delayed

Cause:
- Queue-based rate limiting is active by design.

Fix:
- This is expected for free-tier-safe pacing.
- Consider private infrastructure for high-volume reputation checks.

## Suggested Roadmap

Potential next improvements:

1. Add structured JSON logging mode.
2. Add alert deduplication and suppression windows.
3. Add correlation IDs per event flow.
4. Replace polling loops with lower-latency event APIs where possible.
5. Add MITRE ATT&CK tagging for detections.
6. Introduce plugin interface for custom detectors.
7. Add secure local API/UI for observability and controls.
8. Expand Linux persistence detection coverage.
9. Add configurable allowlist framework.
10. Add integration tests using synthetic telemetry fixtures.

## Contributing

Contributions are welcome.

Suggested contribution flow:

1. Fork repository.
2. Create feature branch.
3. Implement change + tests.
4. Run local lint/tests.
5. Open pull request with:
   - problem statement
   - implementation summary
   - test evidence
   - security/operational impact notes (if applicable)

## License

This project is licensed under the MIT License.

Author: geddzzy  
Copyright (c) 2025 geddzzy
