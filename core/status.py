import json
import platform
from datetime import datetime, timezone
from pathlib import Path


def build_startup_status(args) -> dict:
    return {
        "timestamp_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "platform": platform.system(),
        "monitor_dir": args.monitor_dir,
        "run_seconds": int(getattr(args, "run_seconds", 0)),
        "auto_respond": bool(args.auto_respond),
        "enable_quarantine": bool(args.enable_quarantine),
        "enable_network_blocking": bool(args.enable_network_blocking),
        "suspicious_extensions": list(args.suspicious_extensions),
        "suspicious_process_names": list(args.suspicious_process_names),
        "blacklisted_ips": list(args.blacklisted_ips),
    }


def write_startup_status(path: str, args) -> Path:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build_startup_status(args), indent=2), encoding="utf-8")
    return output
