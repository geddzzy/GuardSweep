import os
from core.alerts import alert

QUARANTINE_DIR = "quarantine"
os.makedirs(QUARANTINE_DIR, exist_ok=True)

def quarantine_file(file_path):
    try:
        basename = os.path.basename(file_path)
        quarantine_path = os.path.join(QUARANTINE_DIR, basename)

        # Handle filename conflicts by appending timestamp if needed
        if os.path.exists(quarantine_path):
            name, ext = os.path.splitext(basename)
            quarantine_path = os.path.join(QUARANTINE_DIR, f"{name}_{int(os.path.getmtime(file_path))}{ext}")

        os.rename(file_path, quarantine_path)
        alert(f"File quarantined: {quarantine_path}", severity="WARNING")
    except Exception as e:
        alert(f"Failed to quarantine file {file_path}: {e}", severity="WARNING")
