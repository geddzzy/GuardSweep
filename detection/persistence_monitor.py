import winreg
import time
from core.alerts import alert

# Define the registry keys to monitor for persistence
AUTORUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
]

def monitor_registry_autoruns():
    """Monitors Windows Registry autorun keys for changes."""
    snapshots = {key_path: get_key_snapshot(hkey, key_path) for hkey, key_path in AUTORUN_KEYS}

    while True:
        time.sleep(60) # Check every minute
        for hkey, key_path in AUTORUN_KEYS:
            current_snapshot = get_key_snapshot(hkey, key_path)
            new_entries = current_snapshot - snapshots[key_path]

            if new_entries:
                for entry in new_entries:
                    alert(f"New persistence entry in '{key_path}': {entry}", severity="ALERT")

            snapshots[key_path] = current_snapshot

def get_key_snapshot(hkey, key_path):
    """Takes a snapshot of the values in a given registry key."""
    entries = set()
    try:
        with winreg.OpenKey(hkey, key_path, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    value_name, value_data, _ = winreg.EnumValue(key, i)
                    entries.add(f"{value_name} -> {value_data}")
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass # Key might not exist, which is fine
    return entries