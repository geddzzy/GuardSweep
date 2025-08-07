import winreg
import subprocess
import time
import platform
from core.alerts import alert

# --- Registry Monitoring Section ---

AUTORUN_KEYS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
]

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
        pass  # Key might not exist, which is fine.
    return entries

def monitor_registry_autoruns():
    """Monitors Windows Registry autorun keys for new entries."""
    alert("Starting registry autorun monitoring.", severity="INFO")
    snapshots = {f"{hkey_to_str(hkey)}\\{key_path}": get_key_snapshot(hkey, key_path) for hkey, key_path in AUTORUN_KEYS}

    while True:
        time.sleep(120)  # Check every 2 minutes
        for hkey, key_path in AUTORUN_KEYS:
            full_path_str = f"{hkey_to_str(hkey)}\\{key_path}"
            current_snapshot = get_key_snapshot(hkey, key_path)
            new_entries = current_snapshot - snapshots[full_path_str]

            if new_entries:
                for entry in new_entries:
                    alert(f"New Registry Persistence: Key='{full_path_str}', Value='{entry}'", severity="ALERT")

            snapshots[full_path_str] = current_snapshot

def hkey_to_str(hkey):
    """Helper to convert HKEY constant to string for logging."""
    if hkey == winreg.HKEY_CURRENT_USER: return "HKCU"
    if hkey == winreg.HKEY_LOCAL_MACHINE: return "HKLM"
    return "HKEY"


# --- Scheduled Task Monitoring Section ---

def get_scheduled_tasks():
    """Returns a set of all scheduled task names on Windows."""
    tasks = set()
    try:
        # Use schtasks to query all tasks in CSV format, skipping the header
        cmd = "schtasks /query /fo csv"
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True, check=True, encoding='utf-8', errors='ignore')
        # The first line is the header, so skip it
        for line in result.stdout.strip().splitlines()[1:]:
            try:
                # The task name is the first value in the CSV
                tasks.add(line.split(",")[0].strip('"'))
            except IndexError:
                continue # Ignore malformed lines
    except Exception as e:
        alert(f"Failed to query scheduled tasks: {e}", severity="WARNING")
    return tasks

def monitor_scheduled_tasks():
    """Monitors for the creation of new scheduled tasks."""
    alert("Starting scheduled task monitoring.", severity="INFO")
    known_tasks = get_scheduled_tasks()

    while True:
        time.sleep(300)  # Check every 5 minutes
        current_tasks = get_scheduled_tasks()

        new_tasks = current_tasks - known_tasks
        if new_tasks:
            for task in new_tasks:
                # Filter out some common, noisy Windows tasks
                if "User_Feed_Synchronization" not in task and "Office" not in task:
                    alert(f"New Scheduled Task Detected: {task}", severity="ALERT")

        known_tasks = current_tasks


# --- Main Entrypoint for Persistence Module ---

def start_persistence_monitor():
    """Starts all persistence monitoring threads for the appropriate OS."""
    if platform.system() == "Windows":
        import threading
        # Run each monitor in its own thread
        threading.Thread(target=monitor_registry_autoruns, daemon=True).start()
        threading.Thread(target=monitor_scheduled_tasks, daemon=True).start()
    else:
        alert("Persistence monitoring is only supported on Windows.", severity="INFO")