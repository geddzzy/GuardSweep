import psutil
import time
import collections
from datetime import datetime, timedelta
from core.alerts import alert

# A dictionary of known suspicious parent -> child process relationships.
# Using a set for the child process names allows for efficient lookups.
SUSPICIOUS_PARENT_CHILD_MAP = {
    "winword.exe": {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "excel.exe": {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "powerpnt.exe": {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "outlook.exe": {"powershell.exe", "cmd.exe", "mshta.exe"},
    "services.exe": {"cmd.exe", "powershell.exe"}, # A service should rarely launch a shell directly.
}


def monitor_processes(auto_respond, suspicious_process_names):
    """
    Monitors for new processes, analyzes their command line, and checks for
    suspicious parent-child relationships.
    """
    known_pids = set(psutil.pids())
    process_events = collections.deque(maxlen=100)
    suspicious_set = {name.lower() for name in suspicious_process_names}

    while True:
        current_pids = set(psutil.pids())
        new_pids = current_pids - known_pids
        now = datetime.now()

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                proc_name_lower = proc_name.lower()

                # Get command line arguments
                try:
                    proc_cmdline = " ".join(proc.cmdline())
                except psutil.AccessDenied:
                    proc_cmdline = "Access Denied"

                # --- NEW FEATURE: Parent Process Anomaly Detection ---
                try:
                    parent = proc.parent()
                    if parent:
                        parent_name_lower = parent.name().lower()
                        # Check if the parent is in our suspicious map
                        if parent_name_lower in SUSPICIOUS_PARENT_CHILD_MAP:
                            # Check if the child process is one of the suspicious children for that parent
                            if proc_name_lower in SUSPICIOUS_PARENT_CHILD_MAP[parent_name_lower]:
                                alert(
                                    f"Suspicious Parent-Child: Parent='{parent.name()}', Child='{proc_name}' (PID: {pid})",
                                    severity="CRITICAL"
                                )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # It's common for a parent to exit before we can inspect it.
                    pass

                # --- Existing Alerting Logic ---
                severity = "CRITICAL" if proc_name_lower in suspicious_set else "INFO"
                alert(f"New process started: {proc_name} (PID {pid}) | CMD: {proc_cmdline}", severity=severity)

                # Behavioral analysis for rapid process creation
                process_events.append(now)
                recent_events = [t for t in process_events if now - t < timedelta(seconds=10)]
                if len(recent_events) > 10:
                    alert("High process creation rate detected!", severity="WARNING")

                # Auto-response logic
                if auto_respond and proc_name_lower in suspicious_set:
                    proc.terminate()
                    alert(f"Auto-terminated suspicious process PID {pid}", severity="WARNING")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        known_pids = current_pids
        time.sleep(3)