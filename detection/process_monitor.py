import psutil
import time
import collections
from datetime import datetime, timedelta
from core.alerts import alert

def monitor_processes(auto_respond, suspicious_process_names):
    known_pids = set(psutil.pids())
    process_events = collections.deque(maxlen=100)

    # Convert to a set for faster lookups
    suspicious_set = set(name.lower() for name in suspicious_process_names)

    while True:
        current_pids = set(psutil.pids())
        new_pids = current_pids - known_pids
        now = datetime.now()

        # Check for new processes
        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                proc_name_lower = proc_name.lower()
                
                try:
                    proc_cmdline = " ".join(proc.cmdline())
                except psutil.AccessDenied:
                    proc_cmdline = "Access Denied"

                # Default to INFO, but elevate to ALERT if the name is in our suspicious list
                severity = "ALERT" if proc_name_lower in suspicious_set else "INFO"
                alert(f"New process started: {proc_name} (PID {pid}) | CMD: {proc_cmdline}", severity=severity)
                
                process_events.append(now)

                recent_events = [t for t in process_events if now - t < timedelta(seconds=10)]
                if len(recent_events) > 10:
                    alert("High process creation rate detected!", severity="WARNING")

                # Auto-terminate if enabled and the process is suspicious
                if auto_respond and proc_name_lower in suspicious_set:
                    proc.terminate()
                    alert(f"Auto-terminated suspicious process PID {pid}", severity="WARNING")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        known_pids = current_pids
        time.sleep(3)