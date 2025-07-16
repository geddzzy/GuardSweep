import psutil
import time
import collections
from datetime import datetime, timedelta
from core.alerts import alert

def monitor_processes(auto_respond, suspicious_process_names):
    known_pids = set(psutil.pids())
    process_events = collections.deque(maxlen=100)

    while True:
        current_pids = set(psutil.pids())
        new_pids = current_pids - known_pids
        now = datetime.now()

        for pid in new_pids:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
                alert(f"New process started: {proc_name} (PID {pid})")
                process_events.append(now)

                recent_events = [t for t in process_events if now - t < timedelta(seconds=10)]
                if len(recent_events) > 10:
                    alert("High process creation rate detected!", severity="WARNING")

                if auto_respond and proc_name.lower() in suspicious_process_names:
                    proc.terminate()
                    alert(f"Auto-terminated suspicious process PID {pid}", severity="WARNING")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        known_pids = current_pids
        time.sleep(3)
