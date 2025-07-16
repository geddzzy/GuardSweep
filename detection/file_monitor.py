import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.alerts import alert
from detection.yara_scanner import scan_file_with_yara, quarantine_file

class FileMonitor(FileSystemEventHandler):
    def __init__(self, ignored_paths, suspicious_extensions, enable_quarantine, yara_rules):
        self.ignored_paths = ignored_paths
        self.suspicious_extensions = suspicious_extensions
        self.enable_quarantine = enable_quarantine
        self.yara_rules = yara_rules

    def on_created(self, event):
        if event.is_directory:
            return
        path_lower = event.src_path.lower()
        if any(ignored.lower() in path_lower for ignored in self.ignored_paths):
            return

        if not os.path.exists(event.src_path):
            alert(f"File {event.src_path} was created but no longer exists.", severity="INFO")
            return

        _, ext = os.path.splitext(event.src_path)
        if ext.lower() not in self.suspicious_extensions:
            return

        alert(f"Suspicious file created: {event.src_path}")

        matches = scan_file_with_yara(self.yara_rules, event.src_path)
        if matches:
            alert(f"YARA matched: {','.join(matches)} on file {event.src_path}", severity="WARNING")
            if self.enable_quarantine:
                quarantine_file(event.src_path)
        else:
            alert(f"No YARA matches for {event.src_path}")

def start_file_monitor(monitor_dir, ignored_paths, suspicious_extensions, enable_quarantine, yara_rules):
    event_handler = FileMonitor(ignored_paths, suspicious_extensions, enable_quarantine, yara_rules)
    observer = Observer()
    observer.schedule(event_handler, path=monitor_dir, recursive=True)
    observer.start()
    return observer
