import hashlib
import time
import threading
import queue
from core.alerts import alert
import requests

_vt_queue = queue.Queue()
_vt_worker_started = False
_vt_worker_lock = threading.Lock()
_last_vt_call = 0.0
_VT_MIN_INTERVAL_SECONDS = 16.0


def get_file_hash(file_path):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        alert(f"Could not hash file {file_path}: {e}", severity="WARNING")
        return None

def _rate_limit_virustotal():
    global _last_vt_call
    now = time.monotonic()
    elapsed = now - _last_vt_call
    if elapsed < _VT_MIN_INTERVAL_SECONDS:
        time.sleep(_VT_MIN_INTERVAL_SECONDS - elapsed)
    _last_vt_call = time.monotonic()


def check_hash_virustotal(api_key, file_hash, file_path):
    """Checks a file hash against the VirusTotal v3 API."""
    if not api_key:
        alert("VirusTotal API key not configured. Skipping check.", severity="INFO")
        return
    
    if not file_hash:
        return

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        _rate_limit_virustotal()
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            
            # Alert if more than 3 engines flag it as malicious
            if stats.get("malicious", 0) > 3:
                alert(f"VirusTotal ALERT: File '{file_path}' is malicious! Detections: {stats.get('malicious')}/{stats.get('malicious') + stats.get('harmless', 0)}", severity="ALERT")
            else:
                alert(f"VirusTotal: File '{file_path}' appears clean. Detections: {stats.get('malicious', 0)}")
        
        elif response.status_code == 404:
            alert(f"VirusTotal: Hash for '{file_path}' not found in database.", severity="INFO")
        
        else:
            alert(f"VirusTotal API error: Status {response.status_code} - {response.text}", severity="WARNING")

    except requests.RequestException as e:
        alert(f"VirusTotal request failed: {e}", severity="WARNING")


def _vt_worker():
    while True:
        api_key, file_hash, file_path = _vt_queue.get()
        try:
            check_hash_virustotal(api_key, file_hash, file_path)
        finally:
            _vt_queue.task_done()


def start_vt_worker():
    global _vt_worker_started
    with _vt_worker_lock:
        if _vt_worker_started:
            return
        threading.Thread(target=_vt_worker, daemon=True).start()
        _vt_worker_started = True


def enqueue_virustotal_check(api_key, file_hash, file_path):
    """Queue a VirusTotal hash check so filesystem event handling stays responsive."""
    if not api_key or not file_hash:
        return
    start_vt_worker()
    _vt_queue.put((api_key, file_hash, file_path))
