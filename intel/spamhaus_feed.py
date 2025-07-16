import ipaddress
import requests
import time
from core.alerts import alert

SPAMHAUS_DROP_URL = "https://www.spamhaus.org/drop/drop.txt"

# Shared global list of malicious IP networks cached from Spamhaus DROP
malicious_networks = []

def update_spamhaus_drop_list():
    global malicious_networks
    while True:
        try:
            r = requests.get(SPAMHAUS_DROP_URL, timeout=15)
            r.raise_for_status()
            nets = []
            for line in r.text.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue
                parts = line.split(";")
                cidr_str = parts[0].strip()
                try:
                    net = ipaddress.ip_network(cidr_str, strict=False)
                    nets.append(net)
                except ValueError:
                    alert(f"Invalid network format in Spamhaus DROP: {cidr_str}", severity="WARNING")
            malicious_networks = nets
            alert(f"Spamhaus DROP: Loaded {len(nets)} malicious networks", severity="INFO")
        except Exception as e:
            alert(f"Spamhaus DROP feed update failed: {e}", severity="WARNING")

        time.sleep(86400)  # Update every 24 hours

def start_spamhaus_thread():
    import threading
    threading.Thread(target=update_spamhaus_drop_list, daemon=True).start()
