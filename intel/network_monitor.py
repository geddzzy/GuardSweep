import psutil
import time
import platform
import subprocess
from core.alerts import alert
from intel.spamhaus_feed import malicious_networks

def ip_in_malicious_networks(ip_str):
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in malicious_networks)
    except ValueError:
        return False

NETWORK_BLOCK_COMMANDS = {
    "Windows": 'netsh advfirewall firewall add rule name="GuardSweepBlock_{ip}" dir=out action=block remoteip={ip}',
    "Linux": "iptables -A OUTPUT -d {ip} -j DROP",
}

def block_network_ip(ip):
    system = platform.system()
    cmd_template = NETWORK_BLOCK_COMMANDS.get(system)
    if not cmd_template:
        alert(f"Network block not supported on {system}", severity="WARNING")
        return
    cmd = cmd_template.format(ip=ip)
    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        alert(f"Blocked network IP: {ip}", severity="WARNING")
    except subprocess.CalledProcessError as e:
        # Check if rule already exists to avoid spamming logs
        if "already exists" in e.stderr.lower():
            alert(f"Firewall rule for {ip} already exists.", severity="INFO")
        else:
            alert(f"Failed to block IP {ip}: {e.stderr.strip()}", severity="WARNING")
    except Exception as e:
        alert(f"Error executing block command for IP {ip}: {e}", severity="WARNING")

def monitor_network(blacklisted_ips, enable_network_blocking):
    known_blocked = set()
    while True:
        # Loop to correlate PID with connection
        for conn in psutil.net_connections(kind="inet"):
            # Check for a connection with a remote address and a PID
            if conn.raddr and conn.pid:
                remote_ip = conn.raddr.ip
                if remote_ip in blacklisted_ips or ip_in_malicious_networks(remote_ip):
                    
                    # Get process info
                    try:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                        proc_user = proc.username()
                        
                        # The Golden Alert!
                        alert(f"Process '{proc_name}' (PID {conn.pid}, User: {proc_user}) connected to malicious IP: {remote_ip}", severity="ALERT")
                        
                    except psutil.NoSuchProcess:
                        # Process might have already terminated
                        alert(f"Connection from terminated PID {conn.pid} to malicious IP: {remote_ip}", severity="ALERT")
                    
                    # Block the IP if enabled 
                    if enable_network_blocking and remote_ip not in known_blocked:
                        block_network_ip(remote_ip)
                        known_blocked.add(remote_ip)
                        
        time.sleep(10)