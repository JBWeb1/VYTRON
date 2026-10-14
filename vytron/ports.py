"""Check devices for open network ports that are commonly abused by attackers."""

import socket
from concurrent.futures import ThreadPoolExecutor

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"

# port: (service, risk, advice)
RISKY_PORTS = {
    21: ("FTP", HIGH, "Sends passwords unencrypted. Turn it off or switch to SFTP."),
    22: ("SSH", MEDIUM, "Remote command access. Use key login only, and never expose it to the internet."),
    23: ("Telnet", HIGH, "Unencrypted remote access. Turn it off, it is often used to hack routers and cameras."),
    25: ("SMTP mail", MEDIUM, "Mail server. Make sure it isn't an open relay that anyone can send spam through."),
    80: ("HTTP web page", LOW, "Unencrypted web page, often a device admin page. Make sure its default password is changed."),
    135: ("Windows RPC", MEDIUM, "Windows remote management. Should not be reachable from guest or camera networks."),
    139: ("NetBIOS file sharing", MEDIUM, "Old Windows file sharing. Turn it off if it isn't needed."),
    445: ("SMB file sharing", MEDIUM, "Windows file sharing, used by ransomware to spread. Only file servers should have this open."),
    554: ("RTSP video stream", MEDIUM, "Camera video feed. Make sure it needs a password."),
    1433: ("Microsoft SQL Server", HIGH, "Database. Only allow the computers that need it to connect."),
    2323: ("Telnet (alternate)", HIGH, "Unencrypted remote access, commonly targeted by IoT malware. Turn it off."),
    3306: ("MySQL database", HIGH, "Database. Only allow the computers that need it to connect."),
    3389: ("Remote Desktop (RDP)", HIGH, "A top ransomware entry point. Turn it off or allow it only through a VPN."),
    5432: ("PostgreSQL database", HIGH, "Database. Only allow the computers that need it to connect."),
    5900: ("VNC remote control", HIGH, "Remote screen control, often with weak or no password. Turn it off or use a VPN."),
    5985: ("Windows Remote Management", MEDIUM, "Remote admin access. Should be limited to IT admin computers."),
    6379: ("Redis database", HIGH, "Often has no password by default. Should never be open on the office network."),
    8080: ("Alternate web / admin page", LOW, "Often a device or app admin page. Make sure its default password is changed."),
    8291: ("MikroTik Winbox", HIGH, "Router admin access, frequently attacked. Limit it to admin computers."),
    9100: ("Raw printing", LOW, "Printer port. Normal for printers, but shouldn't appear on other devices."),
    9200: ("Elasticsearch", HIGH, "Search database, often with no password. Lock it down."),
    27017: ("MongoDB database", HIGH, "Often has no password by default. Lock it down."),
}

RISK_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}


def is_port_open(ip, port, timeout=1.0):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            return s.connect_ex((ip, port)) == 0
        except OSError:
            return False


def scan_ports(ips, ports=None, timeout=1.0, workers=128):
    """Check each IP for each port. Returns {ip: [open ports]}."""
    ports = sorted(ports or RISKY_PORTS)
    jobs = [(ip, port) for ip in ips for port in ports]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda job: is_port_open(*job, timeout), jobs)
        found = {ip: [] for ip in ips}
        for (ip, port), is_open in zip(jobs, results):
            if is_open:
                found[ip].append(port)
    return found


def describe_port(port):
    service, risk, advice = RISKY_PORTS.get(port, ("Unknown service", LOW, ""))
    return {"port": port, "service": service, "risk": risk, "advice": advice}


def sort_by_risk(ports):
    return sorted((describe_port(p) for p in ports),
                  key=lambda d: (RISK_ORDER[d["risk"]], d["port"]))
