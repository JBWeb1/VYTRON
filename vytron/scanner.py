"""Discover devices on the local network.

Works without extra packages: a ping sweep fills the operating system's
ARP table, then the ARP table is read to get each device's MAC address.
"""

import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
MAC_RE = re.compile(r"\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b")

IS_WINDOWS = platform.system() == "Windows"


def normalize_mac(mac):
    """Return a MAC address as lowercase, colon-separated, zero-padded."""
    parts = re.split(r"[:-]", mac)
    return ":".join(p.zfill(2).lower() for p in parts)


def is_real_device_mac(mac):
    """Filter out broadcast, multicast and empty entries."""
    if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
        return False
    # The lowest bit of the first byte marks a multicast address.
    return int(mac.split(":")[0], 16) & 1 == 0


def parse_arp_output(text):
    """Parse output from `arp -a`, `ip neigh` or /proc/net/arp.

    Returns a dict of {ip: mac}.
    """
    devices = {}
    for line in text.splitlines():
        ip_match = IP_RE.search(line)
        mac_match = MAC_RE.search(line)
        if not ip_match or not mac_match:
            continue
        if "incomplete" in line.lower():
            continue
        mac = normalize_mac(mac_match.group(1))
        if is_real_device_mac(mac):
            devices[ip_match.group(1)] = mac
    return devices


def read_arp_table():
    """Read the operating system's ARP table as {ip: mac}."""
    commands = [["arp", "-a"], ["ip", "neigh"]]
    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            continue
        devices = parse_arp_output(result.stdout)
        if devices:
            return devices
    try:
        with open("/proc/net/arp") as f:
            return parse_arp_output(f.read())
    except OSError:
        return {}


def local_ip():
    """Find this computer's LAN IP address (no traffic is actually sent)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]


def default_network():
    """Guess the local network, assuming a typical /24 office network."""
    return ipaddress.ip_network(f"{local_ip()}/24", strict=False)


def ping(ip):
    """Send one ping. Returns True if the device answered."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", "1000", str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def lookup_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


def scan(network=None, workers=64):
    """Scan the network and return a list of device dicts."""
    network = ipaddress.ip_network(network) if network else default_network()
    hosts = list(network.hosts())
    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(ping, hosts))

    arp = read_arp_table()
    in_network = {ip: mac for ip, mac in arp.items()
                  if ipaddress.ip_address(ip) in network}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        names = dict(zip(in_network, pool.map(lookup_hostname, in_network)))

    return [{"ip": ip, "mac": mac, "hostname": names[ip]}
            for ip, mac in sorted(in_network.items(),
                                  key=lambda kv: ipaddress.ip_address(kv[0]))]
