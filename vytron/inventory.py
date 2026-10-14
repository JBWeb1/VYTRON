"""Keep a saved list of known devices and detect new ones."""

import json
import os
from datetime import datetime, timezone


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Inventory:
    """Devices stored by MAC address in a JSON file."""

    def __init__(self, path):
        self.path = path
        self.devices = {}
        if os.path.exists(path):
            with open(path) as f:
                self.devices = json.load(f)

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.devices, f, indent=2, sort_keys=True)
        os.replace(tmp, self.path)

    def update(self, scanned):
        """Merge scan results in. Returns (new_devices, ip_changes).

        new_devices: devices never seen before.
        ip_changes: (device, old_ip) for known devices whose IP changed.
        """
        new_devices, ip_changes = [], []
        timestamp = now()
        for dev in scanned:
            mac = dev["mac"]
            known = self.devices.get(mac)
            if known is None:
                record = {
                    "mac": mac,
                    "ip": dev["ip"],
                    "hostname": dev["hostname"],
                    "name": "",
                    "approved": False,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                }
                self.devices[mac] = record
                new_devices.append(record)
            else:
                if known["ip"] != dev["ip"]:
                    ip_changes.append((known, known["ip"]))
                    known["ip"] = dev["ip"]
                if dev["hostname"]:
                    known["hostname"] = dev["hostname"]
                known["last_seen"] = timestamp
        return new_devices, ip_changes

    def update_ports(self, mac, open_ports):
        """Save a device's open ports. Returns ports not open last time."""
        dev = self.devices[mac]
        previous = set(dev.get("open_ports", []))
        dev["open_ports"] = sorted(open_ports)
        dev["ports_checked"] = now()
        return sorted(set(open_ports) - previous)

    def unapproved(self):
        return [d for d in self.devices.values() if not d["approved"]]

    def approve(self, mac, name=""):
        """Mark a device as trusted. Returns False if the MAC is unknown."""
        dev = self.devices.get(mac.lower().replace("-", ":"))
        if dev is None:
            return False
        dev["approved"] = True
        if name:
            dev["name"] = name
        return True

    def approve_all(self):
        for dev in self.devices.values():
            dev["approved"] = True

    def remove(self, mac):
        return self.devices.pop(mac.lower().replace("-", ":"), None) is not None
