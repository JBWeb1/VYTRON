"""Command line interface: python -m vytron <command>"""

import argparse
import os
import sys
import time

from . import alerts, scanner
from .inventory import Inventory

DATA_DIR = os.environ.get("VYTRON_DATA_DIR", os.path.join(os.path.expanduser("~"), ".vytron"))


def data_path(name):
    os.makedirs(DATA_DIR, exist_ok=True)
    return os.path.join(DATA_DIR, name)


def run_scan(inv, network):
    print(f"Scanning {network or scanner.default_network()} ...")
    found = scanner.scan(network)
    new_devices, ip_changes = inv.update(found)
    inv.save()
    print(f"{len(found)} device(s) online, {len(new_devices)} new.")
    return found, new_devices, ip_changes


def report(new_devices, ip_changes, baseline):
    log = data_path("alerts.log")
    if new_devices and not baseline:
        alerts.alert("New device on network",
                     alerts.build_new_device_message(new_devices), log)
    for dev, old_ip in ip_changes:
        if dev["approved"]:
            continue
        alerts.alert("Unapproved device changed IP",
                     f"{alerts.describe(dev)} (was {old_ip})", log)


def cmd_scan(args, inv):
    baseline = not inv.devices
    found, new_devices, ip_changes = run_scan(inv, args.network)
    if baseline:
        print("\nFirst scan: these devices were saved as your starting list.")
        print("Review them, then approve the ones you trust (or run `approve --all`).")
    print()
    for dev in found:
        status = "OK " if inv.devices[dev["mac"]]["approved"] else "NEW"
        print(f"  [{status}] {alerts.describe(inv.devices[dev['mac']])}")
    report(new_devices, ip_changes, baseline)


def cmd_watch(args, inv):
    print(f"Watching the network every {args.interval} seconds. Press Ctrl+C to stop.")
    try:
        while True:
            baseline = not inv.devices
            _, new_devices, ip_changes = run_scan(inv, args.network)
            report(new_devices, ip_changes, baseline)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")


def cmd_list(args, inv):
    if not inv.devices:
        print("No devices saved yet. Run: python -m vytron scan")
        return
    print(f"{'STATUS':<9}{'IP':<17}{'MAC':<19}{'NAME / HOSTNAME':<30}LAST SEEN")
    for dev in sorted(inv.devices.values(), key=lambda d: d["ip"]):
        status = "approved" if dev["approved"] else "UNKNOWN"
        label = dev["name"] or dev["hostname"] or "-"
        print(f"{status:<9}{dev['ip']:<17}{dev['mac']:<19}{label[:29]:<30}{dev['last_seen']}")


def cmd_approve(args, inv):
    if args.all:
        inv.approve_all()
        inv.save()
        print(f"Approved all {len(inv.devices)} device(s).")
        return
    if not args.mac:
        sys.exit("Give a MAC address or use --all.")
    if not inv.approve(args.mac, args.name):
        sys.exit(f"No device with MAC {args.mac}. Run `python -m vytron list` to see devices.")
    inv.save()
    print(f"Approved {args.mac}.")


def cmd_remove(args, inv):
    if not inv.remove(args.mac):
        sys.exit(f"No device with MAC {args.mac}.")
    inv.save()
    print(f"Removed {args.mac}.")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="vytron", description="Small business LAN monitor.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("scan", help="Scan the network once and report new devices")
    p.add_argument("--network", help="Network to scan, e.g. 192.168.1.0/24 (auto-detected if omitted)")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("watch", help="Keep scanning and alert on new devices")
    p.add_argument("--network", help="Network to scan, e.g. 192.168.1.0/24")
    p.add_argument("--interval", type=int, default=300, help="Seconds between scans (default 300)")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser("list", help="Show all saved devices")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("approve", help="Mark a device as trusted")
    p.add_argument("mac", nargs="?", help="MAC address of the device")
    p.add_argument("--name", default="", help="A friendly name, e.g. \"Reception PC\"")
    p.add_argument("--all", action="store_true", help="Approve every saved device")
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("remove", help="Forget a device")
    p.add_argument("mac")
    p.set_defaults(func=cmd_remove)

    args = parser.parse_args(argv)
    inv = Inventory(data_path("devices.json"))
    args.func(args, inv)


if __name__ == "__main__":
    main()
