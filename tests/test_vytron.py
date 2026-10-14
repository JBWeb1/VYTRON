import os
import tempfile
import unittest
from unittest import mock

from vytron import scanner
from vytron.__main__ import main
from vytron.inventory import Inventory

WINDOWS_ARP = """
Interface: 192.168.1.50 --- 0x5
  Internet Address      Physical Address      Type
  192.168.1.1           a4-2b-b0-11-22-33     dynamic
  192.168.1.20          3c-52-82-aa-bb-cc     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
"""

MAC_ARP = """
? (192.168.1.1) at a4:2b:b0:11:22:33 on en0 ifscope [ethernet]
? (192.168.1.20) at 3c:52:82:aa:bb:cc on en0 ifscope [ethernet]
? (192.168.1.30) at (incomplete) on en0 ifscope [ethernet]
? (192.168.1.40) at 0:1b:2c:3:4:5 on en0 ifscope [ethernet]
"""

LINUX_IP_NEIGH = """
192.168.1.1 dev eth0 lladdr a4:2b:b0:11:22:33 REACHABLE
192.168.1.20 dev eth0 lladdr 3c:52:82:aa:bb:cc STALE
192.168.1.30 dev eth0  FAILED
"""


class ParseArpTests(unittest.TestCase):
    expected = {"192.168.1.1": "a4:2b:b0:11:22:33", "192.168.1.20": "3c:52:82:aa:bb:cc"}

    def test_windows(self):
        self.assertEqual(scanner.parse_arp_output(WINDOWS_ARP), self.expected)

    def test_mac(self):
        result = scanner.parse_arp_output(MAC_ARP)
        self.assertEqual(result["192.168.1.40"], "00:1b:2c:03:04:05")
        self.assertNotIn("192.168.1.30", result)

    def test_linux(self):
        self.assertEqual(scanner.parse_arp_output(LINUX_IP_NEIGH), self.expected)


def device(ip, mac, hostname=""):
    return {"ip": ip, "mac": mac, "hostname": hostname}


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "devices.json")

    def tearDown(self):
        self.dir.cleanup()

    def test_new_device_detected_once(self):
        inv = Inventory(self.path)
        new, _ = inv.update([device("192.168.1.1", "aa:aa:aa:aa:aa:aa")])
        self.assertEqual(len(new), 1)
        new, _ = inv.update([device("192.168.1.1", "aa:aa:aa:aa:aa:aa")])
        self.assertEqual(new, [])

    def test_save_load_and_approve(self):
        inv = Inventory(self.path)
        inv.update([device("192.168.1.1", "aa:aa:aa:aa:aa:aa")])
        self.assertTrue(inv.approve("AA-AA-AA-AA-AA-AA", "Router"))
        inv.save()
        loaded = Inventory(self.path)
        self.assertEqual(loaded.unapproved(), [])
        self.assertEqual(loaded.devices["aa:aa:aa:aa:aa:aa"]["name"], "Router")

    def test_ip_change(self):
        inv = Inventory(self.path)
        inv.update([device("192.168.1.5", "aa:aa:aa:aa:aa:aa")])
        _, changes = inv.update([device("192.168.1.9", "aa:aa:aa:aa:aa:aa")])
        self.assertEqual(changes[0][1], "192.168.1.5")
        self.assertEqual(inv.devices["aa:aa:aa:aa:aa:aa"]["ip"], "192.168.1.9")


class CliTests(unittest.TestCase):
    def test_second_scan_alerts_on_new_device(self):
        with tempfile.TemporaryDirectory() as d, \
                mock.patch("vytron.__main__.DATA_DIR", d), \
                mock.patch("vytron.alerts.email_settings", return_value=None), \
                mock.patch("vytron.scanner.scan") as scan:
            scan.return_value = [device("192.168.1.1", "aa:aa:aa:aa:aa:aa")]
            main(["scan", "--network", "192.168.1.0/24"])
            self.assertFalse(os.path.exists(os.path.join(d, "alerts.log")))

            main(["approve", "--all"])
            scan.return_value.append(device("192.168.1.66", "bb:bb:bb:bb:bb:bb"))
            main(["scan", "--network", "192.168.1.0/24"])
            with open(os.path.join(d, "alerts.log")) as f:
                log = f.read()
            self.assertIn("bb:bb:bb:bb:bb:bb", log)
            self.assertNotIn("aa:aa:aa:aa:aa:aa", log)


if __name__ == "__main__":
    unittest.main()
