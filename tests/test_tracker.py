"""Checks the "new device got an IP" rule using the built-in demo capture.

Run:  .venv/bin/python -m unittest discover -s tests -v
"""

import unittest

from scapy.layers.l2 import ARP, Ether

from packetlens import demo
from packetlens.tracker import DeviceTracker


def run_demo() -> DeviceTracker:
    t = DeviceTracker(router_ip=demo.ROUTER_IP, router_mac=demo.ROUTER_MAC, subnet=demo.SUBNET)
    for pkt in demo.build_demo_packets():
        t.handle(pkt)
    return t


class TestJoinRule(unittest.TestCase):
    def setUp(self):
        self.t = run_demo()

    def dev(self, mac):
        self.assertIn(mac, self.t.devices)
        return self.t.devices[mac]

    def test_existing_devices_from_arp(self):
        for ip, mac in (demo.LAPTOP, demo.TV):
            d = self.dev(mac)
            self.assertEqual((d.ip, d.origin, d.found_by), (ip, "existing", "ARP traffic"))

    def test_join_confirmed_by_dhcp_ack(self):
        d = self.dev(demo.PHONE[1])
        self.assertEqual((d.ip, d.origin, d.found_by, d.hostname),
                         (demo.PHONE[0], "joined", "DHCP ACK", "Pixel-8"))
        self.assertTrue(d.randomized_mac)

    def test_join_confirmed_by_request_plus_arp(self):
        d = self.dev(demo.NEW_LAPTOP[1])
        self.assertEqual((d.ip, d.origin, d.found_by, d.hostname),
                         (demo.NEW_LAPTOP[0], "joined", "DHCP Request + ARP", "Lab-Laptop"))
        self.assertFalse(d.randomized_mac)

    def test_reconnect_without_discover(self):
        d = self.dev(demo.TABLET[1])
        self.assertEqual((d.ip, d.origin, d.found_by), (demo.TABLET[0], "joined", "DHCP ACK"))

    def test_nothing_left_pending(self):
        self.assertEqual(self.t.pending, {})

    def test_router_is_not_a_new_device(self):
        self.assertEqual(self.dev(demo.ROUTER_MAC).role, "router")


class TestEdgeCases(unittest.TestCase):
    def test_request_alone_is_not_enough(self):
        t = DeviceTracker(router_mac=demo.ROUTER_MAC, subnet=demo.SUBNET)
        request = demo._dhcp_from_client("aa:bb:cc:00:00:01", "request", b"x", 1, requested="192.168.50.77")
        request.time = 100.0
        t.handle(request)
        self.assertNotIn("aa:bb:cc:00:00:01", t.devices)
        self.assertIn("aa:bb:cc:00:00:01", t.pending)

    def test_pending_expires(self):
        t = DeviceTracker(router_mac=demo.ROUTER_MAC, subnet=demo.SUBNET)
        request = demo._dhcp_from_client("aa:bb:cc:00:00:01", "request", b"x", 1, requested="192.168.50.77")
        request.time = 100.0
        t.handle(request)
        later = Ether(src="10:22:33:44:55:66") / ARP(hwsrc="10:22:33:44:55:66", psrc="192.168.50.9")
        later.time = 200.0
        t.handle(later)
        self.assertEqual(t.pending, {})
        self.assertEqual(t.log[-2].level, "warn")

    def test_rogue_dhcp_server_warning(self):
        t = DeviceTracker(router_mac=demo.ROUTER_MAC, subnet=demo.SUBNET)
        offer = demo._dhcp_from_router("aa:bb:cc:00:00:01", "offer", "192.168.50.77", 1, broadcast=True)
        offer[Ether].src = "66:66:66:66:66:66"
        t.handle(offer)
        self.assertTrue(any("rogue" in e.text for e in t.log))

    def test_arp_outside_subnet_ignored(self):
        t = DeviceTracker(subnet=demo.SUBNET)
        t.handle(Ether(src="10:22:33:44:55:66") / ARP(hwsrc="10:22:33:44:55:66", psrc="10.0.0.5"))
        self.assertEqual(t.devices, {})


if __name__ == "__main__":
    unittest.main()
