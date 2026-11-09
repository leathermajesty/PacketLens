"""Checks the "new device got an IP" rule using the built-in demo capture.

Run:  .venv/bin/python -m unittest discover -s tests -v
"""

import unittest

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether

from packetlens import demo
from packetlens.tracker import DeviceTracker


def run_demo() -> DeviceTracker:
    t = DeviceTracker(router_ip=demo.ROUTER_IP, router_mac=demo.ROUTER_MAC,
                      self_ip=demo.SELF_IP, self_mac=demo.SELF_MAC, subnet=demo.SUBNET)
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

    def test_device_found_from_ip_traffic(self):
        t = DeviceTracker(subnet=demo.SUBNET)
        t.handle(Ether(bytes(Ether(src="10:22:33:44:55:66") / IP(src="192.168.50.44", dst="192.168.50.1"))))
        self.assertEqual(t.devices["10:22:33:44:55:66"].found_by, "IP traffic")


# --------------------------------------------------------------- presence

ME = (demo.SELF_IP, demo.SELF_MAC)
TV = demo.TV


def at(pkt, ts):
    pkt = Ether(bytes(pkt))
    pkt.time = ts
    return pkt


def checkin(device, ts):
    return at(Ether(src=ME[1], dst=device[1]) / ARP(op=1, hwsrc=ME[1], psrc=ME[0], pdst=device[0]), ts)


def reply(device, ts):
    return at(Ether(src=device[1], dst=ME[1]) / ARP(op=2, hwsrc=device[1], psrc=device[0],
                                                    hwdst=ME[1], pdst=ME[0]), ts)


def chatter(device, ts):
    """The device sending something on its own (a DNS query to the router)."""
    return at(Ether(src=device[1], dst=demo.ROUTER_MAC) / IP(src=device[0], dst=demo.ROUTER_IP)
              / UDP(sport=5000, dport=53), ts)


class TestPresence(unittest.TestCase):
    def setUp(self):
        self.t = DeviceTracker(router_ip=demo.ROUTER_IP, router_mac=demo.ROUTER_MAC,
                               self_ip=ME[0], self_mac=ME[1], subnet=demo.SUBNET)
        self.t.add_existing(TV[1], TV[0], "ARP scan", ts=0.0)
        self.tv = self.t.devices[TV[1]]

    def miss(self, start, times):
        for i in range(times):
            self.t.handle(checkin(TV, start + i * 30))
        self.t.tick(start + times * 30)

    def test_demo_phone_goes_offline(self):
        t = run_demo()
        self.assertEqual(t.devices[demo.PHONE[1]].status, "offline")
        self.assertEqual(t.devices[demo.TV[1]].status, "online")
        self.assertTrue(any(e.level == "leave" and "Pixel-8" in e.text for e in t.log))

    def test_answered_checkin_resets_misses(self):
        self.t.handle(checkin(TV, 100))
        self.t.tick(106)
        self.assertEqual(self.tv.missed_checks, 1)
        self.t.handle(checkin(TV, 130))
        self.t.handle(reply(TV, 130.2))
        self.t.tick(140)
        self.assertEqual((self.tv.missed_checks, self.tv.status), (0, "idle"))

    def test_three_misses_means_offline(self):
        self.miss(100, 2)
        self.assertNotEqual(self.tv.status, "offline")
        self.miss(160, 1)
        self.assertEqual(self.tv.status, "offline")
        self.assertEqual(self.t.log[-1].level, "leave")

    def test_any_packet_brings_it_back(self):
        self.miss(100, 3)
        self.t.handle(chatter(TV, 500))
        self.assertEqual(self.tv.status, "online")
        self.assertIn("back online", self.t.log[-1].text)

    def test_idle_when_quiet_but_answering(self):
        self.t.handle(chatter(TV, 100))
        self.t.tick(100 + 61)
        self.assertEqual(self.tv.status, "idle")
        self.t.handle(chatter(TV, 200))
        self.assertEqual(self.tv.status, "online")

    def test_only_our_own_questions_count(self):
        router_asks = at(Ether(src=demo.ROUTER_MAC, dst="ff:ff:ff:ff:ff:ff")
                         / ARP(op=1, hwsrc=demo.ROUTER_MAC, psrc=demo.ROUTER_IP, pdst=TV[0]), 100)
        for i in range(5):
            router_asks.time = 100 + i * 30
            self.t.handle(router_asks)
        self.t.tick(400)
        self.assertEqual(self.tv.missed_checks, 0)

    def test_release_marks_left(self):
        release = demo._dhcp_from_client(TV[1], "release", b"tv", 9)
        release.time = 100
        self.t.handle(release)
        self.assertEqual(self.tv.status, "released")

    def test_checkin_targets_skip_recent_and_self(self):
        self.t.handle(chatter(TV, 100))
        self.assertNotIn((TV[0], TV[1]), self.t.checkin_targets(110, 30))   # talked 10s ago
        self.assertIn((TV[0], TV[1]), self.t.checkin_targets(140, 30))      # quiet for 40s
        self.assertNotIn((ME[0], ME[1]), self.t.checkin_targets(10_000, 30))


if __name__ == "__main__":
    unittest.main()
