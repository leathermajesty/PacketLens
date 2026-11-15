"""Traffic statistics: rates, conversations and the per-device detail.

Run:  .venv/bin/python -m unittest discover -s tests -v
"""

import unittest

from packetlens import demo
from packetlens.engine import Engine
from packetlens.netinfo import NetworkInfo
from packetlens.traffic import PAIR_FRESH, PAIR_TTL, WINDOW, TrafficStats

A, B, C = "10:00:00:00:00:0a", "10:00:00:00:00:0b", "10:00:00:00:00:0c"
BCAST = "ff:ff:ff:ff:ff:ff"
KNOWN = {A, B}          # C is a stranger


class TestTrafficStats(unittest.TestCase):
    def setUp(self):
        self.t = TrafficStats()

    def test_rate_is_the_average_of_the_last_ten_seconds(self):
        for i in range(20):                                   # one 100-byte packet per second
            self.t.note(100 + i, A, BCAST, 100, "mDNS", KNOWN)
        self.assertEqual(self.t.rates(119)[A], (1.0, 100))
        self.assertEqual(self.t.rates(119 + 30), {})           # quiet again: nothing to report

    def test_broadcast_counts_only_for_the_sender(self):
        self.t.note(100, A, BCAST, 60, "ARP", KNOWN)
        self.assertIn(A, self.t.rates(100))
        self.assertNotIn(B, self.t.rates(100))
        self.assertEqual(self.t.pairs, {})

    def test_unicast_counts_for_both_and_makes_a_conversation(self):
        self.t.note(100, A, B, 500, "TCP", KNOWN)
        self.t.note(101, B, A, 1500, "TCP", KNOWN)
        self.assertEqual(self.t.rates(101)[A], (0.2, 200))     # 2 packets, 2000 bytes, over 10 s
        self.assertEqual(self.t.rates(101)[B], (0.2, 200))
        (c,) = self.t.conversations(101)
        self.assertEqual((c["a"], c["b"], c["bytes"], c["packets"]), (A, B, 2000, 2))
        self.assertEqual((c["a_to_b"], c["b_to_a"], c["protocols"]), (500, 1500, ["TCP"]))

    def test_arp_and_strangers_make_no_conversation(self):
        self.t.note(100, A, B, 60, "ARP", KNOWN)                # our check-ins are questions, not chat
        self.t.note(100, A, C, 500, "TCP", KNOWN)
        self.t.note(100, C, A, 500, "TCP", KNOWN)
        self.assertEqual(self.t.pairs, {})
        self.assertNotIn(C, self.t.devices)
        self.assertIn(A, self.t.rates(100))                     # but A's own bytes still count

    def test_conversations_fade_then_expire(self):
        self.t.note(100, A, B, 500, "TCP", KNOWN)
        self.assertEqual(len(self.t.conversations(100 + PAIR_FRESH)), 1)
        self.assertEqual(self.t.conversations(100 + PAIR_FRESH + 1), [])
        self.t.prune(100 + PAIR_TTL)
        self.assertEqual(len(self.t.pairs), 1)
        self.t.prune(100 + PAIR_TTL + 1)
        self.assertEqual(self.t.pairs, {})

    def test_device_detail(self):
        for i in range(5):
            self.t.note(100 + i, A, B, 1000, "TCP", KNOWN)
        self.t.note(105, A, BCAST, 80, "mDNS", KNOWN)
        d = self.t.device(A, 105)
        self.assertEqual(len(d["series"]), WINDOW)
        self.assertEqual(d["series"][-2:], [1000, 80])          # seconds 104 and 105
        self.assertEqual(d["peak_bps"], 1000)
        self.assertEqual((d["protocols"][0]["proto"], d["protocols"][0]["share"]), ("TCP", 83))
        self.assertEqual((d["peers"][0]["mac"], d["peers"][0]["sent"], d["peers"][0]["received"]), (B, 5000, 0))
        self.assertEqual(self.t.device(C, 105)["rate"]["bps"], 0)   # a stranger: empty, not an error


class TestEngineTraffic(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(NetworkInfo(iface=None, cidr=demo.SUBNET), source="demo")
        for pkt in demo.build_demo_packets():
            self.engine._feed(pkt)

    def test_snapshot_has_rates_and_conversations(self):
        s = self.engine.snapshot()
        by_mac = {d["mac"]: d for d in s["devices"]}
        self.assertGreater(by_mac[demo.TV[1]]["bps"], 0)        # the iPad just streamed to it
        pairs = {(c["a"], c["b"]) for c in s["conversations"]}
        self.assertIn(tuple(sorted((demo.TABLET[1], demo.TV[1]))), pairs)
        self.assertIn(tuple(sorted((demo.SELF_MAC, demo.ROUTER_MAC))), pairs)

    def test_device_detail(self):
        d = self.engine.device_detail(demo.TV[1])
        self.assertEqual(d["hostname"], "Living-Room-TV")
        self.assertEqual(d["traffic"]["peers"][0]["mac"], demo.TABLET[1])
        self.assertEqual(d["traffic"]["protocols"][0]["proto"], "TCP")
        self.assertIsNone(self.engine.device_detail("00:00:00:00:00:99"))


if __name__ == "__main__":
    unittest.main()
