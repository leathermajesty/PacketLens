"""Checks the packet table rows and the detail view.

Run:  .venv/bin/python -m unittest discover -s tests -v
"""

import unittest

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6ND_NS, IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from packetlens import demo
from packetlens.engine import Engine
from packetlens.netinfo import NetworkInfo
from packetlens.packets import dissect, hexdump_lines, summarize

ROWS = [summarize(p, i) for i, p in enumerate(demo.build_demo_packets(), 1)]


def row(proto: str, contains: str) -> dict:
    for r in ROWS:
        if r["proto"] == proto and contains in r["info"]:
            return r
    raise AssertionError(f"no {proto} row containing {contains!r}")


def wire(pkt):
    return Ether(bytes(pkt))


class TestSummaries(unittest.TestCase):
    def test_arp_rows_use_mac_addresses(self):
        r = row("ARP", "Who has 192.168.50.10")
        self.assertEqual((r["src"], r["dst"]), (demo.ROUTER_MAC, "Broadcast"))
        self.assertEqual(row("ARP", "Probe")["info"], "Who has 192.168.50.102? (ARP Probe)")
        self.assertEqual(row("ARP", "Announcement")["info"], "ARP Announcement for 192.168.50.102")

    def test_dhcp_rows(self):
        r = row("DHCP", "Discover")
        self.assertEqual((r["src"], r["dst"]), ("0.0.0.0", "255.255.255.255"))
        self.assertEqual(r["stack"], "eth:ip:udp:bootp:dhcp")

    def test_dns_query_and_failed_response(self):
        self.assertIn("A connectivitycheck.gstatic.com", row("DNS", "Standard query 0x1a2b")["info"])
        self.assertIn("Server failure", row("DNS", "response")["info"])
        self.assertIn("PTR _airplay._tcp.local", row("mDNS", "query")["info"])

    def test_icmp(self):
        self.assertEqual(row("ICMP", "request")["info"], "Echo (ping) request  id=0x004c, seq=1")

    def test_tcp_handshake_flags(self):
        self.assertIn("[SYN]", row("TCP", "51515 → 80 [SYN]")["info"])
        self.assertIn("[SYN, ACK]", row("TCP", "[SYN, ACK]")["info"])

    def test_http_from_payload(self):
        r = row("HTTP", "POST")
        self.assertEqual(r["info"], "POST /login HTTP/1.1")
        self.assertTrue(r["stack"].endswith(":http"))

    def test_tls_client_hello(self):
        hello = bytes([0x16, 0x03, 0x01, 0x00, 0x30, 0x01]) + b"\x00" * 40
        pkt = wire(Ether() / IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=50000, dport=443, flags="PA") / Raw(hello))
        r = summarize(pkt, 1)
        self.assertEqual((r["proto"], r["info"]), ("TLS", "Client Hello"))

    def test_plain_udp_and_ipv6(self):
        r = summarize(wire(Ether() / IP(src="10.0.0.2", dst="10.0.0.3") / UDP(sport=4000, dport=4001) / b"hi"), 1)
        self.assertEqual((r["proto"], r["info"]), ("UDP", "4000 → 4001 Len=2"))
        r = summarize(wire(Ether() / IPv6(src="fe80::1", dst="ff02::1") / ICMPv6ND_NS(tgt="fe80::2")), 2)
        self.assertEqual((r["proto"], r["info"], r["src"]), ("ICMPv6", "Neighbor Solicitation", "fe80::1"))

    def test_unknown_ip_payload_named_by_protocol_number(self):
        igmp = wire(Ether() / IP(src="10.0.0.2", dst="224.0.0.22", proto=2) / Raw(b"\x22\x00\xfa\x01" + b"\x00" * 4))
        r = summarize(igmp, 1)
        self.assertEqual((r["proto"], r["info"]), ("IGMP", "IP protocol 2 (IGMP)"))


class TestDetails(unittest.TestCase):
    def test_http_login_payload_is_readable(self):
        post = next(p for p in demo.build_demo_packets() if b"password=" in bytes(p))
        d = dissect(post)
        names = [layer["name"] for layer in d["layers"]]
        self.assertEqual(names[:3], ["Ethernet II, Src: f0:18:98:bb:02:02, Dst: 00:00:5e:00:53:01",
                                     "Internet Protocol Version 4, Src: 192.168.50.102, Dst: 192.168.50.1",
                                     "Transmission Control Protocol, Src Port: 51515, Dst Port: 80"])
        self.assertTrue(names[3].startswith("Payload as text"))
        lines = [value for _, value in d["layers"][3]["fields"]]
        self.assertIn("username=admin&password=demo-pass-123", lines)

    def test_hexdump_format(self):
        lines = hexdump_lines(bytes(range(20)))
        self.assertEqual(len(lines), 2)
        self.assertTrue(lines[0].startswith("0000  00 01 02 03 04 05 06 07  08 09"))
        self.assertTrue(lines[1].startswith("0010  10 11 12 13"))


class TestEngineBuffer(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(NetworkInfo(iface=None, cidr=demo.SUBNET), source="demo")
        for pkt in demo.build_demo_packets():
            self.engine._feed(pkt)

    def test_numbering_and_relative_time(self):
        rows = self.engine.packets_since(0)
        self.assertEqual([r["no"] for r in rows], list(range(1, len(ROWS) + 1)))
        self.assertEqual(rows[0]["rel"], 0.0)

    def test_packets_since(self):
        self.assertEqual([r["no"] for r in self.engine.packets_since(20)], list(range(21, len(ROWS) + 1)))
        self.assertEqual(len(self.engine.packets_since(0, limit=5)), 5)

    def test_packet_detail(self):
        self.assertEqual(self.engine.packet_detail(1)["summary"]["proto"], "ARP")
        self.assertIsNone(self.engine.packet_detail(999))


if __name__ == "__main__":
    unittest.main()
