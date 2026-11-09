"""A made-up capture for testing PacketLens without real devices.

It plays out on a fictional network 192.168.50.0/24:
  * a laptop and a smart TV are already connected (seen via ARP),
  * a phone joins and the router's DHCP ACK is broadcast  -> confirmed by ACK,
  * a laptop joins but the ACK is unicast (we don't see it) -> confirmed by ARP,
  * a tablet reconnects (skips Discover, sends Request)   -> confirmed by ACK,
  * then normal traffic: DNS (failing - the router has no internet), a ping,
    an mDNS query, and an HTTP login to the router's admin page. Click that
    POST in the packet table: the password is readable, because HTTP isn't encrypted,
  * finally PacketLens (this Mac, .5) sends ARP check-ins: the TV answers, the
    phone doesn't answer three in a row -> the phone has left the network.

Write it to a file and open it in Wireshark to compare:
    python -m packetlens.demo samples/demo.pcap
"""

from __future__ import annotations

import sys
from pathlib import Path

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

SUBNET = "192.168.50.0/24"
ROUTER_IP, ROUTER_MAC = "192.168.50.1", "00:00:5e:00:53:01"  # documentation MAC (RFC 7042)
SELF_IP, SELF_MAC = "192.168.50.5", "00:00:5e:00:53:05"      # the Mac running PacketLens
BCAST = "ff:ff:ff:ff:ff:ff"

LAPTOP = ("192.168.50.10", "3c:22:fb:10:10:10")
TV = ("192.168.50.20", "a4:30:7a:20:20:20")
PHONE = ("192.168.50.101", "da:91:4e:aa:01:01", b"Pixel-8")
NEW_LAPTOP = ("192.168.50.102", "f0:18:98:bb:02:02", b"Lab-Laptop")
TABLET = ("192.168.50.103", "a2:c5:11:cc:03:03", b"iPad")


def _mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))


def _dhcp_from_client(mac: str, msg: str, hostname: bytes, xid: int, requested: str | None = None):
    opts = [("message-type", msg), ("hostname", hostname), ("vendor_class_id", b"android-dhcp-14")]
    if requested:
        opts += [("requested_addr", requested), ("server_id", ROUTER_IP)]
    return (Ether(src=mac, dst=BCAST) / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=_mac_bytes(mac), xid=xid, flags=0x8000)
            / DHCP(options=opts + ["end"]))


def _dhcp_from_router(mac: str, msg: str, ip: str, xid: int, broadcast: bool):
    dst_mac, dst_ip = (BCAST, "255.255.255.255") if broadcast else (mac, ip)
    opts = [("message-type", msg), ("server_id", ROUTER_IP), ("lease_time", 86400),
            ("subnet_mask", "255.255.255.0"), ("router", ROUTER_IP), "end"]
    return (Ether(src=ROUTER_MAC, dst=dst_mac) / IP(src=ROUTER_IP, dst=dst_ip)
            / UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr=ip, siaddr=ROUTER_IP,
                                              chaddr=_mac_bytes(mac), xid=xid)
            / DHCP(options=opts))


def _arp(src_mac: str, src_ip: str, target_ip: str, op: int = 1):
    return Ether(src=src_mac, dst=BCAST) / ARP(op=op, hwsrc=src_mac, psrc=src_ip, pdst=target_ip)


def _checkin(device: tuple):
    """This Mac asking a device 'are you still at your IP?' (broadcast ARP request)."""
    return Ether(src=SELF_MAC, dst=BCAST) / ARP(op=1, hwsrc=SELF_MAC, psrc=SELF_IP, pdst=device[0])


def _ip(src: tuple, dst: tuple):
    """Ethernet + IP between two (ip, mac, ...) devices."""
    return Ether(src=src[1], dst=dst[1]) / IP(src=src[0], dst=dst[0])


def _web_session(client: tuple, server: tuple) -> list[tuple[float, object]]:
    """TCP handshake, a page load and a cleartext login to the router's admin page."""
    cport, c, s = 51515, 1000, 5000
    get = b"GET /login.html HTTP/1.1\r\nHost: 192.168.50.1\r\n\r\n"
    page = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 18\r\n\r\n<form>Login</form>"
    body = b"username=admin&password=demo-pass-123"
    post = (b"POST /login HTTP/1.1\r\nHost: 192.168.50.1\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body)
    up = lambda flags, seq, ack, data=b"": _ip(client, server) / TCP(  # noqa: E731
        sport=cport, dport=80, flags=flags, seq=seq, ack=ack) / (Raw(data) if data else b"")
    down = lambda flags, seq, ack, data=b"": _ip(server, client) / TCP(  # noqa: E731
        sport=80, dport=cport, flags=flags, seq=seq, ack=ack) / (Raw(data) if data else b"")
    return [
        (0.00, up("S", c, 0)),
        (0.01, down("SA", s, c + 1)),
        (0.02, up("A", c + 1, s + 1)),
        (0.03, up("PA", c + 1, s + 1, get)),
        (0.05, down("PA", s + 1, c + 1 + len(get), page)),
        (2.50, up("PA", c + 1 + len(get), s + 1 + len(page), post)),
        (2.52, down("A", s + 1 + len(page), c + 1 + len(get) + len(post))),
    ]


def build_demo_packets(start: float = 1_700_000_000.0) -> list:
    router = (ROUTER_IP, ROUTER_MAC)
    mdns = ("224.0.0.251", "01:00:5e:00:00:fb")
    timeline = [
        # Background: devices that were already here.
        (0.0, _arp(ROUTER_MAC, ROUTER_IP, LAPTOP[0])),
        (0.3, _arp(LAPTOP[1], LAPTOP[0], ROUTER_IP, op=2)),
        (1.5, _arp(TV[1], TV[0], ROUTER_IP)),

        # Phone joins - full DORA, router broadcasts Offer and ACK.
        (4.0, _dhcp_from_client(PHONE[1], "discover", PHONE[2], 0x1001)),
        (4.2, _dhcp_from_router(PHONE[1], "offer", PHONE[0], 0x1001, broadcast=True)),
        (4.5, _dhcp_from_client(PHONE[1], "request", PHONE[2], 0x1001, requested=PHONE[0])),
        (4.7, _dhcp_from_router(PHONE[1], "ack", PHONE[0], 0x1001, broadcast=True)),

        # New laptop joins - Offer/ACK go only to the laptop, so we never capture them.
        (10.0, _dhcp_from_client(NEW_LAPTOP[1], "discover", NEW_LAPTOP[2], 0x2002)),
        (10.4, _dhcp_from_client(NEW_LAPTOP[1], "request", NEW_LAPTOP[2], 0x2002,
                                 requested=NEW_LAPTOP[0])),
        (11.0, _arp(NEW_LAPTOP[1], "0.0.0.0", NEW_LAPTOP[0])),          # ARP probe
        (12.0, _arp(NEW_LAPTOP[1], NEW_LAPTOP[0], NEW_LAPTOP[0])),      # ARP announcement

        # Tablet reconnects with an IP it remembers - straight to Request.
        (17.0, _dhcp_from_client(TABLET[1], "request", TABLET[2], 0x3003, requested=TABLET[0])),
        (17.2, _dhcp_from_router(TABLET[1], "ack", TABLET[0], 0x3003, broadcast=True)),

        # Everyday traffic once they're online.
        (19.0, _ip(PHONE, router) / UDP(sport=50123, dport=53)
               / DNS(id=0x1a2b, rd=1, qd=DNSQR(qname="connectivitycheck.gstatic.com"))),
        (19.1, _ip(router, PHONE) / UDP(sport=53, dport=50123)
               / DNS(id=0x1a2b, qr=1, ra=1, rcode=2, qd=DNSQR(qname="connectivitycheck.gstatic.com"))),
        (20.0, _ip(TABLET, mdns) / UDP(sport=5353, dport=5353)
               / DNS(id=0, qd=DNSQR(qname="_airplay._tcp.local", qtype="PTR"))),
        (21.0, _ip(NEW_LAPTOP, router) / ICMP(type=8, id=0x4c, seq=1) / Raw(b"ping-demo-payload")),
        (21.01, _ip(router, NEW_LAPTOP) / ICMP(type=0, id=0x4c, seq=1) / Raw(b"ping-demo-payload")),
        *[(23.0 + t, pkt) for t, pkt in _web_session(NEW_LAPTOP, router)],

        # ARP check-ins from this Mac. The TV answers; the phone has walked away.
        (28.0, _checkin(TV)),
        (28.02, Ether(src=TV[1], dst=SELF_MAC) / ARP(op=2, hwsrc=TV[1], psrc=TV[0],
                                                     hwdst=SELF_MAC, pdst=SELF_IP)),
        (30.0, _checkin(PHONE)),
        (36.0, _checkin(PHONE)),
        (42.0, _checkin(PHONE)),
        (48.0, _ip(TABLET, mdns) / UDP(sport=5353, dport=5353)
               / DNS(id=0, qd=DNSQR(qname="_companion-link._tcp.local", qtype="PTR"))),
    ]
    packets = []
    for offset, pkt in timeline:
        wire = Ether(bytes(pkt))  # rebuild from raw bytes, exactly like a real capture
        wire.time = start + offset
        packets.append(wire)
    return packets


if __name__ == "__main__":
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "samples/demo.pcap")
    path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(path), build_demo_packets())
    print(f"Wrote {path}")
