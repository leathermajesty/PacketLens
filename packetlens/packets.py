"""Turn captured packets into table rows and Wireshark-style details.

summarize(pkt, no)  -> one row: No., Source, Destination, Protocol, Length, Info
dissect(pkt)        -> every layer with its fields, plus a hex dump
"""

from __future__ import annotations

from scapy.fields import ConditionalField
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, dnsqtypes
from scapy.layers.eap import EAPOL
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import NoPayload, Padding, Raw

from .tracker import DHCP_TYPES

BROADCAST = "ff:ff:ff:ff:ff:ff"

# Well-known ports -> protocol label (what's *probably* on that port).
TCP_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3",
             139: "NetBIOS", 143: "IMAP", 443: "TLS", 445: "SMB", 853: "DoT",
             3389: "RDP", 8080: "HTTP", 8443: "TLS"}
UDP_PORTS = {53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 123: "NTP", 137: "NBNS",
             138: "NetBIOS", 161: "SNMP", 443: "QUIC", 1900: "SSDP", 5353: "mDNS",
             5355: "LLMNR"}
IP_PROTOCOLS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH",
                58: "ICMPv6", 89: "OSPF", 103: "PIM", 112: "VRRP", 132: "SCTP"}
ICMP_TYPES = {0: "Echo (ping) reply", 3: "Destination unreachable", 5: "Redirect",
              8: "Echo (ping) request", 11: "Time-to-live exceeded"}
TCP_FLAGS = [("S", "SYN"), ("F", "FIN"), ("R", "RST"), ("P", "PSH"), ("A", "ACK"),
             ("U", "URG"), ("E", "ECE"), ("C", "CWR")]
DNS_ERRORS = {1: "Format error", 2: "Server failure", 3: "No such name", 5: "Refused"}
LAYER_TAGS = {"Ether": "eth", "IP": "ip", "IPv6": "ipv6", "TCP": "tcp", "UDP": "udp",
              "ARP": "arp", "ICMP": "icmp", "DNS": "dns", "BOOTP": "bootp", "DHCP": "dhcp",
              "EAPOL": "eapol", "Raw": "data"}

HTTP_STARTS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"HTTP/")


# ------------------------------------------------------------------ summary

def _dns_name(value) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return str(value).rstrip(".")


def _dns_info(dns) -> str:
    questions = list(dns.qd or [])
    q = questions[0] if questions else None
    qtype = dnsqtypes.get(q.qtype, str(q.qtype)) if q else ""
    name = _dns_name(q.qname) if q else ""
    text = f"Standard query{' response' if dns.qr else ''} 0x{dns.id:04x} {qtype} {name}".rstrip()
    if dns.qr:
        if dns.rcode:
            text += f"  {DNS_ERRORS.get(dns.rcode, f'error {dns.rcode}')}"
        answers = [_dns_name(rr.rdata) for rr in list(dns.an or [])[:3] if hasattr(rr, "rdata")]
        if answers:
            text += "  → " + ", ".join(answers)
    return text


def _arp_info(arp) -> str:
    if arp.op == 1:
        if arp.psrc == "0.0.0.0":
            return f"Who has {arp.pdst}? (ARP Probe)"
        if arp.psrc == arp.pdst:
            return f"ARP Announcement for {arp.psrc}"
        return f"Who has {arp.pdst}? Tell {arp.psrc}"
    if arp.op == 2:
        return f"{arp.psrc} is at {arp.hwsrc}"
    return f"ARP opcode {arp.op}"


def _tcp_flags(tcp) -> str:
    flags = str(tcp.flags)
    return ", ".join(name for letter, name in TCP_FLAGS if letter in flags)


def _tls_info(data: bytes) -> str:
    kinds = {0x14: "Change Cipher Spec", 0x15: "Alert", 0x16: "Handshake", 0x17: "Application Data"}
    if not data or data[0] not in kinds:
        return "Continuation data"
    if data[0] == 0x16 and len(data) > 5:
        return {1: "Client Hello", 2: "Server Hello", 11: "Certificate"}.get(data[5], "Handshake")
    return kinds[data[0]]


def _first_line(data: bytes, limit: int = 90) -> str:
    line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    return line if len(line) <= limit else line[: limit - 1] + "…"


def _transport(pkt) -> tuple[str, str]:
    """(protocol, info) for TCP/UDP and what's inside them."""
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        payload = bytes(tcp.payload)
        ports = f"{tcp.sport} → {tcp.dport}"
        proto = TCP_PORTS.get(tcp.dport) or TCP_PORTS.get(tcp.sport) or "TCP"
        if payload and payload.startswith(HTTP_STARTS):
            return "HTTP", _first_line(payload)
        if payload and proto == "TLS":
            return "TLS", _tls_info(payload)
        if not payload:
            proto = "TCP"   # handshakes and ACKs: call them TCP, like Wireshark does
        info = f"{ports} [{_tcp_flags(tcp)}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={len(payload)}"
        return proto, info
    udp = pkt[UDP]
    proto = UDP_PORTS.get(udp.dport) or UDP_PORTS.get(udp.sport) or "UDP"
    return proto, f"{udp.sport} → {udp.dport} Len={len(bytes(udp.payload))}"


def _classify(pkt) -> tuple[str, str]:
    if pkt.haslayer(ARP):
        return "ARP", _arp_info(pkt[ARP])
    if pkt.haslayer(EAPOL):
        return "EAPOL", "EAPOL (Wi-Fi authentication)"
    if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
        kind = next((o[1] for o in pkt[DHCP].options if isinstance(o, tuple) and o[0] == "message-type"), None)
        kind = DHCP_TYPES.get(kind, str(kind)) if isinstance(kind, int) else str(kind).capitalize()
        return "DHCP", f"DHCP {kind} - Transaction ID 0x{pkt[BOOTP].xid:08x}"
    if pkt.haslayer(DNS):
        udp = pkt[UDP] if pkt.haslayer(UDP) else None
        label = "mDNS" if udp and 5353 in (udp.sport, udp.dport) else \
                "LLMNR" if udp and 5355 in (udp.sport, udp.dport) else "DNS"
        return label, _dns_info(pkt[DNS])
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        info = ICMP_TYPES.get(icmp.type, f"Type {icmp.type}")
        if icmp.type in (0, 8):
            info += f"  id=0x{icmp.id:04x}, seq={icmp.seq}"
        return "ICMP", info
    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        return _transport(pkt)
    if pkt.haslayer(IPv6) and "ICMPv6" in pkt.lastlayer().name:
        return "ICMPv6", pkt.lastlayer().name.replace("ICMPv6 Neighbor Discovery - ", "")
    if pkt.haslayer(IP) or pkt.haslayer(IPv6):
        last = pkt.lastlayer()
        if not isinstance(last, (Raw, Padding)):
            return last.name.split(" ")[0], last.name
        number = pkt[IP].proto if pkt.haslayer(IP) else pkt[IPv6].nh
        name = IP_PROTOCOLS.get(number, "IP")
        return name, f"IP protocol {number}" + (f" ({name})" if name != "IP" else "")
    if pkt.haslayer(Ether):
        return f"0x{pkt[Ether].type:04x}", f"Ethertype 0x{pkt[Ether].type:04x}"
    return pkt.lastlayer().name, pkt.summary()


def _stack(pkt) -> str:
    """Layer list like Wireshark's 'Protocols in frame': eth:ip:udp:dns."""
    tags = []
    for cls in pkt.layers():
        tag = LAYER_TAGS.get(cls.__name__)
        if tag and tag not in tags:
            tags.append(tag)
    return ":".join(tags)


def summarize(pkt, no: int) -> dict:
    """One row of the packet table."""
    src_mac = pkt[Ether].src.lower() if pkt.haslayer(Ether) else None
    dst_mac = pkt[Ether].dst.lower() if pkt.haslayer(Ether) else None
    if pkt.haslayer(IP):
        src, dst = pkt[IP].src, pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src, dst = pkt[IPv6].src, pkt[IPv6].dst
    else:
        src = src_mac or "?"
        dst = "Broadcast" if dst_mac == BROADCAST else (dst_mac or "?")
    proto, info = _classify(pkt)
    stack = _stack(pkt)
    if proto.lower() not in stack.split(":"):
        stack += ":" + proto.lower()
    return {
        "no": no,
        "ts": float(pkt.time),
        "src": src,
        "dst": dst,
        "src_mac": src_mac,
        "dst_mac": dst_mac,
        "proto": proto,
        "length": len(pkt),
        "info": info,
        "stack": stack,
    }


# ------------------------------------------------------------------ details

def _short(text: str, limit: int = 240) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _layer_title(layer) -> str:
    name = type(layer).__name__
    if name == "Ether":
        return f"Ethernet II, Src: {layer.src}, Dst: {layer.dst}"
    if name == "IP":
        return f"Internet Protocol Version 4, Src: {layer.src}, Dst: {layer.dst}"
    if name == "IPv6":
        return f"Internet Protocol Version 6, Src: {layer.src}, Dst: {layer.dst}"
    if name == "TCP":
        return f"Transmission Control Protocol, Src Port: {layer.sport}, Dst Port: {layer.dport}"
    if name == "UDP":
        return f"User Datagram Protocol, Src Port: {layer.sport}, Dst Port: {layer.dport}"
    if name == "ARP":
        return f"Address Resolution Protocol ({ {1: 'request', 2: 'reply'}.get(layer.op, layer.op) })"
    if name == "BOOTP":
        return "Bootstrap Protocol (BOOTP)"
    if name == "DHCP":
        return "DHCP options"
    if name == "DNS":
        return f"Domain Name System ({'response' if layer.qr else 'query'})"
    return layer.name


def _fields(layer) -> list[list[str]]:
    rows = []
    for fld in layer.fields_desc:
        try:
            if isinstance(fld, ConditionalField) and not fld._evalcond(layer):
                continue
            text = fld.i2repr(layer, layer.getfieldval(fld.name))
        except Exception:  # noqa: BLE001 - some fields can't be shown; don't break the panel
            text = "?"
        rows.append([fld.name, _short(str(text))])
    return rows


def _payload_layer(layer) -> dict:
    """Show readable payloads (HTTP, etc.) as text lines, anything else as hex."""
    data = bytes(layer.load)
    printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
    if data and printable / len(data) > 0.9:
        lines = data.decode("latin-1").replace("\r\n", "\n").split("\n")
        fields = [[f"line {i}", _short(line)] for i, line in enumerate(lines[:40], 1)]
        return {"name": f"Payload as text ({len(data)} bytes)", "fields": fields}
    preview = data[:64].hex(" ") + (" …" if len(data) > 64 else "")
    return {"name": f"{layer.name} ({len(data)} bytes)", "fields": [["data", preview]]}


def hexdump_lines(data: bytes) -> list[str]:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk[:8]) + "  " + " ".join(f"{b:02x}" for b in chunk[8:])
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:04x}  {hexpart:<49}  {text}")
    return lines


def dissect(pkt) -> dict:
    layers = []
    layer = pkt
    while layer is not None and not isinstance(layer, NoPayload):
        if isinstance(layer, (Raw, Padding)):
            layers.append(_payload_layer(layer))
        else:
            layers.append({"name": _layer_title(layer), "fields": _fields(layer)})
        layer = layer.payload
    raw = bytes(pkt)
    return {"layers": layers, "hex": hexdump_lines(raw), "length": len(raw)}
