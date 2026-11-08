"""Device tracker: turns captured DHCP/ARP packets into a list of devices.

The rule for "a new device has joined and been given an IP":

    1. We see a DHCP ACK for the device's MAC          -> joined (router confirmed it), or
    2. We see a DHCP Request for an IP, then an ARP    -> joined (device is now using it)
       probe/announcement from the same MAC for that IP

Rule 2 exists because the router often sends the ACK straight to the new device
(unicast), so other computers on the Wi-Fi never see it. The Request and the ARP
announcement are broadcasts, so we always see those.

Devices discovered any other way (ARP cache, ARP scan, ARP traffic) were already
connected before we started watching.
"""

from __future__ import annotations

import ipaddress
import time
from collections import deque
from dataclasses import asdict, dataclass, field

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether

from .netinfo import is_randomized_mac, is_unicast_mac

DHCP_TYPES = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
              5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
PENDING_TIMEOUT = 60.0  # seconds to wait for confirmation after a DHCP Request
LOG_SIZE = 300


@dataclass
class Device:
    mac: str
    ip: str | None = None
    hostname: str | None = None
    vendor_class: str | None = None
    role: str = "device"          # "router" | "self" | "device"
    origin: str = "existing"      # "existing" (was already connected) | "joined" (we saw it join)
    found_by: str = ""            # how we learned about it
    first_seen: float = 0.0
    last_seen: float = 0.0
    joined_at: float | None = None
    status: str = "online"        # "online" | "released"
    randomized_mac: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PendingJoin:
    """A device that asked for an IP but hasn't been confirmed yet."""
    mac: str
    ts: float
    requested_ip: str | None = None
    hostname: str | None = None
    vendor_class: str | None = None


@dataclass
class LogEntry:
    ts: float
    level: str        # "step" | "success" | "info" | "warn"
    text: str
    mac: str | None = None


def _decode(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").strip("\x00 ") or None
    return str(value)


def _dhcp_options(pkt) -> dict:
    opts = {}
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and len(opt) >= 2:
            opts[opt[0]] = opt[1]
    # Captured packets carry the type as a number; hand-built ones as a name.
    kind = opts.get("message-type")
    if isinstance(kind, str):
        opts["message-type"] = {v.lower(): k for k, v in DHCP_TYPES.items()}.get(kind.lower())
    return opts


@dataclass
class DeviceTracker:
    router_ip: str | None = None
    router_mac: str | None = None
    self_ip: str | None = None
    self_mac: str | None = None
    subnet: str | None = None
    devices: dict[str, Device] = field(default_factory=dict)
    pending: dict[str, PendingJoin] = field(default_factory=dict)
    log: deque = field(default_factory=lambda: deque(maxlen=LOG_SIZE))

    def __post_init__(self):
        self._net = ipaddress.ip_network(self.subnet, strict=False) if self.subnet else None
        now = time.time()
        if self.router_mac:
            self._upsert(self.router_mac, self.router_ip, now, role="router", found_by="Default gateway")
        if self.self_mac:
            self._upsert(self.self_mac, self.self_ip, now, role="self", found_by="This Mac")

    # ---------------------------------------------------------------- helpers

    def _in_subnet(self, ip: str | None) -> bool:
        if not ip or ip == "0.0.0.0":
            return False
        addr = ipaddress.ip_address(ip)
        if self._net is not None:
            return addr in self._net
        return addr.is_private

    def _say(self, ts: float, level: str, text: str, mac: str | None = None) -> None:
        self.log.append(LogEntry(ts=ts, level=level, text=text, mac=mac))

    def _label(self, mac: str, hostname: str | None = None) -> str:
        dev = self.devices.get(mac)
        name = hostname or (dev.hostname if dev else None)
        return f"{name} ({mac})" if name else mac

    def _upsert(self, mac: str, ip: str | None, ts: float, **fields) -> tuple[Device, bool]:
        """Create or update a device. Returns (device, created)."""
        dev = self.devices.get(mac)
        created = dev is None
        if created:
            dev = Device(mac=mac, first_seen=ts, randomized_mac=is_randomized_mac(mac))
            if mac == self.router_mac:
                dev.role = "router"
            elif mac == self.self_mac:
                dev.role = "self"
            self.devices[mac] = dev
        if ip:
            dev.ip = ip
        dev.last_seen = max(dev.last_seen, ts)
        for key, value in fields.items():
            if value is not None and (key != "found_by" or created):
                setattr(dev, key, value)
        return dev, created

    def _expire_pending(self, now: float) -> None:
        for mac, p in list(self.pending.items()):
            if now - p.ts > PENDING_TIMEOUT:
                del self.pending[mac]
                self._say(now, "warn", f"No confirmation for {self._label(mac, p.hostname)} "
                                       f"within {int(PENDING_TIMEOUT)}s - not added", mac)

    def _confirm_join(self, mac: str, ip: str, ts: float, how: str) -> None:
        p = self.pending.pop(mac, None)
        hostname = p.hostname if p else None
        vendor = p.vendor_class if p else None
        existed = mac in self.devices
        dev, _ = self._upsert(mac, ip, ts, hostname=hostname, vendor_class=vendor, status="online")
        if dev.role != "device":
            return
        dev.origin, dev.joined_at, dev.found_by = "joined", ts, how
        verb = "rejoined" if existed else "joined"
        self._say(ts, "success", f"{self._label(mac)} {verb} the network with IP {ip}  [{how}]", mac)

    # ---------------------------------------------------------- public API

    def add_existing(self, mac: str, ip: str, found_by: str, ts: float | None = None) -> bool:
        """Record a device that was already on the network. Returns True if it's new to us."""
        ts = ts or time.time()
        if not is_unicast_mac(mac) or not self._in_subnet(ip):
            return False
        dev, created = self._upsert(mac, ip, ts, found_by=found_by)
        if created and dev.role == "device":
            self._say(ts, "info", f"Already connected: {mac} at {ip}  [{found_by}]", mac)
        return created

    def handle(self, pkt) -> bool:
        """Process one packet. Returns True if devices or the log changed."""
        ts = float(getattr(pkt, "time", None) or time.time())
        before = (len(self.log), len(self.devices), len(self.pending))
        self._expire_pending(ts)
        if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
            self._handle_dhcp(pkt, ts)
        elif pkt.haslayer(ARP):
            self._handle_arp(pkt, ts)
        return before != (len(self.log), len(self.devices), len(self.pending))

    # ------------------------------------------------------------ DHCP

    def _handle_dhcp(self, pkt, ts: float) -> None:
        bootp = pkt[BOOTP]
        opts = _dhcp_options(pkt)
        kind = DHCP_TYPES.get(opts.get("message-type"), "Unknown")
        client = ":".join(f"{b:02x}" for b in bytes(bootp.chaddr)[:6])
        hostname = _decode(opts.get("hostname"))
        vendor = _decode(opts.get("vendor_class_id"))
        server_ip = _decode(opts.get("server_id"))

        if kind in ("Offer", "ACK", "NAK") and pkt.haslayer(Ether):
            src_ip = pkt[IP].src if pkt.haslayer(IP) else None
            self._check_dhcp_server(pkt[Ether].src, server_ip or src_ip, ts)

        if client == self.self_mac:
            if kind == "ACK":
                self._say(ts, "info", f"This Mac renewed its IP {bootp.yiaddr}", client)
            return

        label = self._label(client, hostname)
        if kind == "Discover":
            self.pending[client] = PendingJoin(client, ts, hostname=hostname, vendor_class=vendor)
            self._say(ts, "step", f"DHCP Discover: {label} is looking for an IP address", client)
        elif kind == "Offer":
            self._say(ts, "step", f"DHCP Offer: router offers {bootp.yiaddr} to {label}", client)
        elif kind == "Request":
            ip = _decode(opts.get("requested_addr")) or (bootp.ciaddr if bootp.ciaddr != "0.0.0.0" else None)
            p = self.pending.get(client) or PendingJoin(client, ts)
            p.ts, p.requested_ip = ts, ip or p.requested_ip
            p.hostname, p.vendor_class = hostname or p.hostname, vendor or p.vendor_class
            self.pending[client] = p
            self._say(ts, "step", f"DHCP Request: {label} asks to use {ip or 'an IP'}", client)
        elif kind == "ACK" and bootp.yiaddr != "0.0.0.0":
            self._say(ts, "step", f"DHCP ACK: router assigned {bootp.yiaddr} to {label}", client)
            self._confirm_join(client, bootp.yiaddr, ts, "DHCP ACK")
        elif kind == "NAK":
            self.pending.pop(client, None)
            self._say(ts, "warn", f"DHCP NAK: router refused the request from {label}", client)
        elif kind == "Release":
            if dev := self.devices.get(client):
                dev.status, dev.last_seen = "released", ts
            self.pending.pop(client, None)
            self._say(ts, "info", f"DHCP Release: {label} gave its IP back (leaving)", client)

    def _check_dhcp_server(self, mac: str, ip: str | None, ts: float) -> None:
        mac = mac.lower()
        if self.router_mac is None:
            # Replay mode: learn the router from whoever answers DHCP.
            self.router_mac, self.router_ip = mac, ip or self.router_ip
            self._upsert(mac, ip, ts, role="router", found_by="DHCP server")
            self._say(ts, "info", f"Router identified: {ip} ({mac}) answers DHCP", mac)
        elif mac != self.router_mac:
            self._say(ts, "warn", f"DHCP reply from {ip} ({mac}), which is NOT the router - "
                                  "possible rogue DHCP server", mac)

    # ------------------------------------------------------------- ARP

    def _handle_arp(self, pkt, ts: float) -> None:
        arp = pkt[ARP]
        mac = (arp.hwsrc or "").lower()
        if not mac or not is_unicast_mac(mac):
            return
        sender_ip, target_ip = arp.psrc, arp.pdst

        # A device that just got an IP probes (sender 0.0.0.0) then announces it.
        if (p := self.pending.get(mac)) and p.requested_ip:
            if sender_ip == p.requested_ip or (sender_ip == "0.0.0.0" and target_ip == p.requested_ip):
                kind = "probe" if sender_ip == "0.0.0.0" else "announcement"
                self._say(ts, "step", f"ARP {kind}: {self._label(mac)} is now using {p.requested_ip}", mac)
                self._confirm_join(mac, p.requested_ip, ts, "DHCP Request + ARP")
                return

        if self._in_subnet(sender_ip):
            if mac in self.devices:
                self._upsert(mac, sender_ip, ts)
            elif mac not in self.pending:
                self.add_existing(mac, sender_ip, "ARP traffic", ts)

    # -------------------------------------------------------- snapshot

    def snapshot(self) -> dict:
        role_order = {"router": 0, "self": 1, "device": 2}
        devices = sorted(self.devices.values(), key=lambda d: (role_order[d.role], d.first_seen))
        return {
            "devices": [d.to_dict() for d in devices],
            "pending": [asdict(p) for p in self.pending.values()],
            "log": [asdict(e) for e in self.log],
        }
