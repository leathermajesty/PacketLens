"""Device tracker: turns captured DHCP/ARP packets into a list of devices.

The rule for "a new device has joined and been given an IP":

    1. We see a DHCP ACK for the device's MAC          -> joined (router confirmed it), or
    2. We see a DHCP Request for an IP, then an ARP    -> joined (device is now using it)
       probe/announcement from the same MAC for that IP

Rule 2 exists because the router often sends the ACK straight to the new device
(unicast), so other computers on the Wi-Fi never see it. The Request and the ARP
announcement are broadcasts, so we always see those.

Devices discovered any other way (ARP cache, ARP scan, ARP/IP traffic) were already
connected before we started watching.

Leaving is harder: most devices just go quiet (the Wi-Fi "goodbye" frame is only
visible in monitor mode). So presence works like this:

    online   - sent something in the last IDLE_AFTER seconds
    idle     - quiet, but still answering our ARP check-ins
    offline  - didn't answer OFFLINE_AFTER_MISSES check-ins in a row
    released - said goodbye with a DHCP Release

A check-in is an ARP "who has <ip>?" sent by *this Mac*. The tracker sees the
question in the capture and waits ARP_REPLY_TIMEOUT seconds for any packet from
that device. (Replies to other machines' ARP requests go to them, not to us, so
only our own questions count.)
"""

from __future__ import annotations

import ipaddress
import time
from collections import deque
from dataclasses import asdict, dataclass, field

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether

from .netinfo import is_randomized_mac, is_unicast_mac
from .vendors import guess_kind, lookup_vendor

DHCP_TYPES = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
              5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
PENDING_TIMEOUT = 60.0      # seconds to wait for confirmation after a DHCP Request
IDLE_AFTER = 60.0           # quiet this long -> "idle"
ARP_REPLY_TIMEOUT = 5.0     # a check-in with no answer after this long is a miss
OFFLINE_AFTER_MISSES = 3    # this many misses in a row -> "offline"
LOG_SIZE = 300
WARN_REPEAT = 300.0         # repeat the same "rogue DHCP" warning at most every 5 minutes
IP_HISTORY = 10             # IP addresses remembered per device


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
    last_seen: float = 0.0        # any packet from it, including answers to our check-ins
    last_active: float = 0.0      # packets it sent on its own (not just answering us)
    joined_at: float | None = None
    left_at: float | None = None
    status: str = "online"        # "online" | "idle" | "offline" | "released"
    missed_checks: int = 0
    randomized_mac: bool = False
    # Step 4: details
    hostname_source: str | None = None   # "DHCP" (it told the router) | "mDNS" (it announced itself)
    vendor: str | None = None            # manufacturer, from the MAC's first 3 bytes
    kind: str | None = None              # best guess: "Android 14", "iPhone", "Windows"...
    kind_reason: str | None = None
    ip_history: list = field(default_factory=list)   # [[ip, since], ...], newest last
    packets_sent: int = 0                # only what this Mac can see (see README)
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0

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
    level: str        # "step" | "success" | "info" | "warn" | "leave"
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
    probes: dict[str, float] = field(default_factory=dict)  # mac -> when we asked "are you there?"
    log: deque = field(default_factory=lambda: deque(maxlen=LOG_SIZE))
    clock: float = 0.0                                       # newest time we know about

    def __post_init__(self):
        self._net = ipaddress.ip_network(self.subnet, strict=False) if self.subnet else None
        self._changes = 0
        self._warned: dict[str, float] = {}      # rogue DHCP server mac -> last warning time
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
        self._changes += 1

    def _label(self, mac: str, hostname: str | None = None) -> str:
        dev = self.devices.get(mac)
        name = hostname or (dev.hostname if dev else None)
        return f"{name} ({mac})" if name else mac

    def _upsert(self, mac: str, ip: str | None, ts: float, **fields) -> tuple[Device, bool]:
        """Create or update a device. Returns (device, created)."""
        dev = self.devices.get(mac)
        created = dev is None
        if created:
            dev = Device(mac=mac, first_seen=ts, last_active=ts, randomized_mac=is_randomized_mac(mac),
                         vendor=lookup_vendor(mac))
            if mac == self.router_mac:
                dev.role = "router"
            elif mac == self.self_mac:
                dev.role = "self"
            self.devices[mac] = dev
            self._changes += 1
        if ip and ip != dev.ip:
            if dev.ip and dev.role == "device":
                self._say(ts, "info", f"{self._label(mac)} changed IP from {dev.ip} to {ip}", mac)
            dev.ip = ip
            dev.ip_history = (dev.ip_history + [[ip, ts]])[-IP_HISTORY:]
        dev.last_seen = max(dev.last_seen, ts)
        hostname = fields.pop("hostname", None)
        for key, value in fields.items():
            if value is not None and (key != "found_by" or created):
                setattr(dev, key, value)
        if created or fields.get("vendor_class"):
            self._update_kind(dev)
        if hostname:
            self._set_hostname(dev, hostname, "DHCP", ts)
        return dev, created

    def _set_hostname(self, dev: Device, name: str, source: str, ts: float) -> None:
        """DHCP names win over mDNS names: the device gave them to the router itself."""
        if dev.hostname == name or (dev.hostname_source == "DHCP" and source != "DHCP"):
            return
        dev.hostname, dev.hostname_source = name, source
        self._update_kind(dev)
        self._changes += 1
        if source != "DHCP":
            self._say(ts, "info", f"{dev.mac} calls itself {name}  [{source}]", dev.mac)

    @staticmethod
    def _update_kind(dev: Device) -> None:
        guess = guess_kind(dev.vendor_class, dev.hostname)
        dev.kind, dev.kind_reason = guess if guess else (None, None)

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
        dev.missed_checks, dev.left_at = 0, None
        self.probes.pop(mac, None)
        verb = "rejoined" if existed else "joined"
        self._say(ts, "success", f"{self._label(mac)} {verb} the network with IP {ip}  [{how}]", mac)

    # ---------------------------------------------------------- public API

    def add_existing(self, mac: str, ip: str, found_by: str, ts: float | None = None) -> bool:
        """Record a device that was already on the network. Returns True if it's new to us."""
        ts = time.time() if ts is None else ts
        if not is_unicast_mac(mac) or not self._in_subnet(ip):
            return False
        dev, created = self._upsert(mac, ip, ts, found_by=found_by)
        if created and dev.role == "device":
            self._say(ts, "info", f"Already connected: {mac} at {ip}  [{found_by}]", mac)
        return created

    def handle(self, pkt) -> bool:
        """Process one packet. Returns True if devices, statuses or the log changed."""
        ts = float(getattr(pkt, "time", None) or time.time())
        before = (self._changes, len(self.pending))
        self.clock = max(self.clock, ts)
        self._expire_pending(ts)
        self._expire_probes(ts)

        src = pkt[Ether].src.lower() if pkt.haslayer(Ether) else None
        if src in self.devices:
            # An ARP reply addressed to us is just an answer to our check-in, not activity.
            answering = (pkt.haslayer(ARP) and pkt[ARP].op == 2
                         and pkt[Ether].dst.lower() == self.self_mac)
            self._seen(src, ts, active=not answering)

        if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
            self._handle_dhcp(pkt, ts)
        elif pkt.haslayer(ARP):
            self._handle_arp(pkt, ts)
        elif (pkt.haslayer(IP) and src and is_unicast_mac(src)
              and src not in self.devices and src not in self.pending
              and self._in_subnet(pkt[IP].src)):
            self.add_existing(src, pkt[IP].src, "IP traffic", ts)

        if src in self.devices and pkt.haslayer(DNS) and pkt.haslayer(UDP) and pkt[UDP].sport == 5353:
            self._handle_mdns(src, pkt, ts)
        if pkt.haslayer(Ether):
            self._count(src, (pkt[Ether].dst or "").lower(), len(pkt))
        return before != (self._changes, len(self.pending))

    def _count(self, src: str | None, dst: str, size: int) -> None:
        """Packet/byte counters (no change bump: the 2 s heartbeat shows them)."""
        if dev := self.devices.get(src):
            dev.packets_sent += 1
            dev.bytes_sent += size
        if dst != src and (dev := self.devices.get(dst)):
            dev.packets_received += 1
            dev.bytes_received += size

    def _handle_mdns(self, mac: str, pkt, ts: float) -> None:
        """An mDNS answer like 'Living-Room-TV.local is at <my own IP>' names the device."""
        dns = pkt[DNS]
        if not dns.qr or not pkt.haslayer(IP):
            return
        my_ip = pkt[IP].src
        for rr in list(dns.an or []) + list(dns.ar or []):
            if getattr(rr, "type", None) != 1 or getattr(rr, "rdata", None) != my_ip:
                continue
            name = (_decode(rr.rrname) or "").rstrip(".")
            if name.lower().endswith(".local") and len(name) > len(".local"):
                self._set_hostname(self.devices[mac], name[: -len(".local")], "mDNS", ts)
                return

    # -------------------------------------------------------- presence

    def _seen(self, mac: str, ts: float, active: bool = True) -> None:
        dev = self.devices[mac]
        dev.last_seen = max(dev.last_seen, ts)
        if active:
            dev.last_active = max(dev.last_active, ts)
        self.probes.pop(mac, None)
        dev.missed_checks = 0
        if dev.status in ("offline", "released"):
            gone = f" after {int(ts - dev.left_at)}s away" if dev.left_at else ""
            dev.status, dev.left_at = "online", None
            self._say(ts, "success", f"{self._label(mac)} is back online{gone}", mac)
        elif dev.status == "idle" and active:
            dev.status = "online"
            self._changes += 1

    def _expire_probes(self, now: float) -> None:
        for mac, asked in list(self.probes.items()):
            if now - asked <= ARP_REPLY_TIMEOUT:
                continue
            del self.probes[mac]
            dev = self.devices.get(mac)
            if dev is None or dev.status in ("offline", "released"):
                if dev:
                    dev.missed_checks += 1
                continue
            dev.missed_checks += 1
            self._changes += 1
            if dev.missed_checks >= OFFLINE_AFTER_MISSES:
                dev.status, dev.left_at = "offline", now
                self._say(now, "leave", f"{self._label(mac)} left the network - no reply to "
                                        f"{dev.missed_checks} ARP check-ins", mac)

    def tick(self, now: float) -> bool:
        """Advance the clock without a packet (live mode calls this every second)."""
        before = self._changes
        self.clock = max(self.clock, now)
        self._expire_pending(now)
        self._expire_probes(now)
        for dev in self.devices.values():
            if dev.role != "self" and dev.status == "online" and now - dev.last_active > IDLE_AFTER:
                dev.status = "idle"
                self._changes += 1
        return before != self._changes

    def checkin_targets(self, now: float, quiet_for: float) -> list[tuple[str, str]]:
        """(ip, mac) of devices that have been quiet for `quiet_for` seconds and need a check-in."""
        return [(d.ip, d.mac) for d in self.devices.values()
                if d.role != "self" and d.ip and d.mac not in self.probes
                and now - d.last_seen >= quiet_for]

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

        if (dev := self.devices.get(client)) and kind in ("Discover", "Request", "Inform"):
            if vendor and vendor != dev.vendor_class:
                dev.vendor_class = vendor
                self._update_kind(dev)
            if hostname:
                self._set_hostname(dev, hostname, "DHCP", ts)

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
                dev.status, dev.left_at = "released", ts
            self.pending.pop(client, None)
            self._say(ts, "info", f"DHCP Release: {label} gave its IP back (leaving)", client)

    def _check_dhcp_server(self, mac: str, ip: str | None, ts: float) -> None:
        mac = mac.lower()
        if self.router_mac is None:
            # Replay mode: learn the router from whoever answers DHCP.
            self.router_mac, self.router_ip = mac, ip or self.router_ip
            self._upsert(mac, ip, ts, role="router", found_by="DHCP server")
            self._say(ts, "info", f"Router identified: {ip} ({mac}) answers DHCP", mac)
        elif mac != self.router_mac and ts - self._warned.get(mac, float("-inf")) >= WARN_REPEAT:
            # A second DHCP server answers every lease, so say it once, not once per packet.
            self._warned[mac] = ts
            self._say(ts, "warn", f"DHCP reply from {ip} ({mac}), which is NOT the router - "
                                  "possible rogue DHCP server", mac)

    # ------------------------------------------------------------- ARP

    def _handle_arp(self, pkt, ts: float) -> None:
        arp = pkt[ARP]
        mac = (arp.hwsrc or "").lower()
        if not mac or not is_unicast_mac(mac):
            return
        sender_ip, target_ip = arp.psrc, arp.pdst

        # Our own "are you still there?" check-in: start waiting for an answer.
        if arp.op == 1 and mac == self.self_mac and target_ip != sender_ip:
            target = next((d for d in self.devices.values()
                           if d.ip == target_ip and d.role != "self"), None)
            if target:
                self.probes.setdefault(target.mac, ts)
            return

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
            "clock": self.clock,
            "devices": [d.to_dict() for d in devices],
            "pending": [asdict(p) for p in self.pending.values()],
            "log": [asdict(e) for e in self.log],
        }
