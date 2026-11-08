"""Facts about the network this Mac is on: interface, our IP/MAC, router, Wi-Fi.

Everything here comes from standard macOS command-line tools (route, ifconfig,
ipconfig, arp), so no special permissions are needed.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from dataclasses import asdict, dataclass

IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def normalize_mac(mac: str | None) -> str | None:
    """'0:0:5e:0:53:1' -> '00:00:5e:00:53:01' (macOS drops leading zeros)."""
    if not mac:
        return None
    parts = mac.strip().lower().split(":")
    if len(parts) != 6 or not all(re.fullmatch(r"[0-9a-f]{1,2}", p) for p in parts):
        return None
    return ":".join(p.zfill(2) for p in parts)


def is_unicast_mac(mac: str) -> bool:
    """False for broadcast/multicast MACs (lowest bit of first byte set) and 00:00:00:00:00:00."""
    return mac != "00:00:00:00:00:00" and not int(mac.split(":")[0], 16) & 0x01


def is_randomized_mac(mac: str) -> bool:
    """Phones/laptops use 'private' MACs per network: locally-administered bit set."""
    return bool(int(mac.split(":")[0], 16) & 0x02)


@dataclass
class NetworkInfo:
    iface: str | None
    ip: str | None = None
    mac: str | None = None
    cidr: str | None = None
    gateway_ip: str | None = None
    gateway_mac: str | None = None
    ssid: str | None = None
    bssid: str | None = None
    security: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def default_route() -> tuple[str | None, str | None]:
    """(interface, gateway IP) of the default route."""
    out = _run(["route", "-n", "get", "default"])
    iface = re.search(r"interface:\s*(\S+)", out)
    gw = re.search(rf"gateway:\s*({IPV4})", out)
    return (iface.group(1) if iface else None, gw.group(1) if gw else None)


def read_arp_table(iface: str | None = None) -> list[tuple[str, str]]:
    """Return [(ip, mac)] from the OS ARP cache, skipping incomplete/multicast/own entries."""
    cmd = ["arp", "-an"] + (["-i", iface] if iface else [])
    entries = []
    for line in _run(cmd).splitlines():
        m = re.search(rf"\(({IPV4})\) at (\S+) on (\S+)(.*)", line)
        if not m or "permanent" in m.group(4):
            continue
        ip, mac = m.group(1), normalize_mac(m.group(2))
        if not mac or not is_unicast_mac(mac) or ipaddress.ip_address(ip).is_multicast:
            continue
        entries.append((ip, mac))
    return entries


def _wifi_details(iface: str) -> dict[str, str | None]:
    """SSID/BSSID/security from `ipconfig getsummary`.

    macOS redacts SSID and BSSID unless the app has Location Services permission.
    """
    out = _run(["ipconfig", "getsummary", iface])
    details: dict[str, str | None] = {}
    for key in ("SSID", "BSSID", "Security"):
        m = re.search(rf"^\s*{key}\s*:\s*(.+?)\s*$", out, re.MULTILINE)
        value = m.group(1) if m else None
        details[key.lower()] = None if value in (None, "<redacted>") else value
    return details


def get_network_info(iface: str | None = None) -> NetworkInfo:
    route_iface, gateway_ip = default_route()
    iface = iface or route_iface or "en0"
    info = NetworkInfo(iface=iface)

    ifconfig = _run(["ifconfig", iface])
    if m := re.search(r"ether\s+([0-9a-f:]{17})", ifconfig):
        info.mac = normalize_mac(m.group(1))
    if m := re.search(rf"inet\s+({IPV4})\s+netmask\s+(0x[0-9a-f]+)", ifconfig):
        info.ip = m.group(1)
        mask = str(ipaddress.IPv4Address(int(m.group(2), 16)))
        info.cidr = str(ipaddress.IPv4Network(f"{info.ip}/{mask}", strict=False))

    # Only trust the default gateway if it's actually on this interface.
    if gateway_ip and route_iface == iface:
        info.gateway_ip = gateway_ip
        info.gateway_mac = dict(read_arp_table(iface)).get(gateway_ip)

    wifi = _wifi_details(iface)
    info.ssid, info.bssid, info.security = wifi["ssid"], wifi["bssid"], wifi["security"]
    return info
