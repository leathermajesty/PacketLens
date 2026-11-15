"""Who made a device, and what it probably is.

Vendor: the first 3 bytes of a MAC address (the OUI) are assigned to a manufacturer by
the IEEE. Scapy ships Wireshark's table of them (~50,000 entries), so this works offline.
Phones using a private (randomized) MAC have no real OUI, so their vendor is hidden.

Kind: a best guess from what the device tells the router in DHCP (vendor class, hostname).
It's only a hint - any device can send any name.
"""

from __future__ import annotations

import re

from scapy.config import conf

from .netinfo import is_randomized_mac

DOC_PREFIX = "00:00:5e:00:53:"   # RFC 7042 documentation MACs, used by the demo


def lookup_vendor(mac: str) -> str | None:
    """'3c:22:fb:..' -> 'Apple, Inc.'  (None if unknown or a private MAC)."""
    if mac.startswith(DOC_PREFIX):
        return "Documentation example (RFC 7042)"
    if is_randomized_mac(mac):
        return None
    try:
        _short, long_name = conf.manufdb.lookup(mac)
    except Exception:  # noqa: BLE001 - manuf table missing or broken
        return None
    return None if not long_name or long_name.lower() == mac.lower() else long_name


# (pattern, what it means) - checked against the DHCP vendor class, then the hostname.
_VENDOR_CLASS_HINTS = [
    (r"^android-dhcp-(\d+)", "Android {0}"),
    (r"^android-dhcp", "Android"),
    (r"^MSFT", "Windows"),
    (r"^dhcpcd-[\d.]+:Linux", "Linux (dhcpcd)"),
    (r"^dhcpcd", "Linux or Android (dhcpcd)"),
    (r"^udhcp", "Embedded Linux (router, camera, IoT)"),
]
_HOSTNAME_HINTS = [
    (r"iphone", "iPhone"),
    (r"ipad", "iPad"),
    (r"macbook|imac|mac-?mini|mac-?studio", "Mac"),
    (r"^desktop-|^laptop-", "Windows PC"),
    (r"galaxy|^sm-[a-z]\d", "Samsung Galaxy"),
    (r"pixel", "Google Pixel"),
    (r"^android", "Android"),
    (r"watch", "Smartwatch"),
    (r"\btv\b|-tv|tv-|roku|chromecast|firetv|bravia", "TV / streaming"),
    (r"printer|^hp[a-f0-9]{6}|epson|canon|brother", "Printer"),
    (r"echo|alexa|google-?home|nest", "Smart speaker"),
]


def guess_kind(vendor_class: str | None, hostname: str | None) -> tuple[str, str] | None:
    """Returns (guess, reason), e.g. ('Android 14', 'DHCP vendor class "android-dhcp-14"')."""
    if vendor_class:
        for pattern, label in _VENDOR_CLASS_HINTS:
            if m := re.search(pattern, vendor_class, re.IGNORECASE):
                return label.format(*m.groups()), f'DHCP vendor class "{vendor_class}"'
    if hostname:
        for pattern, label in _HOSTNAME_HINTS:
            if re.search(pattern, hostname, re.IGNORECASE):
                return label, f'name "{hostname}"'
    return None
