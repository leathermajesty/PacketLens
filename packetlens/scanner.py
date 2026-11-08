"""Active discovery: ask every address in the subnet "who has this IP?" (ARP)."""

from __future__ import annotations

import ipaddress

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

MAX_ADDRESSES = 1024  # refuse to sweep anything bigger than a /22


def arp_scan(iface: str, cidr: str, my_mac: str, my_ip: str,
             timeout: float = 2.0) -> list[tuple[str, str]]:
    """Broadcast an ARP request for each IP in `cidr`; return [(ip, mac)] of replies."""
    net = ipaddress.ip_network(cidr, strict=False)
    if net.num_addresses > MAX_ADDRESSES:
        raise ValueError(f"{cidr} is too large to scan (max {MAX_ADDRESSES} addresses)")
    # Fill in our own addresses explicitly; otherwise scapy may send hwsrc=00:00:00:00:00:00.
    request = (Ether(src=my_mac, dst="ff:ff:ff:ff:ff:ff")
               / ARP(hwsrc=my_mac, psrc=my_ip, pdst=str(net)))
    answered, _ = srp(request, iface=iface, timeout=timeout, retry=1, verbose=0)
    return [(reply[ARP].psrc, reply[Ether].src.lower()) for _, reply in answered]
