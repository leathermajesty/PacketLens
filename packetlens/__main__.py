"""Run PacketLens:  python -m packetlens [--demo | --pcap FILE] [-i en0] [--port 8000]"""

from __future__ import annotations

import argparse
import webbrowser

from . import demo
from .engine import Engine
from .netinfo import NetworkInfo, get_network_info
from .server import make_server


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="packetlens",
                                description="See your Wi-Fi network and devices joining it, live.")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--demo", action="store_true", help="play a built-in example (no real network needed)")
    src.add_argument("--pcap", metavar="FILE", help="replay a saved capture instead of sniffing live")
    p.add_argument("-i", "--iface", help="interface to capture on (default: the one with the default route)")
    p.add_argument("--ssid", help="Wi-Fi name to display (macOS may hide the real one)")
    p.add_argument("--port", type=int, default=8000, help="dashboard port (default 8000)")
    p.add_argument("--speed", type=float, default=1.0, help="replay speed multiplier (default 1.0)")
    p.add_argument("--no-scan", action="store_true", help="don't ARP-scan for existing devices at start")
    p.add_argument("--no-browser", action="store_true", help="don't open the browser automatically")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    if args.demo:
        source = "demo"
        net = NetworkInfo(iface=None, cidr=demo.SUBNET, gateway_ip=demo.ROUTER_IP,
                          gateway_mac=demo.ROUTER_MAC, ssid="PacketLens-Demo", security="WPA2_PSK")
    elif args.pcap:
        source = "pcap"
        net = NetworkInfo(iface=None)
    else:
        source = "live"
        net = get_network_info(args.iface)
    if args.ssid:
        net.ssid = args.ssid

    engine = Engine(net, source=source, pcap_path=args.pcap, speed=args.speed)
    engine.start()
    if source == "live":
        engine.load_arp_cache()
        if not args.no_scan:
            engine.start_scan()

    server = make_server(engine, args.port)
    url = f"http://127.0.0.1:{args.port}/"
    what = {"live": f"live on {net.iface}", "demo": "demo", "pcap": f"replaying {args.pcap}"}[source]
    print(f"PacketLens ({what}) -> {url}")
    if engine.capture["error"]:
        print(f"  ! {engine.capture['error']}")
    print("Press Ctrl+C to stop.")
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        engine.stop()
        server.server_close()


if __name__ == "__main__":
    main()
