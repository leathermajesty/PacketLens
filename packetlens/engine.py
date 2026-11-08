"""Capture engine: feeds packets (live, from a .pcap, or the demo) into the tracker.

All state lives behind one lock. Every change bumps `version` and wakes up the
web server, which pushes a fresh snapshot to the browser.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from scapy.sendrecv import AsyncSniffer
from scapy.utils import PcapReader

from .netinfo import NetworkInfo, read_arp_table
from .packets import dissect, summarize
from .scanner import arp_scan
from .tracker import DeviceTracker

BUFFER_SIZE = 2000    # packets kept in memory for the table and the detail view
MAX_REPLAY_GAP = 3.0  # don't wait longer than this between replayed packets


class Engine:
    def __init__(self, net: NetworkInfo, source: str = "live", pcap_path: str | None = None,
                 speed: float = 1.0, capture_filter: str | None = None):
        self.net = net
        self.source = source              # "live" | "pcap" | "demo"
        self.pcap_path = pcap_path
        self.speed = max(speed, 0.01)
        self.capture_filter = capture_filter or None
        self.cond = threading.Condition(threading.RLock())
        self.version = 0                  # bumps when devices/log/status change
        self.packet_seq = 0               # number of the newest packet
        self.packets: deque = deque(maxlen=BUFFER_SIZE)   # (summary, scapy packet)
        self._t0: float | None = None
        self.tracker = DeviceTracker(router_ip=net.gateway_ip, router_mac=net.gateway_mac,
                                     self_ip=net.ip, self_mac=net.mac, subnet=net.cidr)
        self.capture = {"running": False, "error": None, "packets": 0, "finished": False,
                        "filter": self.capture_filter or "", "decode_errors": 0,
                        "buffer": BUFFER_SIZE}
        self.scan = {"running": False, "error": None, "last_run": None, "found": 0}
        self._sniffer: AsyncSniffer | None = None
        self._stop = threading.Event()

    # ------------------------------------------------------------ plumbing

    def _changed(self) -> None:
        with self.cond:
            self.version += 1
            self.cond.notify_all()

    def _feed(self, pkt) -> None:
        with self.cond:
            self.packet_seq += 1
            no = self.packet_seq
            ts = float(pkt.time)
            if self._t0 is None:
                self._t0 = ts
            try:
                summary = summarize(pkt, no)
            except Exception as exc:  # noqa: BLE001 - one odd packet must not stop the capture
                self.capture["decode_errors"] += 1
                summary = {"no": no, "ts": ts, "src": "?", "dst": "?", "src_mac": None,
                           "dst_mac": None, "proto": "?", "length": len(bytes(pkt)),
                           "info": f"Could not decode: {exc}", "stack": ""}
            summary["rel"] = ts - self._t0
            self.packets.append((summary, pkt))
            self.capture["packets"] = no
            try:
                if self.tracker.handle(pkt):
                    self.version += 1
            except Exception:  # noqa: BLE001
                self.capture["decode_errors"] += 1
            self.cond.notify_all()

    def packets_since(self, after: int, limit: int = 500) -> list[dict]:
        """Summaries of packets numbered above `after` (oldest first, at most `limit`)."""
        with self.cond:
            if not self.packets:
                return []
            first = self.packets[0][0]["no"]
            start = max(after - first + 1, 0)
            return [self.packets[i][0] for i in range(start, min(start + limit, len(self.packets)))]

    def packet_detail(self, no: int) -> dict | None:
        with self.cond:
            if not self.packets:
                return None
            idx = no - self.packets[0][0]["no"]
            if not 0 <= idx < len(self.packets):
                return None
            summary, pkt = self.packets[idx]
        return {"summary": summary, **dissect(pkt)}

    # ------------------------------------------------------------- capture

    def start(self) -> None:
        if self.source == "live":
            self._start_live()
        else:
            threading.Thread(target=self._replay, name="replay", daemon=True).start()

    def _start_live(self) -> None:
        self._sniffer = AsyncSniffer(iface=self.net.iface, filter=self.capture_filter,
                                     prn=self._feed, store=False)
        try:
            self._sniffer.start()
            time.sleep(0.5)  # give the sniffer thread a moment to fail if it's going to
            if self._sniffer.exception:
                raise self._sniffer.exception
            self.capture["running"] = True
        except Exception as exc:  # noqa: BLE001 - surface any capture error in the UI
            self.capture["error"] = f"Could not capture on {self.net.iface}: {exc}"
        self._changed()

    def _replay(self) -> None:
        from .demo import build_demo_packets
        self.capture["running"] = True
        self._changed()
        try:
            if self.source == "demo":
                packets = build_demo_packets(start=time.time())
            else:
                packets = PcapReader(self.pcap_path)
            prev = None
            for pkt in packets:
                if self._stop.is_set():
                    break
                if prev is not None:
                    gap = min(float(pkt.time) - prev, MAX_REPLAY_GAP) / self.speed
                    time.sleep(max(gap, 0))
                prev = float(pkt.time)
                self._feed(pkt)
        except Exception as exc:  # noqa: BLE001
            self.capture["error"] = f"Replay failed: {exc}"
        self.capture["running"], self.capture["finished"] = False, True
        self._changed()

    def stop(self) -> None:
        self._stop.set()
        if self._sniffer and self.capture["running"]:
            try:
                self._sniffer.stop()
            except Exception:  # noqa: BLE001
                pass

    # ----------------------------------------------- existing-device discovery

    def load_arp_cache(self) -> None:
        with self.cond:
            for ip, mac in read_arp_table(self.net.iface):
                self.tracker.add_existing(mac, ip, "ARP cache")
            self._changed()

    def start_scan(self) -> bool:
        """Start an ARP sweep in the background. Returns False if not possible right now."""
        with self.cond:
            if self.source != "live" or self.scan["running"] or not self.net.cidr:
                return False
            self.scan.update(running=True, error=None)
            self._changed()
        threading.Thread(target=self._scan, name="arp-scan", daemon=True).start()
        return True

    def _scan(self) -> None:
        started = time.time()
        try:
            results = arp_scan(self.net.iface, self.net.cidr, self.net.mac, self.net.ip)
            with self.cond:
                for ip, mac in results:
                    if not self.tracker.add_existing(mac, ip, "ARP scan"):
                        # The sniffer usually sees the reply first; credit the scan anyway.
                        dev = self.tracker.devices.get(mac)
                        if dev and dev.found_by == "ARP traffic" and dev.first_seen >= started:
                            dev.found_by = "ARP scan"
                self.scan["found"] = len(results)
        except Exception as exc:  # noqa: BLE001
            self.scan["error"] = str(exc)
        with self.cond:
            self.scan.update(running=False, last_run=time.time())
            self._changed()

    # ------------------------------------------------------------- snapshot

    def snapshot(self) -> dict:
        with self.cond:
            return {
                "version": self.version,
                "source": self.source,
                "pcap": self.pcap_path,
                "network": self.net.to_dict(),
                "router": {"ip": self.tracker.router_ip, "mac": self.tracker.router_mac},
                "capture": dict(self.capture),
                "scan": dict(self.scan),
                **self.tracker.snapshot(),
            }
