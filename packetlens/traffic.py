"""Traffic statistics: how much each device talks, with whom, and in which protocols.

Everything here is about volume, not identity (that's tracker.py). Per device we keep
one minute of per-second counters (for the sparkline and the "now" rate), a protocol
tally, and the conversations it had with other devices on the LAN.

What this Mac can see on Wi-Fi: broadcasts and multicasts from everyone, plus traffic
to or from this Mac itself. Other devices' private traffic never reaches us, so their
numbers here are a floor, not the truth. Monitor mode (a later step) sees more.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .netinfo import is_unicast_mac

WINDOW = 60          # seconds of per-second history kept per device (the sparkline)
RATE_SPAN = 10       # "now" rate = average over the last 10 seconds
PAIR_FRESH = 30      # conversations drawn on the topology: active in the last 30 s
PAIR_TTL = 300       # forget a conversation after 5 minutes of silence
MAX_PAIRS = 2000
SIGNALLING = {"ARP"}  # questions, not conversations (our own check-ins would draw lines everywhere)


@dataclass
class DeviceTraffic:
    mac: str
    seconds: dict = field(default_factory=dict)       # second -> [pkts out, bytes out, pkts in, bytes in]
    protocols: Counter = field(default_factory=Counter)     # proto -> packets (sent or received)
    proto_bytes: Counter = field(default_factory=Counter)   # proto -> bytes
    last: float = 0.0

    def bucket(self, sec: int) -> list:
        b = self.seconds.get(sec)
        if b is None:
            b = self.seconds[sec] = [0, 0, 0, 0]
            if len(self.seconds) > WINDOW + 10:
                for old in [k for k in self.seconds if k < sec - WINDOW]:
                    del self.seconds[old]
        return b

    def totals(self, since: float, until: float) -> list:
        """[pkts out, bytes out, pkts in, bytes in] for seconds in (since, until]."""
        out = [0, 0, 0, 0]
        for sec, b in self.seconds.items():
            if since < sec <= until:
                for i in range(4):
                    out[i] += b[i]
        return out

    def series(self, now: float) -> list[int]:
        """Bytes per second (sent + received) for the last WINDOW seconds, oldest first."""
        end = int(now)
        return [sum(self.seconds.get(sec, (0, 0, 0, 0))[1::2]) for sec in range(end - WINDOW + 1, end + 1)]


@dataclass
class Conversation:
    a: str                      # the two MACs, sorted
    b: str
    first: float
    last: float
    packets: int = 0
    bytes: int = 0
    a_to_b: int = 0             # bytes each way
    b_to_a: int = 0
    protocols: Counter = field(default_factory=Counter)

    def to_dict(self) -> dict:
        return {"a": self.a, "b": self.b, "first": self.first, "last": self.last,
                "packets": self.packets, "bytes": self.bytes, "a_to_b": self.a_to_b,
                "b_to_a": self.b_to_a, "protocols": [p for p, _ in self.protocols.most_common(3)]}


class TrafficStats:
    def __init__(self):
        self.devices: dict[str, DeviceTraffic] = {}
        self.pairs: dict[tuple[str, str], Conversation] = {}

    def _dev(self, mac: str) -> DeviceTraffic:
        d = self.devices.get(mac)
        if d is None:
            d = self.devices[mac] = DeviceTraffic(mac)
        return d

    def note(self, ts: float, src: str | None, dst: str | None, length: int, proto: str, known) -> None:
        """Count one packet. `known` holds the tracker's device MACs; anything else is ignored.

        A broadcast or multicast is counted as *sent* by its source only - it isn't
        "received" by any one device in particular.
        """
        sec = int(ts)
        if src in known:
            d = self._dev(src)
            b = d.bucket(sec)
            b[0] += 1
            b[1] += length
            d.protocols[proto] += 1
            d.proto_bytes[proto] += length
            d.last = max(d.last, ts)
        if dst and dst != src and dst in known and is_unicast_mac(dst):
            d = self._dev(dst)
            b = d.bucket(sec)
            b[2] += 1
            b[3] += length
            d.protocols[proto] += 1
            d.proto_bytes[proto] += length
            d.last = max(d.last, ts)
            if src in known and proto not in SIGNALLING:
                self._conversation(src, dst, ts, length, proto)

    def _conversation(self, src: str, dst: str, ts: float, length: int, proto: str) -> None:
        a, b = sorted((src, dst))
        c = self.pairs.get((a, b))
        if c is None:
            if len(self.pairs) >= MAX_PAIRS:   # a capture from a busy switch: keep the newest
                oldest = min(self.pairs, key=lambda k: self.pairs[k].last)
                del self.pairs[oldest]
            c = self.pairs[(a, b)] = Conversation(a, b, first=ts, last=ts)
        c.last = max(c.last, ts)
        c.packets += 1
        c.bytes += length
        if src == a:
            c.a_to_b += length
        else:
            c.b_to_a += length
        c.protocols[proto] += 1

    # ---------------------------------------------------------------- queries

    def rates(self, now: float) -> dict[str, tuple[float, float]]:
        """mac -> (packets/s, bytes/s) over the last RATE_SPAN seconds, sent + received."""
        out = {}
        for mac, d in self.devices.items():
            po, bo, pi, bi = d.totals(now - RATE_SPAN, now)
            if po or pi:
                out[mac] = (round((po + pi) / RATE_SPAN, 1), round((bo + bi) / RATE_SPAN))
        return out

    def conversations(self, now: float, fresh: float = PAIR_FRESH) -> list[dict]:
        """Conversations active in the last `fresh` seconds, biggest first."""
        live = [c for c in self.pairs.values() if now - c.last <= fresh]
        return [c.to_dict() for c in sorted(live, key=lambda c: -c.bytes)]

    def prune(self, now: float) -> None:
        for key in [k for k, c in self.pairs.items() if now - c.last > PAIR_TTL]:
            del self.pairs[key]

    def device(self, mac: str, now: float) -> dict:
        """Everything the details panel shows for one device."""
        d = self.devices.get(mac) or DeviceTraffic(mac)
        po, bo, pi, bi = d.totals(now - RATE_SPAN, now)
        series = d.series(now)
        total_pkts = sum(d.protocols.values()) or 1
        peers = []
        for c in self.pairs.values():
            if mac not in (c.a, c.b):
                continue
            other = c.b if c.a == mac else c.a
            sent = c.a_to_b if c.a == mac else c.b_to_a
            peers.append({"mac": other, "bytes": c.bytes, "packets": c.packets, "last": c.last,
                          "sent": sent, "received": c.bytes - sent,
                          "protocols": [p for p, _ in c.protocols.most_common(3)]})
        peers.sort(key=lambda p: -p["bytes"])
        return {
            "rate": {"pps": round((po + pi) / RATE_SPAN, 1), "bps": round((bo + bi) / RATE_SPAN),
                     "out_bps": round(bo / RATE_SPAN), "in_bps": round(bi / RATE_SPAN)},
            "series": series,
            "peak_bps": max(series) if series else 0,
            "protocols": [{"proto": p, "packets": n, "bytes": d.proto_bytes[p],
                           "share": round(100 * n / total_pkts)}
                          for p, n in d.protocols.most_common(6)],
            "peers": peers[:8],
            "conversations": len(peers),
        }
