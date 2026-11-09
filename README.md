# PacketLens

A small network packet analyzer, built step by step to learn how devices join a Wi-Fi network
and, later, to spot attacks on it.

A live dashboard showing your Wi-Fi network, the devices already on it, a topology map that
adds a new device the moment the router gives it an IP address (and fades it out when it
leaves), and a Wireshark-style live packet table with a details pane.

## Quick start (macOS)

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# Try it without a real network (built-in example)
.venv/bin/python -m packetlens --demo

# Live on your Wi-Fi
.venv/bin/python -m packetlens
```

The dashboard opens at <http://127.0.0.1:8000/>. It only listens on your own machine, so nobody else on the Wi-Fi can open it.

Live capture needs access to `/dev/bpf*`. If you get a permission error, install Wireshark
(its *ChmodBPF* helper grants access) or run with `sudo`.

### Options

| Option | What it does |
|---|---|
| `--demo` | Replay a built-in example network (no devices needed) |
| `--pcap FILE` | Replay a saved capture, e.g. from Wireshark |
| `-i en0` | Capture on a specific interface (default: the one with your default route) |
| `-f "not port 443"` | Capture filter (BPF, same syntax as Wireshark's *capture* filter); default: everything. ARP and DHCP are always added, because joins and presence need them |
| `--ssid NAME` | Wi-Fi name to display (macOS hides the real one, see below) |
| `--no-scan` | Don't ARP-scan the subnet at start |
| `--checkin 30` | Seconds between ARP check-ins on quiet devices (`0` = off, fully passive) |
| `--speed 5` | Replay 5x faster |
| `--port 8000` | Dashboard port |

## How it works

```
                                ┌─► device tracker ──┐
Wi-Fi (en0) ──► sniffer (scapy) ┤   (ARP + DHCP)     ├─► local web server ──► browser dashboard
                                └─► packet buffer ───┘   Server-Sent Events   devices, topology,
                                    (last 2,000)                              packets, details
```

### The live packet table

Every captured packet gets a row, like Wireshark's packet list:

| Column | Meaning |
|---|---|
| No. | Packet number since PacketLens started |
| Time | Seconds since the first packet |
| Source / Destination | IP addresses, or MAC addresses for non-IP packets like ARP |
| Protocol | The most specific protocol PacketLens recognises (ARP, DHCP, DNS, TCP, TLS, HTTP, QUIC…) |
| Length | Bytes on the wire |
| Info | A one-line summary: DNS question, TCP flags, HTTP request line, "Who has…?" |

- **Click a row** (or use ↑/↓) to decode it layer by layer, with a hex dump, and highlight both
  devices on the topology.
- **Filter** shows rows containing every word you type: `dns`, `tcp 192.168.1.5`, `syn`, a MAC…
  It matches the protocol layers too, so `udp` also shows DNS and DHCP.
- **Pause** stops adding rows (capture keeps running); **Clear** empties the table.

Protocol names for TCP/UDP come from well-known ports (443 → TLS, 5353 → mDNS), so a service on
an unusual port shows as plain TCP/UDP. Wireshark does deeper detection.

**Try the demo:** run `--demo`, click the `POST /login` HTTP packet, and read the password in
the payload. That's why router admin pages (and everything else) should use HTTPS.

### Finding devices that are already connected

1. **ARP cache:** devices your Mac has recently talked to (`arp -an`). Passive.
2. **ARP scan:** an ARP "who has 192.168.1.x?" for every address in the subnet. Every
   connected device must answer, because that's how Ethernet/Wi-Fi delivers packets to it.
3. **ARP traffic:** any device that sends an ARP while we're listening.

### Detecting a new device joining (the DHCP "DORA" exchange)

After a device connects to Wi-Fi (the WPA2 password handshake), it asks the router for an IP:

| # | Packet | Sent to | Your Mac sees it? |
|---|---|---|---|
| 1 | **Discover**: "I need an IP" | everyone (broadcast) | yes |
| 2 | **Offer**: "you can have .23" | often only the device | sometimes |
| 3 | **Request**: "I'll take .23" | everyone (broadcast) | yes |
| 4 | **ACK**: ".23 is yours" | often only the device | sometimes |

Because the ACK is often unicast, PacketLens adds a device to the topology when it sees either:

- the **DHCP ACK**, or
- a **DHCP Request** followed by an **ARP probe/announcement** from that device for the same IP
  (devices do this right after getting an IP, to check nobody else is using it).

A Request with no confirmation within 60 seconds is dropped. If a DHCP Offer or ACK comes from
anything other than your router, PacketLens warns about a **possible rogue DHCP server**.

### Detecting a device leaving

When a device disconnects, it usually **doesn't announce it**. Phones that walk out of range,
laptops that sleep, or devices that switch Wi-Fi off simply go quiet:

| Event | What's on the air | Visible to your Mac? |
|---|---|---|
| Wi-Fi switched off / network forgotten | 802.11 *Deauthentication* or *Disassociation* to the router | Only in monitor mode (a later step) |
| Walked out of range, battery died | Nothing - it just stops | Only by noticing the silence |
| Clean shutdown (some laptops) | DHCP *Release* | Yes |

So PacketLens tracks presence itself:

| Status | Meaning |
|---|---|
| **Online** | Sent something in the last 60 s |
| **Idle** | Quiet for 60 s+, but still answers our ARP check-ins (e.g. a phone with the screen off) |
| **Offline** | Didn't answer 3 check-ins in a row (~1.5 min with the default 30 s interval) |
| **Left** | Sent a DHCP Release |

A **check-in** is an ARP "who has 192.168.1.x? tell *me*" sent to each device that's been
quiet for 30 s. It is broadcast, because phones in power-save mode only wake for broadcasts on schedule; unicast frames to a sleeping phone wait at the router. Every connected device must answer ARP, so silence is a strong sign it is gone.
The tracker watches for our own questions in the capture and waits 5 s for any packet back. It
only counts *our* questions, because replies to the router's ARP requests go to the router and
never reach us. Any packet from an offline device brings it straight back online.

It's a strong guess, not a certainty: a phone in deep sleep can occasionally miss a check-in.
Only monitor mode sees the actual "goodbye" frame.

### Try it

1. Run `.venv/bin/python -m packetlens`.
2. On your phone: Settings → Wi-Fi → *Forget this network*, then reconnect with the password.
3. Watch the Join activity log go Discover → Request → ACK/ARP, and the phone appear in green.
4. Turn the phone's Wi-Fi off. About 1.5 minutes later it fades to *Offline* with
   "left the network". Turn Wi-Fi back on and it returns.

To see the same packets in Wireshark, use the display filter `dhcp || arp`. The demo capture is
in `samples/demo.pcap` (regenerate it with `.venv/bin/python -m packetlens.demo`).

### Things you'll notice

- **"private MAC"**: phones use a random MAC per Wi-Fi network (the "locally administered" bit
  is set), so the same phone looks different on different networks.
- **The Wi-Fi name is hidden:** macOS only shows the SSID to apps with Location Services
  permission. Use `--ssid` or the Rename button.
- **Personal hotspot:** the phone becomes the router (172.20.10.x) and may not forward other
  clients' broadcasts to you, so joins can be harder to see than on a home router.

## Project layout

```
packetlens/
  __main__.py   command line, starts everything
  netinfo.py    interface, IP/MAC, router, Wi-Fi details (macOS tools)
  scanner.py    ARP scan of the subnet, ARP check-ins
  tracker.py    the device list: "joined with an IP" rule and online/idle/offline presence
  packets.py    packet table rows + Wireshark-style layer details and hex dump
  engine.py     live capture / replay, packet buffer, feeds the tracker
  server.py     local web server + live updates
  demo.py       made-up example network
  web/          dashboard (HTML, CSS, JS - no internet needed)
tests/          unit tests (device tracker, packet decoding)
samples/        demo capture
```

Run the tests:

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## Roadmap

- [x] **Step 1:** Wi-Fi info, existing devices, live topology, new device on DHCP IP assignment
- [x] **Step 2:** live packet table beside the topology, packet details + hex dump, filter
- [x] **Step 3:** presence: online / idle / offline via ARP check-ins, devices fade when they leave
- [ ] **Step 4:** device details on click (vendor, hostname, first/last seen)
- [ ] **Step 5:** traffic on the topology (links flash, byte counters)
- [ ] **Step 6:** monitor mode: the WPA2 4-way handshake ("device entered the right password")
  and deauthentication frames ("device disconnected" - or a deauth attack)
- [ ] **Step 7:** attack detection: ARP spoofing, port scans, rogue DHCP

Only capture and scan networks you own or have permission to test.
