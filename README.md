# PacketLens

A small network packet analyzer, built step by step to learn how devices join a Wi-Fi network
and, later, to spot attacks on it.

A live dashboard showing your Wi-Fi network, the devices already on it, a topology map that
adds a new device the moment the router gives it an IP address, and a Wireshark-style live
packet table with a details pane.

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
| `-f "not port 443"` | Capture filter (BPF, same syntax as Wireshark's *capture* filter); default: everything |
| `--ssid NAME` | Wi-Fi name to display (macOS hides the real one, see below) |
| `--no-scan` | Don't ARP-scan the subnet at start (passive only) |
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

### Try it

1. Run `.venv/bin/python -m packetlens`.
2. On your phone: Settings → Wi-Fi → *Forget this network*, then reconnect with the password.
3. Watch the Join activity log go Discover → Request → ACK/ARP, and the phone appear in green.

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
  scanner.py    ARP scan of the subnet
  tracker.py    the device list and the "joined with an IP" rule
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
- [ ] **Step 3:** device details on click (vendor, hostname, first/last seen)
- [ ] **Step 4:** traffic on the topology (links flash, byte counters)
- [ ] **Step 5:** monitor mode: catch the WPA2 4-way handshake ("device entered the right password")
- [ ] **Step 6:** attack detection: ARP spoofing, port scans, rogue DHCP

Only capture and scan networks you own or have permission to test.
