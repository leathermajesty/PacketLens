"use strict";
/* PacketLens dashboard: receives snapshots from /api/stream and draws them. */

const $ = (id) => document.getElementById(id);
const SVG_NS = "http://www.w3.org/2000/svg";
const FRESH_MS = 60_000;          // how long a newly joined device keeps pulsing
const SSID_KEY = "packetlens.ssid";
const NAMES_KEY = "packetlens.names";   // your own nicknames for devices (this browser only)

let lastVersion = null;
let lastState = null;
let lastLogKey = null;
let knownJoins = null;            // mac -> joined_at, to detect new joins for toasts
const freshUntil = new Map();     // mac -> timestamp (ms) when the pulse stops
const view = { tab: "device", deviceMac: null };   // what the details card shows

// ----------------------------------------------------------------- helpers

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function svgEl(tag, attrs = {}) {
  const e = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
}

function fmtTime(ts) {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function storedSsid() {
  try { return localStorage.getItem(SSID_KEY); } catch { return null; }
}

function storeSsid(value) {
  try {
    if (value) localStorage.setItem(SSID_KEY, value);
    else localStorage.removeItem(SSID_KEY);
  } catch { /* storage unavailable: name just won't persist */ }
}

function loadNicknames() {
  try { return JSON.parse(localStorage.getItem(NAMES_KEY)) || {}; } catch { return {}; }
}

let nicknames = loadNicknames();

function setNickname(mac, name) {
  if (name) nicknames[mac] = name;
  else delete nicknames[mac];
  try { localStorage.setItem(NAMES_KEY, JSON.stringify(nicknames)); } catch { /* won't persist */ }
}

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} kB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function deviceName(d) {
  if (nicknames[d.mac]) return nicknames[d.mac];
  if (d.role === "router") return d.hostname || "Router";
  if (d.role === "self") return "This Mac";
  return d.hostname || "Unknown device";
}

function lastOctet(ip) {
  return ip ? "." + ip.split(".").pop() : "?";
}

function prettySecurity(sec) {
  if (!sec) return "—";
  return { WPA2_PSK: "WPA2 Personal", WPA3_SAE: "WPA3 Personal", WPA2_WPA3: "WPA2/WPA3 Personal",
           NONE: "Open (no password)" }[sec] || sec.replaceAll("_", " ");
}

function isFresh(mac) {
  return (freshUntil.get(mac) || 0) > Date.now();
}

function ago(seconds) {
  if (seconds < 5) return "just now";
  if (seconds < 60) return `${Math.round(seconds)}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  return `${Math.floor(seconds / 3600)} h ago`;
}

// "clock" is the tracker's time: real time when live, packet time when replaying.
function describePresence(d, clock) {
  if (d.role === "self") return "Online · capturing";
  if (d.status === "offline") return `Offline since ${fmtTime(d.left_at)} · ${d.missed_checks} check-ins unanswered`;
  if (d.status === "released") return `Left ${fmtTime(d.left_at)} · said goodbye (DHCP Release)`;
  if (d.status === "idle") return `Idle · quiet for ${ago(clock - d.last_active).replace(" ago", "")}, still answers`;
  return `Online · seen ${ago(Math.max(0, clock - d.last_seen))}`;
}

function describeOrigin(d) {
  if (d.role === "router") return d.found_by === "Default gateway" ? "Default gateway" : `Router · ${d.found_by}`;
  if (d.role === "self") return "You are capturing from here";
  if (d.origin === "joined") return `Joined ${fmtTime(d.joined_at)} · ${d.found_by}`;
  return `Already connected · ${d.found_by}`;
}

// ------------------------------------------------------------- top + wifi

function renderStatus(s) {
  const pill = $("status");
  let cls = "ok";
  let text;
  const n = s.capture.packets;
  if (s.capture.error) {
    cls = "err";
    text = s.capture.error;
  } else if (s.source === "live") {
    const filter = s.capture.filter ? ` · filter "${s.capture.filter}"` : "";
    text = s.capture.running ? `Live on ${s.network.iface} · ${n} packets${filter}` : "Starting capture…";
  } else {
    const what = s.source === "demo" ? "demo" : s.pcap;
    text = s.capture.finished ? `Replay of ${what} finished · ${n} packets` : `Replaying ${what} · ${n} packets`;
    if (s.capture.finished) cls = "idle";
  }
  pill.className = `status ${cls}`;
  $("status-text").textContent = text;
  pill.title = text;

  const btn = $("scan-btn");
  btn.disabled = s.source !== "live" || s.scan.running;
  btn.textContent = s.scan.running ? "Scanning…" : "Rescan network";
  btn.title = s.source === "live"
    ? "Send an ARP 'who has?' to every address in the subnet"
    : "Scanning only works in live mode";
}

function renderWifi(s) {
  const n = s.network;
  const ssid = storedSsid() || n.ssid;
  const ssidEl = $("ssid");
  ssidEl.textContent = ssid || "Name hidden by macOS";
  ssidEl.classList.toggle("muted", !ssid);
  ssidEl.title = ssid ? "" : "macOS hides the Wi-Fi name unless the app has Location Services permission. Use Rename.";

  const rows = [
    ["Security", prettySecurity(n.security)],
    ["Router", s.router.ip || "—", s.router.mac],
    ["This Mac", n.ip || (s.source === "live" ? "—" : "not capturing live"), n.mac],
    ["Subnet", n.cidr || "—"],
    ["Interface", n.iface || "replay"],
  ];
  const kv = $("wifi-kv");
  kv.replaceChildren();
  for (const [label, value, sub] of rows) {
    const dd = el("dd", null, value);
    if (sub) dd.append(el("span", "sub", sub));
    kv.append(el("dt", null, label), dd);
  }

  const line = $("scan-line");
  const tooBig = /too large/.test(s.scan.error || "");
  line.classList.toggle("err", !!s.scan.error && !tooBig);
  if (s.source !== "live") line.textContent = "";
  else if (tooBig) line.textContent = "Subnet too large for an ARP scan - devices are found passively as they talk";
  else if (s.scan.error) line.textContent = `Scan failed: ${s.scan.error}`;
  else if (s.scan.running) line.textContent = "ARP scan running…";
  else if (s.scan.last_run) line.textContent = `Last ARP scan ${fmtTime(s.scan.last_run)} · ${s.scan.found} devices replied`;
  else line.textContent = "";
}

// ---------------------------------------------------------------- devices

const dl = { query: "", filter: "all", sort: "ip", items: new Map() };   // items: mac -> row parts

function deviceMatches(d) {
  const f = dl.filter;
  if (f === "online" && d.status !== "online") return false;
  if (f === "idle" && d.status !== "idle") return false;
  if (f === "offline" && d.status !== "offline" && d.status !== "released") return false;
  if (f === "joined" && d.origin !== "joined") return false;
  if (f === "private" && !d.randomized_mac) return false;
  if (!dl.query) return true;
  const hay = [deviceName(d), d.hostname, d.ip, d.mac, d.vendor, d.kind].filter(Boolean).join(" ").toLowerCase();
  return dl.query.split(/\s+/).every((w) => hay.includes(w));
}

function ipKey(ip) {
  return ip ? ip.split(".").reduce((a, o) => a * 256 + Number(o), 0) : Infinity;
}

function sortDevices(devices) {
  const role = { router: 0, self: 1, device: 2 };
  const by = {
    ip: (a, b) => ipKey(a.ip) - ipKey(b.ip),
    recent: (a, b) => b.last_seen - a.last_seen,
    name: (a, b) => deviceName(a).localeCompare(deviceName(b)),
  }[dl.sort];
  return devices.slice().sort((a, b) => role[a.role] - role[b.role] || by(a, b));
}

function deviceRow(d) {
  let it = dl.items.get(d.mac);
  if (it) return it;
  const li = el("li", "device");
  li.tabIndex = 0;
  it = { li, name: el("span", "device-name"), ip: el("span", "device-ip mono"), mac: el("div", "device-mac mono"),
         kind: el("div", "device-kind"), how: el("div", "device-how"), presence: el("div", "presence") };
  const top = el("div", "device-top");
  top.append(it.name, it.ip);
  const body = el("div", "device-body");
  body.append(top, it.mac, it.kind, it.how, it.presence);
  li.append(el("span", "dot"), body);
  li.addEventListener("mouseenter", () => highlight(d.mac));
  li.addEventListener("mouseleave", () => highlight(currentHighlight()));
  li.addEventListener("click", () => selectDevice(d.mac));
  li.addEventListener("keydown", (e) => { if (e.key === "Enter") selectDevice(d.mac); });
  dl.items.set(d.mac, it);
  return it;
}

function privateBadge() {
  const badge = el("span", "badge", "private MAC");
  badge.title = "Randomized per-network MAC (locally administered bit set) - common on phones";
  return badge;
}

// Rows are kept and updated in place (keyed by MAC), so the list doesn't jump or
// flicker on every 2-second update - this matters with a hundred devices.
function renderDevices(s) {
  const list = $("device-list");
  const frag = document.createDocumentFragment();

  for (const p of s.pending) {
    const li = el("li", "device pending");
    const body = el("div", "device-body");
    const top = el("div", "device-top");
    top.append(el("span", "device-name", p.hostname || "Joining device"),
               el("span", "device-ip mono", p.requested_ip || "no IP yet"));
    body.append(top, el("div", "device-mac mono", p.mac),
                el("div", "device-how", "Asked for an IP · waiting for confirmation"));
    li.append(el("span", "dot"), body);
    frag.append(li);
  }

  const present = new Set();
  let shown = 0;
  for (const d of sortDevices(s.devices)) {
    present.add(d.mac);
    const it = deviceRow(d);
    it.li.className = `device role-${d.role} origin-${d.origin} st-${d.status}${d.mac === view.deviceMac ? " selected" : ""}`;
    it.name.textContent = deviceName(d);
    it.ip.textContent = d.ip || "no IP";
    it.mac.replaceChildren(d.mac, ...(d.randomized_mac ? [privateBadge()] : []));
    it.kind.textContent = d.kind || d.vendor || "";
    it.kind.hidden = !(d.kind || d.vendor);
    it.how.textContent = describeOrigin(d);
    it.presence.className = `presence st-${d.status}`;
    it.presence.textContent = describePresence(d, s.clock);
    const match = deviceMatches(d);
    it.li.hidden = !match;
    shown += match;
    frag.append(it.li);
  }
  for (const [mac, it] of dl.items) {
    if (!present.has(mac)) { it.li.remove(); dl.items.delete(mac); }
  }
  const scroll = list.scrollTop;
  list.replaceChildren(frag);
  list.scrollTop = scroll;

  const total = s.devices.length;
  $("device-count").textContent = shown === total ? total : `${shown} / ${total}`;
  $("device-empty").hidden = shown > 0 || total === 0;
}

function setDeviceFilter(filter) {
  dl.filter = filter;
  $("dev-filter").value = filter;
  if (lastState) renderDevices(lastState);
  $("device-list").scrollIntoView({ block: "nearest" });
}

// --------------------------------------------------------------- topology

const topo = {
  svg: $("topo"),
  links: svgEl("g"),
  nodes: svgEl("g"),
  hint: svgEl("text", { class: "topo-hint", "text-anchor": "middle" }),
  items: new Map(),     // key -> {g, line, x, y, tx, ty, ...}
  routerKey: null,
  devices: [],
  expanded: false,      // big networks: quiet devices are folded into one bubble until clicked
  r: 27,                // node radius: shrinks as the network grows (chosen in relayout)
  labels: true,         // false on big networks: only notable nodes keep their labels
  clock: 0,
  hl: new Set(),        // highlighted node keys (selected device, hovered row, packet ends)
  animStart: 0,         // nodes glide from (fx, fy) to (tx, ty) between animStart and animEnd
  animEnd: 0,
  fallback: null,
  w: 0,
  h: 0,
  raf: null,
};
const GROUP_ABOVE = 12;          // more devices than this -> quiet ones fold into a group bubble
const GROUP_KEY = "__group__";
const JOINED_NOTABLE = 1800;     // a join stays out of the bubble for 30 min...
const LEFT_NOTABLE = 600;        // ...a departure for 10 min (big networks only)

// Notable devices are always drawn on their own, with a label, on the outer ring:
// the ones this tool is about (joined, left) plus the router, this Mac and the selection.
function notable(d) {
  if (d.role !== "device" || d.mac === view.deviceMac || isFresh(d.mac)) return true;
  if (d.origin === "joined" && topo.clock - d.joined_at < JOINED_NOTABLE) return true;
  return (d.status === "offline" || d.status === "released") && topo.clock - d.left_at < LEFT_NOTABLE;
}

function named(d) {
  return d.role !== "device" || !!(nicknames[d.mac] || d.hostname);
}

// Small network: everything. Big network: notable devices + one bubble for the quiet rest,
// until the bubble is clicked open.
function topoPartition(s) {
  const others = s.devices.filter((d) => d.role !== "router");
  if (others.length <= GROUP_ABOVE || topo.expanded) return { shown: others, grouped: [] };
  return { shown: others.filter(notable), grouped: others.filter((d) => !notable(d)) };
}

function groupNode(grouped) {
  const n = (...st) => grouped.filter((d) => st.includes(d.status)).length;
  const parts = [[n("online"), "online"], [n("idle"), "idle"], [n("offline", "released"), "offline"]]
    .filter(([c]) => c).map(([c, w]) => `${c} ${w}`);
  return { mac: GROUP_KEY, role: "group", origin: "existing", status: "online", count: grouped.length,
           summary: parts.join(" · ") };
}

function setRadius(it, r) {
  if (it.r === r) return;
  it.r = r;
  it.pulse.setAttribute("r", r);
  it.body.setAttribute("r", r);
  it.name.setAttribute("y", r + 16);
  it.sub.setAttribute("y", r + 30);
  it.inner.style.display = r < 14 ? "none" : "";   // no room for the ".23" inside small dots
}
topo.svg.append(topo.links, topo.nodes, topo.hint);

function makeItem(d, from) {
  const g = svgEl("g", { class: "node" });
  const parts = {
    pulse: svgEl("circle", { class: "pulse" }),
    body: svgEl("circle", { class: "body" }),
    inner: svgEl("text", { class: "inner", "text-anchor": "middle", dy: "0.35em" }),
    name: svgEl("text", { class: "name", "text-anchor": "middle" }),
    sub: svgEl("text", { class: "sub", "text-anchor": "middle" }),
    title: svgEl("title"),
  };
  g.append(...Object.values(parts));
  if (d.mac === GROUP_KEY) {
    g.addEventListener("click", () => setExpanded(true));
    g.style.cursor = "pointer";
  } else if (d.mac !== "__router__") {
    g.addEventListener("click", () => selectDevice(d.mac));
    g.style.cursor = "pointer";
  }
  const line = svgEl("line", { class: "link" });
  topo.links.append(line);
  topo.nodes.append(g);
  return { g, line, ...parts, r: 0, x: from.x, y: from.y, fx: from.x, fy: from.y, tx: from.x, ty: from.y };
}

function ringRadii(r, labels) {
  const pad = labels ? 62 : r + 36;        // room for labels, or for the notable nodes' names
  return { rx: Math.max(90, topo.w / 2 - pad), ry: Math.max(80, topo.h / 2 - pad - 8) };
}

// How big can the nodes be? Full labels on one ring while they fit; then smaller nodes,
// several rings, and labels only on notable nodes.
function chooseDensity() {
  const n = topo.devices.length - 1;
  const fits = (r) => {
    const { rx, ry } = ringRadii(r, true);
    return n <= Math.floor(Math.PI * (rx + ry) / (2.3 * r + 58));
  };
  if (fits(27)) return { r: 27, labels: true };
  if (fits(18)) return { r: 18, labels: true };
  return { r: n <= 40 ? 14 : n <= 90 ? 11 : n <= 150 ? 9 : 7, labels: false };
}

function layoutTargets() {
  const r = topo.r;
  const { rx, ry } = ringRadii(r, topo.labels);
  const cx = topo.w / 2;
  const cy = topo.h / 2 - (topo.labels ? 10 : 0);
  const targets = new Map([[topo.routerKey, { x: cx, y: cy }]]);
  const others = topo.devices.filter((d) => d.mac !== topo.routerKey)
    .sort((a, b) => notable(b) - notable(a));     // notable first -> outer ring (stable sort)

  let rings;
  if (topo.labels) {
    rings = [{ f: 1, count: others.length }];     // labels need the room: one ring only
  } else {
    // Rings from the outside in, each one a dot's footprint closer to the router.
    const spacing = 2.4 * r + 4;
    const step = Math.max(0.12, (2.6 * r + 6) / Math.min(rx, ry));
    rings = [];
    for (let k = 0, left = others.length; left > 0; k++) {
      const f = 1 - k * step;
      if (k > 0 && f * Math.min(rx, ry) < 34 + r + 14) {   // would touch the router: stop
        rings[rings.length - 1].count += left;
        break;
      }
      const capacity = Math.max(3, Math.floor(Math.PI * (rx + ry) * f / spacing));
      rings.push({ f, count: Math.min(capacity, left) });
      left -= capacity;
    }
  }

  let i = 0;
  rings.forEach((ring, ri) => {
    const stagger = (ri % 2) * (Math.PI / ring.count);   // alternate rings interleave
    for (let j = 0; j < ring.count; j++, i++) {
      const angle = -Math.PI / 2 + stagger + (j / ring.count) * Math.PI * 2;
      targets.set(others[i].mac, { x: cx + Math.cos(angle) * rx * ring.f, y: cy + Math.sin(angle) * ry * ring.f });
    }
  });
  return targets;
}

// Radius and label visibility depend on the density, which depends on the card size.
function styleItem(it) {
  const d = it.d;
  setRadius(it, d.role === "router" ? 34 : d.role === "group" ? 30 : topo.r);
  const quiet = !topo.labels && !notable(d);
  const state = `role-${d.role} origin-${d.origin} st-${d.status}${isFresh(d.mac) ? " fresh" : ""}`;
  it.g.setAttribute("class", `node ${state}${quiet ? " quiet" : ""}${topo.hl.has(d.mac) ? " hl" : ""}`);
  it.line.setAttribute("class", `link ${state}`);
}

function renderTopology(s) {
  const router = s.devices.find((d) => d.role === "router")
    || { mac: "__router__", role: "router", ip: s.router.ip, origin: "existing", status: "online" };
  topo.routerKey = router.mac;
  topo.clock = s.clock;
  const { shown, grouped } = topoPartition(s);
  // The bubble goes first so it lands at the top of the outer ring.
  topo.devices = [router, ...(grouped.length ? [groupNode(grouped)] : []), ...shown];
  $("topo-collapse").hidden = !(topo.expanded && s.devices.length - 1 > GROUP_ABOVE);

  if (topo.items.size === 0) topo.snapNext = true;  // first draw: place nodes, don't animate
  const center = { x: topo.w / 2, y: topo.h / 2 };
  const routerItem = topo.items.get(router.mac);
  const spawnAt = routerItem ? { x: routerItem.x, y: routerItem.y } : center;

  const present = new Set();
  for (const d of topo.devices) {
    present.add(d.mac);
    let it = topo.items.get(d.mac);
    if (!it) {
      it = makeItem(d, spawnAt);
      topo.items.set(d.mac, it);
    }
    it.d = d;
    it.line.style.display = d.mac === router.mac ? "none" : "";
    if (d.role === "group") {
      it.inner.textContent = d.count;
      it.name.textContent = `${d.count} quiet devices`;
      it.sub.textContent = "click to expand";
      it.title.textContent = `${d.count} devices that were already connected and are just online\n${d.summary}\nClick to show them`;
      continue;
    }
    it.inner.textContent = lastOctet(d.ip);
    const name = deviceName(d);
    // Only devices with a real name get a label; "Unknown device" eleven times is noise.
    it.name.textContent = !named(d) ? "" : name.length > 20 ? name.slice(0, 19) + "…" : name;
    it.sub.textContent = d.mac === "__router__" ? "" : d.mac;   // shown only when selected (CSS)
    it.title.textContent = `${name}\n${d.ip || "no IP"}\n${d.mac}\n${describeOrigin(d)}` +
      (d.mac === "__router__" ? "" : `\n${describePresence(d, s.clock)}`);
  }
  for (const [mac, it] of topo.items) {
    if (!present.has(mac)) {
      it.g.remove();
      it.line.remove();
      topo.items.delete(mac);
    }
  }

  const deviceCount = s.devices.filter((d) => d.role === "device").length;
  topo.hint.textContent = !deviceCount
    ? "Waiting for devices… reconnect a phone to this Wi-Fi to watch it appear."
    : grouped.length ? "Joined or left recently · click the bubble or a dot for more"
    : "Click a device for its details";
  highlight(currentHighlight());   // setAttribute("class") above dropped the highlight
  relayout();
}

function relayout() {
  if (!topo.w || !topo.h) return;  // not sized yet; ResizeObserver will call us again
  const density = chooseDensity();
  topo.r = density.r;
  topo.labels = density.labels;
  for (const it of topo.items.values()) if (it.d) styleItem(it);
  const targets = layoutTargets();
  for (const [mac, t] of targets) {
    const it = topo.items.get(mac);
    if (!it) continue;
    it.fx = it.x;         // glide from wherever the node is now...
    it.fy = it.y;
    it.tx = t.x;          // ...to its new place
    it.ty = t.y;
  }
  topo.animStart = performance.now();
  topo.animEnd = topo.animStart + (topo.snapNext ? 0 : 500);
  topo.snapNext = false;
  topo.hint.setAttribute("x", topo.w / 2);
  topo.hint.setAttribute("y", topo.h - 14);
  tick();               // draw the starting frame right away
}

// The glide is time-based, so it finishes on schedule even when the tab is in the
// background and requestAnimationFrame is paused: a timer then draws the final frame.
function scheduleTick() {
  if (topo.raf) return;
  topo.raf = requestAnimationFrame(tick);
  clearTimeout(topo.fallback);
  topo.fallback = setTimeout(() => { topo.raf = null; tick(); }, 700);
}

function tick() {
  topo.raf = null;
  const span = topo.animEnd - topo.animStart;
  const p = span <= 0 ? 1 : Math.min(1, (performance.now() - topo.animStart) / span);
  const e = 1 - (1 - p) ** 3;     // ease out
  for (const it of topo.items.values()) {
    it.x = it.fx + (it.tx - it.fx) * e;
    it.y = it.fy + (it.ty - it.fy) * e;
    it.g.setAttribute("transform", `translate(${it.x.toFixed(1)},${it.y.toFixed(1)})`);
  }
  const r = topo.items.get(topo.routerKey);
  if (r) {
    for (const it of topo.items.values()) {
      it.line.setAttribute("x1", r.x); it.line.setAttribute("y1", r.y);
      it.line.setAttribute("x2", it.x); it.line.setAttribute("y2", it.y);
    }
  }
  if (p < 1) scheduleTick();
  else clearTimeout(topo.fallback);
}

function highlight(macs) {
  topo.hl = new Set([].concat(macs || []).filter(Boolean));
  for (const [key, it] of topo.items) it.g.classList.toggle("hl", topo.hl.has(key));
}

new ResizeObserver(() => {
  topo.w = topo.svg.clientWidth;
  topo.h = topo.svg.clientHeight;
  topo.svg.setAttribute("viewBox", `0 0 ${topo.w} ${topo.h}`);
  relayout();
}).observe(topo.svg);

// -------------------------------------------------------------------- log

const LOG_FILTERS = { all: null, joins: new Set(["step", "success"]), leaves: new Set(["leave"]), alerts: new Set(["warn"]) };
const LOG_EMPTY = {
  all: "Nothing yet. DHCP and ARP steps will appear here as they're captured.",
  joins: "No joins yet. Reconnect a phone to this Wi-Fi to watch the DHCP steps.",
  leaves: "Nobody has left yet. A device that stops answering check-ins will show here.",
  alerts: "No alerts. A rogue DHCP server, a refused request or an unconfirmed join would show here.",
};
const logView = { filter: "all" };

function setLogFilter(name) {
  logView.filter = name;
  for (const b of document.querySelectorAll("#log-tabs .tab")) b.classList.toggle("active", b.dataset.filter === name);
  lastLogKey = null;
  if (lastState) renderLog(lastState);
  $("log").scrollIntoView({ block: "nearest" });
}

function renderLog(s) {
  const alerts = s.log.filter((e) => e.level === "warn").length;
  $("alerts-count").textContent = alerts || "";
  $("alerts-count").hidden = !alerts;
  const key = `${logView.filter}:${s.log.length}:${s.log.length ? s.log[s.log.length - 1].ts : 0}`;
  if (key === lastLogKey) return;
  lastLogKey = key;
  const keep = LOG_FILTERS[logView.filter];
  const entries = s.log.filter((e) => !keep || keep.has(e.level));
  const ol = $("log");
  ol.replaceChildren();
  if (!entries.length) {
    ol.append(el("li", "empty", LOG_EMPTY[logView.filter]));
    return;
  }
  for (const e of entries.reverse()) {
    const li = el("li", e.level);
    const t = el("time", null, fmtTime(e.ts));
    li.append(t, el("span", "lvl"), el("span", "msg", e.text));
    if (e.mac) {
      li.style.cursor = "pointer";
      li.title = "Show this device";
      li.addEventListener("click", () => selectDevice(e.mac));
    }
    ol.append(li);
  }
}

// ------------------------------------------------- joins and departures

let knownStatus = null;           // mac -> status, to spot devices leaving / coming back

function detectJoins(s) {
  const joins = new Map(s.devices.filter((d) => d.origin === "joined").map((d) => [d.mac, d.joined_at]));
  if (knownJoins) {
    for (const [mac, at] of joins) {
      if (knownJoins.get(mac) !== at) {
        freshUntil.set(mac, Date.now() + FRESH_MS);
        const d = s.devices.find((x) => x.mac === mac);
        toast(`New device joined: ${deviceName(d)}`, `${d.ip} · ${d.mac}`);
        setTimeout(rerender, FRESH_MS + 100); // redraw to stop the pulse
      }
    }
  }
  knownJoins = joins;

  const statuses = new Map(s.devices.map((d) => [d.mac, d.status]));
  if (knownStatus) {
    for (const d of s.devices) {
      const before = knownStatus.get(d.mac);
      const gone = (st) => st === "offline" || st === "released";
      if (before && !gone(before) && gone(d.status)) {
        toast(`Device left: ${deviceName(d)}`, `${d.ip} · ${d.mac}`, "leave");
      } else if (before && gone(before) && !gone(d.status)) {
        toast(`Back online: ${deviceName(d)}`, `${d.ip} · ${d.mac}`);
      }
    }
  }
  knownStatus = statuses;
}

function toast(title, detail, kind = "") {
  const t = el("div", `toast ${kind}`);
  t.append(el("strong", null, title), el("span", "mono", detail));
  $("toasts").append(t);
  setTimeout(() => t.remove(), 6000);
}

// ---------------------------------------------------------------- packets

const MAX_ROWS = 1500;            // rows kept in the table (oldest are dropped)
const pk = {
  tbody: $("packet-rows"),
  wrap: $("table-wrap"),
  filter: [],                     // lower-case words; a row must contain all of them
  paused: false,
  queued: [],                     // rows that arrived while paused
  lastNo: 0,                      // newest packet number received
  clearedUpTo: 0,                 // ignore packets at or below this (after Clear)
  selected: null,
  selectedMacs: null,
};

function protoClass(proto) {
  return "p-" + proto.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function rowMatches(tr) {
  return pk.filter.every((word) => tr.dataset.text.includes(word));
}

function makeRow(p) {
  const tr = document.createElement("tr");
  tr.dataset.no = p.no;
  tr.dataset.text = [p.proto, p.stack, p.src, p.dst, p.src_mac, p.dst_mac, p.info]
    .filter(Boolean).join(" ").toLowerCase();
  tr._pkt = p;
  const values = [p.no, p.rel.toFixed(3), p.src, p.dst, null, p.length, p.info];
  values.forEach((value, i) => {
    const td = document.createElement("td");
    if (i === 4) td.append(el("span", `proto ${protoClass(p.proto)}`, p.proto));
    else td.textContent = value;
    if (i === 0) td.className = "num";
    if (i === 2 || i === 3 || i === 6) td.title = value;
    tr.append(td);
  });
  if (!rowMatches(tr)) tr.classList.add("hidden");
  return tr;
}

function updatePacketCount() {
  const total = pk.tbody.rows.length;
  const shown = pk.filter.length ? pk.tbody.querySelectorAll("tr:not(.hidden)").length : total;
  $("packet-count").textContent = pk.filter.length ? `${shown} / ${total}` : total;
  const empty = $("table-empty");
  empty.style.display = shown ? "none" : "";
  empty.textContent = total ? "No packets match the filter." : "Waiting for packets…";
}

function appendRows(batch) {
  const wrap = pk.wrap;
  const atBottom = wrap.scrollHeight - wrap.scrollTop - wrap.clientHeight < 40;
  const frag = document.createDocumentFragment();
  for (const p of batch) frag.append(makeRow(p));
  pk.tbody.append(frag);
  while (pk.tbody.rows.length > MAX_ROWS) pk.tbody.rows[0].remove();
  updatePacketCount();
  if (atBottom) wrap.scrollTop = wrap.scrollHeight;  // follow new packets unless you scrolled up
}

function addPackets(batch) {
  batch = batch.filter((p) => p.no > pk.lastNo && p.no > pk.clearedUpTo);
  if (!batch.length) return;
  pk.lastNo = batch[batch.length - 1].no;
  if (pk.paused) {
    pk.queued.push(...batch);
    if (pk.queued.length > MAX_ROWS) pk.queued.splice(0, pk.queued.length - MAX_ROWS);
    updatePauseButton();
  } else {
    appendRows(batch);
  }
}

function resetPackets() {
  pk.tbody.replaceChildren();
  pk.queued = [];
  pk.lastNo = 0;
  pk.clearedUpTo = 0;
  clearSelection();
  updatePacketCount();
}

function updatePauseButton() {
  const btn = $("pause-btn");
  btn.classList.toggle("active", pk.paused);
  btn.textContent = pk.paused ? `Resume${pk.queued.length ? ` (${pk.queued.length} new)` : ""}` : "Pause";
}

function clearSelection() {
  pk.selected = null;
  pk.selectedMacs = null;
  pk.hint = "Click a packet to decode it";
  highlight(currentHighlight());
  updateHint();
  $("detail").replaceChildren(el("p", "empty", "Select a row in Live packets to see every layer, like Wireshark's details pane."));
}

async function selectPacket(tr) {
  if (!tr || !tr._pkt) return;
  pk.tbody.querySelector("tr.selected")?.classList.remove("selected");
  tr.classList.add("selected");
  tr.scrollIntoView({ block: "nearest" });
  const p = tr._pkt;
  pk.selected = p.no;
  pk.selectedMacs = [p.src_mac, p.dst_mac];
  pk.hint = `Packet ${p.no} · ${p.length} bytes · ${p.stack}`;
  showTab("packet");
  try {
    const res = await fetch(`/api/packet/${p.no}`);
    const data = await res.json();
    if (pk.selected !== p.no) return;  // user already clicked something else
    if (!res.ok) throw new Error(data.error);
    renderDetail(data);
  } catch (err) {
    $("detail").replaceChildren(el("p", "empty", err.message || "Could not load this packet."));
  }
}

function renderDetail(d) {
  const box = $("detail");
  box.replaceChildren();
  d.layers.forEach((layer, i) => {
    const section = document.createElement("details");
    section.open = i === d.layers.length - 1;  // open the innermost layer (the interesting bit)
    section.append(el("summary", null, layer.name));
    const dl = el("dl");
    for (const [name, value] of layer.fields) dl.append(el("dt", null, name), el("dd", null, value));
    section.append(dl);
    box.append(section);
  });
  box.append(el("pre", "hex", d.hex.join("\n")));
}

pk.tbody.addEventListener("click", (e) => selectPacket(e.target.closest("tr")));

pk.wrap.tabIndex = 0;
pk.wrap.addEventListener("keydown", (e) => {
  if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
  e.preventDefault();
  const current = pk.tbody.querySelector("tr.selected");
  let next = current
    ? (e.key === "ArrowDown" ? current.nextElementSibling : current.previousElementSibling)
    : pk.tbody.querySelector("tr:not(.hidden)");
  while (next && next.classList.contains("hidden")) {
    next = e.key === "ArrowDown" ? next.nextElementSibling : next.previousElementSibling;
  }
  if (next) selectPacket(next);
});

$("pkt-filter").addEventListener("input", (e) => {
  pk.filter = e.target.value.trim().toLowerCase().split(/\s+/).filter(Boolean);
  for (const tr of pk.tbody.rows) tr.classList.toggle("hidden", !rowMatches(tr));
  updatePacketCount();
});

$("pause-btn").addEventListener("click", () => {
  pk.paused = !pk.paused;
  if (!pk.paused && pk.queued.length) {
    appendRows(pk.queued);
    pk.queued = [];
  }
  updatePauseButton();
});

$("clear-btn").addEventListener("click", () => {
  pk.tbody.replaceChildren();
  pk.queued = [];
  pk.clearedUpTo = pk.lastNo;
  clearSelection();
  updatePauseButton();
  updatePacketCount();
});

clearSelection();

// ---------------------------------------------------------- device details

function currentHighlight() {
  return view.tab === "device" ? view.deviceMac : pk.selectedMacs;
}

function updateHint() {
  const d = view.deviceMac && lastState?.devices.find((x) => x.mac === view.deviceMac);
  $("detail-hint").textContent = view.tab === "packet" ? pk.hint
    : d ? "" : "Click a device to see who it is";
}

function showTab(tab) {
  view.tab = tab;
  for (const name of ["device", "packet"]) {
    const btn = $(`tab-${name}`);
    btn.classList.toggle("active", name === tab);
    btn.setAttribute("aria-selected", name === tab);
  }
  $("device-detail").hidden = tab !== "device";
  $("detail").hidden = tab !== "packet";
  highlight(currentHighlight());
  updateHint();
}

function selectDevice(mac) {
  view.deviceMac = mac;
  showTab("device");
  if (lastState) {
    renderDevices(lastState);
    renderDeviceDetail(lastState);
    renderTopology(lastState);   // the selected node keeps its label on big networks
  }
}

function kvRows(rows) {
  const dl = el("dl", "kv");
  for (const [label, value, sub, title] of rows) {
    if (value == null) continue;
    const dd = el("dd", null, value);
    if (sub) dd.append(el("span", "sub", sub));
    if (title) dd.title = title;
    dl.append(el("dt", null, label), dd);
  }
  return dl;
}

function describeName(d) {
  const source = { DHCP: "told the router in its DHCP request", mDNS: "announced itself over mDNS" };
  if (d.hostname) return [d.hostname, source[d.hostname_source] || ""];
  if (d.role === "self") return ["This Mac", ""];
  return ["Not announced", "It hasn't sent a name in DHCP or mDNS yet"];
}

function describeVendor(d) {
  if (d.vendor) return [d.vendor, `from the MAC prefix ${d.mac.slice(0, 8)} (IEEE OUI list)`];
  if (d.randomized_mac) return ["Hidden", "Private MAC: the first 3 bytes are random, not a manufacturer"];
  return ["Unknown", `MAC prefix ${d.mac.slice(0, 8)} isn't in the OUI list`];
}

function section(title, ...children) {
  const sec = el("section", "dd-section");
  sec.append(el("h3", null, title), ...children);
  return sec;
}

function renderDeviceDetail(s) {
  const box = $("device-detail");
  if (view.tab === "device") updateHint();
  if (!view.deviceMac) {
    box.replaceChildren(el("p", "empty",
      "Click a device in the list or on the topology to see who made it, what it calls itself, " +
      "and when it was seen."));
    return;
  }
  const d = s.devices.find((x) => x.mac === view.deviceMac);
  if (!d) {
    box.replaceChildren(el("p", "empty", "That device is no longer in the list (PacketLens restarted?)."));
    return;
  }

  // Header: name, address, status, actions
  const head = el("div", `dd-head role-${d.role} origin-${d.origin} st-${d.status}`);
  const title = el("div", "dd-title");
  title.append(el("span", "dot"), el("strong", null, deviceName(d)),
               el("span", "mono dd-addr", `${d.ip || "no IP"} · ${d.mac}`));
  const actions = el("div", "dd-actions");
  const showPackets = el("button", "btn small", "Show its packets");
  showPackets.title = "Filter the packet table to this MAC address";
  showPackets.addEventListener("click", () => {
    const input = $("pkt-filter");
    input.value = d.mac;
    input.dispatchEvent(new Event("input"));
  });
  const rename = el("button", "btn small", nicknames[d.mac] ? "Rename" : "Name it");
  rename.title = "Give this device your own name (saved in this browser only)";
  rename.addEventListener("click", () => {
    const name = window.prompt(`Your name for ${d.mac} (leave empty to reset):`, nicknames[d.mac] || "");
    if (name === null) return;
    setNickname(d.mac, name.trim());
    rerender();
  });
  actions.append(showPackets, rename);
  head.append(title, actions);

  // Identity: who is it?
  const [name, nameSub] = describeName(d);
  const [vendor, vendorSub] = describeVendor(d);
  const identity = kvRows([
    nicknames[d.mac] ? ["Your name", nicknames[d.mac], "saved in this browser only"] : null,
    ["Announced", name, nameSub],
    ["Vendor", vendor, vendorSub],
    ["MAC type", d.randomized_mac ? "Private (randomized)" : "Global (burned-in)",
     d.randomized_mac ? "Phones pick a new one per Wi-Fi network" : "The same on every network"],
    ["Looks like", d.kind || (d.role === "self" ? "This Mac" : "No clue yet"),
     d.kind_reason ? `guess from its ${d.kind_reason}` : null],
    ["DHCP client", d.vendor_class || null, "vendor class (DHCP option 60)"],
  ].filter(Boolean));

  // Activity: when and how much?
  const history = d.ip_history.slice().reverse()
    .map(([ip, since]) => `${ip} since ${fmtTime(since)}`);
  const activity = kvRows([
    ["Status", describePresence(d, s.clock)],
    ["Found by", describeOrigin(d)],
    ["First seen", fmtTime(d.first_seen), ago(Math.max(0, s.clock - d.first_seen))],
    ["Last seen", fmtTime(d.last_seen),
     d.last_active < d.last_seen ? `last sent on its own ${fmtTime(d.last_active)}` : null],
    ["IP address", history[0] || "none yet", history.length > 1 ? `before: ${history.slice(1).join(", ")}` : null],
    ["Packets", `${d.packets_sent} sent · ${d.packets_received} received`,
     `${fmtBytes(d.bytes_sent)} sent · ${fmtBytes(d.bytes_received)} received`,
     "Only what this Mac can see: broadcasts, multicasts and traffic to/from this Mac"],
  ]);

  // Timeline from the activity log
  const events = s.log.filter((e) => e.mac === d.mac).reverse().slice(0, 12);
  const ol = el("ol", "log dd-log");
  if (!events.length) ol.append(el("li", "empty", "No join, leave or rename events for this device yet."));
  for (const e of events) {
    const li = el("li", e.level);
    li.append(el("time", null, fmtTime(e.ts)), el("span", "lvl"), el("span", "msg", e.text));
    ol.append(li);
  }

  const grid = el("div", "dd-grid");
  grid.append(section("Who is it?", identity), section("Activity", activity), section("History", ol));
  const note = el("p", "dd-note",
    d.role === "self" ? "This is the computer PacketLens is capturing on."
      : "On Wi-Fi your Mac only receives broadcasts and traffic addressed to it, so this " +
        "device's private traffic (e.g. its web browsing) isn't counted. Monitor mode (Step 6) sees more.");
  box.replaceChildren(head, grid, note);
}

for (const name of ["device", "packet"]) {
  $(`tab-${name}`).addEventListener("click", () => showTab(name));
}
showTab("device");

// ------------------------------------------------------------- top stats

const rate = { stamps: [] };   // [ms, packets] per batch received in the last 10 s

function notePackets(n) {
  const now = Date.now();
  rate.stamps.push([now, n]);
  while (rate.stamps.length && now - rate.stamps[0][0] > 10_000) rate.stamps.shift();
}

function packetsPerSecond() {
  if (rate.stamps.length < 2) return 0;
  const span = (Date.now() - rate.stamps[0][0]) / 1000;
  return span > 1 ? rate.stamps.reduce((a, [, n]) => a + n, 0) / span : 0;
}

function renderStats(s) {
  const devs = s.devices.filter((d) => d.role === "device");
  const count = (...st) => devs.filter((d) => st.includes(d.status)).length;
  const alerts = s.log.filter((e) => e.level === "warn").length;
  const pps = packetsPerSecond();
  const chips = [
    ["online", count("online"), "online", "Sent something in the last minute", () => setDeviceFilter("online")],
    ["idle", count("idle"), "idle", "Quiet, but still answering ARP check-ins", () => setDeviceFilter("idle")],
    ["offline", count("offline", "released"), "offline", "Stopped answering, or said goodbye", () => setDeviceFilter("offline")],
    ["joined", devs.filter((d) => d.origin === "joined").length, "joined", "Seen joining via DHCP while PacketLens was running", () => setDeviceFilter("joined")],
    ["alerts", alerts, alerts === 1 ? "alert" : "alerts", "Warnings: rogue DHCP, refused or unconfirmed joins", () => setLogFilter("alerts")],
    ["rate", pps >= 10 ? Math.round(pps) : pps.toFixed(1), "pkt/s", "Packets per second reaching this Mac", null],
  ];
  const box = $("stats");
  box.replaceChildren();
  for (const [cls, value, label, title, onClick] of chips) {
    const chip = el(onClick ? "button" : "span", `stat ${cls}${cls === "alerts" && alerts ? " hot" : ""}`);
    chip.append(el("b", null, value), el("span", null, label));
    chip.title = title;
    if (onClick) chip.addEventListener("click", onClick);
    box.append(chip);
  }
}

// ------------------------------------------------------------------ theme

const THEME_KEY = "packetlens.theme";
const THEMES = [["", "Auto", "Follows your system theme"], ["light", "Light", ""], ["dark", "Dark", ""]];

function currentTheme() {
  try { return localStorage.getItem(THEME_KEY) || ""; } catch { return ""; }
}

function applyTheme() {
  const t = currentTheme();
  if (t) document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
  const [, label, title] = THEMES.find(([k]) => k === t) || THEMES[0];
  $("theme-btn").textContent = label;
  $("theme-btn").title = `Theme: ${label}. ${title || "Click to change"}`;
}

$("theme-btn").addEventListener("click", () => {
  const i = THEMES.findIndex(([k]) => k === currentTheme());
  const next = THEMES[(i + 1) % THEMES.length][0];
  try { next ? localStorage.setItem(THEME_KEY, next) : localStorage.removeItem(THEME_KEY); } catch { /* fine */ }
  applyTheme();
});
applyTheme();

// -------------------------------------------------------- toolbar wiring

$("dev-search").addEventListener("input", (e) => {
  dl.query = e.target.value.trim().toLowerCase();
  if (lastState) renderDevices(lastState);
});
$("dev-filter").addEventListener("change", (e) => setDeviceFilter(e.target.value));
$("dev-sort").addEventListener("change", (e) => {
  dl.sort = e.target.value;
  if (lastState) renderDevices(lastState);
});
function setExpanded(on) {
  topo.expanded = on;
  rerender();
}
$("topo-collapse").addEventListener("click", () => setExpanded(false));
for (const b of document.querySelectorAll("#log-tabs .tab")) {
  b.addEventListener("click", () => setLogFilter(b.dataset.filter));
}

// ----------------------------------------------------------------- wiring

function rerender() {
  lastVersion = null;
  if (lastState) apply(lastState);
}

function apply(s) {
  if (s.capture.packets < pk.lastNo) resetPackets();  // PacketLens was restarted
  lastState = s;
  renderStatus(s);
  renderStats(s);
  renderDevices(s);                    // every update: keeps "seen 12s ago" fresh
  renderDeviceDetail(s);
  if (s.version === lastVersion) return;
  lastVersion = s.version;
  detectJoins(s);
  renderWifi(s);
  renderTopology(s);
  renderLog(s);
}

function connect() {
  const es = new EventSource("/api/stream");
  es.addEventListener("state", (e) => apply(JSON.parse(e.data)));
  es.addEventListener("packets", (e) => {
    const batch = JSON.parse(e.data);
    notePackets(batch.length);
    addPackets(batch);
  });
  es.onerror = () => {
    $("status").className = "status err";
    $("status-text").textContent = "Lost connection to PacketLens - is it still running?";
    lastVersion = null;
  };
}

$("scan-btn").addEventListener("click", () => {
  $("scan-btn").disabled = true;
  fetch("/api/scan", { method: "POST" }).catch(() => {});
});

$("rename-btn").addEventListener("click", () => {
  const current = storedSsid() || "";
  const name = window.prompt("Wi-Fi name to show (leave empty to reset):", current);
  if (name === null) return;
  storeSsid(name.trim());
  rerender();
});

connect();
