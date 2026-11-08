"use strict";
/* PacketLens dashboard: receives snapshots from /api/stream and draws them. */

const $ = (id) => document.getElementById(id);
const SVG_NS = "http://www.w3.org/2000/svg";
const FRESH_MS = 60_000;          // how long a newly joined device keeps pulsing
const SSID_KEY = "packetlens.ssid";

let lastVersion = null;
let lastState = null;
let lastLogKey = null;
let knownJoins = null;            // mac -> joined_at, to detect new joins for toasts
const freshUntil = new Map();     // mac -> timestamp (ms) when the pulse stops

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

function deviceName(d) {
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

function describeOrigin(d) {
  if (d.status === "released") return "Left the network (DHCP Release)";
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
    text = s.capture.running ? `Live on ${s.network.iface} · ${n} DHCP/ARP packets` : "Starting capture…";
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
  line.classList.toggle("err", !!s.scan.error);
  if (s.source !== "live") line.textContent = "";
  else if (s.scan.error) line.textContent = `Scan failed: ${s.scan.error}`;
  else if (s.scan.running) line.textContent = "ARP scan running…";
  else if (s.scan.last_run) line.textContent = `Last ARP scan ${fmtTime(s.scan.last_run)} · ${s.scan.found} devices replied`;
  else line.textContent = "";
}

// ---------------------------------------------------------------- devices

function renderDevices(s) {
  const list = $("device-list");
  list.replaceChildren();
  $("device-count").textContent = s.devices.length;

  for (const p of s.pending) {
    const li = el("li", "device pending");
    const body = el("div", "device-body");
    const top = el("div", "device-top");
    top.append(el("span", "device-name", p.hostname || "Joining device"),
               el("span", "device-ip mono", p.requested_ip || "no IP yet"));
    body.append(top, el("div", "device-mac mono", p.mac),
                el("div", "device-how", "Asked for an IP · waiting for confirmation"));
    li.append(el("span", "dot"), body);
    list.append(li);
  }

  for (const d of s.devices) {
    const li = el("li", `device role-${d.role} origin-${d.origin}${d.status === "released" ? " released" : ""}`);
    const body = el("div", "device-body");
    const top = el("div", "device-top");
    top.append(el("span", "device-name", deviceName(d)), el("span", "device-ip mono", d.ip || "no IP"));
    const mac = el("div", "device-mac mono", d.mac);
    if (d.randomized_mac) {
      const badge = el("span", "badge", "private MAC");
      badge.title = "Randomized per-network MAC (locally administered bit set) - common on phones";
      mac.append(badge);
    }
    body.append(top, mac, el("div", "device-how", describeOrigin(d)));
    li.append(el("span", "dot"), body);
    li.addEventListener("mouseenter", () => highlight(d.mac));
    li.addEventListener("mouseleave", () => highlight(null));
    list.append(li);
  }
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
  w: 0,
  h: 0,
  raf: null,
};
topo.svg.append(topo.links, topo.nodes, topo.hint);

function makeItem(d, from) {
  const r = d.role === "router" ? 34 : 27;
  const g = svgEl("g", { class: "node" });
  const parts = {
    pulse: svgEl("circle", { class: "pulse", r }),
    body: svgEl("circle", { class: "body", r }),
    inner: svgEl("text", { class: "inner", "text-anchor": "middle", dy: "0.35em" }),
    name: svgEl("text", { class: "name", "text-anchor": "middle", y: r + 17 }),
    sub: svgEl("text", { class: "sub", "text-anchor": "middle", y: r + 31 }),
    title: svgEl("title"),
  };
  g.append(...Object.values(parts));
  const line = svgEl("line", { class: "link" });
  topo.links.append(line);
  topo.nodes.append(g);
  return { g, line, ...parts, x: from.x, y: from.y, tx: from.x, ty: from.y };
}

function layoutTargets() {
  const cx = topo.w / 2;
  const cy = topo.h / 2 - 10;
  const others = topo.devices.filter((d) => d.mac !== topo.routerKey);
  const rx = Math.max(90, topo.w / 2 - 90);
  const ry = Math.max(80, topo.h / 2 - 70);
  const targets = new Map([[topo.routerKey, { x: cx, y: cy }]]);
  const twoRings = others.length > 12;
  others.forEach((d, i) => {
    const angle = -Math.PI / 2 + (i / others.length) * Math.PI * 2;
    const k = twoRings && i % 2 ? 0.6 : 1;
    targets.set(d.mac, { x: cx + Math.cos(angle) * rx * k, y: cy + Math.sin(angle) * ry * k });
  });
  return targets;
}

function renderTopology(s) {
  const router = s.devices.find((d) => d.role === "router")
    || { mac: "__router__", role: "router", ip: s.router.ip, origin: "existing", status: "online" };
  topo.routerKey = router.mac;
  topo.devices = [router, ...s.devices.filter((d) => d.role !== "router")];

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
    const fresh = isFresh(d.mac);
    const state = `role-${d.role} origin-${d.origin}${d.status === "released" ? " released" : ""}${fresh ? " fresh" : ""}`;
    it.g.setAttribute("class", `node ${state}`);
    it.line.setAttribute("class", `link ${state}`);
    it.line.style.display = d.mac === router.mac ? "none" : "";
    it.inner.textContent = lastOctet(d.ip);
    const name = deviceName(d);
    it.name.textContent = name.length > 20 ? name.slice(0, 19) + "…" : name;
    it.sub.textContent = d.mac === "__router__" ? "" : d.mac;
    it.title.textContent = `${name}\n${d.ip || "no IP"}\n${d.mac}\n${describeOrigin(d)}`;
  }
  for (const [mac, it] of topo.items) {
    if (!present.has(mac)) {
      it.g.remove();
      it.line.remove();
      topo.items.delete(mac);
    }
  }

  const deviceCount = topo.devices.filter((d) => d.role === "device").length;
  topo.hint.textContent = deviceCount
    ? ""
    : "Waiting for devices… reconnect a phone to this Wi-Fi to watch it appear.";
  relayout();
}

function relayout() {
  if (!topo.w || !topo.h) return;  // not sized yet; ResizeObserver will call us again
  const targets = layoutTargets();
  for (const [mac, t] of targets) {
    const it = topo.items.get(mac);
    if (!it) continue;
    it.tx = t.x;
    it.ty = t.y;
    if (topo.snapNext) { it.x = t.x; it.y = t.y; }
  }
  topo.snapNext = false;
  topo.hint.setAttribute("x", topo.w / 2);
  topo.hint.setAttribute("y", topo.h - 14);
  if (!topo.raf) topo.raf = requestAnimationFrame(tick);
}

function tick() {
  let moving = false;
  for (const it of topo.items.values()) {
    const dx = it.tx - it.x;
    const dy = it.ty - it.y;
    if (Math.abs(dx) > 0.3 || Math.abs(dy) > 0.3) {
      it.x += dx * 0.12;
      it.y += dy * 0.12;
      moving = true;
    } else {
      it.x = it.tx;
      it.y = it.ty;
    }
    it.g.setAttribute("transform", `translate(${it.x.toFixed(1)},${it.y.toFixed(1)})`);
  }
  const r = topo.items.get(topo.routerKey);
  if (r) {
    for (const it of topo.items.values()) {
      it.line.setAttribute("x1", r.x); it.line.setAttribute("y1", r.y);
      it.line.setAttribute("x2", it.x); it.line.setAttribute("y2", it.y);
    }
  }
  topo.raf = moving ? requestAnimationFrame(tick) : null;
}

function highlight(mac) {
  for (const [key, it] of topo.items) it.g.classList.toggle("hl", key === mac);
}

new ResizeObserver(() => {
  topo.w = topo.svg.clientWidth;
  topo.h = topo.svg.clientHeight;
  topo.svg.setAttribute("viewBox", `0 0 ${topo.w} ${topo.h}`);
  relayout();
}).observe(topo.svg);

// -------------------------------------------------------------------- log

function renderLog(s) {
  const key = `${s.log.length}:${s.log.length ? s.log[s.log.length - 1].ts : 0}`;
  if (key === lastLogKey) return;
  lastLogKey = key;
  const ol = $("log");
  ol.replaceChildren();
  if (!s.log.length) {
    ol.append(el("li", "empty", "Nothing yet. DHCP and ARP steps will appear here as they're captured."));
    return;
  }
  for (const e of [...s.log].reverse()) {
    const li = el("li", e.level);
    const t = el("time", null, fmtTime(e.ts));
    li.append(t, el("span", "lvl"), el("span", "msg", e.text));
    ol.append(li);
  }
}

// ------------------------------------------------------------ new joins

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
}

function toast(title, detail) {
  const t = el("div", "toast");
  t.append(el("strong", null, title), el("span", "mono", detail));
  $("toasts").append(t);
  setTimeout(() => t.remove(), 6000);
}

// ----------------------------------------------------------------- wiring

function rerender() {
  lastVersion = null;
  if (lastState) apply(lastState);
}

function apply(s) {
  lastState = s;
  renderStatus(s);
  if (s.version === lastVersion) return;
  lastVersion = s.version;
  detectJoins(s);
  renderWifi(s);
  renderDevices(s);
  renderTopology(s);
  renderLog(s);
}

function connect() {
  const es = new EventSource("/api/stream");
  es.onmessage = (e) => apply(JSON.parse(e.data));
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
