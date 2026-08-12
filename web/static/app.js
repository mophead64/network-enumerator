"use strict";

/* ---------------------------------------------------------------------- */
/* small utilities                                                        */
/* ---------------------------------------------------------------------- */

const qs = (sel, root) => (root || document).querySelector(sel);
const qsa = (sel, root) => Array.from((root || document).querySelectorAll(sel));

function el(tag, attrs, children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined) node.setAttribute(k, v);
  }
  for (const c of children || []) {
    if (c === null || c === undefined) continue;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

function debounce(fn, ms) {
  let t = null;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function timeAgo(iso) {
  if (!iso || iso.startsWith("0001-01-01")) return "never"; // Go's zero-value time.Time
  const d = new Date(iso);
  if (isNaN(d)) return "—";
  const secs = Math.max(0, (Date.now() - d.getTime()) / 1000);
  if (secs < 5) return "just now";
  if (secs < 60) return Math.floor(secs) + "s ago";
  if (secs < 3600) return Math.floor(secs / 60) + "m ago";
  if (secs < 86400) return Math.floor(secs / 3600) + "h ago";
  return Math.floor(secs / 86400) + "d ago";
}

function fmtTime(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return "";
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/* ---------------------------------------------------------------------- */
/* IPv4 / CIDR arithmetic (used to bucket large subnets in the graph)     */
/* ---------------------------------------------------------------------- */

function ipToInt(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    const v = Number(p);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}

function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

function cidrPrefix(cidr) {
  const parts = (cidr || "").split("/");
  if (parts.length !== 2) return null;
  const p = Number(parts[1]);
  return Number.isInteger(p) && p >= 0 && p <= 32 ? p : null;
}

/** The prefix length of the next bucketing level below `prefix`, stepping
 * in 8-bit (one octet) increments and capping at /24 — the level at which
 * individual hosts are shown instead of another layer of buckets. */
function nextBucketPrefix(prefix) {
  const rounded = prefix % 8 === 0 ? prefix + 8 : Math.ceil(prefix / 8) * 8;
  return Math.min(24, rounded);
}

/** The dotted CIDR of the bucket `ip` falls into at `prefix`. */
function networkCIDR(ip, prefix) {
  const n = ipToInt(ip);
  if (n === null) return null;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return intToIp((n & mask) >>> 0) + "/" + prefix;
}

/** Groups hosts one bucketing level below `prefix` — stepping in octets,
 * capped at /24 where individual hosts show instead of another bucket
 * layer — used by Graph._layoutLevel. Returns null at a leaf level
 * (prefix >= 24 or unknown), meaning "render these hosts directly, no
 * further grouping". */
function nextTreeLevel(hosts, prefix) {
  if (prefix === null || prefix >= 24) return null;
  const childPrefix = nextBucketPrefix(prefix);
  const groups = new Map();
  for (const h of hosts) {
    const cidr = networkCIDR(h.ip, childPrefix);
    if (!groups.has(cidr)) groups.set(cidr, []);
    groups.get(cidr).push(h);
  }
  return { childPrefix, groups };
}

/* ---------------------------------------------------------------------- */
/* API                                                                    */
/* ---------------------------------------------------------------------- */

const AUTH_EXEMPT_PATHS = new Set(["/api/auth/login", "/api/auth/me"]);

// Changing credentials revokes every outstanding session token server-side
// before minting a fresh one. Any request already in flight at that moment
// (a background poll, a live SSE reconnect) can land in between and get a
// stray 401 on a session that's actually fine going forward — without this
// guard that 401 would boot the user straight back to the login screen a
// split second after a successful password change. Sits in module scope
// (not per-request state) so every concurrent request checks the same flag.
let suppressSessionExpiry = false;

const Api = {
  async _req(method, path, body) {
    const res = await fetch(path, {
      method,
      headers: body ? { "Content-Type": "application/json" } : undefined,
      body: body ? JSON.stringify(body) : undefined,
    });
    if (res.status === 401 && !AUTH_EXEMPT_PATHS.has(path)) {
      if (!suppressSessionExpiry) showLoginScreen();
      throw new Error("Session expired — please sign in again.");
    }
    if (!res.ok) {
      let msg = res.statusText;
      try { msg = (await res.json()).error || msg; } catch (_) { /* ignore */ }
      throw new Error(msg);
    }
    if (res.status === 204) return null;
    return res.json();
  },
  login: (username, password) => Api._req("POST", "/api/auth/login", { username, password }),
  logout: () => Api._req("POST", "/api/auth/logout"),
  me: () => Api._req("GET", "/api/auth/me"),
  changePassword: (currentPassword, newUsername, newPassword) =>
    Api._req("POST", "/api/auth/change-password", { currentPassword, newUsername, newPassword }),
  activeSessions: () => Api._req("GET", "/api/auth/sessions"),

  subnets: () => Api._req("GET", "/api/subnets"),
  addSubnet: (cidr, name) => Api._req("POST", "/api/subnets", { cidr, name }),
  renameSubnet: (id, name) => Api._req("PATCH", `/api/subnets/${id}`, { name }),
  setSubnetHidden: (id, hidden) => Api._req("PATCH", `/api/subnets/${id}`, { hidden }),
  setSubnetEnabled: (id, enabled) => Api._req("PATCH", `/api/subnets/${id}`, { enabled }),
  deleteSubnet: (id) => Api._req("DELETE", `/api/subnets/${id}`),

  hosts: () => Api._req("GET", "/api/hosts"),
  addHost: (subnetId, ip, hostname, notes) => Api._req("POST", "/api/hosts", { subnetId, ip, hostname, notes }),
  updateHost: (id, fields) => Api._req("PATCH", `/api/hosts/${id}`, fields),
  deleteHost: (id) => Api._req("DELETE", `/api/hosts/${id}`),
  clearAllHosts: (confirm) => Api._req("DELETE", `/api/hosts?confirm=${encodeURIComponent(confirm)}`),
  addHostTag: (hostId, tagId) => Api._req("POST", `/api/hosts/${hostId}/tags`, { tagId }),
  removeHostTag: (hostId, tagId) => Api._req("DELETE", `/api/hosts/${hostId}/tags/${tagId}`),

  tags: () => Api._req("GET", "/api/tags"),
  createTag: (name, color) => Api._req("POST", "/api/tags", { name, color }),
  deleteTag: (id) => Api._req("DELETE", `/api/tags/${id}`),

  ackHost: (id) => Api._req("POST", `/api/hosts/${id}/ack`),
  unackHost: (id) => Api._req("DELETE", `/api/hosts/${id}/ack`),
  ackHostNew: (id) => Api._req("POST", `/api/hosts/${id}/new-ack`),
  ackAllHostsNew: () => Api._req("POST", "/api/hosts/new-ack-all"),
  deepScanHost: (id) => Api._req("POST", `/api/hosts/${id}/deep-scan`),

  riskRules: () => Api._req("GET", "/api/risk-rules"),
  createRiskRule: (port, label, severity, service, versionBelow) =>
    Api._req("POST", "/api/risk-rules", { port, label, severity, service, versionBelow }),
  updateRiskRule: (id, fields) => Api._req("PATCH", `/api/risk-rules/${id}`, fields),
  deleteRiskRule: (id) => Api._req("DELETE", `/api/risk-rules/${id}`),

  healthz: () => Api._req("GET", "/api/healthz"),

  settings: () => Api._req("GET", "/api/settings"),
  updateSettings: (scanMethod) => Api._req("PATCH", "/api/settings", { scanMethod }),
  updateNetdiscoverEnabled: (netdiscoverEnabled) => Api._req("PATCH", "/api/settings", { netdiscoverEnabled }),

  importNetworkMap: (doc) => Api._req("POST", "/api/import/network-map", doc),
  importSystem: (doc) => Api._req("POST", "/api/import/system", doc),
  importDnsRecon: (records) => Api._req("POST", "/api/import/dnsrecon", records),
  // Raw XML, not JSON — bypasses _req's JSON.stringify/Content-Type: application/json.
  importNmapXml: async (xmlText) => {
    const res = await fetch("/api/import/nmap", {
      method: "POST",
      headers: { "Content-Type": "text/xml" },
      body: xmlText,
    });
    if (res.status === 401 && !AUTH_EXEMPT_PATHS.has("/api/import/nmap")) {
      if (!suppressSessionExpiry) showLoginScreen();
      throw new Error("Session expired — please sign in again.");
    }
    if (!res.ok) {
      let msg = res.statusText;
      try { msg = (await res.json()).error || msg; } catch (_) { /* ignore */ }
      throw new Error(msg);
    }
    return res.json();
  },

  events: () => Api._req("GET", "/api/events"),
  toolStatus: () => Api._req("GET", "/api/tools/status"),
  quickScanAll: () => Api._req("POST", "/api/scan/quick"),
  massScanAll: () => Api._req("POST", "/api/scan/mass"),
  deepScanAll: () => Api._req("POST", "/api/scan/deep"),
  reverseDnsScanAll: () => Api._req("POST", "/api/scan/reverse-dns"),
  scanStatus: () => Api._req("GET", "/api/scan/status"),
};

/* ---------------------------------------------------------------------- */
/* state                                                                  */
/* ---------------------------------------------------------------------- */

const state = {
  subnets: [],
  hosts: [],
  tags: [],
  events: [],
  riskRules: [],
  selectedHostId: null,
  filters: { search: "", status: "", newOnly: false, subnetId: "", risk: "", hideSuspect: false, priorityOnly: false, tagIds: new Set(), showHiddenSubnets: false },
  sortBy: "priority",
  // Bucket keys expanded in the graph (a subnet bigger than /24 groups its
  // hosts into buckets — see Graph._layoutLevel — until clicked open).
  expandedBuckets: new Set(),
  // Subnet keys collapsed in the graph — inverse sense of expandedBuckets
  // (subnets default to expanded, so this tracks the exception).
  collapsedSubnets: new Set(),
  notifDismissed: new Set(), // event ids the user has cleared from the bell panel
  notifUnread: new Set(), // event ids not yet seen (drives the bell badge count)
  pendingTagAdds: [], // staged in the host modal until Save is clicked
  pendingTagRemoves: [],
  // "graph" | "table" — table view swaps the animated canvas out entirely
  // for a searchable, expandable subnet/host table. Persisted per browser,
  // not per account, since it's about viewing preference.
  viewMode: localStorage.getItem("viewMode") === "table" ? "table" : "graph",
  // Subnet ids expanded in the table view — independent of the graph's
  // collapsedSubnets (opposite default: table rows start collapsed, so
  // this tracks which ones the user opened, not which they closed).
  tableExpandedSubnets: new Set(),
};

function subnetById(id) { return state.subnets.find((s) => s.id === id); }
function hostById(id) { return state.hosts.find((h) => h.id === id); }
function tagById(id) { return state.tags.find((t) => t.id === id); }

/* ---------------------------------------------------------------------- */
/* graph (force-directed canvas visualization)                            */
/* ---------------------------------------------------------------------- */

const TAG_PALETTE = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"];

class Graph {
  static ZOOM_MIN = 0.15;
  static ZOOM_MAX = 4;

  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.nodes = new Map(); // key -> node
    this.links = [];
    this.transform = { x: 0, y: 0, k: 1 };
    this.dragging = null;
    this.panning = null;
    this.hoverKey = null;
    this.running = false;
    this.paused = false;
    this.dpr = window.devicePixelRatio || 1;

    this._resize = this._resize.bind(this);
    window.addEventListener("resize", this._resize);
    this._resize();

    canvas.addEventListener("mousedown", (e) => this._onMouseDown(e));
    window.addEventListener("mousemove", (e) => this._onMouseMove(e));
    window.addEventListener("mouseup", () => this._onMouseUp());
    canvas.addEventListener("wheel", (e) => this._onWheel(e), { passive: false });
    canvas.addEventListener("click", (e) => this._onClick(e));
    canvas.addEventListener("dblclick", (e) => this._onDblClick(e));
  }

  _resize() {
    const rect = this.canvas.parentElement.getBoundingClientRect();
    this.dpr = window.devicePixelRatio || 1;
    this.canvas.width = rect.width * this.dpr;
    this.canvas.height = rect.height * this.dpr;
    this.canvas.style.width = rect.width + "px";
    this.canvas.style.height = rect.height + "px";
    this.width = rect.width;
    this.height = rect.height;
    if (!this._centered && this.width) {
      this.transform.x = this.width / 2;
      this.transform.y = this.height / 2;
      this._centered = true;
    }
    this.wake();
  }

  screenToWorld(sx, sy) {
    return { x: (sx - this.transform.x) / this.transform.k, y: (sy - this.transform.y) / this.transform.k };
  }

  _nodeAt(sx, sy) {
    const w = this.screenToWorld(sx, sy);
    let best = null, bestD = Infinity;
    for (const n of this.nodes.values()) {
      const d = Math.hypot(n.x - w.x, n.y - w.y);
      if (d < n.r + 3 && d < bestD) { best = n; bestD = d; }
    }
    return best;
  }

  _onMouseDown(e) {
    const rect = this.canvas.getBoundingClientRect();
    const sx = e.clientX - rect.left, sy = e.clientY - rect.top;
    const n = this._nodeAt(sx, sy);
    if (n) {
      this.dragging = n;
      n.pinned = true;
      this._dragMoved = false;
    } else {
      this.panning = { startX: sx, startY: sy, ox: this.transform.x, oy: this.transform.y };
    }
  }

  _onMouseMove(e) {
    const rect = this.canvas.getBoundingClientRect();
    const sx = e.clientX - rect.left, sy = e.clientY - rect.top;
    if (this.dragging) {
      const w = this.screenToWorld(sx, sy);
      this.dragging.x = w.x;
      this.dragging.y = w.y;
      this.dragging.vx = 0;
      this.dragging.vy = 0;
      this._dragMoved = true;
      this.wake();
    } else if (this.panning) {
      this.transform.x = this.panning.ox + (sx - this.panning.startX);
      this.transform.y = this.panning.oy + (sy - this.panning.startY);
      this.wake();
    } else {
      const n = this._nodeAt(sx, sy);
      const key = n ? n.key : null;
      if (key !== this.hoverKey) { this.hoverKey = key; this.canvas.style.cursor = n ? "pointer" : "grab"; this.wake(); }
    }
  }

  _onMouseUp() {
    this.dragging = null;
    this.panning = null;
  }

  _onWheel(e) {
    e.preventDefault();
    const rect = this.canvas.getBoundingClientRect();
    this._zoomAt(e.clientX - rect.left, e.clientY - rect.top, Math.exp(-e.deltaY * 0.001));
  }

  /** Zooms by factor around the screen point (sx, sy) so that point stays
   * under the cursor — shared by scroll-to-zoom (_onWheel, screen point =
   * cursor) and the +/- zoom buttons (zoomBy, screen point = canvas center,
   * for users who'd rather click than scroll/pinch). */
  _zoomAt(sx, sy, factor) {
    const before = this.screenToWorld(sx, sy);
    this.transform.k = Math.min(Graph.ZOOM_MAX, Math.max(Graph.ZOOM_MIN, this.transform.k * factor));
    const after = this.screenToWorld(sx, sy);
    this.transform.x += (after.x - before.x) * this.transform.k;
    this.transform.y += (after.y - before.y) * this.transform.k;
    this.wake();
  }

  /** Zooms in (factor > 1) or out (factor < 1) centered on the canvas —
   * the +/- zoom buttons' handler. */
  zoomBy(factor) {
    this._zoomAt(this.width / 2, this.height / 2, factor);
  }

  /** Restores the default 1:1 zoom, centered — the "reset zoom" button. */
  resetZoom() {
    this.transform.x = this.width / 2;
    this.transform.y = this.height / 2;
    this.transform.k = 1;
    this.wake();
  }

  _onClick(e) {
    if (this._dragMoved) { this._dragMoved = false; return; }
    const rect = this.canvas.getBoundingClientRect();
    const sx = e.clientX - rect.left, sy = e.clientY - rect.top;
    const n = this._nodeAt(sx, sy);
    if (n && n.type === "host") openHostModal(n.hostId);
    else if (n && n.type === "bucket") this.toggleBucket(n.key);
    else if (n && n.type === "subnet") this.toggleSubnet(n.key);
  }

  _onDblClick(e) {
    const rect = this.canvas.getBoundingClientRect();
    const sx = e.clientX - rect.left, sy = e.clientY - rect.top;
    const n = this._nodeAt(sx, sy);
    if (n) { n.pinned = false; this.wake(); }
  }

  /** (Re)starts the physics/redraw loop if it isn't already running.
   * paused suppresses it completely — see setPaused. */
  wake() {
    this._sleepFrames = 0;
    if (this.paused) return;
    if (!this.running) { this.running = true; requestAnimationFrame(() => this._tick()); }
  }

  /** Pausing stops the physics/redraw loop outright — wake() becomes a
   * no-op rather than just hiding the canvas — so table view (which shows
   * neither this canvas) genuinely costs nothing, instead of continuing to
   * repaint an invisible element. Unpausing wakes it so the (possibly
   * stale, since sync() was still updating the node/link data underneath)
   * layout redraws immediately. */
  setPaused(paused) {
    this.paused = paused;
    if (!paused) this.wake();
  }

  _ensureNode(key, factory) {
    if (!this.nodes.has(key)) this.nodes.set(key, factory());
    return this.nodes.get(key);
  }

  _jitterNear(parent, cx, cy) {
    const jitter = () => (Math.random() - 0.5) * 40;
    return { x: (parent ? parent.x : cx) + jitter(), y: (parent ? parent.y : cy) + jitter() };
  }

  /** Recursively lays out hosts under parentKey, bucketing by /24-aligned
   * octet boundaries whenever the containing subnet is bigger than /24 —
   * otherwise a subnet with hundreds or thousands of hosts (a /16, a /8)
   * would dump one node per host straight into the canvas and the physics
   * simulation and rendering both fall over. Buckets stay collapsed
   * (showing just a count) until clicked; expanding one drills one octet
   * level deeper, down to real host nodes at /24. */
  _layoutLevel(parentKey, hosts, prefix, subnetId, nextKeys, cx, cy) {
    const parent = this.nodes.get(parentKey);
    const level = nextTreeLevel(hosts, prefix);
    if (!level) {
      for (const h of hosts) {
        const key = "host:" + h.id;
        nextKeys.add(key);
        const node = this._ensureNode(key, () => ({
          key, type: "host", hostId: h.id, r: 7, vx: 0, vy: 0, pinned: false,
          ...this._jitterNear(parent, cx, cy),
        }));
        node.data = h;
        this.links.push({ a: parentKey, b: key });
      }
      return;
    }

    for (const [cidr, groupHosts] of level.groups) {
      const bucketKey = "bucket:" + subnetId + ":" + cidr;
      nextKeys.add(bucketKey);
      const node = this._ensureNode(bucketKey, () => ({
        key: bucketKey, type: "bucket", subnetId, cidr, prefix: level.childPrefix, r: 14, vx: 0, vy: 0, pinned: false,
        ...this._jitterNear(parent, cx, cy),
      }));
      node.count = groupHosts.length;
      node.expanded = state.expandedBuckets.has(bucketKey);
      this.links.push({ a: parentKey, b: bucketKey });
      if (node.expanded) {
        this._layoutLevel(bucketKey, groupHosts, level.childPrefix, subnetId, nextKeys, cx, cy);
      }
    }
  }

  /** Rebuild node/link set from current subnets+hosts, preserving positions
   * of nodes that still exist. */
  sync(subnets, hosts) {
    const nextKeys = new Set();
    const cx = 0, cy = 0;

    subnets.forEach((sn, i) => {
      const key = "subnet:" + sn.id;
      nextKeys.add(key);
      if (!this.nodes.has(key)) {
        const angle = (i / Math.max(1, subnets.length)) * Math.PI * 2;
        this.nodes.set(key, {
          key, type: "subnet", subnetId: sn.id, r: 16,
          x: cx + Math.cos(angle) * 160, y: cy + Math.sin(angle) * 160,
          vx: 0, vy: 0, pinned: false,
        });
      }
      this.nodes.get(key).data = sn;
    });

    const bySubnet = new Map();
    hosts.forEach((h) => {
      if (!bySubnet.has(h.subnetId)) bySubnet.set(h.subnetId, []);
      bySubnet.get(h.subnetId).push(h);
    });

    this.links = [];
    for (const sn of subnets) {
      const subnetKey = "subnet:" + sn.id;
      const subnetHosts = bySubnet.get(sn.id) || [];
      const node = this.nodes.get(subnetKey);
      node.count = subnetHosts.length;
      node.expanded = !state.collapsedSubnets.has(subnetKey);
      if (node.expanded) {
        this._layoutLevel(subnetKey, subnetHosts, cidrPrefix(sn.cidr), sn.id, nextKeys, cx, cy);
      }
    }

    for (const key of Array.from(this.nodes.keys())) {
      if (!nextKeys.has(key)) this.nodes.delete(key);
    }

    this.wake();
  }

  toggleBucket(bucketKey) {
    if (state.expandedBuckets.has(bucketKey)) state.expandedBuckets.delete(bucketKey);
    else state.expandedBuckets.add(bucketKey);
    renderGraph();
  }

  toggleSubnet(subnetKey) {
    if (state.collapsedSubnets.has(subnetKey)) state.collapsedSubnets.delete(subnetKey);
    else state.collapsedSubnets.add(subnetKey);
    renderGraph();
  }

  _physicsTick() {
    const nodes = Array.from(this.nodes.values());
    const n = nodes.length;
    if (n === 0) return 0;

    // Repulsion used to be skipped entirely above a node-count cutoff (an
    // O(n^2) all-pairs check was too slow past a few hundred nodes). That
    // meant a large scan's hosts had nothing keeping them apart once a
    // subnet got busy, so they'd pile on top of each other in the graph.
    // A uniform spatial-hash grid keeps the same collision behavior but
    // only checks nearby nodes, so repulsion now always runs regardless of
    // node count. cell must be >= the largest possible minDist below (a
    // subnet-subnet pair, 16+16+70=102) so any interacting pair is
    // guaranteed to land in the same or a neighboring cell.
    const cell = 110;
    const grid = new Map();
    for (const node of nodes) {
      const key = Math.floor(node.x / cell) + "," + Math.floor(node.y / cell);
      let bucket = grid.get(key);
      if (!bucket) { bucket = []; grid.set(key, bucket); }
      bucket.push(node);
    }

    for (const a of nodes) {
      const acx = Math.floor(a.x / cell), acy = Math.floor(a.y / cell);
      for (let gx = acx - 1; gx <= acx + 1; gx++) {
        for (let gy = acy - 1; gy <= acy + 1; gy++) {
          const bucket = grid.get(gx + "," + gy);
          if (!bucket) continue;
          for (const b of bucket) {
            if (a.key >= b.key) continue; // process each unordered pair once, skip self
            let dx = a.x - b.x, dy = a.y - b.y;
            let d2 = dx * dx + dy * dy;
            if (d2 < 0.01) { dx = (Math.random() - 0.5); dy = (Math.random() - 0.5); d2 = 0.01; }
            const aWide = a.type === "subnet" || a.type === "bucket";
            const bWide = b.type === "subnet" || b.type === "bucket";
            const minDist = a.r + b.r + (aWide || bWide ? 70 : 24);
            if (d2 < minDist * minDist) {
              const d = Math.sqrt(d2);
              const force = ((minDist - d) / d) * 0.06;
              const fx = dx * force, fy = dy * force;
              if (!a.pinned) { a.vx += fx; a.vy += fy; }
              if (!b.pinned) { b.vx -= fx; b.vy -= fy; }
            }
          }
        }
      }
    }

    for (const link of this.links) {
      const a = this.nodes.get(link.a), b = this.nodes.get(link.b);
      if (!a || !b) continue;
      const target = 90;
      let dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.hypot(dx, dy) || 0.01;
      const force = (d - target) * 0.02;
      const fx = (dx / d) * force, fy = (dy / d) * force;
      if (!a.pinned) { a.vx += fx; a.vy += fy; }
      if (!b.pinned) { b.vx -= fx; b.vy -= fy; }
    }

    let maxSpeed = 0;
    for (const node of nodes) {
      if (node.pinned) { node.vx = 0; node.vy = 0; continue; }
      // gentle pull toward origin so the graph doesn't drift off screen
      node.vx += -node.x * 0.0015;
      node.vy += -node.y * 0.0015;
      node.vx *= 0.82;
      node.vy *= 0.82;
      node.x += node.vx;
      node.y += node.vy;
      maxSpeed = Math.max(maxSpeed, Math.abs(node.vx), Math.abs(node.vy));
    }
    return maxSpeed;
  }

  _tick() {
    const speed = this._physicsTick();
    this._draw();
    this._sleepFrames = speed < 0.05 ? (this._sleepFrames || 0) + 1 : 0;
    if (this._sleepFrames > 60) {
      this.running = false;
      return;
    }
    requestAnimationFrame(() => this._tick());
  }

  _draw() {
    const ctx = this.ctx;
    ctx.save();
    ctx.setTransform(this.dpr, 0, 0, this.dpr, 0, 0);
    ctx.clearRect(0, 0, this.width, this.height);
    ctx.translate(this.transform.x, this.transform.y);
    ctx.scale(this.transform.k, this.transform.k);

    const css = getComputedStyle(document.documentElement);
    const grid = css.getPropertyValue("--grid").trim();
    const muted = css.getPropertyValue("--text-muted").trim();
    const primary = css.getPropertyValue("--text-primary").trim();
    const surface1 = css.getPropertyValue("--surface-1").trim();
    const good = css.getPropertyValue("--status-good").trim();
    const critical = css.getPropertyValue("--status-critical").trim();
    const warning = css.getPropertyValue("--status-warning").trim();
    const seriesBlue = css.getPropertyValue("--series-1").trim();

    ctx.lineWidth = 1 / this.transform.k;
    ctx.strokeStyle = grid;
    for (const link of this.links) {
      const a = this.nodes.get(link.a), b = this.nodes.get(link.b);
      if (!a || !b) continue;
      ctx.beginPath();
      ctx.moveTo(a.x, a.y);
      ctx.lineTo(b.x, b.y);
      ctx.stroke();
    }

    const showLabels = this.transform.k > 0.55 && this.nodes.size < 260;

    for (const node of this.nodes.values()) {
      if (node.type === "subnet") {
        ctx.save();
        ctx.translate(node.x, node.y);
        ctx.strokeStyle = muted;
        ctx.lineWidth = 2 / this.transform.k;
        ctx.strokeRect(-node.r, -node.r, node.r * 2, node.r * 2);
        ctx.fillStyle = surface1;
        ctx.fillRect(-node.r + 1, -node.r + 1, node.r * 2 - 2, node.r * 2 - 2);
        ctx.fillStyle = muted;
        ctx.font = `600 ${11 / this.transform.k}px system-ui, sans-serif`;
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(node.expanded ? "−" : "+", 0, 0);
        ctx.textBaseline = "alphabetic";
        ctx.restore();
        if (this.transform.k > 0.35) {
          ctx.fillStyle = node.count ? muted : warning;
          ctx.font = `${11 / this.transform.k}px system-ui, sans-serif`;
          ctx.textAlign = "center";
          const label = node.data ? subnetGraphLabel(node.data, node.count) : "";
          ctx.fillText(label, node.x, node.y - node.r - 6 / this.transform.k);
        }
        continue;
      }

      if (node.type === "bucket") {
        ctx.save();
        ctx.translate(node.x, node.y);
        ctx.setLineDash([3 / this.transform.k, 3 / this.transform.k]);
        ctx.strokeStyle = seriesBlue;
        ctx.lineWidth = 2 / this.transform.k;
        ctx.strokeRect(-node.r, -node.r, node.r * 2, node.r * 2);
        ctx.setLineDash([]);
        ctx.fillStyle = surface1;
        ctx.fillRect(-node.r + 1, -node.r + 1, node.r * 2 - 2, node.r * 2 - 2);
        ctx.fillStyle = seriesBlue;
        ctx.font = `600 ${11 / this.transform.k}px system-ui, sans-serif`;
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(node.expanded ? "−" : "+", 0, 0);
        ctx.textBaseline = "alphabetic";
        ctx.restore();
        if (this.transform.k > 0.3) {
          ctx.fillStyle = muted;
          ctx.font = `${11 / this.transform.k}px system-ui, sans-serif`;
          ctx.textAlign = "center";
          ctx.fillText(`${node.cidr} (${node.count})`, node.x, node.y - node.r - 6 / this.transform.k);
        }
        continue;
      }

      const h = node.data;
      let color = muted;
      let alpha = 1;
      if (h) {
        if (h.status === "down") { color = critical; alpha = 0.55; }
        else if (h.status === "unknown") { color = muted; alpha = 0.75; }
        else { color = good; }
      }
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.globalAlpha = alpha;
      ctx.fill();
      ctx.globalAlpha = 1;

      if (h && h.isNew) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r + 3 / this.transform.k, 0, Math.PI * 2);
        ctx.strokeStyle = warning;
        ctx.lineWidth = 2 / this.transform.k;
        ctx.stroke();
      }

      if (node.key === this.hoverKey || node.hostId === state.selectedHostId) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r + 5 / this.transform.k, 0, Math.PI * 2);
        ctx.strokeStyle = seriesBlue;
        ctx.lineWidth = 2 / this.transform.k;
        ctx.stroke();
      }

      if (h && h.tags && h.tags.length) {
        const t = h.tags[0];
        ctx.beginPath();
        ctx.arc(node.x + node.r * 0.7, node.y - node.r * 0.7, 3 / this.transform.k, 0, Math.PI * 2);
        ctx.fillStyle = t.color;
        ctx.fill();
      }

      if (showLabels || node.key === this.hoverKey) {
        ctx.fillStyle = primary;
        ctx.font = `${10.5 / this.transform.k}px system-ui, sans-serif`;
        ctx.textAlign = "center";
        ctx.fillText((h && (h.hostname || h.ip)) || "", node.x, node.y + node.r + 11 / this.transform.k);
      }
    }
    ctx.restore();
  }
}

let graph;

/* ---------------------------------------------------------------------- */
/* rendering                                                              */
/* ---------------------------------------------------------------------- */

function filteredHosts() {
  const { search, status, newOnly, subnetId, risk, hideSuspect, priorityOnly, tagIds, showHiddenSubnets } = state.filters;
  const q = search.trim().toLowerCase();
  return state.hosts.filter((h) => {
    if (status && h.status !== status) return false;
    if (newOnly && !h.isNew) return false;
    if (subnetId && String(h.subnetId) !== String(subnetId)) return false;
    if (hideSuspect && h.suspect) return false;
    if (priorityOnly && (!h.riskLevel || h.acknowledged)) return false;
    if (tagIds.size > 0 && !(h.tags || []).some((t) => tagIds.has(t.id))) return false;
    if (!showHiddenSubnets && subnetById(h.subnetId)?.hidden) return false;
    if (risk) {
      if (risk === "any" ? !h.riskLevel : h.riskLevel !== risk) return false;
    }
    if (q) {
      const tagNames = (h.tags || []).map((t) => t.name.toLowerCase()).join(" ");
      const portNames = (h.ports || []).map((p) => `${p.port} ${p.service || ""} ${p.product || ""} ${p.version || ""}`.toLowerCase()).join(" ");
      const hay = `${h.ip} ${h.hostname || ""} ${h.mac || ""} ${h.vendor || ""} ${h.notes || ""} ${tagNames} ${portNames}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

const RISK_SORT_RANK = { critical: 3, warning: 2, info: 1 };

function sortHosts(hosts) {
  const by = state.sortBy;
  const sorted = hosts.slice();
  if (by === "ip") {
    sorted.sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
  } else if (by === "lastSeen") {
    sorted.sort((a, b) => new Date(b.lastSeen) - new Date(a.lastSeen));
  } else if (by === "firstSeen") {
    sorted.sort((a, b) => new Date(b.firstSeen) - new Date(a.firstSeen));
  } else {
    // priority: unacknowledged high-severity first, then by IP within each tier
    sorted.sort((a, b) => {
      const ra = a.acknowledged ? 0 : (RISK_SORT_RANK[a.riskLevel] || 0);
      const rb = b.acknowledged ? 0 : (RISK_SORT_RANK[b.riskLevel] || 0);
      if (ra !== rb) return rb - ra;
      return a.ip.localeCompare(b.ip, undefined, { numeric: true });
    });
  }
  return sorted;
}

/** Subnets used for the graph: only narrowed by the subnet filter (not
 * search/status/etc) so subnet nodes don't flicker in and out as a search
 * term happens to match or miss their hosts. */
function graphSubnets() {
  let subnets = state.filters.showHiddenSubnets ? state.subnets : state.subnets.filter((sn) => !sn.hidden);
  if (state.filters.subnetId) subnets = subnets.filter((sn) => String(sn.id) === String(state.filters.subnetId));
  return subnets;
}

/** Graph label for a subnet node: its name (if set) prefixed onto the CIDR,
 * followed by its host count — see Graph._draw's subnet branch. */
function subnetGraphLabel(sn, count) {
  const prefix = sn.name ? `${sn.name} — ` : "";
  return `${prefix}${sn.cidr} (${count || 0})`;
}

/** Host modal's "Subnet" field: name plus CIDR if the subnet has one, just
 * the CIDR otherwise — see openHostModal. */
function subnetDisplayLabel(sn) {
  if (!sn) return "—";
  return sn.name ? `${sn.name} (${sn.cidr})` : sn.cidr;
}

/** "unknown" hosts were found only via a dig -x PTR record — no ping/TCP/ARP
 * response and no confirmed open port yet — so they're neither up (green)
 * nor down (red), just unconfirmed (muted). */
function statusColorVar(status) {
  if (status === "down") return "var(--status-critical)";
  if (status === "unknown") return "var(--text-muted)";
  return "var(--status-good)";
}

function statusPillClass(status) {
  if (status === "down") return "pill-bad";
  if (status === "unknown") return "pill-muted";
  return "pill-good";
}

const RISK_LABEL = { critical: "CRITICAL", warning: "WARNING", info: "INFO" };

function riskBadge(level, reasons, acknowledged) {
  const cls = `badge-risk badge-risk-${level}` + (acknowledged ? " badge-risk-acked" : "");
  const label = (RISK_LABEL[level] || level.toUpperCase()) + (acknowledged ? " (ACK)" : "");
  return el("span", { class: cls, title: (reasons || []).join("; ") }, [label]);
}

/** Hosts belonging to a hidden subnet, excluded from every count/list/graph
 * unless the "show hidden subnets" filter is on — independent of the other
 * transient filters (search, status, etc.) so counts stay meaningful even
 * while those are active. */
function visibleHosts() {
  if (state.filters.showHiddenSubnets) return state.hosts;
  return state.hosts.filter((h) => !subnetById(h.subnetId)?.hidden);
}

function renderCounts() {
  const hosts = visibleHosts();
  qs("#countHosts").textContent = hosts.length;
  qs("#countSubnets").textContent = state.subnets.length;

  const critical = hosts.filter((h) => h.riskLevel && !h.acknowledged).length;
  const newCount = hosts.filter((h) => h.isNew).length;
  const down = hosts.filter((h) => h.status === "down").length;
  qs("#dashHostsCount").textContent = hosts.length;
  qs("#dashCriticalCount").textContent = critical;
  qs("#dashNewCount").textContent = newCount;
  qs("#dashDownCount").textContent = down;
}

function renderHostList() {
  const list = qs("#hostList");
  const hosts = sortHosts(filteredHosts());
  list.innerHTML = "";
  if (hosts.length === 0) {
    list.appendChild(el("div", { class: "muted small", style: "padding:16px;" , text: "No hosts match."}));
  }
  for (const h of hosts) {
    const sn = subnetById(h.subnetId);
    const openPortCount = (h.ports || []).filter((p) => p.state === "open").length;
    const row = el("div", { class: "host-row", onclick: () => openHostModal(h.id) }, [
      el("span", { class: "status-dot", style: `background:${statusColorVar(h.status)}` }),
      el("div", { class: "host-main" }, [
        el("div", { class: "host-ip" }, [h.ip + (h.hostname ? "  " : ""), h.hostname ? el("span", { class: "muted", text: h.hostname }) : null]),
        el("div", { class: "host-sub" }, [sn ? sn.cidr : "", openPortCount ? ` · ${openPortCount} open port${openPortCount === 1 ? "" : "s"}` : ""]),
      ]),
      ...(h.tags || []).slice(0, 3).map((t) => el("span", { class: "tag-dot", style: `background:${t.color}`, title: t.name })),
      h.riskLevel ? riskBadge(h.riskLevel, h.riskReasons, h.acknowledged) : null,
      h.suspect ? el("span", { class: "badge-suspect", title: h.suspectReason, text: "SUSPECT" }) : null,
      h.status === "unknown" ? el("span", { class: "badge-unconfirmed", title: "Found via reverse DNS only — not yet confirmed by ping/TCP/ARP or an open port", text: "UNCONFIRMED" }) : null,
      h.isNew ? el("span", { class: "badge-new", text: "NEW" }) : null,
    ]);
    list.appendChild(row);
  }
}

/* ---------------------------------------------------------------------- */
/* notifications (bell menu) — replaces the old always-visible Activity   */
/* tab; historical + live events all land here instead, dismissible one   */
/* at a time or all together, with only critical ones also popping a      */
/* toast.                                                                  */
/* ---------------------------------------------------------------------- */

const CRITICAL_EVENT_TYPES = new Set(["host_down", "port_closed", "scan_anomaly", "hosts_cleared", "priority_reflag", "deep_scan_finished"]);

function renderNotifBadge() {
  const badge = qs("#notifBadge");
  const n = state.notifUnread.size;
  badge.textContent = n > 99 ? "99+" : String(n);
  badge.hidden = n === 0;
}

function renderNotifPanel() {
  const list = qs("#notifList");
  list.innerHTML = "";
  const visible = state.events.filter((ev) => !state.notifDismissed.has(ev.id)).slice(0, 100);
  if (visible.length === 0) {
    list.appendChild(el("div", { class: "muted small", style: "padding:16px;", text: "No notifications." }));
  }
  for (const ev of visible) {
    list.appendChild(el("div", { class: `notif-item ev-${ev.type}` + (state.notifUnread.has(ev.id) ? " notif-unread" : "") }, [
      el("div", { class: "notif-item-main" }, [
        el("div", { class: "notif-item-msg", text: ev.message }),
        el("div", { class: "ev-time", text: fmtTime(ev.timestamp) + " · " + timeAgo(ev.timestamp) }),
      ]),
      el("button", {
        class: "btn-icon", title: "Dismiss", "aria-label": "Dismiss",
        onclick: (e) => { e.stopPropagation(); dismissNotification(ev.id); },
      }, ["✕"]),
    ]));
  }
  renderNotifBadge();
}

function dismissNotification(id) {
  state.notifDismissed.add(id);
  state.notifUnread.delete(id);
  renderNotifPanel();
}

function markAllNotificationsRead() {
  if (state.notifUnread.size === 0) return;
  state.notifUnread.clear();
  renderNotifBadge();
}

function receiveNotification(ev) {
  state.events.unshift(ev);
  if (state.events.length > 300) state.events.length = 300;
  state.notifUnread.add(ev.id);
  renderNotifPanel();
}

function renderSubnetList() {
  const list = qs("#subnetList");
  list.innerHTML = "";
  for (const sn of state.subnets) {
    const count = state.hosts.filter((h) => h.subnetId === sn.id).length;
    list.appendChild(el("div", { class: "subnet-card" + (sn.hidden ? " subnet-card-hidden" : "") + (sn.enabled === false ? " subnet-card-hidden" : "") }, [
      el("div", { class: "sc-top" }, [
        el("div", { class: "sc-cidr" }, [
          sn.cidr,
          sn.hidden ? el("span", { class: "badge-suspect", text: "HIDDEN" }) : null,
          sn.enabled === false ? el("span", { class: "badge-suspect", text: "EXCLUDED" }) : null,
        ]),
        el("div", {}, [
          el("button", {
            class: "btn-icon", title: sn.enabled === false ? "Include subnet in scans again" : "Exclude subnet from scans — keeps its existing hosts, stops refreshing them",
            onclick: async () => { await Api.setSubnetEnabled(sn.id, sn.enabled === false); await refreshSubnets(); },
          }, [sn.enabled === false ? "▶" : "⏸"]),
          el("button", {
            class: "btn-icon", title: sn.hidden ? "Unhide subnet — show its hosts again" : "Hide subnet — suppress its hosts from the list, graph, and counts",
            onclick: async () => { await Api.setSubnetHidden(sn.id, !sn.hidden); await refreshSubnets(); },
          }, [sn.hidden ? "👁" : "🙈"]),
          el("button", { class: "btn-icon", title: "Rename subnet", onclick: () => openSubnetModal(sn) }, ["✎"]),
          el("button", { class: "btn-icon", title: "Remove subnet", onclick: () => removeSubnet(sn.id) }, ["✕"]),
        ]),
      ]),
      el("div", { class: "sc-meta", text: `${sn.name ? sn.name + " · " : ""}${sn.source} · ${count} host${count === 1 ? "" : "s"} · scanned ${timeAgo(sn.lastScanAt)}` }),
    ]));
  }
}

function toggleTableSubnet(id) {
  if (state.tableExpandedSubnets.has(id)) state.tableExpandedSubnets.delete(id);
  else state.tableExpandedSubnets.add(id);
  renderTableView();
}

/** The data cells for one host — Status, IP, Hostname, Open ports, Flags,
 * Last seen — used by a subnet's expanded sub-rows (hostSubRow). Subnet
 * itself is omitted since hostSubRow's parent row already says which
 * subnet it is. */
function hostRowCells(h) {
  const openPorts = (h.ports || []).filter((p) => p.state === "open").map((p) => p.port).sort((a, b) => a - b);
  return [
    el("td", {}, [el("span", { class: "status-dot", style: `background:${statusColorVar(h.status)}` }), " " + statusLabel(h.status)]),
    el("td", { class: "host-ip" }, [h.ip]),
    el("td", {}, [h.hostname || "—"]),
    el("td", {}, [openPorts.length ? openPorts.join(", ") : "—"]),
    el("td", {}, [
      h.riskLevel ? riskBadge(h.riskLevel, h.riskReasons, h.acknowledged) : null,
      h.suspect ? el("span", { class: "badge-suspect", title: h.suspectReason, text: "SUSPECT" }) : null,
      h.isNew ? el("span", { class: "badge-new", text: "NEW" }) : null,
    ]),
    el("td", { class: "muted small" }, [timeAgo(h.lastSeen)]),
  ];
}

/** One host, nested under its expanded subnet row in the subnets table.
 * Deliberately shows every host in the subnet regardless of the table's
 * own search/subnet filter — expanding a specific subnet is a direct
 * request to see everything in it, not something a stale search term
 * should be able to empty out. */
function hostSubRow(h) {
  return el("tr", { class: "host-subrow", onclick: () => openHostModal(h.id) }, [
    el("td", {}, []),
    ...hostRowCells(h),
  ]);
}

/** Subnets table: one row per subnet with a live up/down/unconfirmed
 * breakdown, click to expand its hosts inline (see hostSubRow) — the
 * "table view of subnets, which can then be expanded into hosts" half of
 * table view. */
function renderSubnetsTable() {
  const tbody = qs("#subnetsTableBody");
  if (!tbody) return;
  tbody.innerHTML = "";
  if (state.subnets.length === 0) {
    tbody.appendChild(el("tr", {}, [el("td", { colspan: "7", class: "muted small", style: "padding:16px;" }, ["No subnets yet."])]));
    return;
  }
  for (const sn of state.subnets) {
    const snHosts = state.hosts.filter((h) => h.subnetId === sn.id);
    const up = snHosts.filter((h) => h.status === "up").length;
    const down = snHosts.filter((h) => h.status === "down").length;
    const unknown = snHosts.filter((h) => h.status === "unknown").length;
    const expanded = state.tableExpandedSubnets.has(sn.id);
    tbody.appendChild(el("tr", { class: "subnet-row" + (sn.hidden ? " subnet-row-hidden" : ""), onclick: () => toggleTableSubnet(sn.id) }, [
      el("td", { class: "expand-cell" }, [expanded ? "▾" : "▸"]),
      el("td", {}, [subnetDisplayLabel(sn), sn.hidden ? el("span", { class: "badge-suspect", text: "HIDDEN" }) : null]),
      el("td", {}, [String(snHosts.length)]),
      el("td", {}, [String(up)]),
      el("td", {}, [String(down)]),
      el("td", {}, [String(unknown)]),
      el("td", { class: "muted small" }, [timeAgo(sn.lastScanAt)]),
    ]));
    if (!expanded) continue;
    if (snHosts.length === 0) {
      tbody.appendChild(el("tr", { class: "host-subrow" }, [el("td", {}, []), el("td", { colspan: "6", class: "muted small" }, ["No hosts in this subnet."])]));
    } else {
      for (const h of snHosts.slice().sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }))) {
        tbody.appendChild(hostSubRow(h));
      }
    }
  }
}

function renderTableView() {
  renderSubnetsTable();
}

function renderTagSelects() {
  const modalSelect = qs("#hamSubnet");
  modalSelect.innerHTML = "";
  for (const sn of state.subnets) {
    modalSelect.appendChild(el("option", { value: sn.id }, [sn.cidr + (sn.name ? ` (${sn.name})` : "")]));
  }
}

/** Renders the tag checkbox list in the filter panel, preserving which tags
 * are currently checked across re-renders (e.g. after a tag is renamed or
 * the tag set otherwise changes). */
function renderTagFilterOptions() {
  const wrap = qs("#filterTags");
  wrap.innerHTML = "";
  if (state.tags.length === 0) {
    wrap.appendChild(el("div", { class: "muted small", text: "No tags yet." }));
    return;
  }
  for (const t of state.tags) {
    wrap.appendChild(el("label", { class: "checkbox-inline filter-tag-item" }, [
      el("input", {
        type: "checkbox",
        checked: state.filters.tagIds.has(t.id) ? "checked" : null,
        onchange: (e) => {
          if (e.target.checked) state.filters.tagIds.add(t.id);
          else state.filters.tagIds.delete(t.id);
          updateFilterActiveCount();
          renderHostList();
          renderGraph();
        },
      }),
      el("span", { class: "tag-dot", style: `background:${t.color}` }),
      t.name,
    ]));
  }
}

function renderSubnetFilterOptions() {
  const sel = qs("#filterSubnet");
  const current = sel.value;
  sel.innerHTML = "";
  sel.appendChild(el("option", { value: "" }, ["All subnets"]));
  for (const sn of state.subnets) {
    sel.appendChild(el("option", { value: sn.id }, [sn.cidr + (sn.name ? ` (${sn.name})` : "")]));
  }
  if (current && state.subnets.some((sn) => String(sn.id) === current)) sel.value = current;
}

function renderGraph() {
  const subnets = graphSubnets(), hosts = filteredHosts();
  if (graph) graph.sync(subnets, hosts);
  renderTableView();
}

function renderAll() {
  renderCounts();
  renderHostList();
  renderNotifPanel();
  renderSubnetList();
  renderSubnetFilterOptions();
  renderTagFilterOptions();
  renderTagSelects();
  qs("#emptyState").hidden = visibleHosts().length > 0;
  renderGraph();
}

/* ---------------------------------------------------------------------- */
/* host modal                                                             */
/* ---------------------------------------------------------------------- */

function openHostModal(hostId) {
  state.selectedHostId = hostId;
  state.pendingTagAdds = [];
  state.pendingTagRemoves = [];
  const h = hostById(hostId);
  if (!h) return;
  qs("#hmIP").textContent = h.ip;

  const callouts = qs("#hmCallouts");
  callouts.innerHTML = "";
  if (h.suspect) {
    callouts.appendChild(el("div", { class: "hm-callout hm-callout-suspect" }, [
      "⚠ Likely not a real host: ", h.suspectReason,
    ]));
  }
  if (h.riskLevel) {
    const label = h.riskLevel === "critical" ? "Priority target — harden first" : h.riskLevel === "warning" ? "Worth reviewing" : "Informational";
    callouts.appendChild(el("div", { class: `hm-callout hm-callout-${h.riskLevel}` }, [
      el("strong", {}, [label]),
      h.acknowledged ? el("span", { class: "badge-acked", text: "ACKNOWLEDGED" }) : null,
      el("ul", {}, (h.riskReasons || []).map((r) => el("li", { text: r }))),
    ]));
  }

  // The NEW badge stays on a host until a person actually looks at it and
  // dismisses it here — there's no timer anymore. Deliberately separate from
  // "mark as checked" below: this is a one-time acknowledgement (no undo,
  // and nothing brings the badge back later), while checked is a priority
  // triage state that auto-clears the moment a new port opens.
  const newInfoTip = "Clears the NEW badge for this host. This is one-time and can't be undone — it won't come back later the way \"marked as checked\" can.";
  const newRow = qs("#hmNewRow");
  newRow.innerHTML = "";
  newRow.hidden = !h.isNew;
  if (h.isNew) {
    newRow.appendChild(el("span", { class: "badge-new", text: "NEW" }));
    newRow.appendChild(el("span", { class: "hm-ack-status", text: "Not yet reviewed." }));
    newRow.appendChild(el("button", {
      class: "btn btn-small", onclick: async () => {
        await Api.ackHostNew(h.id);
        await refreshHosts();
        openHostModal(h.id);
        toast("Host reviewed — no longer flagged as new.");
      },
    }, ["Reviewed"]));
    newRow.appendChild(el("span", { class: "hm-ack-info", tabindex: "0", "aria-label": "What does dismissing NEW do?", "data-tooltip": newInfoTip }, ["ⓘ"]));
  }

  const ackInfoTip = "Marking as checked means you're happy the current list of open ports is fine, so it drops out of priority views (the ⚑ filter, the dashboard's priority count) until something changes. It's automatically un-marked and re-flagged the moment a new port opens on it — it doesn't silence the host permanently.";
  const ackInfoIcon = el("span", { class: "hm-ack-info", tabindex: "0", "aria-label": "What does marking as checked do?", "data-tooltip": ackInfoTip }, ["ⓘ"]);

  const ackRow = qs("#hmAckRow");
  ackRow.innerHTML = "";
  ackRow.hidden = !h.riskLevel;
  if (h.riskLevel) {
    if (h.acknowledged) {
      ackRow.appendChild(el("div", { class: "hm-ack-status" }, [
        "Marked as checked — won't be flagged as priority unless a new port opens.",
        el("button", {
          class: "btn btn-small", onclick: async () => {
            await Api.unackHost(h.id);
            await refreshHosts();
            openHostModal(h.id);
            toast("Host unmarked.");
          },
        }, ["Unmark"]),
        ackInfoIcon,
      ]));
    } else {
      ackRow.appendChild(el("button", {
        class: "btn btn-small", onclick: async () => {
          await Api.ackHost(h.id);
          closeModal("#hostModal");
          await refreshHosts();
          toast("Host marked as checked. It'll be re-flagged if a new port opens.");
        },
      }, ["Mark as checked"]));
      ackRow.appendChild(ackInfoIcon);
    }
  }

  const unconfirmedTitle = "Found via reverse DNS only — no ping/TCP/ARP response yet, and no open port has confirmed it up";
  qs("#hmStatus").innerHTML = "";
  qs("#hmStatus").appendChild(el("span", { class: "pill " + statusPillClass(h.status), title: h.status === "unknown" ? unconfirmedTitle : "" }, [
    el("span", { class: "dot" }), h.status,
  ]));
  qs("#hmSubnet").textContent = subnetDisplayLabel(subnetById(h.subnetId));
  qs("#hmHostnameInput").value = h.hostname || "";
  qs("#hmMacInput").value = h.mac || "";
  qs("#hmSource").textContent = h.source;
  qs("#hmFirstSeen").textContent = timeAgo(h.firstSeen);
  qs("#hmLastSeen").textContent = timeAgo(h.lastSeen);
  qs("#hmNotes").value = h.notes || "";

  renderHostModalTags(h);
  const addSelect = qs("#hmTagAdd");
  addSelect.onchange = () => {
    const tagId = Number(addSelect.value);
    if (!tagId) return;
    if (!state.pendingTagAdds.includes(tagId)) state.pendingTagAdds.push(tagId);
    renderHostModalTags(h);
    markUnsaved();
  };

  const portsBody = qs("#hmPorts");
  portsBody.innerHTML = "";
  const ports = (h.ports || []).slice().sort((a, b) => {
    if (a.state !== b.state) return a.state === "open" ? -1 : 1;
    return a.port - b.port;
  });
  qs("#hmPortCount").textContent = ports.length ? `(${ports.length})` : "";
  for (const p of ports) {
    const version = [p.product, p.version].filter(Boolean).join(" ");
    const isClosed = p.state !== "open";
    portsBody.appendChild(el("tr", { class: isClosed ? "port-row-closed" : "" }, [
      el("td", { text: `${p.port}/${p.protocol}` }),
      el("td", {}, [el("span", { class: "pill " + (isClosed ? "pill-muted" : "pill-good") }, [el("span", { class: "dot" }), p.state])]),
      el("td", { text: p.service || "—" }),
      el("td", { text: version || "—", class: "muted small" }),
      el("td", { text: p.banner || "—", class: "muted small" }),
      el("td", {}, [p.isNew ? el("span", { class: "badge-new", text: "NEW" }) : null]),
    ]));
  }

  qs("#hmNotes").oninput = markUnsaved;
  qs("#hmHostnameInput").oninput = markUnsaved;
  qs("#hmMacInput").oninput = markUnsaved;

  const deepScanBtn = qs("#hmDeepScan");
  deepScanBtn.disabled = false;
  deepScanBtn.textContent = "Deep scan (all ports)";
  deepScanBtn.onclick = async () => {
    deepScanBtn.disabled = true;
    deepScanBtn.textContent = "Deep scan running…";
    try {
      await Api.deepScanHost(h.id);
      toast(`Deep scan started for ${h.ip} — this can take a few minutes; new ports appear as they're found.`);
    } catch (err) {
      deepScanBtn.disabled = false;
      deepScanBtn.textContent = "Deep scan (all ports)";
      toast(err.message, "bad");
    }
  };

  qs("#hmSave").onclick = async () => {
    // hostname/mac are only sent when actually edited, not on every save —
    // avoids an unnecessary PATCH when they're untouched.
    const fields = { notes: qs("#hmNotes").value };
    const hostnameVal = qs("#hmHostnameInput").value.trim();
    if (hostnameVal !== (h.hostname || "")) fields.hostname = hostnameVal;
    const macVal = qs("#hmMacInput").value.trim();
    if (macVal !== (h.mac || "")) fields.mac = macVal;
    try {
      await Api.updateHost(h.id, fields);
    } catch (err) {
      toast(err.message, "bad");
      return;
    }
    for (const tagId of state.pendingTagRemoves) await Api.removeHostTag(h.id, tagId);
    for (const tagId of state.pendingTagAdds) await Api.addHostTag(h.id, tagId);
    state.pendingTagAdds = [];
    state.pendingTagRemoves = [];
    await refreshHosts();
    closeModal("#hostModal");
    toast("Saved.");
  };
  qs("#hmCancel").onclick = () => closeModal("#hostModal");
  qs("#hmDelete").onclick = async () => {
    if (!confirm(`Remove ${h.ip} from inventory? It will reappear if seen in a future scan.`)) return;
    await Api.deleteHost(h.id);
    closeModal("#hostModal");
    await refreshHosts();
  };

  markUnsaved(false);
  showModal("#hostModal");
}

/** Renders the tag-chip list for the host modal from the host's persisted
 * tags plus any staged (not-yet-saved) additions/removals. */
function renderHostModalTags(h) {
  const chips = qs("#hmTags");
  chips.innerHTML = "";
  const removed = new Set(state.pendingTagRemoves);
  for (const t of h.tags || []) {
    if (removed.has(t.id)) {
      chips.appendChild(el("span", { class: "tag-chip tag-chip-removing" }, [
        t.name,
        el("button", {
          title: "Undo removal",
          onclick: () => { state.pendingTagRemoves = state.pendingTagRemoves.filter((id) => id !== t.id); renderHostModalTags(h); },
        }, ["↺"]),
      ]));
      continue;
    }
    chips.appendChild(el("span", { class: "tag-chip", style: `background:${t.color}` }, [
      t.name,
      el("button", {
        onclick: () => { state.pendingTagRemoves.push(t.id); renderHostModalTags(h); markUnsaved(); },
      }, ["✕"]),
    ]));
  }
  for (const tagId of state.pendingTagAdds) {
    const t = tagById(tagId);
    if (!t) continue;
    chips.appendChild(el("span", { class: "tag-chip tag-chip-pending", style: `background:${t.color}` }, [
      t.name + " (unsaved)",
      el("button", {
        onclick: () => { state.pendingTagAdds = state.pendingTagAdds.filter((id) => id !== tagId); renderHostModalTags(h); },
      }, ["✕"]),
    ]));
  }

  const addSelect = qs("#hmTagAdd");
  addSelect.innerHTML = '<option value="">+ add tag…</option>';
  const existingIds = new Set((h.tags || []).map((t) => t.id));
  for (const t of state.tags) {
    if (existingIds.has(t.id) || state.pendingTagAdds.includes(t.id)) continue;
    addSelect.appendChild(el("option", { value: t.id }, [t.name]));
  }
  addSelect.value = "";
}

/** Shows the "Unsaved changes" hint; pass false to hide it (used when the
 * modal is freshly opened, before anything's been touched). */
function markUnsaved(unsaved = true) {
  qs("#hmUnsavedHint").hidden = !unsaved;
}

/* ---------------------------------------------------------------------- */
/* modal plumbing                                                         */
/* ---------------------------------------------------------------------- */

function showModal(sel) { qs(sel).hidden = false; }
function closeModal(sel) { qs(sel).hidden = true; }

function wireModal(backdropSel, closeSel) {
  const backdrop = qs(backdropSel);
  qs(closeSel).addEventListener("click", () => closeModal(backdropSel));
  backdrop.addEventListener("click", (e) => { if (e.target === backdrop) closeModal(backdropSel); });
}

/* ---------------------------------------------------------------------- */
/* toasts                                                                 */
/* ---------------------------------------------------------------------- */

// Capped so a burst of events (e.g. a big subnet going down at once) can't
// stack toasts up past the topbar — oldest is dropped as soon as a new one
// would exceed the cap.
const MAX_VISIBLE_TOASTS = 4;

function toast(message, kind) {
  const container = qs("#toastContainer");
  let removed = false;
  const remove = () => { if (!removed) { removed = true; t.remove(); } };
  const t = el("div", { class: "toast" + (kind ? " toast-" + kind : "") }, [
    el("div", { class: "toast-msg" }, [message]),
    el("button", { class: "toast-dismiss", title: "Dismiss", "aria-label": "Dismiss", onclick: remove }, ["✕"]),
  ]);
  container.appendChild(t);
  while (container.children.length > MAX_VISIBLE_TOASTS) {
    container.firstChild.remove();
  }
  setTimeout(remove, 8000);
}

/* ---------------------------------------------------------------------- */
/* data refresh                                                           */
/* ---------------------------------------------------------------------- */

async function refreshHosts() {
  state.hosts = await Api.hosts();
  renderAll();
}

async function refreshSubnets() {
  state.subnets = await Api.subnets();
  renderAll();
}

async function refreshTags() {
  state.tags = await Api.tags();
}

async function refreshHostsAndSubnets() {
  const [hosts, subnets] = await Promise.all([Api.hosts(), Api.subnets()]);
  state.hosts = hosts;
  state.subnets = subnets;
  renderAll();
}

// Re-pulls risk rules and scan settings and re-renders their Settings-tab
// UI — used after a system import, the only import that can also change
// these (see wireImport), since renderRiskRules/renderScanMethodSettings
// only run against whatever was already in memory otherwise.
async function refreshRiskRulesAndSettings() {
  const [riskRules, settings] = await Promise.all([Api.riskRules(), Api.settings()]);
  state.riskRules = riskRules;
  renderRiskRules();
  renderScanMethodSettings(settings);
}

const refreshDebounced = debounce(refreshHostsAndSubnets, 350);

/* ---------------------------------------------------------------------- */
/* SSE                                                                    */
/* ---------------------------------------------------------------------- */

// sse/scanPollTimer are module-level (rather than local to connectSSE/
// startLiveUpdates) so stopLiveUpdates() can tear them down from anywhere —
// notably showLoginScreen(), so a session going stale (expiry, logout, or
// the in-memory session store losing everything on a server restart)
// actually stops hitting the server instead of the EventSource's built-in
// reconnect and the 4s scan-status poll both hammering it with 401s forever
// in the background with no visible sign to the user.
let sse = null;
let scanPollTimer = null;
let sessionsPollTimer = null;

function connectSSE() {
  const connLabel = qs("#connLabel"), connState = qs("#connState");
  sse = new EventSource("/api/events/stream");

  sse.addEventListener("ready", () => {
    connLabel.textContent = "live";
    connState.className = "pill pill-good";
  });

  const evTypes = ["new_subnet", "new_host", "new_port", "host_down", "port_closed", "scan_anomaly", "hosts_cleared", "priority_reflag", "deep_scan_started", "deep_scan_finished"];
  for (const type of evTypes) {
    sse.addEventListener(type, (e) => {
      const ev = JSON.parse(e.data);
      receiveNotification(ev);
      renderCounts();
      // Most events just land quietly in the notification bell; only the
      // ones that need eyes right now also interrupt with a dismissible
      // toast.
      if (CRITICAL_EVENT_TYPES.has(type)) toast(ev.message, "bad");
      if (type !== "scan_anomaly") refreshDebounced();
      if (type === "deep_scan_finished" && ev.entityId === state.selectedHostId) {
        const btn = qs("#hmDeepScan");
        btn.disabled = false;
        btn.textContent = "Deep scan (all ports)";
      }
    });
  }

  sse.onerror = () => {
    connLabel.textContent = "reconnecting…";
    connState.className = "pill pill-bad";
  };
}

/** Starts the SSE connection and the 4s scan-status poll if they aren't
 * already running — called once on first login and again on every re-login
 * after stopLiveUpdates() tore them down. Idempotent so it's safe to call
 * from both startApp() paths without risking a duplicate interval/
 * connection. */
function startLiveUpdates() {
  if (scanPollTimer) return;
  connectSSE();
  pollScanStatus();
  scanPollTimer = setInterval(pollScanStatus, 4000);
  pollActiveSessions();
  sessionsPollTimer = setInterval(pollActiveSessions, 15000); // changes rarely, no need for the 4s cadence
}

/** Tears down the SSE connection and scan-status/active-sessions polls —
 * see the comment on sse/scanPollTimer above for why. Safe to call even if
 * nothing is running (e.g. the very first, pre-login showLoginScreen()
 * call). */
function stopLiveUpdates() {
  if (scanPollTimer) {
    clearInterval(scanPollTimer);
    scanPollTimer = null;
  }
  if (sessionsPollTimer) {
    clearInterval(sessionsPollTimer);
    sessionsPollTimer = null;
  }
  if (sse) {
    sse.close();
    sse = null;
  }
}

async function pollActiveSessions() {
  try {
    const { count } = await Api.activeSessions();
    qs("#activeUsersCount").textContent = count;
    qs("#activeUsers").title = count === 1 ? "1 user currently signed in" : `${count} users currently signed in`;
  } catch (_) { /* transient */ }
}

/* ---------------------------------------------------------------------- */
/* scan status polling                                                    */
/* ---------------------------------------------------------------------- */

let lastScanStatus = null; // cached between the 4s network polls so the countdown can tick every 1s locally

async function pollScanStatus() {
  try {
    lastScanStatus = await Api.scanStatus();
    renderScanStatus();
  } catch (_) { /* transient */ }
}

// Mirrors discovery.ScanMode's values ("" = the regular automatic/system-
// triggered cycle, otherwise one of the manually forced techniques).
const SCAN_MODE_LABEL = {
  "": "scanning…",
  quick: "quick scanning…",
  mass: "mass scanning…",
  deep: "deep scanning…",
  dns: "reverse DNS scanning…",
};

/** Renders from the cached lastScanStatus — called every second so "next
 * scan in Ns" counts down smoothly without a network round-trip each time. */
function renderScanStatus() {
  const st = lastScanStatus;
  if (!st) return;
  const label = qs("#scanLabel"), pill = qs("#scanState");
  if (st.running) {
    // st.mode is "" for the regular automatic/system-triggered cycle, or
    // "quick"/"mass"/"deep"/"dns" for a manually forced one — see ScanMode.
    label.textContent = SCAN_MODE_LABEL[st.mode] || "scanning…";
    pill.className = "pill pill-active";
  } else {
    label.textContent = "idle";
    pill.className = "pill pill-muted";
  }

  const lastScanEl = qs("#lastScan");
  const hasFinished = st.lastFinished && !st.lastFinished.startsWith("0001-01-01");
  if (!hasFinished) {
    lastScanEl.textContent = "";
    return;
  }
  const lastUTC = new Date(st.lastFinished).toISOString().slice(11, 19) + "Z";
  if (st.running) {
    lastScanEl.textContent = `last scan: ${lastUTC}`;
    return;
  }
  const nextAtMs = new Date(st.lastFinished).getTime() + st.intervalSec * 1000;
  const remainingSec = Math.max(0, Math.round((nextAtMs - Date.now()) / 1000));
  lastScanEl.textContent = `last scan: ${lastUTC} · next scan in ${remainingSec}s`;
}

/* ---------------------------------------------------------------------- */
/* wiring                                                                 */
/* ---------------------------------------------------------------------- */

function wireTabs() {
  qsa(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      qsa(".tab").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      qsa(".tab-panel").forEach((p) => (p.hidden = true));
      qs("#panel-" + btn.dataset.tab).hidden = false;
    });
  });
}

function updateFilterActiveCount() {
  const f = state.filters;
  const active = [f.subnetId, f.status, f.risk, f.newOnly, f.hideSuspect, f.showHiddenSubnets, f.priorityOnly].filter(Boolean).length + f.tagIds.size;
  const badge = qs("#filterActiveCount");
  badge.textContent = String(active);
  badge.hidden = active === 0;
}

/** All the topbar/dropdown panels (filters, notifications, scan/export/
 * import menus, account menu) toggle independently via their own
 * document-click listener, but that listener never fires for a click on a
 * *different* toggle button — those calls stopPropagation() so their own
 * panel can open without immediately re-closing itself. Left alone, that
 * meant opening one panel never closed whichever other one was already
 * open. Every toggle calls closeDropdownPanels(exceptPanel) first so at
 * most one is ever visible at a time. */
const dropdownPanels = [];
function registerDropdownPanel(panel) {
  dropdownPanels.push(panel);
  return panel;
}
function closeDropdownPanels(except) {
  for (const p of dropdownPanels) {
    if (p !== except) p.hidden = true;
  }
}

function wireFilters() {
  const onChange = (key, transform) => (e) => {
    state.filters[key] = transform ? transform(e.target.value) : e.target.value;
    updateFilterActiveCount();
    renderHostList();
    renderGraph();
  };
  qs("#hostSearch").addEventListener("input", onChange("search"));
  qs("#filterSubnet").addEventListener("change", onChange("subnetId"));
  qs("#filterStatus").addEventListener("change", onChange("status"));
  qs("#filterRisk").addEventListener("change", onChange("risk"));
  qs("#filterNew").addEventListener("change", (e) => { state.filters.newOnly = e.target.checked; updateFilterActiveCount(); renderHostList(); renderGraph(); });
  qs("#filterHideSuspect").addEventListener("change", (e) => { state.filters.hideSuspect = e.target.checked; updateFilterActiveCount(); renderHostList(); renderGraph(); });
  qs("#filterShowHidden").addEventListener("change", (e) => { state.filters.showHiddenSubnets = e.target.checked; updateFilterActiveCount(); renderCounts(); renderHostList(); renderGraph(); });

  qs("#hostSort").addEventListener("change", (e) => { state.sortBy = e.target.value; renderHostList(); });

  const priorityBtn = qs("#btnPriorityOnly");
  priorityBtn.addEventListener("click", () => {
    state.filters.priorityOnly = !state.filters.priorityOnly;
    priorityBtn.classList.toggle("active", state.filters.priorityOnly);
    priorityBtn.setAttribute("aria-pressed", String(state.filters.priorityOnly));
    updateFilterActiveCount();
    renderHostList();
    renderGraph();
  });

  const filterPanel = registerDropdownPanel(qs("#filterPanel"));
  qs("#btnFilters").addEventListener("click", (e) => {
    e.stopPropagation();
    const opening = filterPanel.hidden;
    closeDropdownPanels(filterPanel);
    filterPanel.hidden = !opening;
  });
  filterPanel.addEventListener("click", (e) => e.stopPropagation());
  document.addEventListener("click", () => { filterPanel.hidden = true; });
}

/** Mini-dashboard counter tiles double as filter shortcuts: click "priority"
 * or "new" to jump the host list straight to that subset, click "hosts" to
 * clear back to everything. */
function wireMiniDash() {
  qs("#dashHosts").addEventListener("click", () => {
    state.filters.priorityOnly = false;
    state.filters.newOnly = false;
    qs("#filterNew").checked = false;
    qs("#btnPriorityOnly").classList.remove("active");
    qs("#btnPriorityOnly").setAttribute("aria-pressed", "false");
    updateFilterActiveCount();
    renderHostList();
    renderGraph();
  });
  qs("#dashCritical").addEventListener("click", () => {
    state.filters.priorityOnly = true;
    qs("#btnPriorityOnly").classList.add("active");
    qs("#btnPriorityOnly").setAttribute("aria-pressed", "true");
    updateFilterActiveCount();
    renderHostList();
    renderGraph();
  });
  qs("#dashNew").addEventListener("click", () => {
    state.filters.newOnly = true;
    qs("#filterNew").checked = true;
    updateFilterActiveCount();
    renderHostList();
    renderGraph();
  });
  qs("#dashDown").addEventListener("click", () => {
    state.filters.status = state.filters.status === "down" ? "" : "down";
    qs("#filterStatus").value = state.filters.status;
    updateFilterActiveCount();
    renderHostList();
    renderGraph();
  });
}

function wireNotifications() {
  const panel = registerDropdownPanel(qs("#notifPanel"));
  qs("#btnNotifs").addEventListener("click", (e) => {
    e.stopPropagation();
    const opening = panel.hidden;
    closeDropdownPanels(panel);
    panel.hidden = !opening;
    if (!panel.hidden) markAllNotificationsRead();
  });
  panel.addEventListener("click", (e) => e.stopPropagation());
  document.addEventListener("click", () => { panel.hidden = true; });
  qs("#notifClearAll").addEventListener("click", () => {
    for (const ev of state.events) state.notifDismissed.add(ev.id);
    state.notifUnread.clear();
    renderNotifPanel();
  });
}

function wireGraphControls() {
  qs("#btnCollapseAll").addEventListener("click", () => {
    state.expandedBuckets.clear();
    for (const sn of state.subnets) state.collapsedSubnets.add("subnet:" + sn.id);
    renderGraph();
  });
}

const VIEW_LABELS = { graph: "Graph", table: "Table" };

/** Applies state.viewMode to the layout and to whether the graph is
 * actively rendering. Pausing it (rather than just hiding it with CSS) is
 * the point in table view: the canvas stops doing any per-frame work
 * outright, instead of continuing to repaint an element the user can't
 * see. */
function applyViewMode() {
  const mode = state.viewMode;
  const layout = qs("#layout");
  layout.classList.toggle("table-view", mode === "table");

  qs("#btnViewMenuToggle").textContent = `View: ${VIEW_LABELS[mode]} ▾`;
  for (const btn of qsa("#viewMenu .account-menu-item")) {
    btn.classList.toggle("active", btn.dataset.view === mode);
  }

  if (graph) {
    if (mode === "table") {
      graph.setPaused(true);
    } else {
      // Its canvas was display:none while hidden, so its rect (and
      // anything sized from it) may be stale or zero; recompute before
      // unpausing so switching to it doesn't briefly draw into a
      // zero-sized canvas.
      graph._resize();
      graph.setPaused(false);
    }
  }
  if (mode === "table") renderTableView();
}

function wireViewToggle() {
  const menu = registerDropdownPanel(qs("#viewMenu"));
  qs("#btnViewMenuToggle").addEventListener("click", (e) => {
    e.stopPropagation();
    const opening = menu.hidden;
    closeDropdownPanels(menu);
    menu.hidden = !opening;
  });
  menu.addEventListener("click", (e) => e.stopPropagation());
  document.addEventListener("click", () => { menu.hidden = true; });

  for (const btn of qsa("#viewMenu .account-menu-item")) {
    btn.addEventListener("click", () => {
      state.viewMode = btn.dataset.view;
      localStorage.setItem("viewMode", state.viewMode);
      menu.hidden = true;
      applyViewMode();
    });
  }
}

/** The graph, when it's the visible view — what the +/- zoom buttons and
 * any other view-agnostic graph control should act on. null in table
 * view, where the canvas isn't shown. */
function activeGraph() {
  return state.viewMode === "table" ? null : graph;
}

/** +/- zoom buttons: an explicit, clickable alternative to scroll-to-zoom
 * for anyone who'd rather not scroll or pinch-zoom to read the graph. */
function wireZoomControls() {
  const ZOOM_STEP = 1.4;
  qs("#btnZoomIn").addEventListener("click", () => activeGraph()?.zoomBy(ZOOM_STEP));
  qs("#btnZoomOut").addEventListener("click", () => activeGraph()?.zoomBy(1 / ZOOM_STEP));
  qs("#btnZoomReset").addEventListener("click", () => activeGraph()?.resetZoom());
}

/** Reads file as JSON, calls apiFn with the parsed result, refreshes the
 * host/subnet lists, and toasts summarizeFn's description of what happened
 * — the common shape both import flows share, they only differ in which
 * endpoint they call and how they describe the result. */
async function runImport(file, apiFn, summarizeFn) {
  let doc;
  try {
    doc = JSON.parse(await file.text());
  } catch (err) {
    toast("That file isn't valid JSON.", "bad");
    return;
  }
  try {
    const result = await apiFn(doc);
    await refreshHostsAndSubnets();
    toast(summarizeFn(result));
  } catch (err) {
    toast(`Import failed: ${err.message}`, "bad");
  }
}

// Like runImport, but for formats that aren't JSON (nmap/masscan XML) — reads
// the file as raw text instead of parsing it client-side and hands it
// straight to apiFn.
async function runImportText(file, apiFn, summarizeFn) {
  try {
    const result = await apiFn(await file.text());
    await refreshHostsAndSubnets();
    toast(summarizeFn(result));
  } catch (err) {
    toast(`Import failed: ${err.message}`, "bad");
  }
}

/** Builds a segments/hosts/ports export document (same snake_case schema as
 * the server's /api/export/network-map, see exportNetworkMap in
 * internal/api/export.go) from a client-side host list, so "Export
 * (filtered)" can restrict the download to what's currently on screen
 * without a round trip to teach the backend the whole filter set. */
function exportSegmentsFor(hosts) {
  const subnetIds = new Set(hosts.map((h) => h.subnetId));
  return state.subnets
    .filter((sn) => subnetIds.has(sn.id))
    .map((sn) => ({ id: `seg-${sn.id}`, name: sn.name || "", cidr: sn.cidr }));
}

/** Appends this host's risk findings (see riskBadge/riskForPorts) to its
 * notes, mirroring hostExportNotes in internal/api/export.go, so the
 * recommendations the app surfaces in-app survive into the exported file. */
function exportNotesFor(h) {
  if (!(h.riskReasons || []).length) return h.notes || "";
  const findings = "Flagged: " + h.riskReasons.join("; ");
  return h.notes ? `${h.notes}\n\n${findings}` : findings;
}

function exportHostFor(h) {
  const eh = { id: `host-${h.id}`, segment_id: `seg-${h.subnetId}` };
  if (h.hostname) eh.hostname = h.hostname;
  eh.ip = h.ip;
  if (h.mac) eh.mac = h.mac;
  eh.management_ip = h.ip;
  if (h.vendor) eh.vendor = h.vendor;
  const notes = exportNotesFor(h);
  if (notes) eh.notes = notes;
  return eh;
}

function exportPortsFor(h) {
  return (h.ports || []).map((p) => {
    const ep = { host_id: `host-${h.id}`, protocol: p.protocol, port: p.port, state: p.state };
    if (p.service) ep.service = p.service;
    const version = p.version || p.product;
    if (version) ep.version = version;
    if (p.banner) ep.notes = p.banner;
    return ep;
  });
}

function buildExportDoc(hosts) {
  return {
    segments: exportSegmentsFor(hosts),
    hosts: hosts.map(exportHostFor),
    ports: hosts.flatMap(exportPortsFor),
  };
}

function exportTimestamp() {
  return new Date().toISOString().replace(/[:.]/g, "").replace("T", "-").slice(0, 15);
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function downloadJSON(doc, filenamePrefix) {
  downloadBlob(new Blob([JSON.stringify(doc)], { type: "application/json" }), `${filenamePrefix}-${exportTimestamp()}.json`);
}

/** Hosts flagged as priority — riskLevel set and not yet acknowledged — the
 * same definition the dashboard's "priority" tile and ⚑ filter use (see
 * renderCounts/priorityOnly), sorted worst-first for the report. Uses
 * visibleHosts() rather than filteredHosts() so the report always covers
 * every priority host regardless of whatever search/status/tag filter
 * happens to be active, the same way the dashboard counts do. */
function priorityReportHosts() {
  return visibleHosts()
    .filter((h) => h.riskLevel && !h.acknowledged)
    .slice()
    .sort((a, b) => {
      const ra = RISK_SORT_RANK[a.riskLevel] || 0;
      const rb = RISK_SORT_RANK[b.riskLevel] || 0;
      if (ra !== rb) return rb - ra;
      return a.ip.localeCompare(b.ip, undefined, { numeric: true });
    });
}

function csvCell(value) {
  const s = String(value ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function buildPriorityReportCsv(hosts) {
  const header = ["IP", "Hostname", "Subnet", "Risk Level", "Findings", "MAC", "Vendor"];
  const rows = hosts.map((h) => [
    h.ip,
    h.hostname || "",
    subnetById(h.subnetId)?.cidr || "",
    h.riskLevel,
    (h.riskReasons || []).join("; "),
    h.mac || "",
    h.vendor || "",
  ]);
  return [header, ...rows].map((row) => row.map(csvCell).join(",")).join("\r\n");
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

function priorityReportHtmlRow(h) {
  const findings = (h.riskReasons || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("");
  return `<tr>
    <td>${escapeHtml(h.ip)}</td>
    <td>${escapeHtml(h.hostname || "—")}</td>
    <td>${escapeHtml(subnetById(h.subnetId)?.cidr || "—")}</td>
    <td><span class="badge badge-${h.riskLevel}">${escapeHtml(h.riskLevel.toUpperCase())}</span></td>
    <td><ul>${findings}</ul></td>
  </tr>`;
}

function buildPriorityReportHtml(hosts) {
  const counts = { critical: 0, warning: 0, info: 0 };
  for (const h of hosts) counts[h.riskLevel] = (counts[h.riskLevel] || 0) + 1;
  const rows = hosts.map(priorityReportHtmlRow).join("") ||
    `<tr><td colspan="5">No priority hosts — nothing to report.</td></tr>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Priority Host Report</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: system-ui, sans-serif; margin: 0; padding: 32px; background: #12141a; color: #e6e6e6; }
  h1 { margin: 0 0 4px; font-size: 22px; }
  .meta { color: #9aa0a6; font-size: 13px; margin-bottom: 24px; }
  .summary { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
  .summary div { padding: 10px 16px; border-radius: 8px; background: #1c1f27; font-size: 13px; min-width: 90px; }
  .summary strong { display: block; font-size: 20px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #2a2e37; vertical-align: top; }
  th { color: #9aa0a6; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: .04em; }
  ul { margin: 0; padding-left: 18px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; white-space: nowrap; }
  .badge-critical { background: #4a1414; color: #ff6b6b; }
  .badge-warning { background: #4a3a10; color: #fab219; }
  .badge-info { background: #16324a; color: #6cb6ff; }
  @media print { body { background: #fff; color: #000; } .summary div { background: #f2f2f2; } }
</style>
</head>
<body>
  <h1>Priority Host Report</h1>
  <div class="meta">Generated ${escapeHtml(new Date().toLocaleString())} — Network Enumerator</div>
  <div class="summary">
    <div><strong>${hosts.length}</strong>Priority hosts</div>
    <div><strong>${counts.critical}</strong>Critical</div>
    <div><strong>${counts.warning}</strong>Warning</div>
    <div><strong>${counts.info}</strong>Info</div>
  </div>
  <table>
    <thead><tr><th>IP</th><th>Hostname</th><th>Subnet</th><th>Risk</th><th>Findings</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
</body>
</html>`;
}

function downloadPriorityReport(format) {
  const hosts = priorityReportHosts();
  const stamp = exportTimestamp();
  if (format === "csv") {
    downloadBlob(new Blob([buildPriorityReportCsv(hosts)], { type: "text/csv" }), `priority-report-${stamp}.csv`);
  } else {
    downloadBlob(new Blob([buildPriorityReportHtml(hosts)], { type: "text/html" }), `priority-report-${stamp}.html`);
  }
}

/** Mermaid label text can't contain a literal double quote or newline —
 * #quot; is Mermaid's own HTML-entity escape for a literal quote inside a
 * quoted label, and a run of newlines is flattened to a single space since
 * multi-line labels use <br/> instead (see mermaidHostLabel). */
function mermaidEscape(s) {
  return String(s ?? "").replace(/"/g, "#quot;").replace(/[\r\n]+/g, " ").trim();
}

function mermaidStatusClass(status) {
  if (status === "down") return "statusDown";
  if (status === "unknown") return "statusUnknown";
  return "statusUp";
}

/** Fill/stroke/font trio per status class, shared by both diagram exports —
 * buildMermaidDiagram's classDef lines and buildDrawioDiagram's native node
 * styles — so a host's status maps to the same color everywhere. "down" is
 * yellow rather than red: red reads as "this needs urgent action" for a
 * pentest audience, when a non-responding host is routine and expected.
 * Yellow's fill is light enough that it needs a dark font color, unlike
 * the other two statuses' white text on a dark fill. */
const STATUS_FILL = {
  statusUp: { fill: "#0ca30c", stroke: "#087a08", font: "#ffffff" },
  statusDown: { fill: "#e6b800", stroke: "#a37f00", font: "#3d2e00" },
  statusUnknown: { fill: "#898781", stroke: "#5f5d59", font: "#ffffff" },
};

/** Number of columns for a roughly-square grid of n items — ceil(sqrt(n)),
 * so hosts within a subnet square off (4→2x2, 5→3+2, 6→3x3) instead of
 * forming one long row or column. Shared by buildMermaidDiagram (nested
 * row subgraphs) and buildDrawioDiagram (a literal x/y grid). */
function gridColumns(n) {
  return Math.max(1, Math.ceil(Math.sqrt(n)));
}

/** Splits items into row-major chunks of `cols` — the last row gets
 * whatever's left over (e.g. 5 items at 3 cols → rows of [3, 2]). */
function gridRows(items, cols) {
  const rows = [];
  for (let i = 0; i < items.length; i += cols) rows.push(items.slice(i, i + cols));
  return rows;
}

/** One host node's label: IP, then hostname (via <br/>) when present,
 * prefixed with a warning marker for an unacknowledged priority host — the
 * same "priority" definition priorityReportHosts uses. Ports are
 * deliberately not shown here — they live only in the ports table
 * (mermaidPortsTableLines) so the diagram stays readable and each host's
 * ports appear in exactly one place. */
function mermaidHostLabel(h) {
  const lines = [h.ip];
  if (h.hostname) lines.push(h.hostname);
  const prefix = h.riskLevel && !h.acknowledged ? "⚠ " : "";
  return prefix + lines.map(mermaidEscape).join("<br/>");
}

function statusLabel(status) {
  if (status === "down") return "Down";
  if (status === "unknown") return "Unconfirmed";
  return "Up";
}

/** Legend block for buildMermaidDiagram — plain classDef'd nodes, same trick
 * the diagram itself uses to communicate status by color, just labeled in
 * English so the file explains its own color key without external docs. */
function mermaidLegendLines() {
  return [
    '  subgraph LEGEND["Legend"]',
    '    legUp["Up — confirmed live"]:::statusUp',
    '    legDown["Down — not responding"]:::statusDown',
    '    legUnk["Unconfirmed — PTR only, no open port"]:::statusUnknown',
    "  end",
  ];
}

/** Escapes a value for use inside an HTML <td>/<th> in a Mermaid node label
 * — different rules from mermaidEscape's plain-text labels, since this text
 * lands inside real HTML tags rather than Mermaid label text: & < > " all
 * need entity-escaping, and the trailing &quot; also keeps the value from
 * breaking out of the label's own surrounding quotes. */
function mermaidTableCell(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/[\r\n]+/g, " ")
    .trim() || "—";
}

/** Builds the "Hosts & Open Ports" HTML table shared by both diagram
 * exports (mermaidPortsTableLines below, and buildDrawioDiagram's native
 * table node) — one row per host across every subnet, sorted the same way
 * each diagram's host nodes are. */
function buildHostPortsTableHtml(subnets, hosts) {
  const bySubnet = new Map();
  for (const h of hosts) {
    if (!bySubnet.has(h.subnetId)) bySubnet.set(h.subnetId, []);
    bySubnet.get(h.subnetId).push(h);
  }

  const rows = ["<tr><th>Subnet</th><th>IP</th><th>Hostname</th><th>Status</th><th>Open Ports</th></tr>"];
  for (const sn of subnets) {
    const snHosts = (bySubnet.get(sn.id) || []).slice().sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
    for (const h of snHosts) {
      const openPorts = (h.ports || [])
        .filter((p) => p.state === "open")
        .map((p) => p.port)
        .sort((a, b) => a - b)
        .join(", ");
      rows.push(
        "<tr>" +
          `<td>${mermaidTableCell(subnetDisplayLabel(sn))}</td>` +
          `<td>${mermaidTableCell(h.ip)}</td>` +
          `<td>${mermaidTableCell(h.hostname)}</td>` +
          `<td>${statusLabel(h.status)}</td>` +
          `<td>${mermaidTableCell(openPorts)}</td>` +
          "</tr>",
      );
    }
  }

  return `<table>${rows.join("")}</table>`;
}

/** Mermaid has no dedicated "table" diagram type, but its flowchart renderer
 * accepts raw HTML inside a quoted node label (htmlLabels is on by
 * default) — so a single node whose label is one big <table> renders as an
 * actual table. */
function mermaidPortsTableLines(subnets, hosts) {
  return [
    '  subgraph PORTS["Hosts & Open Ports"]',
    `    portsTable["${buildHostPortsTableHtml(subnets, hosts)}"]`,
    "  end",
  ];
}

/** Builds the single Mermaid export: a status legend, subnets as subgraphs
 * with hosts as color-coded nodes (IP/hostname only, no ports), and a table
 * node listing every host's open ports — one self-contained .mmd file, pure
 * Mermaid syntax, no Markdown wrapper. The host/port table relies on raw
 * HTML inside a node label (htmlLabels), which is a newer-Mermaid feature
 * some tools' Mermaid parsers (e.g. draw.io's) may not render — this
 * trades that compatibility for having ports in one place instead of
 * duplicated onto every node label. */
function buildMermaidDiagram(subnets, hosts) {
  const bySubnet = new Map();
  for (const h of hosts) {
    if (!bySubnet.has(h.subnetId)) bySubnet.set(h.subnetId, []);
    bySubnet.get(h.subnetId).push(h);
  }

  const lines = [
    "flowchart LR",
    ...Object.entries(STATUS_FILL).map(([cls, c]) => `classDef ${cls} fill:${c.fill},stroke:${c.stroke},color:${c.font};`),
    "classDef gridRow fill:none,stroke:none;",
    ...mermaidLegendLines(),
  ];

  for (const sn of subnets) {
    const snHosts = (bySubnet.get(sn.id) || []).slice().sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
    lines.push(`  subgraph seg${sn.id}["${mermaidEscape(subnetDisplayLabel(sn))}"]`);
    lines.push("    direction TB");
    if (snHosts.length === 0) {
      lines.push(`    seg${sn.id}empty["no hosts"]`);
    } else {
      // Each row is its own nested subgraph so hosts square off into a
      // grid instead of one long column: gridRows splits snHosts into
      // roughly-sqrt(n)-wide rows, each row gets "direction LR" so its
      // hosts sit side by side, and an invisible link (~~~) between the
      // hosts in a row is what actually forces that — same reason (and
      // same fix) the subnet-to-subnet chain below exists. The row
      // subgraphs themselves are disconnected from each other, so they
      // also need chaining to stack top to bottom under "direction TB".
      const rows = gridRows(snHosts, gridColumns(snHosts.length));
      rows.forEach((row, ri) => {
        lines.push(`    subgraph seg${sn.id}row${ri}[" "]:::gridRow`);
        lines.push("      direction LR");
        for (const h of row) {
          lines.push(`      host${h.id}["${mermaidHostLabel(h)}"]:::${mermaidStatusClass(h.status)}`);
        }
        if (row.length > 1) lines.push(`      ${row.map((h) => `host${h.id}`).join(" ~~~ ")}`);
        lines.push("    end");
      });
      if (rows.length > 1) {
        lines.push(`    ${rows.map((_, ri) => `seg${sn.id}row${ri}`).join(" ~~~ ")}`);
      }
    }
    lines.push("  end");
  }

  // Subgraphs aren't connected to each other by anything, so the layout
  // engine treats each subnet as its own disconnected component and stacks
  // them top-to-bottom regardless of the top-level "LR" direction — the
  // same reason host nodes need chaining above. An invisible link between
  // consecutive subgraphs is what actually forces subnets to line up
  // side-by-side.
  if (subnets.length > 1) {
    lines.push(`  ${subnets.map((sn) => `seg${sn.id}`).join(" ~~~ ")}`);
  }

  lines.push(...mermaidPortsTableLines(subnets, hosts));

  return lines.join("\n");
}

/** Downloads the Mermaid export for every non-hidden subnet/host — the same
 * "what's actually in scope" default visibleHosts()/priorityReportHosts use
 * elsewhere, so a hidden management subnet doesn't clutter a diagram meant
 * for sharing outside the app. */
function downloadMermaidDiagram() {
  const subnets = state.subnets.filter((sn) => !sn.hidden);
  const subnetIds = new Set(subnets.map((sn) => sn.id));
  const hosts = state.hosts.filter((h) => subnetIds.has(h.subnetId));
  downloadBlob(new Blob([buildMermaidDiagram(subnets, hosts)], { type: "text/plain" }), `network-map-${exportTimestamp()}.mmd`);
}

/** Escapes a value for an XML attribute in the draw.io export — & < > "
 * need entity-escaping same as any XML attribute, and a literal newline
 * needs the numeric reference &#10; since XML attribute-value
 * normalization would otherwise flatten it to a space. */
function drawioAttr(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/\n/g, "&#10;");
}

/** One host node's label for the draw.io export — same content as
 * mermaidHostLabel (IP, then hostname, prefixed with a warning marker for
 * an unacknowledged priority host) but plain-text lines instead of <br/>,
 * since draw.io node values aren't HTML unless the node's style says so. */
function drawioHostLabel(h) {
  const lines = [h.ip];
  if (h.hostname) lines.push(h.hostname);
  const prefix = h.riskLevel && !h.acknowledged ? "⚠ " : "";
  return prefix + lines.join("\n");
}

/** draw.io's built-in "Network" stencil set (stencils/networks.xml, ships
 * with no import/library step needed) has no generic "Server" or
 * "Workstation" pictogram — only specific ones. "Mail Server" and "PC" are
 * the closest visual stand-ins (a generic server-chassis glyph and a
 * generic desktop-computer glyph respectively); "Router" is a direct hit. */
const HOST_KIND_SHAPE = {
  router: "mxgraph.networks.router",
  server: "mxgraph.networks.mail_server",
  workstation: "mxgraph.networks.pc",
};

/** The app has no explicit "role" field for a host, so the draw.io export
 * guesses one from cheap signals: a .1 (or named rtr/router/gw/gateway/fw)
 * address is almost always a gateway; a host with a classic server-side
 * port open (web/mail/dns/db/directory, as opposed to the Windows
 * admin/RPC ports every workstation in this app's scans tends to expose)
 * is a server; anything else defaults to a workstation. It's a heuristic,
 * not ground truth — good enough for an icon, not for a security finding. */
function inferHostKind(h) {
  const lastOctet = Number(h.ip.split(".").pop());
  const name = (h.hostname || "").toLowerCase();
  if (lastOctet === 1 || /(^|[-_.])(rtr|router|gw|gateway|fw|firewall)([-_.]|$)/.test(name)) return "router";
  const SERVER_PORTS = new Set([21, 25, 53, 80, 110, 143, 389, 443, 636, 993, 995, 1433, 1521, 3306, 5432, 8080, 8443]);
  const hasServerPort = (h.ports || []).some((p) => p.state === "open" && SERVER_PORTS.has(p.port));
  return hasServerPort ? "server" : "workstation";
}

/** Builds a single native draw.io (.drawio) file: a status legend and an
 * icon-key legend, subnets as labeled boxes with hosts arranged in a
 * roughly-square grid inside (see gridColumns/gridRows — same layout
 * buildMermaidDiagram produces), each host drawn as a router/server/
 * workstation icon (see inferHostKind) tinted by status, and a table node
 * listing every host's open ports. Unlike the Mermaid export, draw.io
 * opens this directly with no import step — so layout is computed here
 * with a fixed grid rather than relying on draw.io's own Mermaid-import
 * layout engine. */
function buildDrawioDiagram(subnets, hosts) {
  const bySubnet = new Map();
  for (const h of hosts) {
    if (!bySubnet.has(h.subnetId)) bySubnet.set(h.subnetId, []);
    bySubnet.get(h.subnetId).push(h);
  }

  // 60x44 is a compromise box: close to "PC"/"Mail Server"'s native aspect
  // (100x70, 103x107) without either dominating; "Router" (100x29) still
  // renders a bit taller than its native aspect, but recognizable.
  const ICON_W = 60, ICON_H = 44, LABEL_H = 30, CELL_W = 150, CELL_GAP_X = 20, CELL_GAP_Y = 15;
  const CELL_H = ICON_H + LABEL_H;
  const PAD = 20, TITLE_H = 30, SUBNET_GAP_X = 40;
  const CONTAINER_STYLE = "rounded=0;whiteSpace=wrap;html=1;verticalAlign=top;fillColor=#f5f5f5;strokeColor=#666666;fontStyle=1;fontSize=14;";
  const iconStyle = (shape, fill, stroke, font) =>
    `shape=${shape};html=1;fillColor=${fill};strokeColor=${stroke};fontColor=${font};` +
    "verticalLabelPosition=bottom;verticalAlign=top;align=center;fontSize=11;outlineConnect=0;";

  let idCounter = 2;
  const cells = [];
  const addNode = (value, style, x, y, w, h) => {
    const id = `n${idCounter++}`;
    cells.push(
      `        <mxCell id="${id}" value="${drawioAttr(value)}" style="${drawioAttr(style)}" vertex="1" parent="1">` +
        `<mxGeometry x="${x}" y="${y}" width="${w}" height="${h}" as="geometry" /></mxCell>`,
    );
    return id;
  };

  // ---- Legends: status color, and icon-shape key ----
  const LEGEND_W = 380, SWATCH_H = 40, SWATCH_GAP = 10;
  const legendEntries = [
    ["statusUp", "Up — confirmed live"],
    ["statusDown", "Down — not responding"],
    ["statusUnknown", "Unconfirmed — PTR only, no open port"],
  ];
  const legendH = TITLE_H + PAD + legendEntries.length * SWATCH_H + (legendEntries.length - 1) * SWATCH_GAP + PAD;
  addNode("Legend", CONTAINER_STYLE, PAD, PAD, LEGEND_W, legendH);
  legendEntries.forEach(([cls, label], i) => {
    const c = STATUS_FILL[cls];
    addNode(
      label,
      `whiteSpace=wrap;html=1;strokeWidth=1;fillColor=${c.fill};strokeColor=${c.stroke};fontColor=${c.font};fontSize=12;`,
      PAD * 2, PAD + TITLE_H + PAD + i * (SWATCH_H + SWATCH_GAP), LEGEND_W - PAD * 2, SWATCH_H,
    );
  });

  const kindLegendX = PAD + LEGEND_W + 40;
  const kindLegendCellW = 110;
  const kindEntries = [["router", "Router"], ["server", "Server"], ["workstation", "Workstation"]];
  const kindLegendW = kindEntries.length * kindLegendCellW + PAD * 2;
  const kindLegendH = TITLE_H + PAD + ICON_H + LABEL_H + PAD;
  addNode("Icons", CONTAINER_STYLE, kindLegendX, PAD, kindLegendW, kindLegendH);
  kindEntries.forEach(([kind, label], i) => {
    addNode(
      label,
      iconStyle(HOST_KIND_SHAPE[kind], "#dae8fc", "#6c8ebf", "#333333"),
      kindLegendX + PAD + i * kindLegendCellW + (kindLegendCellW - ICON_W) / 2, PAD + TITLE_H + PAD, ICON_W, ICON_H,
    );
  });

  // ---- Subnets: left-to-right, hosts in a roughly-square grid within each ----
  const subnetRowY = PAD + Math.max(legendH, kindLegendH) + 40;
  let x = PAD;
  let maxSubnetH = 0;
  for (const sn of subnets) {
    const snHosts = (bySubnet.get(sn.id) || []).slice().sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
    const cols = gridColumns(snHosts.length || 1);
    const rows = Math.max(Math.ceil(snHosts.length / cols), 1);
    const subnetW = cols * CELL_W + (cols - 1) * CELL_GAP_X + PAD * 2;
    const subnetH = TITLE_H + PAD + rows * CELL_H + (rows - 1) * CELL_GAP_Y + PAD;
    maxSubnetH = Math.max(maxSubnetH, subnetH);
    addNode(subnetDisplayLabel(sn), CONTAINER_STYLE, x, subnetRowY, subnetW, subnetH);
    if (snHosts.length === 0) {
      addNode(
        "no hosts",
        "whiteSpace=wrap;html=1;strokeWidth=1;fillColor=#ffffff;strokeColor=#999999;fontColor=#666666;fontSize=12;fontStyle=2;",
        x + PAD, subnetRowY + TITLE_H + PAD, CELL_W, ICON_H,
      );
    } else {
      snHosts.forEach((h, i) => {
        const col = i % cols;
        const row = Math.floor(i / cols);
        const c = STATUS_FILL[mermaidStatusClass(h.status)];
        const cellX = x + PAD + col * (CELL_W + CELL_GAP_X);
        const cellY = subnetRowY + TITLE_H + PAD + row * (CELL_H + CELL_GAP_Y);
        addNode(
          drawioHostLabel(h),
          iconStyle(HOST_KIND_SHAPE[inferHostKind(h)], c.fill, c.stroke, "#333333"),
          cellX + (CELL_W - ICON_W) / 2, cellY, ICON_W, ICON_H,
        );
      });
    }
    x += subnetW + SUBNET_GAP_X;
  }

  // ---- Ports table ----
  const tableY = subnetRowY + maxSubnetH + 40;
  const tableW = Math.max(x - SUBNET_GAP_X - PAD, 700);
  const tableH = 30 + (hosts.length + 1) * 26;
  addNode(
    buildHostPortsTableHtml(subnets, hosts),
    "html=1;whiteSpace=wrap;strokeWidth=1;fillColor=#ECECFF;strokeColor=#9370DB;align=left;verticalAlign=top;fontSize=12;",
    PAD, tableY, tableW, tableH,
  );

  const diagramId = `net-${Date.now().toString(36)}`;
  return `<mxfile host="app.diagrams.net">
  <diagram name="Network Map" id="${diagramId}">
    <mxGraphModel dx="800" dy="600" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="850" pageHeight="1100" math="0" shadow="0">
      <root>
        <mxCell id="0" />
        <mxCell id="1" parent="0" />
${cells.join("\n")}
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>
`;
}

/** Downloads the draw.io export for every non-hidden subnet/host — same
 * scope as downloadMermaidDiagram. */
function downloadDrawioDiagram() {
  const subnets = state.subnets.filter((sn) => !sn.hidden);
  const subnetIds = new Set(subnets.map((sn) => sn.id));
  const hosts = state.hosts.filter((h) => subnetIds.has(h.subnetId));
  downloadBlob(new Blob([buildDrawioDiagram(subnets, hosts)], { type: "application/xml" }), `network-map-${exportTimestamp()}.drawio`);
}

/** "Export ▾" mirrors the "Import ▾" menu right next to it:
 *  - Host & subnet data export — Export (filtered) (JSON): only the hosts
 *    matching the current search/status/tag/risk/etc. filters (see
 *    filteredHosts) and hidden-subnet setting — built client-side since the
 *    backend has no equivalent filter API.
 *  - Host & subnet data export — Export (all, including hidden) (JSON): the
 *    complete network map regardless of any UI filter, via the same
 *    download the button used to be.
 *  - Reports (HTML/CSV): a human-readable report of every priority-flagged
 *    host and its findings, for handing to someone who isn't going to load
 *    the network map JSON back into this app.
 *  - Network diagrams: a single .mmd file with subnets/hosts as a
 *    color-coded flowchart plus an embedded host/port table (see
 *    buildMermaidDiagram), or the same content as a native .drawio file
 *    needing no import step (see buildDrawioDiagram).
 *  - System: a full backup (subnets — including hidden/disabled state —
 *    hosts, ports, settings, and risky service triage rules) via
 *    /api/export/system, for restoring this exact app state elsewhere
 *    rather than interop with other tooling (see exportSystem in
 *    internal/api/systemexport.go). */
function wireExport() {
  const exportMenu = registerDropdownPanel(qs("#exportMenu"));
  qs("#btnExportMenuToggle").addEventListener("click", (e) => {
    e.stopPropagation();
    const opening = exportMenu.hidden;
    closeDropdownPanels(exportMenu);
    exportMenu.hidden = !opening;
  });
  exportMenu.addEventListener("click", (e) => e.stopPropagation());
  document.addEventListener("click", () => { exportMenu.hidden = true; });

  qs("#btnExportFiltered").addEventListener("click", () => {
    exportMenu.hidden = true;
    downloadJSON(buildExportDoc(filteredHosts()), "network-map-export-filtered");
  });
  qs("#btnExportAll").addEventListener("click", () => {
    exportMenu.hidden = true;
    window.location.href = "/api/export/network-map";
  });
  qs("#btnReportPriorityHtml").addEventListener("click", () => {
    exportMenu.hidden = true;
    downloadPriorityReport("html");
  });
  qs("#btnReportPriorityCsv").addEventListener("click", () => {
    exportMenu.hidden = true;
    downloadPriorityReport("csv");
  });
  qs("#btnExportMermaid").addEventListener("click", () => {
    exportMenu.hidden = true;
    downloadMermaidDiagram();
  });
  qs("#btnExportDrawio").addEventListener("click", () => {
    exportMenu.hidden = true;
    downloadDrawioDiagram();
  });
  qs("#btnExportSystem").addEventListener("click", () => {
    exportMenu.hidden = true;
    window.location.href = "/api/export/system";
  });
}

/** Four import flows share one dropdown menu, split into "scan imports"
 * (output from an external scan tool run outside this app) and "system
 * imports" (a document previously exported by this app itself), mirroring
 * the "Scan now ▾" menu right next to it:
 *  - DNS recon scan (JSON) [scan import]: enriches hosts with hostnames from
 *    a dnsrecon -j scan, creating subnets/hosts that don't exist yet.
 *  - Nmap/masscan scan (XML) [scan import]: imports hosts and open ports
 *    from an -oX scan (nmap or masscan — both use the same schema), creating
 *    subnets/hosts that don't exist yet.
 *  - Network map (JSON) [system import]: restores subnets/hosts/open-ports
 *    from a network map previously downloaded via "Export JSON" — mainly for
 *    a fresh run (in-memory, or a -db-file that doesn't exist yet) that
 *    would otherwise start from a completely empty inventory.
 *  - System import (all data) [system import]: restores everything a system
 *    export produced — subnets (including hidden/disabled state), hosts,
 *    ports, settings, and risky service triage rules — via
 *    /api/import/system (see importSystem in internal/api/systemexport.go).
 * All four are additive: re-importing, or importing on top of a database
 * that already has scan data, only ever fills in gaps. */
function wireImport() {
  const importMenu = registerDropdownPanel(qs("#importMenu"));
  qs("#btnImportMenuToggle").addEventListener("click", (e) => {
    e.stopPropagation();
    const opening = importMenu.hidden;
    closeDropdownPanels(importMenu);
    importMenu.hidden = !opening;
  });
  importMenu.addEventListener("click", (e) => e.stopPropagation());
  document.addEventListener("click", () => { importMenu.hidden = true; });

  // extraRefresh covers state runFn's own refreshHostsAndSubnets doesn't
  // touch — only the system import needs it, since it's the only import
  // that can also change risk rules and settings, and the UI otherwise
  // wouldn't pick those up until a full page reload.
  const wireImportItem = (buttonId, fileInputId, apiFn, summarizeFn, runFn = runImport, extraRefresh = null) => {
    const fileInput = qs(fileInputId);
    qs(buttonId).addEventListener("click", () => {
      importMenu.hidden = true;
      fileInput.click();
    });
    fileInput.addEventListener("change", async () => {
      const file = fileInput.files[0];
      fileInput.value = ""; // so picking the same file again still fires "change"
      if (!file) return;
      await runFn(file, apiFn, summarizeFn);
      if (extraRefresh) await extraRefresh();
    });
  };

  wireImportItem("#btnImportNetworkMap", "#importNetworkMapFileInput", Api.importNetworkMap,
    (r) => `Imported ${r.segments} segment(s), ${r.hosts} host(s) (${r.newHosts} new), ${r.newPorts} new open port(s).`);
  wireImportItem("#btnImportSystem", "#importSystemFileInput", Api.importSystem,
    (r) => `Imported system export: ${r.segments} segment(s), ${r.hosts} host(s) (${r.newHosts} new), ${r.newPorts} new open port(s), ${r.riskRules} risk rule(s) (${r.newRiskRules} new), settings restored.`,
    runImport, refreshRiskRulesAndSettings);
  wireImportItem("#btnImportDnsRecon", "#importDnsReconFileInput", Api.importDnsRecon,
    (r) => `Imported dnsrecon scan: ${r.addresses} address(es), ${r.newSubnets} new subnet(s), ${r.newHosts} new host(s).`);
  wireImportItem("#btnImportNmap", "#importNmapFileInput", Api.importNmapXml,
    (r) => `Imported nmap scan: ${r.hosts} host(s) (${r.newSubnets} new subnet(s), ${r.newHosts} new), ${r.newPorts} new open port(s).`,
    runImportText);
}

function wireTopbar() {
  const scanMenu = registerDropdownPanel(qs("#scanMenu"));
  qs("#btnScanMenuToggle").addEventListener("click", (e) => {
    e.stopPropagation();
    const opening = scanMenu.hidden;
    closeDropdownPanels(scanMenu);
    scanMenu.hidden = !opening;
  });
  scanMenu.addEventListener("click", (e) => e.stopPropagation());
  document.addEventListener("click", () => { scanMenu.hidden = true; });

  qs("#btnScanQuick").addEventListener("click", async () => {
    scanMenu.hidden = true;
    try {
      await Api.quickScanAll();
      pollScanStatus();
      toast("Quick scan triggered.");
    } catch (err) {
      toast(err.message, "bad");
    }
  });
  qs("#btnScanMass").addEventListener("click", () => {
    scanMenu.hidden = true;
    openScanConfirmModal("mass");
  });
  qs("#btnScanDeepAll").addEventListener("click", () => {
    scanMenu.hidden = true;
    openScanConfirmModal("deep");
  });
  qs("#btnScanReverseDns").addEventListener("click", () => {
    scanMenu.hidden = true;
    openScanConfirmModal("dns");
  });

  qs("#btnAddSubnet").addEventListener("click", () => openSubnetModal(null));
  qs("#btnAddHost").addEventListener("click", () => { qs("#hamError").hidden = true; qs("#hamIP").value = ""; qs("#hamHostname").value = ""; qs("#hamNotes").value = ""; renderTagSelects(); showModal("#hostAddModal"); });
  qs("#btnTags").addEventListener("click", () => { renderTagManager(); showModal("#tagModal"); });
  wireExport();
  wireImport();

  const accountMenu = registerDropdownPanel(qs("#accountMenu"));
  qs("#btnAccountMenu").addEventListener("click", (e) => {
    e.stopPropagation();
    const opening = accountMenu.hidden;
    closeDropdownPanels(accountMenu);
    accountMenu.hidden = !opening;
  });
  accountMenu.addEventListener("click", (e) => e.stopPropagation());
  document.addEventListener("click", () => { accountMenu.hidden = true; });

  qs("#btnLogout").addEventListener("click", async () => {
    accountMenu.hidden = true;
    await Api.logout().catch(() => {});
    showLoginScreen();
  });
}

async function removeSubnet(id) {
  if (!confirm("Remove this subnet and all its discovered hosts?")) return;
  await Api.deleteSubnet(id);
  await refreshSubnets();
  await refreshHosts();
}

// Set while #subnetModal is open for renaming an existing subnet (see
// openSubnetModal) rather than adding a new one; null means "add" mode.
let editingSubnetId = null;

/** Opens #subnetModal in "add" mode (sn omitted) or "edit" mode (existing
 * subnet passed) — edit mode locks the CIDR field, since the IP range isn't
 * editable after creation (UpsertAutoSubnet matches on it, and hosts
 * reference the subnet by id, not by address range). */
function openSubnetModal(sn) {
  qs("#smError").hidden = true;
  editingSubnetId = sn ? sn.id : null;
  qs("#smHeading").textContent = sn ? "Edit subnet" : "Add subnet";
  qs("#smCIDR").value = sn ? sn.cidr : "";
  qs("#smCIDR").disabled = !!sn;
  qs("#smCidrLock").hidden = !sn;
  qs("#smName").value = sn ? (sn.name || "") : "";
  qs("#smSubmit").textContent = sn ? "Save" : "Add & scan";
  showModal("#subnetModal");
}

function wireSubnetForm() {
  wireModal("#subnetModal", "#smClose");
  qs("#smSubmit").addEventListener("click", async () => {
    const name = qs("#smName").value.trim();
    try {
      if (editingSubnetId) {
        await Api.renameSubnet(editingSubnetId, name);
        closeModal("#subnetModal");
        await refreshSubnets();
        toast("Subnet renamed.");
      } else {
        const cidr = qs("#smCIDR").value.trim();
        await Api.addSubnet(cidr, name);
        closeModal("#subnetModal");
        await refreshSubnets();
        toast(`Subnet ${cidr} added. Scan triggered.`);
      }
    } catch (err) {
      qs("#smError").textContent = err.message;
      qs("#smError").hidden = false;
    }
  });
}

function wireHostAddForm() {
  wireModal("#hostAddModal", "#hamClose");
  qs("#hamSubmit").addEventListener("click", async () => {
    const subnetId = Number(qs("#hamSubnet").value);
    const ip = qs("#hamIP").value.trim();
    const hostname = qs("#hamHostname").value.trim();
    const notes = qs("#hamNotes").value.trim();
    try {
      await Api.addHost(subnetId, ip, hostname, notes);
      closeModal("#hostAddModal");
      await refreshHosts();
      toast(`Host ${ip} added.`);
    } catch (err) {
      qs("#hamError").textContent = err.message;
      qs("#hamError").hidden = false;
    }
  });
}

let tmSelectedColor = TAG_PALETTE[0];

function renderTagManager() {
  const list = qs("#tagManagerList");
  list.innerHTML = "";
  for (const t of state.tags) {
    list.appendChild(el("div", { class: "tag-manager-row" }, [
      el("span", { class: "tm-swatch", style: `background:${t.color}` }),
      el("span", { class: "tm-name", text: t.name }),
      el("button", { class: "btn-icon", title: "Delete tag", onclick: async () => { await Api.deleteTag(t.id); await refreshTags(); renderTagManager(); await refreshHosts(); } }, ["✕"]),
    ]));
  }
  const swatches = qs("#tmSwatches");
  swatches.innerHTML = "";
  for (const c of TAG_PALETTE) {
    const b = el("button", { style: `background:${c}`, class: c === tmSelectedColor ? "selected" : "", onclick: () => { tmSelectedColor = c; renderTagManager(); } });
    swatches.appendChild(b);
  }
}

function wireTagManager() {
  wireModal("#tagModal", "#tmClose");
  qs("#tmClose2").addEventListener("click", () => closeModal("#tagModal"));
  const createTag = async () => {
    const name = qs("#tmName").value.trim();
    if (!name) return false;
    await Api.createTag(name, tmSelectedColor);
    qs("#tmName").value = "";
    await refreshTags();
    renderTagManager();
    return true;
  };
  qs("#tmSubmit").addEventListener("click", createTag);
  qs("#tmName").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); createTag(); } });
}

/* ---------------------------------------------------------------------- */
/* settings tab                                                          */
/* ---------------------------------------------------------------------- */

function renderScanMethodSettings(settings) {
  qs("#stScanMethod").value = settings.scanMethod;
  qs("#stNmapStatus").textContent = settings.nmapAvailable ? "nmap is installed on this host." : "nmap isn't installed — falling back to built-in scanning.";
  qs("#stNetdiscoverEnabled").checked = settings.netdiscoverEnabled;
  qs("#stNetdiscoverStatus").textContent = settings.netdiscoverAvailable ? "netdiscover is installed on this host." : "netdiscover isn't installed — this has no effect until it is.";
}

/** Baked into the binary at build time (see internal/version, set via
 * -ldflags in build.sh) rather than read from a sidecar file — a `go run`/
 * plain `go build` without those flags shows "dev"/"unknown", which is the
 * signal that you're not looking at a real release build. */
/** Used by the Settings-tab footer (post-login, from /api/settings) and
 * the login screen (pre-login, from the unauthenticated /api/healthz) —
 * same version/buildDate fields either way, but the login screen only
 * shows the version (see loadLoginVersionInfo), not the build date. */
function versionInfoText(info) {
  const built = new Date(info.buildDate);
  const builtStr = isNaN(built) ? info.buildDate : built.toLocaleString();
  return `Network Enumerator ${info.version} · built ${builtStr}`;
}

function renderVersionInfo(settings) {
  qs("#stVersionInfo").textContent = versionInfoText(settings);
}

/** The login screen shows before any session exists, so it can't use the
 * authenticated /api/settings — it hits /api/healthz instead, which
 * exposes the same version/buildDate without requiring auth. Best-effort:
 * if it fails for any reason, the login screen just shows no version line
 * rather than blocking sign-in over it. Deliberately version-only (no build
 * date) here — the full "version · built <date>" form is reserved for the
 * Settings footer post-login. */
async function loadLoginVersionInfo() {
  try {
    const info = await Api.healthz();
    qs("#loginVersionInfo").textContent = `Network Enumerator ${info.version}`;
  } catch (_) {
    // not worth surfacing — signing in still works without it
  }
}

function renderRiskRules() {
  const list = qs("#riskRuleList");
  list.innerHTML = "";
  for (const r of state.riskRules) {
    const rowClass = `risk-rule-row sev-${r.severity}` + (r.enabled ? "" : " rr-disabled");
    let labelText = r.label;
    if (r.versionBelow) labelText += ` (< ${r.versionBelow}${r.service ? " " + r.service : ""})`;
    else if (r.service) labelText += ` (${r.service})`;
    list.appendChild(el("div", { class: rowClass, title: r.enabled ? "" : "Disabled — not currently flagging hosts" }, [
      el("span", { class: "rr-port", text: String(r.port) }),
      el("span", { class: "rr-label", text: labelText }),
      el("button", { class: "btn-icon", title: "Edit rule", onclick: () => openRiskRuleModal(r) }, ["✎"]),
      el("button", {
        class: "btn-icon", title: "Delete rule",
        onclick: async () => { await Api.deleteRiskRule(r.id); state.riskRules = await Api.riskRules(); renderRiskRules(); await refreshHosts(); },
      }, ["✕"]),
    ]));
  }
}

/* ---------------------------------------------------------------------- */
/* risk rule add/edit modal                                              */
/* ---------------------------------------------------------------------- */

const SEVERITY_OPTIONS = [
  { value: "critical", label: "Critical" },
  { value: "warning", label: "Warning" },
  { value: "info", label: "Info" },
];

let rrmSelectedSeverity = "warning";
let rrmEditingID = null; // null while adding a new rule

function renderSeverityPicker() {
  const wrap = qs("#rrmSeverityPicker");
  wrap.innerHTML = "";
  for (const opt of SEVERITY_OPTIONS) {
    wrap.appendChild(el("button", {
      type: "button",
      class: `sev-${opt.value}` + (rrmSelectedSeverity === opt.value ? " selected" : ""),
      onclick: () => { rrmSelectedSeverity = opt.value; renderSeverityPicker(); },
    }, [opt.label]));
  }
}

/** Opens the risk-rule modal. Pass an existing rule to edit it, or omit to
 * add a new one. */
function openRiskRuleModal(rule) {
  rrmEditingID = rule ? rule.id : null;
  qs("#rrmTitle").textContent = rule ? "Edit risk rule" : "Add risk rule";
  qs("#rrmPort").value = rule ? rule.port : "";
  qs("#rrmService").value = rule ? rule.service || "" : "";
  qs("#rrmLabel").value = rule ? rule.label : "";
  qs("#rrmVersionBelow").value = rule ? rule.versionBelow || "" : "";
  qs("#rrmEnabled").checked = rule ? rule.enabled : true;
  rrmSelectedSeverity = rule ? rule.severity : "warning";
  renderSeverityPicker();
  qs("#rrmError").hidden = true;
  showModal("#riskRuleModal");
}

function wireRiskRuleModal() {
  wireModal("#riskRuleModal", "#rrmClose");
  qs("#rrmCancel").addEventListener("click", () => closeModal("#riskRuleModal"));
  qs("#rrmSubmit").addEventListener("click", async () => {
    const port = Number(qs("#rrmPort").value);
    const service = qs("#rrmService").value.trim();
    const label = qs("#rrmLabel").value.trim();
    const versionBelow = qs("#rrmVersionBelow").value.trim();
    const enabled = qs("#rrmEnabled").checked;
    const errEl = qs("#rrmError");
    if (!port || port < 1 || port > 65535) {
      errEl.textContent = "Port must be between 1 and 65535.";
      errEl.hidden = false;
      return;
    }
    if (!label) {
      errEl.textContent = "Reason is required.";
      errEl.hidden = false;
      return;
    }
    try {
      if (rrmEditingID) {
        await Api.updateRiskRule(rrmEditingID, { port, label, severity: rrmSelectedSeverity, service, versionBelow, enabled });
      } else {
        const created = await Api.createRiskRule(port, label, rrmSelectedSeverity, service, versionBelow);
        if (!enabled) await Api.updateRiskRule(created.id, { enabled: false });
      }
      closeModal("#riskRuleModal");
      state.riskRules = await Api.riskRules();
      renderRiskRules();
      await refreshHosts();
      toast(rrmEditingID ? "Risk rule updated." : "Risk rule added.");
    } catch (err) {
      errEl.textContent = err.message;
      errEl.hidden = false;
    }
  });
}

/* ---------------------------------------------------------------------- */
/* mass/deep/reverse-DNS scan confirm modal                              */
/* ---------------------------------------------------------------------- */

// One shared modal for every forced-technique action — they only differ in
// copy and which endpoint Proceed calls.
const SCAN_CONFIRM_COPY = {
  mass: {
    title: "Mass scan all hosts (nmap)",
    body: "This forces an nmap sweep of the common-port list across every host, regardless of the configured scan method. It's noisier than the built-in prober and can take a while on a large network.",
    confirmLabel: "I understand this forces nmap and may take a while",
    proceedLabel: "Start mass scan",
    api: () => Api.massScanAll(),
    toastMessage: "Mass scan triggered — forcing an nmap sweep across every host.",
  },
  deep: {
    title: "Deep scan all hosts (nmap)",
    body: "This forces an nmap sweep of every TCP port (1–65535) on every host instead of the usual common-port list. It can take a long time on a large network, and it blocks the normal scheduled scan cycle from running until it finishes.",
    confirmLabel: "I understand this will take a while and block normal scanning",
    proceedLabel: "Start deep scan",
    api: () => Api.deepScanAll(),
    toastMessage: "Deep scan triggered — scanning every port on every host. This can take a long time on a large network.",
  },
  dns: {
    title: "Reverse DNS scan all hosts",
    body: "This sweeps every address in every subnet for a PTR record (dnsrecon if installed, otherwise dig -x per address), independent of ping/TCP/ARP discovery. Hosts found this way are recorded but not marked up until an open port confirms them. Can be slow on a large network without dnsrecon installed — check the tools icon in the top bar.",
    confirmLabel: "I understand this may take a while, especially without dnsrecon",
    proceedLabel: "Start reverse DNS scan",
    api: () => Api.reverseDnsScanAll(),
    toastMessage: "Reverse DNS scan triggered — sweeping every address for a PTR record.",
  },
};

let pendingScanMode = null; // "mass" | "deep" — which one Proceed should run

function openScanConfirmModal(mode) {
  pendingScanMode = mode;
  const copy = SCAN_CONFIRM_COPY[mode];
  qs("#scmTitle").textContent = copy.title;
  qs("#scmBody").textContent = copy.body;
  qs("#scmConfirmLabel").textContent = copy.confirmLabel;
  qs("#scmProceed").textContent = copy.proceedLabel;
  qs("#scmConfirm").checked = false;
  qs("#scmProceed").disabled = true;
  showModal("#scanConfirmModal");
}

function wireScanConfirmModal() {
  wireModal("#scanConfirmModal", "#scmClose");
  qs("#scmConfirm").addEventListener("change", (e) => {
    qs("#scmProceed").disabled = !e.target.checked;
  });
  qs("#scmCancel").addEventListener("click", () => closeModal("#scanConfirmModal"));
  qs("#scmProceed").addEventListener("click", async () => {
    closeModal("#scanConfirmModal");
    const copy = SCAN_CONFIRM_COPY[pendingScanMode];
    try {
      await copy.api();
      pollScanStatus();
      toast(copy.toastMessage, "warn");
    } catch (err) {
      toast(err.message, "bad");
    }
  });
}

function wireSettings() {
  qs("#accountForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const submitBtn = qs("#stAccountSubmit");
    // A double-submit (double-click, or Enter plus a click both landing)
    // fired two change-password requests against the same still-valid
    // cookie; the first one's server-side RevokeAll could invalidate the
    // second one's cookie before it's processed, so the *second* request
    // legitimately 401s with "session expired" even though the change
    // itself already succeeded. Disabling the button for the duration is
    // the actual fix — the suppression window below only covers unrelated
    // background requests racing the same revoke.
    if (submitBtn.disabled) return;
    submitBtn.disabled = true;

    const currentPassword = qs("#stCurrentPassword").value;
    const newPassword = qs("#stNewPassword").value.trim() || currentPassword;
    qs("#stAccountError").hidden = true;
    suppressSessionExpiry = true;
    try {
      const result = await Api.changePassword(currentPassword, "", newPassword);
      qs("#stAccountUsername").textContent = result.username;
      qs("#stCurrentPassword").value = "";
      qs("#stNewPassword").value = "";
      toast("Credentials updated.");
    } catch (err) {
      qs("#stAccountError").textContent = err.message;
      qs("#stAccountError").hidden = false;
    } finally {
      submitBtn.disabled = false;
      // Give any requests that were already in flight against the old
      // session a moment to land and fail quietly before re-arming the
      // redirect; a real subsequent 401 (session actually expired) still
      // sends the user to the login screen as normal.
      setTimeout(() => { suppressSessionExpiry = false; }, 2000);
    }
  });

  qs("#stScanMethod").addEventListener("change", async (e) => {
    const errEl = qs("#stScanMethodError");
    errEl.hidden = true;
    try {
      const settings = await Api.updateSettings(e.target.value);
      renderScanMethodSettings(settings);
      toast("Scan method updated.");
    } catch (err) {
      errEl.textContent = err.message;
      errEl.hidden = false;
    }
  });

  qs("#stNetdiscoverEnabled").addEventListener("change", async (e) => {
    const errEl = qs("#stNetdiscoverError");
    errEl.hidden = true;
    try {
      const settings = await Api.updateNetdiscoverEnabled(e.target.checked);
      renderScanMethodSettings(settings);
      toast("Netdiscover setting updated.");
    } catch (err) {
      e.target.checked = !e.target.checked;
      errEl.textContent = err.message;
      errEl.hidden = false;
    }
  });

  qs("#btnAddRiskRule").addEventListener("click", () => openRiskRuleModal());

  qs("#stClearConfirm").addEventListener("input", (e) => {
    qs("#stClearHosts").disabled = e.target.value.trim() !== "1001";
  });
  qs("#stClearHosts").addEventListener("click", async () => {
    if (!confirm("Remove every host from inventory? This can't be undone.")) return;
    await Api.clearAllHosts(qs("#stClearConfirm").value.trim());
    qs("#stClearConfirm").value = "";
    qs("#stClearHosts").disabled = true;
    await refreshHosts();
    toast("All hosts cleared.");
  });

  qs("#stMarkAllReviewed").addEventListener("click", async () => {
    const { reviewed } = await Api.ackAllHostsNew();
    await refreshHosts();
    toast(reviewed > 0 ? `${reviewed} host(s) marked as reviewed.` : "No hosts were flagged as new.");
  });
}

/* ---------------------------------------------------------------------- */
/* auth / init                                                            */
/* ---------------------------------------------------------------------- */

let appStarted = false;

function showLoginScreen() {
  // Stop polling/SSE the moment the session is known dead — otherwise the
  // 4s scan-status poll and the SSE reconnect both keep hitting the server
  // with a doomed request forever (a session naturally expires after 24h,
  // or a server restart wipes the in-memory session store), 401ing in the
  // background with nothing on screen to show for it. Safe to call even
  // when nothing is running yet (page just loaded, never logged in).
  stopLiveUpdates();

  // Called redundantly whenever a stray in-flight request (a background
  // poll, an SSE reconnect) lands a 401 after the login screen is already
  // showing — e.g. right after logout. Only reset the form and steal focus
  // the first time it's shown, so that redundant call doesn't yank focus
  // back to the username field out from under someone already typing their
  // password.
  const alreadyShown = !qs("#loginScreen").hidden;
  qs("#app").hidden = true;
  qs("#loginScreen").hidden = false;
  if (alreadyShown) return;
  qs("#loginPassword").value = "";
  qs("#loginUsername").focus();
}

function showApp() {
  qs("#loginScreen").hidden = true;
  qs("#app").hidden = false;
}

async function loadAppData() {
  const [subnets, hosts, tags, events, riskRules, settings] = await Promise.all([
    Api.subnets(), Api.hosts(), Api.tags(), Api.events(), Api.riskRules(), Api.settings(),
  ]);
  state.subnets = subnets;
  state.hosts = hosts;
  state.tags = tags;
  state.events = events;
  state.riskRules = riskRules;
  renderAll();
  renderRiskRules();
  renderScanMethodSettings(settings);
  renderVersionInfo(settings);
  // Fetched separately, not part of the Promise.all above: PATH doesn't
  // change over the life of the server, so a transient failure here just
  // means trying again next login rather than something worth failing the
  // rest of the app's data load over.
  Api.toolStatus().then(renderToolStatus).catch(() => {});
}

/** Renders the combined tools pill (nmap/netdiscover/dnsrecon) shown before
 * the live-connection icon: an at-a-glance "N/M available" count, with a
 * hover panel (#toolStatusPanel, see .tool-status-wrap in style.css)
 * breaking down each tool's availability and, when installed, its exact
 * path — fetched once per login since PATH doesn't change over the life of
 * a running server, unlike the polled scan-status/active-users pills next
 * to it. The panel is a sibling element rather than a data-tooltip on the
 * pill itself, since this function replaces the pill's whole className on
 * every refresh below — any class living on the pill would get wiped. */
function renderToolStatus(tools) {
  const available = tools.filter((t) => t.available).length;
  let pillClass = "pill-muted";
  if (available === tools.length) pillClass = "pill-good";
  else if (available === 0) pillClass = "pill-bad";
  qs("#toolStatusCount").textContent = `${available}/${tools.length}`;
  qs("#toolStatus").className = "pill " + pillClass;

  const panel = qs("#toolStatusPanel");
  panel.innerHTML = "";
  for (const t of tools) {
    panel.appendChild(el("div", { class: "tool-status-row" }, [
      el("span", { class: "tool-status-mark " + (t.available ? "tool-status-ok" : "tool-status-bad"), text: t.available ? "✓" : "✗" }),
      `${t.name} — ${t.available ? t.path : "not found on PATH"}`,
    ]));
  }
}

async function startApp() {
  showApp();
  if (appStarted) {
    await loadAppData(); // returning from a re-login after a session expiry
    startLiveUpdates(); // stopLiveUpdates() tore these down when the session went stale
    return;
  }
  appStarted = true;

  graph = new Graph(qs("#graph"));
  applyViewMode();
  wireTabs();
  wireGraphControls();
  wireViewToggle();
  wireZoomControls();
  wireFilters();
  wireMiniDash();
  wireNotifications();
  wireTopbar();
  wireSubnetForm();
  wireHostAddForm();
  wireTagManager();
  wireSettings();
  wireRiskRuleModal();
  wireScanConfirmModal();
  wireModal("#hostModal", "#hmClose");

  await loadAppData();

  startLiveUpdates();
  setInterval(renderScanStatus, 1000); // ticks the "next scan in Ns" countdown between polls
  setInterval(renderNotifPanel, 30000); // keep relative timestamps fresh
  setInterval(renderHostList, 30000);
}

async function checkAuthAndStart() {
  try {
    const me = await Api.me();
    qs("#stAccountUsername").textContent = me.username;
    await startApp();
  } catch (_) {
    showLoginScreen();
  }
}

function wireLogin() {
  qs("#loginForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = qs("#loginUsername").value.trim();
    const password = qs("#loginPassword").value;
    const errEl = qs("#loginError");
    errEl.hidden = true;
    try {
      await Api.login(username, password);
      qs("#stAccountUsername").textContent = username;
      await startApp();
    } catch (err) {
      errEl.textContent = err.message;
      errEl.hidden = false;
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  wireLogin();
  checkAuthAndStart();
  loadLoginVersionInfo();
});
