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

/** Groups hosts one bucketing level below `prefix`, the same rule the
 * canvas graph's Graph._layoutLevel uses (stepping in octets, capped at
 * /24 where individual hosts show instead of another bucket layer) — kept
 * as a separate pure function (no canvas/positioning) so the simple-view
 * tree can reuse the exact same grouping without depending on the Graph
 * class. Returns null at a leaf level (prefix >= 24 or unknown), meaning
 * "render these hosts directly, no further grouping". */
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

  subnets: () => Api._req("GET", "/api/subnets"),
  addSubnet: (cidr, name) => Api._req("POST", "/api/subnets", { cidr, name }),
  setSubnetHidden: (id, hidden) => Api._req("PATCH", `/api/subnets/${id}`, { hidden }),
  setSubnetEnabled: (id, enabled) => Api._req("PATCH", `/api/subnets/${id}`, { enabled }),
  deleteSubnet: (id) => Api._req("DELETE", `/api/subnets/${id}`),

  hosts: () => Api._req("GET", "/api/hosts"),
  addHost: (subnetId, ip, hostname, notes) => Api._req("POST", "/api/hosts", { subnetId, ip, hostname, notes }),
  updateHostNotes: (id, notes) => Api._req("PATCH", `/api/hosts/${id}`, { notes }),
  deleteHost: (id) => Api._req("DELETE", `/api/hosts/${id}`),
  clearAllHosts: (confirm) => Api._req("DELETE", `/api/hosts?confirm=${encodeURIComponent(confirm)}`),
  addHostTag: (hostId, tagId) => Api._req("POST", `/api/hosts/${hostId}/tags`, { tagId }),
  removeHostTag: (hostId, tagId) => Api._req("DELETE", `/api/hosts/${hostId}/tags/${tagId}`),

  tags: () => Api._req("GET", "/api/tags"),
  createTag: (name, color) => Api._req("POST", "/api/tags", { name, color }),
  deleteTag: (id) => Api._req("DELETE", `/api/tags/${id}`),

  ackHost: (id) => Api._req("POST", `/api/hosts/${id}/ack`),
  unackHost: (id) => Api._req("DELETE", `/api/hosts/${id}/ack`),
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

  events: () => Api._req("GET", "/api/events"),
  scanNow: () => Api._req("POST", "/api/scan"),
  deepScanAll: () => Api._req("POST", "/api/scan/deep"),
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
  // Bucket keys expanded in either graph view — shared between the
  // animated canvas and the static one, so expanding a bucket in one is
  // reflected in the other.
  expandedBuckets: new Set(),
  notifDismissed: new Set(), // event ids the user has cleared from the bell panel
  notifUnread: new Set(), // event ids not yet seen (drives the bell badge count)
  pendingTagAdds: [], // staged in the host modal until Save is clicked
  pendingTagRemoves: [],
  // "graph" | "simple" — simple view swaps the physics-animated canvas for
  // a second canvas showing the same segments > hosts hierarchy laid out
  // as a static tree (deterministic positions, draw-on-demand instead of a
  // continuous per-frame loop). For remote/thin-client sessions where that
  // continuous redraw is heavy or laggy. Persisted per browser, not per
  // account, since it's about the viewing hardware.
  viewMode: localStorage.getItem("viewMode") === "simple" ? "simple" : "graph",
};

function subnetById(id) { return state.subnets.find((s) => s.id === id); }
function hostById(id) { return state.hosts.find((h) => h.id === id); }
function tagById(id) { return state.tags.find((t) => t.id === id); }

/* ---------------------------------------------------------------------- */
/* graph (force-directed canvas visualization)                            */
/* ---------------------------------------------------------------------- */

const TAG_PALETTE = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#4a3aa7", "#e34948"];

class Graph {
  /** animated (default true) picks the physics-simulated layout used by
   * the main graph view. Passing false gives the simple-view graph: same
   * node/link model, same pan/zoom/drag/click-to-expand interactions, but
   * positions come from a one-shot deterministic tree layout (see
   * _syncStatic) instead of a spring simulation, and wake() draws once on
   * demand instead of starting a continuous requestAnimationFrame loop. */
  constructor(canvas, opts = {}) {
    this.canvas = canvas;
    this.animated = opts.animated !== false;
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
    const sx = e.clientX - rect.left, sy = e.clientY - rect.top;
    const before = this.screenToWorld(sx, sy);
    const factor = Math.exp(-e.deltaY * 0.001);
    this.transform.k = Math.min(4, Math.max(0.15, this.transform.k * factor));
    const after = this.screenToWorld(sx, sy);
    this.transform.x += (after.x - before.x) * this.transform.k;
    this.transform.y += (after.y - before.y) * this.transform.k;
    this.wake();
  }

  _onClick(e) {
    if (this._dragMoved) { this._dragMoved = false; return; }
    const rect = this.canvas.getBoundingClientRect();
    const sx = e.clientX - rect.left, sy = e.clientY - rect.top;
    const n = this._nodeAt(sx, sy);
    if (n && n.type === "host") openHostModal(n.hostId);
    else if (n && n.type === "bucket") this.toggleBucket(n.key);
  }

  _onDblClick(e) {
    const rect = this.canvas.getBoundingClientRect();
    const sx = e.clientX - rect.left, sy = e.clientY - rect.top;
    const n = this._nodeAt(sx, sy);
    if (n) { n.pinned = false; this.wake(); }
  }

  /** Animated: (re)starts the physics/redraw loop if it isn't already
   * running. Static: there's no loop to start — every wake() is a single
   * immediate redraw, since positions only ever change from an explicit
   * sync()/drag/pan/zoom, never from a settling simulation. Either way,
   * paused suppresses it completely: the point of the static view is that
   * a client with weak video acceleration pays for a redraw only when
   * something actually visibly changed, never on a timer. */
  wake() {
    this._sleepFrames = 0;
    if (this.paused) return;
    if (!this.animated) { this._draw(); return; }
    if (!this.running) { this.running = true; requestAnimationFrame(() => this._tick()); }
  }

  /** Pausing stops the physics/redraw loop outright — wake() becomes a
   * no-op rather than just hiding the canvas — so whichever view isn't
   * currently shown genuinely costs nothing, instead of continuing to
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
   * of nodes that still exist. Static graphs use a completely different
   * (non-physics) layout algorithm — see _syncStatic — since there's no
   * simulation running to spread freshly-seeded nodes apart. */
  sync(subnets, hosts) {
    if (!this.animated) { this._syncStatic(subnets, hosts); return; }

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
      this._layoutLevel(subnetKey, subnetHosts, cidrPrefix(sn.cidr), sn.id, nextKeys, cx, cy);
    }

    for (const key of Array.from(this.nodes.keys())) {
      if (!nextKeys.has(key)) this.nodes.delete(key);
    }

    this.wake();
  }

  /** Builds a plain-object tree (subnet -> bucket* -> host) describing
   * what should be visible under key given the current bucket-expansion
   * state, with no canvas/positioning concerns mixed in — the static
   * layout's equivalent of what _layoutLevel does while it recurses, but
   * as a separate pass since the tree layout below needs the whole shape
   * (to compute subtree widths) before it can place anything, unlike the
   * physics layout which only needs a rough starting point per node.
   * Subnets always expand (no top-level collapse, matching the animated
   * view); buckets expand only via the same state.expandedBuckets the
   * animated view's bucket click-to-expand uses. */
  _buildLogicalTree(key, type, data, hosts, prefix, subnetId) {
    const node = { key, type, data, subnetId, children: [] };
    if (type === "host") return node;

    node.count = hosts.length;
    node.expanded = type === "subnet" || state.expandedBuckets.has(key);
    if (node.expanded) {
      const level = nextTreeLevel(hosts, prefix);
      node.children = !level
        ? hosts.map((h) => this._buildLogicalTree("host:" + h.id, "host", h, null, null, null))
        : Array.from(level.groups.entries())
          .sort((a, b) => a[0].localeCompare(b[0]))
          .map(([cidr, groupHosts]) => this._buildLogicalTree(
            "bucket:" + subnetId + ":" + cidr, "bucket", { cidr }, groupHosts, level.childPrefix, subnetId));
    }
    return node;
  }

  /** Static-view equivalent of sync(): lays out the same segments > hosts
   * hierarchy as a top-down tree instead of a physics simulation. Depth
   * comes straight from tree depth; horizontal position comes from a
   * simple two-pass scheme — leaves get sequential slots left to right,
   * each internal node centers over its children's slots — which is all
   * that's needed since (unlike the animated view) nothing has to spread
   * newly-added nodes apart after the fact. Positions are only assigned to
   * brand-new nodes; anything the user already dragged keeps its place
   * across re-syncs, same as pinning does in the animated view. */
  _syncStatic(subnets, hosts) {
    const bySubnet = new Map();
    hosts.forEach((h) => {
      if (!bySubnet.has(h.subnetId)) bySubnet.set(h.subnetId, []);
      bySubnet.get(h.subnetId).push(h);
    });

    const roots = subnets.map((sn) => this._buildLogicalTree(
      "subnet:" + sn.id, "subnet", sn, bySubnet.get(sn.id) || [], cidrPrefix(sn.cidr), sn.id));

    const leafCounter = { n: 0 };
    const assignSlots = (node, depth) => {
      node.depth = depth;
      if (node.children.length === 0) {
        node.tx = leafCounter.n++;
        return;
      }
      node.children.forEach((c) => assignSlots(c, depth + 1));
      const txs = node.children.map((c) => c.tx);
      node.tx = (Math.min(...txs) + Math.max(...txs)) / 2;
    };
    roots.forEach((root) => assignSlots(root, 0));

    const spacingX = 70, spacingY = 90;
    const offsetX = -Math.max(0, (leafCounter.n - 1) * spacingX) / 2;

    const nextKeys = new Set();
    const place = (node, parentKey) => {
      nextKeys.add(node.key);
      const r = node.type === "subnet" ? 16 : node.type === "bucket" ? 14 : 7;
      const cn = this._ensureNode(node.key, () => ({
        key: node.key, type: node.type, r, vx: 0, vy: 0, pinned: false,
        hostId: node.type === "host" ? node.data.id : undefined,
        x: node.tx * spacingX + offsetX, y: node.depth * spacingY,
      }));
      cn.data = node.data;
      if (node.type === "bucket") {
        cn.subnetId = node.subnetId;
        cn.cidr = node.data.cidr;
        cn.count = node.count;
        cn.expanded = node.expanded;
      }
      if (parentKey) this.links.push({ a: parentKey, b: node.key });
      node.children.forEach((c) => place(c, node.key));
    };

    this.links = [];
    roots.forEach((root) => place(root, null));

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
        ctx.restore();
        if (this.transform.k > 0.35) {
          ctx.fillStyle = muted;
          ctx.font = `${11 / this.transform.k}px system-ui, sans-serif`;
          ctx.textAlign = "center";
          ctx.fillText(node.data ? node.data.cidr : "", node.x, node.y - node.r - 6 / this.transform.k);
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
      const color = !h ? muted : h.status === "down" ? critical : good;
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.globalAlpha = h && h.status === "down" ? 0.55 : 1;
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

let graph; // animated, physics-simulated
let simpleGraph; // static tree layout, for simple view

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
      el("span", { class: "status-dot", style: `background:${h.status === "down" ? "var(--status-critical)" : "var(--status-good)"}` }),
      el("div", { class: "host-main" }, [
        el("div", { class: "host-ip" }, [h.ip + (h.hostname ? "  " : ""), h.hostname ? el("span", { class: "muted", text: h.hostname }) : null]),
        el("div", { class: "host-sub" }, [sn ? sn.cidr : "", openPortCount ? ` · ${openPortCount} open port${openPortCount === 1 ? "" : "s"}` : ""]),
      ]),
      ...(h.tags || []).slice(0, 3).map((t) => el("span", { class: "tag-dot", style: `background:${t.color}`, title: t.name })),
      h.riskLevel ? riskBadge(h.riskLevel, h.riskReasons, h.acknowledged) : null,
      h.suspect ? el("span", { class: "badge-suspect", title: h.suspectReason, text: "SUSPECT" }) : null,
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
          el("button", { class: "btn-icon", title: "Remove subnet", onclick: () => removeSubnet(sn.id) }, ["✕"]),
        ]),
      ]),
      el("div", { class: "sc-meta", text: `${sn.name ? sn.name + " · " : ""}${sn.source} · ${count} host${count === 1 ? "" : "s"} · scanned ${timeAgo(sn.lastScanAt)}` }),
    ]));
  }
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
  if (simpleGraph) simpleGraph.sync(subnets, hosts);
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

  const ackInfoTip = "Marking as checked means you've reviewed this host, so it drops out of priority views (the ⚑ filter, the dashboard's priority count) until something changes. It's automatically un-marked and re-flagged the moment a new port opens on it — it doesn't silence the host permanently.";
  const ackInfoIcon = el("span", { class: "hm-ack-info", tabindex: "0", "aria-label": "What does marking as checked do?", "data-tooltip": ackInfoTip }, ["ⓘ"]);

  const ackRow = qs("#hmAckRow");
  ackRow.innerHTML = "";
  ackRow.hidden = !h.riskLevel;
  if (h.riskLevel) {
    if (h.acknowledged) {
      ackRow.appendChild(el("div", { class: "hm-ack-status" }, [
        "Marked as checked — won't be flagged as priority unless a new port opens.",
        ackInfoIcon,
        el("button", {
          class: "btn btn-small", onclick: async () => {
            await Api.unackHost(h.id);
            await refreshHosts();
            openHostModal(h.id);
            toast("Host unmarked.");
          },
        }, ["Unmark"]),
      ]));
    } else {
      ackRow.appendChild(ackInfoIcon);
      ackRow.appendChild(el("button", {
        class: "btn btn-small", onclick: async () => {
          await Api.ackHost(h.id);
          closeModal("#hostModal");
          await refreshHosts();
          toast("Host marked as checked. It'll be re-flagged if a new port opens.");
        },
      }, ["Mark as checked"]));
    }
  }

  qs("#hmStatus").innerHTML = "";
  qs("#hmStatus").appendChild(el("span", { class: "pill " + (h.status === "down" ? "pill-bad" : "pill-good") }, [
    el("span", { class: "dot" }), h.status,
  ]));
  qs("#hmHostname").textContent = h.hostname || "—";
  qs("#hmMac").textContent = h.mac || "—";
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
    await Api.updateHostNotes(h.id, qs("#hmNotes").value);
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

const refreshDebounced = debounce(async () => {
  const [hosts, subnets] = await Promise.all([Api.hosts(), Api.subnets()]);
  state.hosts = hosts;
  state.subnets = subnets;
  renderAll();
}, 350);

/* ---------------------------------------------------------------------- */
/* SSE                                                                    */
/* ---------------------------------------------------------------------- */

function connectSSE() {
  const connLabel = qs("#connLabel"), connState = qs("#connState");
  const es = new EventSource("/api/events/stream");

  es.addEventListener("ready", () => {
    connLabel.textContent = "live";
    connState.className = "pill pill-good";
  });

  const evTypes = ["new_subnet", "new_host", "new_port", "host_down", "port_closed", "scan_anomaly", "hosts_cleared", "priority_reflag", "deep_scan_started", "deep_scan_finished"];
  for (const type of evTypes) {
    es.addEventListener(type, (e) => {
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

  es.onerror = () => {
    connLabel.textContent = "reconnecting…";
    connState.className = "pill pill-bad";
  };
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

/** Renders from the cached lastScanStatus — called every second so "next
 * scan in Ns" counts down smoothly without a network round-trip each time. */
function renderScanStatus() {
  const st = lastScanStatus;
  if (!st) return;
  const label = qs("#scanLabel"), pill = qs("#scanState");
  if (st.running) {
    label.textContent = st.deep ? "deep scanning…" : "scanning…";
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

  const filterPanel = qs("#filterPanel");
  qs("#btnFilters").addEventListener("click", (e) => {
    e.stopPropagation();
    filterPanel.hidden = !filterPanel.hidden;
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
  const panel = qs("#notifPanel");
  qs("#btnNotifs").addEventListener("click", (e) => {
    e.stopPropagation();
    panel.hidden = !panel.hidden;
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
    if (state.expandedBuckets.size === 0) return;
    state.expandedBuckets.clear();
    renderGraph();
  });
}

/** Applies state.viewMode to the layout and to which of the two Graph
 * instances is actively rendering. Pausing the hidden one (rather than
 * just hiding it with CSS) is the point of simple view: whichever graph
 * isn't shown stops doing any per-frame or on-demand canvas work outright,
 * instead of continuing to repaint an element the user can't see. */
function applyViewMode() {
  const simple = state.viewMode === "simple";
  qs("#layout").classList.toggle("simple-view", simple);
  const btn = qs("#btnViewToggle");
  btn.textContent = simple ? "Graph view" : "Simple view";
  btn.setAttribute("aria-pressed", String(simple));

  const shown = simple ? simpleGraph : graph;
  const hidden = simple ? graph : simpleGraph;
  if (hidden) hidden.setPaused(true);
  if (shown) {
    // Its canvas was display:none while hidden, so its rect (and anything
    // sized from it) may be stale or zero; recompute before unpausing so
    // switching to it doesn't briefly draw into a zero-sized canvas.
    shown._resize();
    shown.setPaused(false);
  }
}

function wireViewToggle() {
  qs("#btnViewToggle").addEventListener("click", () => {
    state.viewMode = state.viewMode === "simple" ? "graph" : "simple";
    localStorage.setItem("viewMode", state.viewMode);
    applyViewMode();
  });
}

function wireTopbar() {
  const scanMenu = qs("#scanMenu");
  qs("#btnScanMenuToggle").addEventListener("click", (e) => {
    e.stopPropagation();
    scanMenu.hidden = !scanMenu.hidden;
  });
  scanMenu.addEventListener("click", (e) => e.stopPropagation());
  document.addEventListener("click", () => { scanMenu.hidden = true; });

  qs("#btnScanNow").addEventListener("click", async () => {
    scanMenu.hidden = true;
    await Api.scanNow();
    pollScanStatus();
    toast("Scan triggered.");
  });
  qs("#btnDeepScanAll").addEventListener("click", () => {
    scanMenu.hidden = true;
    qs("#dsmConfirm").checked = false;
    qs("#dsmProceed").disabled = true;
    showModal("#deepScanModal");
  });

  qs("#btnAddSubnet").addEventListener("click", () => { qs("#smError").hidden = true; qs("#smCIDR").value = ""; qs("#smName").value = ""; showModal("#subnetModal"); });
  qs("#btnAddHost").addEventListener("click", () => { qs("#hamError").hidden = true; qs("#hamIP").value = ""; qs("#hamHostname").value = ""; qs("#hamNotes").value = ""; renderTagSelects(); showModal("#hostAddModal"); });
  qs("#btnTags").addEventListener("click", () => { renderTagManager(); showModal("#tagModal"); });

  const accountMenu = qs("#accountMenu");
  qs("#btnAccountMenu").addEventListener("click", (e) => {
    e.stopPropagation();
    accountMenu.hidden = !accountMenu.hidden;
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

function wireSubnetForm() {
  wireModal("#subnetModal", "#smClose");
  qs("#smSubmit").addEventListener("click", async () => {
    const cidr = qs("#smCIDR").value.trim();
    const name = qs("#smName").value.trim();
    try {
      await Api.addSubnet(cidr, name);
      closeModal("#subnetModal");
      await refreshSubnets();
      toast(`Subnet ${cidr} added. Scan triggered.`);
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
/** Shared by the Settings-tab footer (post-login, from /api/settings) and
 * the login screen (pre-login, from the unauthenticated /api/healthz) —
 * same version/buildDate fields either way. */
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
 * rather than blocking sign-in over it. */
async function loadLoginVersionInfo() {
  try {
    const info = await Api.healthz();
    qs("#loginVersionInfo").textContent = versionInfoText(info);
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
/* deep scan confirm modal                                               */
/* ---------------------------------------------------------------------- */

function wireDeepScanModal() {
  wireModal("#deepScanModal", "#dsmClose");
  qs("#dsmConfirm").addEventListener("change", (e) => {
    qs("#dsmProceed").disabled = !e.target.checked;
  });
  qs("#dsmCancel").addEventListener("click", () => closeModal("#deepScanModal"));
  qs("#dsmProceed").addEventListener("click", async () => {
    closeModal("#deepScanModal");
    await Api.deepScanAll();
    pollScanStatus();
    toast("Deep scan triggered — scanning every port on every host. This can take a long time on a large network.", "warn");
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
}

/* ---------------------------------------------------------------------- */
/* auth / init                                                            */
/* ---------------------------------------------------------------------- */

let appStarted = false;

function showLoginScreen() {
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
}

async function startApp() {
  showApp();
  if (appStarted) {
    await loadAppData(); // returning from a re-login after a session expiry
    return;
  }
  appStarted = true;

  graph = new Graph(qs("#graph"));
  simpleGraph = new Graph(qs("#simpleGraph"), { animated: false });
  applyViewMode();
  wireTabs();
  wireGraphControls();
  wireViewToggle();
  wireFilters();
  wireMiniDash();
  wireNotifications();
  wireTopbar();
  wireSubnetForm();
  wireHostAddForm();
  wireTagManager();
  wireSettings();
  wireRiskRuleModal();
  wireDeepScanModal();
  wireModal("#hostModal", "#hmClose");

  await loadAppData();

  connectSSE();
  pollScanStatus();
  setInterval(pollScanStatus, 4000);
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
