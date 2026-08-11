/* System Explorer — operator UI (SPEC §8).
   Vanilla, no build step. Consumes only the public /v1 API; renders only
   what is in the envelope. Deep links: #/subsystem/collection[/object-id] —
   behind the per-site hub (hub/server.py) a host name is the first segment
   (#/host/…) and every agent call is proxied through /agents/<host>.

   Detail is an inline expansion beneath the row that produced it. Evidence
   offers two views of one captured payload — a command-style rendering and
   raw JSON; nothing is ever executed to produce either.

   Concurrency: every fetch captures state.epoch (bumped on collection
   change) and its own target; responses that no longer match current state
   are discarded. The last *wanted* response wins, not the last to arrive. */

"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  hub: null,             // /hub/hosts payload when the hub serves us, else null
  currentHost: null,     // hub mode: the agent every api() call is proxied to
  capabilities: null,
  status: null,          // /v1/status roll-up for the current host (nav badges)
  subsystem: null,
  collection: null,
  page: null,
  selectedId: null,
  detailObs: null,
  evidence: null,        // {data, view}
  sortKey: null,
  sortDir: 1,
  filterText: "",
  facet: null,
  showHidden: false,     // reveal rows a HIDDEN rule suppresses by default
  colPicker: false,      // the columns dropdown in the facet bar
  lookupDraft: null,     // in-progress lookup input, preserved across refresh
  lookupCatalog: null,   // launcher entries, fetched once per host
  ovIdentity: null,      // overview KPI identity facts, cached per host
  ovPrev: null,          // overview's previous counter sample (client-side rates)
  owners: null,          // native_id -> owning workload, for the current list
  ovHistory: [],         // sparkline ring: derived cpu/mem samples, this session
  ovHistoryHost: null,   // which host that ring belongs to
  observedAt: null,
  refreshTimer: null,
  suppressAutoOpen: false,
  epoch: 0,
};

const COLUMNS = {
  "units/units": ["ActiveState", "SubState", "Description"],
  "logs/journal": ["Timestamp", "Priority", "SyslogIdentifier", "Message"],
  "docker/containers": ["State", "Status", "Image", "ComposeProject"],
  "docker/volumes": ["Driver", "Mountpoint", "ComposeProject"],
  "docker/networks": ["Driver", "BridgeInterface", "ComposeProject", "Internal"],
  "storage/mounts": ["Source", "FsType", "UsePercent", "SizeBytes", "AvailBytes"],
  "storage/block-devices": ["Type", "Transport", "Size", "FsType", "Mountpoints", "Model"],
  "storage/arrays": ["Status", "Level", "SyncPercent", "RaidDisks", "SizeBytes"],
  "storage/pools": ["State", "CapacityPercent", "ScanFunction", "Errors"],
  "storage/datasets": ["UsedBytes", "SnapshotUsedBytes", "AvailBytes", "UsePercent", "Mountpoint", "ReadOnly", "Mounted"],
  "nix/generations": ["NixosVersion", "Kernel", "ConfigurationRevision", "Created", "Current", "Booted", "Profile"],
  "packages/packages": ["Name", "Version", "Manager", "Architecture", "StorePath"],
  "system/overview": ["LoadAvg1", "LoadPerCpu1", "MemUsedPercent", "MemAvailableBytes", "SwapUsedPercent", "UptimeSeconds"],
  "hardware/platform": ["ProductName", "CPUModel", "CPUs", "MemoryTotalBytes", "BiosVersion"],
  "hardware/pci": ["Class", "Vendor", "Model", "Driver"],
  "hardware/usb": ["Vendor", "Product", "SpeedMbps", "USBVersion"],
  "hardware/scsi": ["Kind", "Transport", "Vendor", "Model", "SizeBytes", "LinkSpeed", "State", "Block", "Devices", "EnclosureSlot", "SmartTemperatureC"],
  "hardware/nvme": ["LinkSpeed", "LinkWidth", "Model", "FirmwareRev", "Serial", "State", "SmartTemperatureC", "Namespaces"],
  "network/links": ["OperState", "Kind", "MTU", "MACAddress", "Addresses"],
  "network/routes": ["Gateway", "Device", "Protocol", "Scope", "Family"],
  "network/lookups": ["Question", "Input", "Example"],
  "storage/lookups": ["Question", "Input", "Example"],
  "network/resolver": ["CurrentDNSServer", "DNSServersInUse", "SearchDomains", "DNSSEC"],
  "network/tailscale": ["TailscaleIPs", "Online", "Relay", "CurAddr", "OS", "LastSeen"],
  "network/nft-tables": ["Family", "ChainCount", "RuleCount", "Chains"],
  "vms/domains": ["State", "IPAddresses", "MemoryMiB", "VCPUs", "Autostart"],
};

/* Columns whose value is not a fact. "Kind" is the object's own declared type
   from the envelope, which every item has carried all along and the grid never
   showed. It matters most where a collection is heterogeneous: hardware/scsi
   mixes host adapters, expanders, enclosures and disks, so without this a
   controller renders as a disk with every disk column blank — which is exactly
   how an operator concluded the collection was broken. The facet bar could
   already group by it; the rows could not say it. */
const PSEUDO_COLUMNS = {
  Kind: (item) => item.type,
};

const FACETS = {
  "units/units": (item) => item.type,
  "logs/journal": (item) => item.facts.SyslogIdentifier,
  "docker/containers": (item) => item.facts.State,
  "hardware/pci": (item) => item.facts.Class,
  "hardware/scsi": (item) => item.type,
};

/* Rows hidden by default, systemctl-status style: the default view is what
   is running (plus anything failed — that is never hidden). A toggle chip
   in the facet bar reveals the rest; the API always returns everything. */
const HIDDEN = {
  "units/units": { label: "inactive", match: (item) => item.facts.ActiveState === "inactive" },
  "hardware/scsi": { label: "empty hosts",
                     match: (item) => item.type === "scsi-host" && !item.facts.Devices },
};

const PREFIX_ROUTE = {
  unit: ["units", "units"],
  entry: ["logs", "journal"],
  "block-device": ["storage", "block-devices"],
  mount: ["storage", "mounts"],
  array: ["storage", "arrays"],
  pool: ["storage", "pools"],
  dataset: ["storage", "datasets"],
  container: ["docker", "containers"],
  volume: ["docker", "volumes"],
  "docker-network": ["docker", "networks"],
  identity: ["system", "identity"],
  time: ["system", "time"],
  boot: ["system", "boot"],
  overview: ["system", "overview"],
  generation: ["nix", "generations"],
  package: ["packages", "packages"],
  platform: ["hardware", "platform"],
  pci: ["hardware", "pci"],
  usb: ["hardware", "usb"],
  scsi: ["hardware", "scsi"],
  nvme: ["hardware", "nvme"],
  link: ["network", "links"],
  route: ["network", "routes"],
  lookup: ["network", "lookups"],
  resolver: ["network", "resolver"],
  "nft-table": ["network", "nft-tables"],
  domain: ["vms", "domains"],
};

const VALUE_CLASS = {
  active: "ok", running: "ok", up: "ok", online: "ok", loaded: "ok", enabled: "ok",
  failed: "crit", crashed: "crit", unhealthy: "crit", degraded: "crit",
  down: "warn", exited: "warn", paused: "warn", blocked: "warn", restarting: "warn",
  inactive: "neutral", shutoff: "neutral", dead: "neutral", unknown: "neutral",
};

const PRIORITY_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];
const NBSP = "\u00a0";

/* ── helpers ─────────────────────────────────────────────── */

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function idPath(objectId) {
  return encodeURIComponent(objectId).replace(/%2F/gi, "/").replace(/%3A/gi, ":");
}

function safeDecode(part) {
  try { return decodeURIComponent(part); } catch { return part; }
}

/* A lookup result (lookup:route-get/1.1.1.1) is not a row of its own; it
   anchors to the descriptor row (lookup:route-get) that produced it. */
function anchorRowId() {
  const id = state.selectedId;
  return id && id.startsWith("lookup:") ? id.split("/")[0] : id;
}

async function api(path) {
  // Hub mode reaches each agent same-origin through the proxy; the paths
  // themselves (including evidence_ref values) stay agent-relative.
  //
  // The site is named in the URL because the hub is stateless: a host at a
  // sibling site is forwarded to the hub that owns it, and without the site in
  // the path that hub would have to ask every sibling who owns the host on
  // every single request. The browser already knows, from /hub/hosts.
  const res = await fetch(state.hub ? `${hubBase()}${path}` : path);
  if (!res.ok) throw new Error(`${res.status} ${await res.text().then(t => t.slice(0, 140))}`);
  return res.json();
}

/* Proxy prefix for the current host. Falls back to the unscoped route when the
   hub reports no site for it — an older hub, or one started without
   SE_HUB_SITE — so a mixed-version estate degrades to today's behaviour rather
   than 404ing. */
function hubBase() {
  const site = state.hub?.hosts?.[state.currentHost]?.site;
  return site ? `/sites/${encodeURIComponent(site)}/agents/${state.currentHost}`
              : `/agents/${state.currentHost}`;
}

function humanBytes(n) {
  if (typeof n !== "number") return String(n);
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

function ageOf(iso) {
  if (!iso) return "";
  const s = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 1000));
  if (s < 90) return `${s}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}

/* ageOf's ladder with wider stops — durations (uptimes) rather than ages. */
function humanSeconds(n) {
  if (n < 120) return `${Math.round(n)}s`;
  if (n < 7200) return `${Math.round(n / 60)}m`;
  if (n < 172800) return `${Math.round(n / 3600)}h`;
  return `${Math.round(n / 86400)}d`;
}

/* Hours, the unit SMART reports drive age in. The fact stays native (SPEC
   rule: native concepts before abstractions) because 69392 is the number the
   drive gave; it is simply not a number anyone reads. Past a couple of days
   it becomes days, past a year it becomes years to one decimal — enough to
   tell a 4.0y drive from a 7.9y one at a glance, which is the actual
   question being asked of a pool member. */
function humanHours(n) {
  if (typeof n !== "number") return String(n);
  if (n < 48) return `${Math.round(n)}h`;
  if (n < 8760) return `${Math.round(n / 24)}d`;
  return `${(n / 8760).toFixed(1)}y`;
}

/* Unit-aware scalar formatting, keyed on fact-name conventions: *Bytes
   humanizes, *Seconds becomes a duration, *Hours an age, *Percent / *Pct
   wears its % sign. Returns null when the key carries no unit convention —
   callers fall through to generic rendering.

   THE one place a unit becomes text. It was not: renderCell carried its own
   *Bytes branch (dead, since this function already claimed those keys) and
   the overview's fact table carried a third copy. A second implementation is
   how *Hours went four releases without anyone noticing it was unreadable —
   there was no single place to add it. Add new units here and nowhere. */
const PERCENT_KEY_RE = /(Percent|Pct)/;
function scalarText(key, value, exact = false) {
  if (typeof value !== "number") return null;
  const withExact = (text) => exact ? `${text}  (${value})` : text;
  if (key.endsWith("Bytes")) return withExact(humanBytes(value));
  if (key.endsWith("Seconds")) return withExact(humanSeconds(value));
  if (key.endsWith("Hours")) return withExact(humanHours(value));
  // PCIe lane counts. A bare "2" beside a bare "4" did not read as the cause of
  // a warning; "x2" beside "x4" does.
  if (/LinkWidth(Max)?$/.test(key)) return `x${value}`;
  if (PERCENT_KEY_RE.test(key)) return `${value}%`;
  return null;
}

function vstr(v) {
  if (v === null || v === undefined) return "";
  if (Array.isArray(v)) return v.map(vstr).join(" ");
  if (typeof v === "object") {
    if ("__bytes_base64__" in v) {
      const b64 = v.__bytes_base64__;
      const bytes = Math.floor(b64.length * 3 / 4) - (b64.endsWith("==") ? 2 : b64.endsWith("=") ? 1 : 0);
      return `<binary ${bytes} bytes>`;
    }
    return JSON.stringify(v);
  }
  return String(v);
}

/* ── boot ────────────────────────────────────────────────── */

async function boot() {
  initTheme();
  // One UI, two servers: each agent serves it single-host, the per-site hub
  // serves the same files with /hub/hosts in front. That route existing is
  // the mode switch — an agent 404s it and everything behaves as before.
  try {
    const res = await fetch("/hub/hosts");
    if (res.ok) state.hub = await res.json();
  } catch { /* server unreachable entirely; loadHost reports it below */ }
  if (state.hub && !Object.keys(state.hub.hosts).length) {
    banner("The hub has no agents configured (SE_HUB_AGENTS).");
    return;
  }
  if (state.hub) {
    const first = location.hash.replace(/^#\/?/, "").split("/")[0];
    state.currentHost = knownHost(first) ? first : defaultHost();
    $("host-select").onchange = onHostSelect;
  }
  const ok = await loadHost();
  window.addEventListener("hashchange", route);
  if (ok) route();
  setInterval(() => { $("age").textContent = state.observedAt ? `observed ${ageOf(state.observedAt)}` : ""; }, 5000);
  // The status poll keeps its own, slower clock: every tick re-collects
  // every collection server-side (statelessness's deliberate cost), so 60s
  // against the collection view's 15s, and only while visible.
  setInterval(() => { if (!document.hidden) refreshStatus(); }, 60000);
}

function knownHost(name) {
  return !!state.hub && !!name && Object.hasOwn(state.hub.hosts, name);
}

function defaultHost() {
  const names = Object.keys(state.hub.hosts);
  return names.find(n => state.hub.hosts[n].reachable) ?? names[0];
}

/* Fetch the current host's capabilities and rebuild the chrome around them.
   Everything host-scoped resets here; in-flight responses from the previous
   host die on the epoch bump. */
async function loadHost() {
  const epoch = ++state.epoch;
  state.lookupCatalog = null;
  state.status = null;
  state.ovPrev = null;         // counter deltas never span two hosts
  state.owners = null;         // and neither does attribution
  state.capabilities = null;   // stale caps must not describe the new host
  renderHostCard();
  let caps;
  try {
    caps = await api("/v1/capabilities");
  } catch (err) {
    if (epoch !== state.epoch) return false;
    state.capabilities = null;
    renderNav();
    banner(state.hub
      ? `${state.currentHost} is unreachable: ${err.message}`
      : `Cannot reach the agent: ${err.message}`);
    return false;
  }
  if (epoch !== state.epoch) return false;
  state.capabilities = caps;
  banner(null);
  renderHostCard();
  // AWAITED, unlike before. The nav hides collections the roll-up reports as
  // honestly empty, so painting it first meant offering every collection for a
  // moment and then withdrawing some — and a collection clicked inside that
  // window pins itself visible (by design, so deep links keep their anchor)
  // showing a bare table. That is what "storage/arrays is empty, feels like a
  // regression" was: not a data regression, a nav that shrank under the
  // pointer. One round-trip before the nav appears is the cheaper trade.
  //
  // A failed roll-up leaves state.status null, and renderNav then offers
  // everything — the same fallback as before, which is right: without the
  // roll-up the UI cannot know what is empty and must not guess.
  await refreshStatus();
  // Isolated on purpose. The chrome and the content are independent concerns,
  // and letting a rendering fault in one destroy the other is how a single null
  // dereference in the nav produced an entirely blank page — no rows, no panel,
  // no error, nothing to diagnose from. A broken nav with working content is a
  // bad afternoon; a white screen is an outage.
  try {
    renderNav();
  } catch (err) {
    banner(`Navigation failed to render: ${err.message}`);
  }
  return true;
}

function onHostSelect() {
  // Switching host is navigation: the URL stays the one source of truth.
  const rest = state.subsystem && state.collection
    ? `/${state.subsystem}/${state.collection}` : "";
  location.hash = `#/${$("host-select").value}${rest}`;
}

/* Which build am I looking at. The version alone cannot answer that: between
   releases every host reports the same one, so the footer read identically
   before and after a deploy and the only way to check whether a change had
   landed was to probe the API. In hub mode this is the SELECTED agent's build,
   not the hub's, which is the one the page's data came from — and the two can
   legitimately differ mid-rollout. */
function renderBuild() {
  const caps = state.capabilities;
  const foot = $("build");
  if (!caps) { foot.textContent = ""; return; }
  foot.textContent = caps.revision ? `v${caps.version} · ${caps.revision}`
                                   : `v${caps.version}`;
}

function renderHostCard() {
  renderBuild();
  if (!state.hub) {
    const host = state.capabilities?.host;
    if (host) {
      $("host-name").textContent = host.hostname;
      $("host-meta").textContent = host.machine_id.slice(0, 12) + "…";
    }
    // An agent serves exactly one host, so there is no switcher here — and
    // that silence once cost an operator a whole deployed capability: running
    // four hosts behind two hubs, they asked what had happened to the host
    // switcher while browsing an agent directly. The agent does not discover
    // its hub (aggregation must never be a precondition for observation), so
    // this appears only where the deployment configured hubUrl.
    const site = state.capabilities?.site;
    if (site?.hub_url) {
      const link = el("a", "site-link", site.name ? `all of ${site.name} →` : "site view →");
      link.href = site.hub_url;
      link.title = `This host is one of a site. Its hub serves every host at ${site.hub_url}`;
      $("host-meta").append(document.createTextNode(" · "), link);
    }
    return;
  }
  const select = $("host-select");
  $("host-name").hidden = true;
  select.hidden = false;
  select.textContent = "";

  // Grouped by site, which is the estate's actual shape (ROADMAP §6: an estate
  // spans sites; a site is not a small estate). A flat list of hostnames left
  // that structure to be inferred, and the operator had to be the one to point
  // out that theirs is one estate of two sites.
  const bySite = new Map();
  for (const [name, probe] of Object.entries(state.hub.hosts)) {
    const site = probe.site || state.hub.site || "";
    if (!bySite.has(site)) bySite.set(site, []);
    bySite.get(site).push([name, probe]);
  }
  // This site first, then siblings alphabetically: the local one is what the
  // operator opened this address for.
  const order = [...bySite.keys()].sort((a, b) =>
    a === state.hub.site ? -1 : b === state.hub.site ? 1 : a.localeCompare(b));

  for (const site of order) {
    const siteState = state.hub.sites?.[site];
    // A whole site being dark is its own statement, distinct from a host being
    // down — say which, in the group label, rather than listing its hosts as
    // individually unreachable and leaving the cause to be guessed.
    const label = siteState && siteState.reachable === false
      ? `${site} — site unreachable` : site;
    const group = bySite.size > 1 || site ? el("optgroup") : null;
    if (group) group.label = label || "(unnamed site)";
    for (const [name, probe] of bySite.get(site).sort((a, b) => a[0].localeCompare(b[0]))) {
      // Unreachable hosts stay listed and selectable — picking one shows the
      // error banner rather than silently hiding the host.
      const opt = el("option", null, probe.reachable ? name : `${name} — unreachable`);
      opt.value = name;
      (group || select).appendChild(opt);
    }
    if (group) select.appendChild(group);
  }

  select.value = state.currentHost;
  const probe = state.hub.hosts[state.currentHost];
  const machineId = state.capabilities?.host?.machine_id ?? probe?.host?.machine_id;
  // The host's OWN site, not the hub's — they differ for a sibling's host, and
  // showing the hub's would misattribute it.
  const hostSite = probe?.site || state.hub.site;
  $("host-meta").textContent = (hostSite ? `${hostSite} · ` : "")
    + (machineId ? machineId.slice(0, 12) + "…" : "unreachable");
}

/* The order [ and ] walk, read from the RENDERED nav rather than rebuilt from
   capabilities.

   Two orderings used to exist — capability order for the keys, render order for
   the eye — and they agreed only by coincidence. Promoting overview out of
   `system` broke the coincidence: the keys still walked through it in its old
   position, between boot and nix, so [ and ] behaved as though it were sitting
   under boot while the sidebar showed it at the top.

   Reading the DOM also skips what the roll-up hides as honestly empty, which a
   capability list cannot know: the keys can no longer land on a collection the
   nav deliberately refuses to offer, pinning it visible with a bare table.

   Falls back to capabilities if the nav is empty — renderNav is wrapped in a
   catch, so a rendering fault must not also cost keyboard navigation. */
function navRoutes() {
  // Order from the model — one source of truth with the sidebar — and the hidden
  // state from the DOM, which is the only place that knows what the roll-up
  // suppressed as honestly empty. Without that filter the keys could land on a
  // collection the nav deliberately refuses to offer.
  const hidden = new Set();
  for (const box of document.querySelectorAll("#nav .nav-sub")) {
    for (const link of box.querySelectorAll(".nav-item")) {
      if (link.hidden || box.hidden) hidden.add(link.dataset.route);
    }
  }
  const out = [];
  for (const section of navModel()) {
    for (const item of section.items) {
      if (!hidden.has(item.route)) out.push([item.sub, item.coll]);
    }
  }
  return out;
}

/* The overview is its own section, above the subsystems, because it already is
   one everywhere else in the code: the landing view, a designed panel rather
   than a grid, no rows to facet, a pseudo-page in the router. Its route stays
   system/overview — this is presentation, not a contract change. */
const STANDALONE = [["system", "overview", "overview"]];

/* Nav headings that group collections regardless of which subsystem owns them.
   Presentation only — routes, object ids, opinions and stored history are all
   untouched, which is what makes this the cheap answer to a question that looked
   expensive.

   "disks" exists because hardware is organised by TRANSPORT and an operator is
   not: `scsi` holds SAS, SATA and USB drives (Linux routes all three through the
   SCSI subsystem) while NVMe has its own, so "where are my disks" had no single
   place to look and the answer depended on knowing kernel taxonomy. Renaming
   `scsi` would have been a worse lie — it also holds hosts, expanders and
   enclosures — and making `disks` a real collection would have meant a second
   object identity per drive, double-counted SMART verdicts, and rehoming nine
   opinion keys before findings even exist. A heading costs none of that. */
const GROUPS = [
  // Placed after storage rather than at the top: physical disks are the
  // substrate the filesystems, arrays and pools above them are built on, so
  // reading downward goes from what is mounted to what it sits on. `after` names
  // the section it follows so position is declared here with the grouping,
  // instead of falling out of the order the loops happen to run in.
  { heading: "disks", after: "storage",
    members: [["hardware", "scsi"], ["hardware", "nvme"]] },
];

/* THE nav structure, computed once and consumed by everything.

   Three bugs came out of not having this. renderNav built the sidebar while
   applyNavBadges and navRoutes each re-derived the same structure with their own
   assumptions — so promoting overview out of `system` tripped a null dereference
   in one (blanking the entire page) and an ordering assumption in the other
   ([ and ] walking a position nobody could see). Both were the same mistake:
   adding a rendering variant without updating what reads the shape.

   So the shape is data. This decides sections, order, membership and headings;
   renderNav only draws it and the consumers only read it. Another promoted
   section, a group, a divider — one edit here. And it is testable with no DOM at
   all, which is what the smoke test now exercises. */
function navModel() {
  const subsystems = state.capabilities?.subsystems || {};
  const sections = [];
  const claimed = new Set();

  const listed = (sub, coll) =>
    subsystems[sub]?.available && (subsystems[sub].collections || []).includes(coll);

  for (const [sub, coll, label] of STANDALONE) {
    if (!listed(sub, coll)) continue;
    claimed.add(`${sub}/${coll}`);
    // No heading, deliberately: separated by space rather than by a label it
    // does not need. Consumers must tolerate a headless section — which is
    // precisely what one of them did not.
    sections.push({ solo: true, heading: null, available: true,
                    items: [{ sub, coll, label, route: `${sub}/${coll}` }] });
  }

  // Group membership is claimed BEFORE the subsystem sections are built, so a
  // grouped collection cannot also appear under its own subsystem — the same
  // collection reachable twice is what the smoke test guards.
  const groups = [];
  for (const group of GROUPS) {
    const items = group.members
      .filter(([sub, coll]) => listed(sub, coll) && !claimed.has(`${sub}/${coll}`))
      .map(([sub, coll]) => ({ sub, coll, label: coll, route: `${sub}/${coll}` }));
    // An empty group is not a heading, it is a lie about what is here.
    if (!items.length) continue;
    items.forEach(item => claimed.add(item.route));
    groups.push({ solo: false, heading: group.heading, available: true,
                  grouped: true, after: group.after ?? null, items });
  }

  for (const [name, cap] of Object.entries(subsystems)) {
    const items = (cap.collections || [])
      .filter(coll => !claimed.has(`${name}/${coll}`))
      .map(coll => ({ sub: name, coll, label: coll, route: `${name}/${coll}` }));
    // A subsystem whose collections were all promoted or grouped has nothing
    // left to head. An unavailable one still shows, carrying its reason.
    if (!items.length && cap.available) continue;
    sections.push({ solo: false, heading: name, available: !!cap.available,
                    reason: cap.reason, items });
  }

  // Splice each group in after the section it names. An unplaceable group goes
  // last rather than vanishing: its collections must stay reachable even if the
  // subsystem it wanted to follow is absent from this host.
  for (const group of groups) {
    const at = group.after
      ? sections.findIndex(section => section.heading === group.after)
      : -1;
    if (at === -1) sections.push(group);
    else sections.splice(at + 1, 0, group);
  }
  return sections;
}

function renderNav() {
  const nav = $("nav");
  nav.textContent = "";
  for (const section of navModel()) {
    const box = el("div", "nav-sub"
      + (section.solo ? " nav-solo" : "")
      + (section.available ? "" : " unavailable"));
    if (section.heading) {
      const label = el("div", "sub-label", section.heading);
      if (!section.available) label.title = section.reason || "unavailable";
      box.appendChild(label);
    }
    for (const item of section.items) {
      const link = el("a", "nav-item", item.label);
      link.href = hashFor(item.sub, item.coll);
      link.dataset.route = item.route;
      box.appendChild(link);
    }
    nav.appendChild(box);
  }
  applyNavBadges();
}

/* ── status badges ───────────────────────────────────────── */

/* The nav's attention layer (ROADMAP slice 1). Failures clear the badges
   rather than freeze them — a stale count is worse than none. */
async function refreshStatus() {
  const host = state.currentHost;
  let status = null;
  try { status = await api("/v1/status"); }
  catch { /* no roll-up (old agent, dead host) → no badges */ }
  if (host !== state.currentHost) return;   // host switched mid-flight
  state.status = status;
  applyNavBadges();
}

/* Applied onto the built nav rather than rebuilding it: warn+critical row
   counts on the collection link, a dot on the subsystem label. worst:null
   with a reason is silence by design (the roll-up is nullable); a failed
   roll-up is a muted "!" carrying the error as its title. */
function applyNavBadges() {
  const subsystems = state.status?.subsystems || {};
  for (const box of document.querySelectorAll("#nav .nav-sub")) {
    let subLevel = null;
    let visible = 0;
    for (const link of box.querySelectorAll(".nav-item")) {
      link.querySelector(".nav-badge")?.remove();
      const [sub, coll] = link.dataset.route.split("/");
      const entry = subsystems[sub]?.[coll];
      // A collection that observed fine and found nothing (total 0, no
      // verdict, no decline reason) has nothing to navigate to — hide it
      // until an object exists (a host with no md arrays never shows
      // "arrays"). The current route stays visible so deep links and the
      // open view never lose their nav anchor; declined and unavailable
      // entries keep their row — absence of data and inability to look
      // are different statements.
      const empty = entry && entry.total === 0 && entry.worst === null
        && !entry.reason && !entry.error;
      link.hidden = !!empty && link.dataset.route !== `${state.subsystem}/${state.collection}`;
      if (!link.hidden) visible++;
      if (!entry) continue;
      if (entry.error) {
        const badge = el("span", "nav-badge err", "!");
        badge.title = entry.error;
        link.appendChild(badge);
      } else if (entry.counts) {
        const crit = entry.counts.critical || 0;
        const warn = entry.counts.warn || 0;
        if (!crit && !warn) continue;
        const badge = el("span", `nav-badge ${crit ? "critical" : "warn"}`, String(crit + warn));
        badge.title = [crit && `${crit} critical`, warn && `${warn} warn`].filter(Boolean).join(", ");
        link.appendChild(badge);
        subLevel = crit ? "critical" : subLevel ?? "warn";
      }
    }
    // A subsystem whose every collection is hidden-empty disappears with
    // them (an all-empty group label would navigate to nothing).
    box.hidden = visible === 0;
    // Optional, because a promoted section (.nav-solo, the overview) is a
    // .nav-sub with no heading to hang a dot on. Dereferencing this
    // unconditionally is what blanked the whole page when that section was
    // added: the TypeError killed renderNav, which killed loadHost, so route()
    // never ran and the content area was never populated at all.
    const label = box.querySelector(".sub-label");
    if (!label) continue;
    label.querySelector(".dot")?.remove();
    if (subLevel) label.appendChild(el("span", `dot ${subLevel}`));
  }
}

/* ── routing ─────────────────────────────────────────────── */

function defaultRoute() {
  // Landing view: the host overview when this host serves one — a degraded
  // object is visible without knowing which collection to open (ROADMAP
  // slice 1). Agents predating overview land on units as before.
  const system = state.capabilities?.subsystems?.system;
  return system?.available && (system.collections || []).includes("overview")
    ? ["system", "overview"] : ["units", "units"];
}

function route() {
  let parts = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  if (state.hub) {
    if (!knownHost(parts[0])) {
      // Deep-link migration (ROADMAP slice 1): a hash whose first segment is
      // no known host is a legacy single-agent link; give it a host once and
      // keep the rest verbatim.
      history.replaceState(null, "", "#/" + [state.currentHost, ...parts].join("/"));
      parts = [state.currentHost, ...parts];
    }
    const host = parts.shift();
    if (host !== state.currentHost) { switchHost(host, parts); return; }
  }
  const [defSub, defColl] = defaultRoute();
  const subsystem = parts[0] || defSub;
  const collection = parts[1] ||
    (parts[0] ? state.capabilities?.subsystems?.[subsystem]?.collections?.[0] ?? "units" : defColl);
  let objectId = parts.length > 2 ? safeDecode(parts.slice(2).join("/")) : null;
  if (subsystem === "system" && collection === "overview" && objectId) {
    // The overview is a designed panel, not a row expansion; its single
    // object adds nothing a deep link needs. Normalise old object links.
    objectId = null;
    history.replaceState(null, "", hashFor("system", "overview"));
  }

  const changedCollection = subsystem !== state.subsystem || collection !== state.collection;
  state.subsystem = subsystem;
  state.collection = collection;

  document.querySelectorAll(".nav-item").forEach(a =>
    a.classList.toggle("active", a.dataset.route === `${subsystem}/${collection}`));

  if (changedCollection) {
    state.epoch++;
    Object.assign(state, { sortKey: null, filterText: "", facet: null,
                           selectedId: null, detailObs: null, evidence: null,
                           suppressAutoOpen: false, page: null, lookupDraft: null,
                           showHidden: false, colPicker: false, owners: null });
    $("filter").value = "";
    // The facet bar describes a collection's rows; on a route change the
    // old chips are stale immediately — clear now, not when the new data
    // lands (they used to linger over the overview until touched).
    renderFacets();
    loadCollection(objectId);
    armAutoRefresh();
  } else if (objectId && objectId !== state.selectedId) {
    openDetail(objectId);
  } else if (!objectId && state.selectedId) {
    collapseDetail();
  }
}

/* The host changed under the route. Rebuild the host-scoped chrome, then
   re-route: the subsystem/collection carries over when the new host serves
   it, else falls back to that host's default. */
async function switchHost(host, rest) {
  state.currentHost = host;
  clearInterval(state.refreshTimer);   // no polls of the old route mid-switch
  const ok = await loadHost();
  if (state.currentHost !== host) return;   // switched again while loading
  if (!ok) {
    // Unreachable host: the banner (set by loadHost) plus an emptied grid;
    // the select still lists it, so recovery is one change event away.
    Object.assign(state, { page: null, selectedId: null, detailObs: null,
                           evidence: null, observedAt: null,
                           subsystem: rest[0] || null,
                           collection: rest[1] || null });
    $("grid-head").textContent = ""; $("grid-body").textContent = "";
    $("grid-empty").hidden = true;
    $("overview").hidden = true; $("collection-pane").hidden = false;
    renderCrumb(); renderFacets();
    return;
  }
  const cols = state.capabilities.subsystems[rest[0]]?.collections || [];
  if (!rest[0] || !(rest[1] ? cols.includes(rest[1]) : cols.length)) {
    history.replaceState(null, "", hashFor(...defaultRoute()));
  }
  state.subsystem = null;                   // force a reload on the new host
  state.collection = null;
  route();
}

function hashFor(subsystem, collection, objectId) {
  const path = objectId
    ? `${subsystem}/${collection}/${idPath(objectId)}`
    : `${subsystem}/${collection}`;
  return state.hub ? `#/${state.currentHost}/${path}` : `#/${path}`;
}

function goTo(subsystem, collection, objectId, { replace = false } = {}) {
  const hash = hashFor(subsystem, collection, objectId);
  if (location.hash === hash) return route();
  if (replace) {
    history.replaceState(null, "", hash);
    route();
  } else {
    location.hash = hash;
  }
}

function stripObjectFromHash() {
  history.replaceState(null, "", hashFor(state.subsystem, state.collection));
}

/* ── collection view ─────────────────────────────────────── */

const PAGE_LIMIT = 500;
const MAX_ROWS = 2000;   // client-side ceiling; the crumb says when it's hit

async function loadCollection(deepLinkId = null) {
  if (state.subsystem === "system" && state.collection === "overview")
    return loadOverview();
  $("overview").hidden = true;
  $("collection-pane").hidden = false;
  const { subsystem, collection, epoch } = state;
  $("refresh").classList.add("spin");
  let page;
  try {
    page = await api(`/v1/${subsystem}/${collection}?limit=${PAGE_LIMIT}`);
    // Follow the server's explicit cursor so filtering and facets see the
    // whole collection, not just the first page — bounded, because the
    // journal's history is effectively endless.
    while (page.next_cursor && page.items.length < MAX_ROWS && epoch === state.epoch) {
      const more = await api(`/v1/${subsystem}/${collection}?limit=${PAGE_LIMIT}` +
                             `&cursor=${encodeURIComponent(page.next_cursor)}`);
      page.items = page.items.concat(more.items);
      page.next_cursor = more.next_cursor;
      if (!more.items.length) break;
    }
  } catch (err) {
    if (epoch === state.epoch) {
      banner(`Failed to load ${subsystem}/${collection}: ${err.message}`);
      state.page = null;
      renderCrumb(); renderFacets(); renderGrid();
    }
    $("refresh").classList.remove("spin");
    return;
  }
  $("refresh").classList.remove("spin");
  if (epoch !== state.epoch) return;   // user navigated away; stale response

  state.page = page;
  state.observedAt = page.observed_at;
  banner(page.status !== "ok" ? (page.errors || []).join("; ") : null);
  renderCrumb();
  renderFacets();
  renderGrid();

  // Attribution lands after the rows, never before them: it costs an extra
  // request or two, and a list that is slower to appear would be a bad trade
  // for a label. Re-renders in place when it arrives.
  loadOwners().then((owners) => {
    if (epoch !== state.epoch || !owners) return;
    state.owners = owners;
    renderGrid();
  });

  if (deepLinkId) {
    openDetail(deepLinkId);
  } else if (state.selectedId && state.detailObs) {
    // Keep an open expansion current with the rows around it — except a
    // lookup result, which runs only when asked, never on the poll.
    if (!(state.selectedId.startsWith("lookup:") && state.selectedId.includes("/")))
      openDetail(state.selectedId, { quiet: true });
  } else if (!state.selectedId && !state.suppressAutoOpen
             && page.items.length === 1 && page.total === 1) {
    openDetail(page.items[0].id, { quiet: true });
  }
}

/* Why a collection has no rows. "Collection is empty." was the whole message,
   which conflated the three things the API is careful to distinguish (SPEC §2
   rule 7): declined with a reason, acquisition failed, and observed fine with
   nothing there. The agent has said honest absence at three scales for a while;
   the browser had no rendering for any of them, so an operator who landed on an
   empty page could not tell a host with no md arrays from a broken adapter. */
function emptyMessage() {
  if (state.filterText || state.facet) return "Nothing matches the filter.";
  const page = state.page;
  const entry = state.status?.subsystems?.[state.subsystem]?.[state.collection];
  const sub = state.capabilities?.subsystems?.[state.subsystem];
  // A whole unavailable subsystem is the strongest statement available.
  if (sub && sub.available === false && sub.reason)
    return `${state.subsystem} is unavailable on this host: ${sub.reason}`;
  // Then the collection's own decline, which the roll-up and the error envelope
  // both carry — prefer whichever answered.
  const declined = entry?.reason
    || (page?.status === "error" ? (page.errors || []).join("; ") : null);
  if (declined) return `Not collected on this host: ${declined}`;
  if (entry?.error) return `Acquisition failed: ${entry.error}`;
  return `No ${state.collection} exist on this host. `
       + "The agent looked and found none — this is an answer, not a gap.";
}

/* ── workload attribution ────────────────────────────────────────────
   The kernel names virtual plumbing after itself, never after what runs on
   it: vnet4, br-ae307a67bed8, veth960eb05, docker-59286b95….scope. That cost
   a real diagnosis — per-unit PSI correctly identified the scope stalling
   silo on I/O and the operator could not tell it was syncthing.

   Only the owning subsystem can name these, so each publishes its half as a
   fact (vms: HostTaps; docker: BridgeInterface and ContainerID; units:
   ContainerID and MachineName) and this joins them for the list view. The
   same edges exist as relationships for MCP consumers, so this is a
   projection of the graph rather than a second source of truth.

   Every source is capability-guarded and every failure is silent: a missing
   label is a worse list, a broken list is a broken page. */

async function loadOwners() {
  const route = `${state.subsystem}/${state.collection}`;
  const subs = state.capabilities?.subsystems || {};
  const has = (s, c) => subs[s]?.available && (subs[s].collections || []).includes(c);
  const rows = state.page?.items || [];
  const owners = {};
  try {
    if (route === "network/links") {
      const [doms, nets] = await Promise.all([
        has("vms", "domains") ? api("/v1/vms/domains?limit=200") : null,
        has("docker", "networks") ? api("/v1/docker/networks?limit=200") : null,
      ]);
      // A tap belongs to exactly one domain — the strongest attribution here.
      for (const d of doms?.items || [])
        for (const tap of d.facts.HostTaps || [])
          owners[tap] = { parts: [{ label: d.native_id,
                                    href: hashFor("vms", "domains", d.id) }] };
      // A bridge is named by its network and nothing else. It used to carry
      // the compose project too ("proxy · arr"), which read as two unlabelled
      // words with no way to tell which was which and only one of them
      // clickable. The project is a column on docker/networks instead.
      const byBridge = {};
      for (const n of nets?.items || []) {
        const bridge = n.facts.BridgeInterface;
        if (!bridge) continue;
        byBridge[bridge] = { label: n.native_id, id: n.id };
        owners[bridge] = { parts: [{ label: n.native_id,
                                     href: hashFor("docker", "networks", n.id) }] };
      }
      // veth: name the container, not just the network. The interface itself
      // gives nothing away — libnetwork names it randomly and it wears its own
      // MAC — but the bridge learns the CONTAINER's MAC on this port, and
      // Docker reports that same MAC per attachment. Only the network inspect
      // payload has it, so those are fetched per bridge-backed network (three
      // on a real host, not one per container).
      const bridgesInUse = new Set(rows.filter(r => r.facts.Kind === "veth")
                                       .map(r => r.facts.Master));
      const containerByMac = {};
      const inspected = await Promise.all(
        [...bridgesInUse].filter(b => byBridge[b]).map(b =>
          api(`/v1/docker/networks/${encodeURIComponent(byBridge[b].id)}`)
            .catch(() => null)));
      for (const obs of inspected)
        for (const ep of obs?.facts?.ContainerEndpoints || [])
          if (ep.MACAddress) containerByMac[ep.MACAddress.toLowerCase()] = ep.Name;
      for (const item of rows) {
        if (item.facts.Kind !== "veth") continue;
        const via = byBridge[item.facts.Master];
        if (!via) continue;
        const net = { label: via.label, href: hashFor("docker", "networks", via.id) };
        const name = (item.facts.PeerMACAddresses || [])
          .map(m => containerByMac[String(m).toLowerCase()]).find(Boolean);
        if (name) {
          owners[item.native_id] = { parts: [net, {
            label: name,
            href: hashFor("docker", "containers", `container:${name}`),
          }] };
        } else {
          // The forwarding table is LEARNED and ages out, so a container that
          // has sent nothing recently has no entry. That is silence, not
          // evidence — so this names the network and hedges rather than
          // guessing which of its containers is behind the port.
          owners[item.native_id] = { parts: [net], hedge: true };
        }
      }
    } else if (route === "units/units") {
      const containers = has("docker", "containers")
        ? await api("/v1/docker/containers?limit=500") : null;
      const byId = {};
      for (const c of containers?.items || [])
        if (c.facts.ContainerID) byId[c.facts.ContainerID] = c;
      for (const item of rows) {
        const container = byId[item.facts.ContainerID];
        if (container) {
          owners[item.native_id] = { parts: [{
            label: container.native_id,
            href: hashFor("docker", "containers", container.id),
          }] };
        } else if (item.facts.MachineName) {
          // The unit's own name proves this one, so it is labelled whether or
          // not the vms subsystem is reachable; only the link needs vms.
          owners[item.native_id] = { parts: [{
            label: item.facts.MachineName,
            href: has("vms", "domains")
              ? hashFor("vms", "domains", `domain:${item.facts.MachineName}`) : null,
          }] };
        }
      }
    }
  } catch {
    return null;
  }
  return owners;
}

/* ── host overview: a designed panel, not the generic grid ──
   One meter per resource area. Meter severity comes from the agent's own
   opinions on the overview object (shared rulebook, SPEC rule 14) — the UI
   holds scales, never thresholds. */

const OPINION_METER = {
  // load-pressure is gone (retired in favour of psi-cpu, which measures the
  // same thing directly); psi-cpu now colours the CPU panel it replaced.
  "memory-available": "mem", "swap-pressure": "swap",
  "psi-cpu": "cpu", "psi-memory": "psi-memory", "psi-io": "psi-io",
};

/* How many samples the sparklines hold. The browser accumulates these across
   its own polls: the agent ships counters and holds no history (SPEC rules
   4/10), and the 15-minute snapshot store is far too coarse to draw with. So
   this is deliberately session-local and the panel states its window — a graph
   that silently resets on reload is only dishonest if it pretends otherwise. */
const SPARK_SAMPLES = 40;

/* A bar sparkline. Ordinary spans rather than SVG or canvas: the UI builds all
   DOM through textContent (conformance lints for HTML sinks) and forty divs is
   cheaper than either. Values are 0..100. */
function sparkline(values, cls) {
  const wrap = el("div", `spark${cls ? " " + cls : ""}`);
  for (const value of values) {
    const bar = el("span", "sb");
    // A floor of 2% so a real zero still draws a mark: an empty gap reads as
    // "no data", which is a different statement from "nothing happening".
    bar.style.height = `${Math.max(2, Math.min(100, value))}%`;
    wrap.appendChild(bar);
  }
  return wrap;
}

/* What a sparkline actually covers, said out loud. A chart whose x-axis is
   "however often this tab happened to poll" is fine; one that leaves the
   reader to assume a fixed interval is not. */
function sparkWindow(dt) {
  const n = state.ovHistory?.length || 0;
  if (!dt || n < 2) return "collecting samples";
  const span = Math.round(dt * (n - 1));
  return `last ${span < 90 ? `${span}s` : `${Math.round(span / 60)}m`} `
       + `· ${n} samples this session`;
}

/* Busy share of an interval from cumulative CPU tick counters, plus the part of
   it that was only waiting for a disk. Derived here because the agent ships
   counters, so the window is the one this page actually observed. */
function cpuBusy(now, prev) {
  if (!now || !prev) return null;
  const total = (t) => Object.values(t).reduce((sum, v) => sum + v, 0);
  const dTotal = total(now) - total(prev);
  if (dTotal <= 0) return null;
  const dIdle = (now.Idle - prev.Idle) + ((now.Iowait || 0) - (prev.Iowait || 0));
  const dIowait = (now.Iowait || 0) - (prev.Iowait || 0);
  return {
    // Iowait counts as NOT busy: a core waiting on a disk is available, and
    // folding it into utilisation is how a storage problem gets misread as a
    // CPU one. It is reported separately instead.
    busy: Math.max(0, Math.min(100, Math.round((dTotal - dIdle) * 100 / dTotal))),
    iowait: Math.max(0, Math.min(100, Math.round(dIowait * 100 / dTotal))),
  };
}

async function loadOverview() {
  const { epoch } = state;
  $("refresh").classList.add("spin");
  // The overview composes from the same public collections everything else
  // reads (two consumers, one contract) — each ask is capability-guarded
  // and individually allowed to fail; a missing source is an absent
  // section, never a broken page.
  const subs = state.capabilities?.subsystems || {};
  const has = (s, c) => subs[s]?.available && (subs[s].collections || []).includes(c);
  const asks = { obs: api("/v1/system/overview/overview:host") };
  if (has("network", "links")) asks.links = api("/v1/network/links?limit=100");
  if (has("storage", "mounts")) asks.mounts = api("/v1/storage/mounts?limit=100");
  if (has("storage", "pools")) asks.pools = api("/v1/storage/pools?limit=100");
  if (has("docker", "containers")) {
    asks.crun = api("/v1/docker/containers?State=running&limit=1");
    asks.call = api("/v1/docker/containers?limit=1");
  }
  if (has("vms", "domains")) {
    asks.vrun = api("/v1/vms/domains?State=running&limit=1");
    asks.vall = api("/v1/vms/domains?limit=1");
  }
  if (has("units", "units")) asks.ufail = api("/v1/units/units?ActiveState=failed&limit=1");
  // The stalled-unit list beside the pressure meter. Cheap because the PSI
  // numbers already ride on the row (that was the point of putting them there),
  // so this is one page of units rather than a walk of every object.
  if (has("units", "units")) asks.stalled = api("/v1/units/units?limit=800");
  if (has("system", "identity") && state.ovIdentity?.host !== state.currentHost)
    asks.identity = api("/v1/system/identity");
  const keys = Object.keys(asks);
  const settled = await Promise.allSettled(Object.values(asks));
  $("refresh").classList.remove("spin");
  if (epoch !== state.epoch) return;
  const got = {};
  keys.forEach((k, i) => { if (settled[i].status === "fulfilled") got[k] = settled[i].value; });
  if (!got.obs) {
    banner(`Failed to load overview: ${settled[0].reason?.message || "unreachable"}`);
    return;
  }
  if (got.identity?.items?.length)
    state.ovIdentity = { host: state.currentHost, facts: got.identity.items[0].facts };
  const obs = got.obs;
  state.page = { items: [], total: 1, observed_at: obs.observed_at,
                 status: obs.status, next_cursor: null };
  state.observedAt = obs.observed_at;
  banner(obs.status !== "ok" ? (obs.errors || []).join("; ") : null);
  renderCrumb();
  $("facets").hidden = true;
  $("collection-pane").hidden = true;
  $("overview").hidden = false;
  renderOverview(obs, got);
}

function meter(pct, cls, ticks = [], segments = null) {
  const m = el("div", `meter${cls ? " " + cls : ""}`);
  for (const at of ticks) {
    const t = el("span", "tick");
    t.style.left = `${at}%`;
    m.appendChild(t);
  }
  const clamp = (v) => `${Math.max(0, Math.min(100, v))}%`;
  if (segments) {
    for (const seg of segments) {
      const s = el("span", `seg${seg.aux ? " aux" : ""}`);
      s.style.width = clamp(seg.pct);
      if (seg.title) s.title = seg.title;
      m.appendChild(s);
    }
  } else {
    const s = el("span", "seg");
    s.style.width = clamp(pct);
    m.appendChild(s);
  }
  return m;
}

function ovRow(label, meterNode, value, side) {
  const row = el("div", "ov-row");
  row.appendChild(el("span", "lbl", label));
  if (side !== undefined) row.appendChild(el("span", "side", side));
  row.appendChild(meterNode);
  row.appendChild(el("span", "val", value));
  return row;
}

function ovKpi(parent, label, value, { href = null, level = null } = {}) {
  const kpi = href ? el("a", "ov-kpi") : el("span", "ov-kpi");
  if (href) kpi.href = href;
  kpi.appendChild(el("span", "k", label));
  kpi.appendChild(el("span", `v${level ? " " + level : ""}`, value));
  parent.appendChild(kpi);
}

function hostAddresses(links) {
  // Global addresses of up links, IPv4 first — the ones an operator dials.
  // Container-plumbing gateways (docker0, compose's br-<hex>) are addresses
  // nobody dials the host by; the links collection still lists them.
  const v4 = [], v6 = [];
  for (const item of links?.items || []) {
    if (item.facts.OperState !== "up") continue;
    if (/^(docker0|br-[0-9a-f]{12})$/.test(item.native_id)) continue;
    for (const cidr of item.facts.Addresses || []) {
      const addr = String(cidr).split("/")[0];
      if (addr.startsWith("127.") || addr === "::1" || addr.startsWith("fe80")) continue;
      (addr.includes(":") ? v6 : v4).push(addr);
    }
  }
  return [...new Set([...v4, ...v6])];
}

function renderOverview(obs, got = {}) {
  const root = $("overview");
  root.textContent = "";
  const f = obs.facts || {};
  const levels = {};
  for (const op of obs.opinions || []) {
    const target = OPINION_METER[op.key];
    if (target) levels[target] = op.level === "critical" ? "critical" : "warn";
  }

  // Counter sampling, hoisted here because CPU utilisation needs it as much as
  // the I/O rates do: the agent ships cumulative counters and holds no previous
  // sample (SPEC rules 4/10), so every derived rate on this page is a delta
  // across this page's own polls, over a window it can state.
  const now = Date.parse(obs.observed_at);
  const prev = state.ovPrev?.host === state.currentHost ? state.ovPrev : null;
  const dt = prev ? (now - prev.t) / 1000 : 0;
  const cpuNow = cpuBusy(f.CpuTimes, prev?.cpu);

  // The sparkline ring, session-local by construction. Reset with the host, so
  // one host's history can never be drawn under another's name.
  if (state.ovHistoryHost !== state.currentHost) {
    state.ovHistory = [];
    state.ovHistoryHost = state.currentHost;
  }
  const history = state.ovHistory;
  // Memory excludes the ARC for the same reason the verdict does: cache that
  // yields under demand is occupancy, not consumption.
  const memPct = f.MemTotalBytes
    ? Math.round(Math.max(0, (f.MemUsedBytes || 0) - (f.ArcSizeBytes || 0))
                 * 100 / f.MemTotalBytes)
    : null;
  if (cpuNow || memPct !== null) {
    history.push({ cpu: cpuNow?.busy ?? null, mem: memPct });
    while (history.length > SPARK_SAMPLES) history.shift();
  }

  // Key-info line: identity, addresses, workload counts — every value a
  // door into the collection that backs it.
  const kpis = el("div", "ov-kpis");
  const ident = state.ovIdentity?.host === state.currentHost ? state.ovIdentity.facts : null;
  if (ident) {
    ovKpi(kpis, "os", ident.OperatingSystemPrettyName || "?",
          { href: hashFor("system", "identity") });
    ovKpi(kpis, "kernel", ident.KernelRelease || "?", { href: hashFor("system", "identity") });
  }
  const addrs = hostAddresses(got.links);
  if (addrs.length)
    ovKpi(kpis, "ip", addrs.slice(0, 3).join("  "), { href: hashFor("network", "links") });
  if (got.call?.total !== undefined)
    ovKpi(kpis, "containers", `${got.crun?.total ?? "?"}/${got.call.total} running`,
          { href: hashFor("docker", "containers") });
  if (got.vall?.total !== undefined)
    ovKpi(kpis, "vms", `${got.vrun?.total ?? "?"}/${got.vall.total} running`,
          { href: hashFor("vms", "domains") });
  if (got.ufail?.total !== undefined)
    ovKpi(kpis, "failed units", String(got.ufail.total),
          { href: hashFor("units", "units"),
            level: got.ufail.total ? "critical" : null });
  if (kpis.childNodes.length) root.appendChild(kpis);

  // Attention strip: the /v1/status roll-up the nav badges already fetch —
  // what needs looking at, before any resource detail.
  const attention = [];
  for (const [sub, colls] of Object.entries(state.status?.subsystems || {})) {
    for (const [coll, v] of Object.entries(colls)) {
      if (v.worst !== "warn" && v.worst !== "critical") continue;
      const n = (v.counts?.critical || 0) + (v.counts?.warn || 0);
      attention.push({ sub, coll, worst: v.worst, n });
    }
  }
  if (attention.length) {
    const strip = el("div", "ov-attention");
    attention.sort((a, b) => (a.worst === b.worst ? 0 : a.worst === "critical" ? -1 : 1));
    for (const a of attention) {
      const chip = el("a", `ov-chip ${a.worst}`);
      chip.href = hashFor(a.sub, a.coll);
      chip.appendChild(el("span", "n", String(a.n)));
      chip.appendChild(el("span", null, `${a.sub}/${a.coll}`));
      strip.appendChild(chip);
    }
    root.appendChild(strip);
  }

  const grid = el("div", "ov-grid");

  // CPU: real utilisation, replacing the load-average panel. Load average
  // answered a different question badly — it counts uninterruptible sleep, so
  // a host merely waiting on a slow disk read as CPU-starved. The facts are
  // still on the object; nothing judges or charts them.
  if (f.CpuTimes) {
    const cpu = cpuNow;
    const p = el("div", "ov-panel");
    p.appendChild(el("h3", null, `CPU · ${f.CpuCount ?? "?"} cpus`));
    if (cpu) {
      p.appendChild(ovRow("busy", meter(cpu.busy, levels.cpu), `${cpu.busy}%`));
      // Shown as its own row, not folded into busy: a core waiting on a disk
      // is available, and lumping the two is how a storage problem gets read
      // as a CPU problem. Its scale is the same 0..100 so the eye can compare.
      p.appendChild(ovRow("io wait", meter(cpu.iowait, levels["psi-io"]),
                          `${cpu.iowait}%`));
      p.appendChild(sparkline(history.map(s => s.cpu ?? 0), "accent"));
      p.appendChild(el("div", "ov-sub", sparkWindow(dt)));
    } else {
      // First sample of a session has no previous counter to difference.
      p.appendChild(el("div", "ov-sub", "measuring — utilisation needs two samples"));
    }
    if (f.LoadAvg1 !== undefined)
      p.appendChild(el("div", "ov-sub",
        `load average ${f.LoadAvg1} / ${f.LoadAvg5} / ${f.LoadAvg15} `
        + "(1/5/15 min, unjudged — see io wait above)"));
    grid.appendChild(p);
  }

  // Memory: one stacked meter — the ARC rides as its own segment (it is
  // reclaimable cache wearing "used" clothes) and never takes severity.
  if (f.MemTotalBytes) {
    const p = el("div", "ov-panel");
    p.appendChild(el("h3", null, "Memory"));
    const arc = f.ArcSizeBytes || 0;
    const apps = Math.max(0, (f.MemUsedBytes || 0) - arc);
    const segs = [{ pct: apps * 100 / f.MemTotalBytes, title: "in use" }];
    if (arc) segs.push({ pct: arc * 100 / f.MemTotalBytes, aux: true, title: "ZFS ARC (reclaimable)" });
    p.appendChild(ovRow("used", meter(null, levels.mem, [], segs),
                        `${f.MemUsedPercent}%`));
    const sub = el("div", "ov-sub");
    sub.append(el("span", "k", `${humanBytes(f.MemUsedBytes)} used`),
               ` of ${humanBytes(f.MemTotalBytes)} · ${humanBytes(f.MemAvailableBytes)} available`);
    if (arc) sub.append(` · ARC ${humanBytes(arc)}`);
    p.appendChild(sub);
    if (history.some(s => s.mem != null)) {
      // Excludes the ARC, for the same reason the verdict does: charting
      // occupancy that yields under demand would draw a cliff that is not one.
      p.appendChild(sparkline(history.map(s => s.mem ?? 0)));
      p.appendChild(el("div", "ov-sub", sparkWindow(dt) + " · excludes ZFS ARC"));
    }
    if (f.SwapTotalBytes) {
      p.appendChild(ovRow("swap", meter((f.SwapUsedPercent ?? 0), levels.swap),
                          `${f.SwapUsedPercent ?? 0}%`));
      p.appendChild(el("div", "ov-sub",
        `${humanBytes(f.SwapUsedBytes)} of ${humanBytes(f.SwapTotalBytes)} swap`));
    } else if (f.SwapTotalBytes === 0) {
      p.appendChild(el("div", "ov-sub", "no swap configured"));
    }
    grid.appendChild(p);
  }

  // Pressure: the kernel's own stall shares. The meter carries the share
  // the rulebook judges (cpu some / memory full / io full) over the last
  // minute; the flanks give the 10s and 5m readings of the same share.
  const psi = [
    ["cpu", f.PsiCpuSomeAvg60, f.PsiCpuSomeAvg10, f.PsiCpuSomeAvg300, "psi-cpu"],
    ["memory", f.PsiMemoryFullAvg60, f.PsiMemoryFullAvg10, f.PsiMemoryFullAvg300, "psi-memory"],
    ["io", f.PsiIoFullAvg60, f.PsiIoFullAvg10, f.PsiIoFullAvg300, "psi-io"],
  ].filter(([, v]) => v !== undefined);
  if (psi.length) {
    const p = el("div", "ov-panel");
    p.appendChild(el("h3", null, "Pressure · stall share, 60s"));
    for (const [name, v60, v10, v300, key] of psi)
      p.appendChild(ovRow(name, meter(v60, levels[key]), `${v60}%`, `${v10}%`));
    p.appendChild(el("div", "ov-sub",
      "left flank: 10s · meter and value: 60s (what the rules judge)"));
    grid.appendChild(p);
  }

  // I/O: the agent ships cumulative counters (it holds no previous sample —
  // SPEC rules 4/10); the rates here are deltas across this page's own
  // polls, and the window is stated rather than implied. First sample
  // honestly reads "measuring".
  const rate = (cur, old) => (dt > 0 && cur >= old ? (cur - old) / dt : null);
  const perSec = (v) => v === null ? "—" : `${humanBytes(Math.round(v))}/s`;
  if (f.NetCounters || f.DiskCounters) {
    const p = el("div", "ov-panel");
    p.appendChild(el("h3", null, dt > 0 ? `I/O · over the last ${Math.round(dt)}s` : "I/O · measuring"));
    const io = el("div", "ov-io-grid");
    const ioRow = (name, verbA, a, verbB, b) => {
      io.appendChild(el("span", "io-name", name));
      io.appendChild(el("span", "io-verb", verbA));
      io.appendChild(el("span", "io-val", perSec(a)));
      io.appendChild(el("span", "io-verb", verbB));
      io.appendChild(el("span", "io-val", perSec(b)));
    };
    const rows = [];
    for (const [name, c] of Object.entries(f.NetCounters || {})) {
      if (name === "lo") continue;
      const rx = rate(c.RxBytes, prev?.net?.[name]?.RxBytes ?? Infinity);
      const tx = rate(c.TxBytes, prev?.net?.[name]?.TxBytes ?? Infinity);
      rows.push({ name, a: rx, b: tx, sum: (rx || 0) + (tx || 0) });
    }
    rows.sort((x, y) => y.sum - x.sum);
    if (rows.length) io.appendChild(el("span", "io-head", "network"));
    for (const r of rows.slice(0, 3)) ioRow(r.name, "rx", r.a, "tx", r.b);
    const drows = [];
    for (const [name, c] of Object.entries(f.DiskCounters || {})) {
      const rd = rate(c.ReadBytes, prev?.disk?.[name]?.ReadBytes ?? Infinity);
      const wr = rate(c.WriteBytes, prev?.disk?.[name]?.WriteBytes ?? Infinity);
      // Busy share of the window, from the kernel's ms-doing-I/O counter. This
      // is the number the panel was missing: throughput cannot tell a saturated
      // disk from an idle one, because a small-random workload saturates a
      // device at a rate a sequential one would call nothing. Host PSI said
      // "stalled on I/O 55% of the last minute" while every device showed a few
      // hundred KiB/s, and there was nowhere to go next.
      const busyMs = rate(c.IoTicksMs, prev?.disk?.[name]?.IoTicksMs ?? Infinity);
      const busy = busyMs === null ? null
        : Math.max(0, Math.min(100, Math.round(busyMs / 10)));   // ms/s → %
      drows.push({ name, a: rd, b: wr, busy, sum: (rd || 0) + (wr || 0) });
    }
    // Sorted by BUSY, not by bytes: the point of having utilisation is that it
    // ranks differently from throughput, and the saturated device is the one
    // worth putting first.
    drows.sort((x, y) => (y.busy ?? -1) - (x.busy ?? -1) || y.sum - x.sum);
    if (drows.length) io.appendChild(el("span", "io-head", "disk"));
    for (const r of drows.slice(0, 4)) {
      ioRow(r.name, "read", r.a, "write", r.b);
      if (r.busy !== null) {
        io.appendChild(el("span", "io-name dim", ""));
        io.appendChild(el("span", "io-verb", "busy"));
        const cell = el("span", "io-val io-busy");
        cell.appendChild(meter(r.busy, r.busy >= 90 ? "warn" : null));
        cell.appendChild(el("span", "mono", `${r.busy}%`));
        io.appendChild(cell);
        io.appendChild(el("span", "io-verb", ""));
        io.appendChild(el("span", "io-val", ""));
      }
    }
    p.appendChild(io);
    grid.appendChild(p);
  }

  // Which units are stalling, beside the pressure that says the host is. This
  // is the other half of the I/O diagnosis the per-unit PSI work owed: the
  // attribution existed on the rows of units/units, but an operator staring at
  // a host pressure meter had to know to go looking for it.
  if (got.stalled?.items?.length) {
    const p = el("div", "ov-panel");
    p.appendChild(el("h3", null, "Stalling most · unit, 60s"));
    const worst = [...got.stalled.items]
      .filter(u => (u.facts.PsiIoFullAvg60 ?? 0) > 0)
      .sort((a, b) => (b.facts.PsiIoFullAvg60 ?? 0) - (a.facts.PsiIoFullAvg60 ?? 0))
      .slice(0, 5);
    if (!worst.length) {
      p.appendChild(el("div", "ov-sub", "no unit reports an I/O stall"));
    } else {
      for (const u of worst) {
        const share = u.facts.PsiIoFullAvg60;
        const row = el("div", "ov-row");
        const lbl = el("a", "lbl wide", u.native_id);
        lbl.href = hashFor("units", "units", u.id);
        lbl.title = u.native_id;
        row.appendChild(lbl);
        row.appendChild(meter(share, share >= 20 ? "warn" : null));
        row.appendChild(el("span", "val", `${share}%`));
        p.appendChild(row);
      }
      p.appendChild(el("div", "ov-sub",
        "share of the minute in which every task in the unit that had work to "
        + "do was waiting on I/O"));
    }
    grid.appendChild(p);
  }
  state.ovPrev = { host: state.currentHost, t: now, cpu: f.CpuTimes,
                   net: f.NetCounters, disk: f.DiskCounters };

  // Storage: pools and the biggest real filesystems — rows wear the same
  // rule-driven severity their collections carry; nothing is re-judged here.
  if (got.pools?.items?.length || got.mounts?.items?.length) {
    const p = el("div", "ov-panel");
    p.appendChild(el("h3", null, "Storage"));
    for (const item of got.pools?.items || []) {
      const cap = item.facts.CapacityPercent;
      // A pool's worst level can come from any of its rules (a stale scrub,
      // vdev errors), so it must not colour the capacity meter — a warm bar
      // at 54% would read as a fullness problem. The dot carries overall
      // severity; the meter stays a magnitude.
      const lvl = item.worst_opinion_level;
      const row = el("div", "ov-row");
      const lbl = el("a", "lbl wide", item.native_id);
      lbl.href = hashFor("storage", "pools", item.id);
      row.appendChild(lbl);
      if (["warn", "critical"].includes(lvl)) row.appendChild(el("span", `dot ${lvl}`));
      row.appendChild(meter(cap ?? 0, null));
      row.appendChild(el("span", "val",
        cap !== null && cap !== undefined ? `${cap}%` : "—"));
      p.appendChild(row);
      if (item.facts.SizeBytes)
        p.appendChild(el("div", "ov-sub",
          `${humanBytes(item.facts.AllocatedBytes)} of ${humanBytes(item.facts.SizeBytes)} · pool ${item.facts.State}`));
    }
    const mounts = (got.mounts?.items || [])
      .filter(m => m.facts.SizeBytes && m.facts.UsePercent !== null)
      .sort((a, b) => (b.facts.SizeBytes || 0) - (a.facts.SizeBytes || 0));
    const seen = new Set();
    let shown = 0;
    for (const m of mounts) {
      if (seen.has(m.facts.Source) || shown >= 5) continue;
      seen.add(m.facts.Source); shown++;
      const lvl = ["warn", "critical"].includes(m.worst_opinion_level)
        ? (m.worst_opinion_level === "critical" ? "critical" : "warn") : null;
      const row = el("div", "ov-row");
      const lbl = el("a", "lbl wide", m.native_id);
      lbl.title = `${m.native_id} (${m.facts.Source})`;
      lbl.href = hashFor("storage", "mounts", m.id);
      row.appendChild(lbl);
      row.appendChild(meter(m.facts.UsePercent, lvl));
      row.appendChild(el("span", "val", `${m.facts.UsePercent}%`));
      p.appendChild(row);
    }
    if (mounts.length > shown) {
      const more = el("a", "ov-sub", `+ ${mounts.length - shown} more filesystems`);
      more.href = hashFor("storage", "mounts");
      more.style.display = "block";
      p.appendChild(more);
    }
    grid.appendChild(p);
  }

  root.appendChild(grid);

  const foot = el("div", "ov-foot");
  if (f.UptimeSeconds !== undefined)
    foot.append(el("span", "k", "up "), humanSeconds(f.UptimeSeconds));
  if (f.BootedAt) foot.append(el("span", "k", " · booted "), f.BootedAt);
  root.appendChild(foot);

  // Opinions verbatim, same rendering contract as the detail pane: the
  // meters above are these opinions' visual form, not a replacement.
  if ((obs.opinions || []).length) {
    const box = el("div", "ov-opinions");
    for (const op of obs.opinions)
      box.appendChild(el("div", `opinion ${op.level}`, `${op.key} — ${op.message}`));
    root.appendChild(box);
  }

  // Everything else the object carries, without leaving the designed view.
  const details = el("details", "ov-facts");
  details.appendChild(el("summary", null, "all facts"));
  const table = el("table");
  for (const [k, v] of Object.entries(f)) {
    const tr = el("tr");
    tr.appendChild(el("td", null, k));
    tr.appendChild(el("td", null, scalarText(k, v, true) ?? vstr(v)));
    table.appendChild(tr);
  }
  details.appendChild(table);
  root.appendChild(details);
}

function renderCrumb() {
  const crumb = $("crumb");
  crumb.textContent = "";
  crumb.append(el("b", null, state.subsystem || ""), " / ", state.collection || "");
  const p = state.page;
  if (p) {
    const shown = visibleItems().length;
    const total = p.total ?? p.items.length;
    crumb.appendChild(el("span", "count", shown === total ? `${total}` : `${shown} of ${total}`));
    if (p.next_cursor) crumb.appendChild(el("span", "count", `(first ${p.items.length} loaded; history continues)`));
  }
  $("age").textContent = state.observedAt ? `observed ${ageOf(state.observedAt)}` : "";
}

function renderFacets() {
  const bar = $("facets");
  const route = `${state.subsystem}/${state.collection}`;
  const facetOf = FACETS[route];
  const hidden = HIDDEN[route];
  // The overview is a designed panel with no rows to facet; its pseudo-page
  // must not resurrect the bar.
  bar.hidden = !state.page || route === "system/overview";
  bar.textContent = "";
  if (bar.hidden) return;
  // Facet counts describe what is on screen, so they respect the hide rule.
  const base = hidden && !state.showHidden
    ? state.page.items.filter(it => !hidden.match(it)) : state.page.items;
  if (facetOf) {
    const counts = new Map();
    for (const item of base) {
      const key = facetOf(item);
      if (key) counts.set(key, (counts.get(key) || 0) + 1);
    }
    const entries = [...counts.entries()].sort((a, b) => b[1] - a[1]);
    const all = el("button", "chip" + (state.facet ? "" : " on"), `all ${base.length}`);
    all.onclick = () => { state.facet = null; renderFacets(); renderGrid(); renderCrumb(); };
    bar.appendChild(all);
    for (const [key, count] of entries.slice(0, 14)) {
      const chip = el("button", "chip" + (state.facet === key ? " on" : ""));
      chip.append(key, el("span", "chip-n", String(count)));
      chip.onclick = () => {
        state.facet = state.facet === key ? null : key;
        renderFacets(); renderGrid(); renderCrumb();
      };
      bar.appendChild(chip);
    }
  }
  if (hidden) {
    const n = state.page.items.filter(hidden.match).length;
    if (n) {
      const chip = el("button", "chip ghost" + (state.showHidden ? " on" : ""));
      chip.append(`${state.showHidden ? "hide" : "show"} ${hidden.label}`,
                  el("span", "chip-n", String(n)));
      chip.onclick = () => {
        state.showHidden = !state.showHidden;
        renderFacets(); renderGrid(); renderCrumb();
      };
      bar.appendChild(chip);
    }
  }

  // Column picker: any fact key can be a column; choices stick per
  // collection (localStorage), so every identifier a disk carries is one
  // toggle away without bloating the defaults.
  const picker = el("button", "chip ghost" + (state.colPicker ? " on" : ""), "columns ▾");
  picker.onclick = () => { state.colPicker = !state.colPicker; renderFacets(); };
  bar.appendChild(picker);
  if (state.colPicker) {
    const menu = el("div", "col-menu");
    const current = new Set(columnsFor());
    const preset = baseColumnsFor(route);
    for (const key of allFactKeys()) {
      const opt = el("button", "col-opt" + (current.has(key) ? " on" : ""));
      opt.append(el("span", "tick", current.has(key) ? "✓" : NBSP), key);
      opt.onclick = () => {
        const prefs = colPrefs(route);
        if (current.has(key)) {
          if (preset.includes(key)) prefs.remove = [...(prefs.remove || []), key];
          prefs.add = (prefs.add || []).filter(k => k !== key);
        } else {
          prefs.remove = (prefs.remove || []).filter(k => k !== key);
          if (!preset.includes(key)) prefs.add = [...(prefs.add || []), key];
        }
        setColPrefs(route, prefs);
        renderFacets(); renderGrid();
      };
      menu.appendChild(opt);
    }
    bar.appendChild(menu);
  }
}

/* Column choices stick per collection: presets (or the first item's keys)
   are the base, and the picker's additions/removals live in localStorage.
   Keys stay route-scoped with no host segment, deliberately: a collection's
   fact vocabulary is the same on every host, so preferences travel. */
function colPrefs(route) {
  try { return JSON.parse(localStorage.getItem("se-cols:" + route)) || {}; }
  catch { return {}; }
}

function setColPrefs(route, prefs) {
  localStorage.setItem("se-cols:" + route, JSON.stringify(prefs));
}

function baseColumnsFor(route) {
  const preset = COLUMNS[route];
  if (preset) return preset;
  const first = state.page?.items?.[0];
  return first ? Object.keys(first.facts).slice(0, 5) : [];
}

function columnsFor() {
  const route = `${state.subsystem}/${state.collection}`;
  const prefs = colPrefs(route);
  const removed = new Set(prefs.remove || []);
  const cols = baseColumnsFor(route).filter(c => !removed.has(c));
  for (const extra of prefs.add || []) if (!cols.includes(extra)) cols.push(extra);
  return cols;
}

function allFactKeys() {
  const keys = new Set();
  for (const item of state.page?.items ?? []) {
    for (const k of Object.keys(item.facts)) keys.add(k);
  }
  return [...keys].sort();
}

function visibleItems() {
  let items = state.page?.items ?? [];
  const hidden = HIDDEN[`${state.subsystem}/${state.collection}`];
  if (hidden && !state.showHidden) items = items.filter(it => !hidden.match(it));
  const facetOf = FACETS[`${state.subsystem}/${state.collection}`];
  if (facetOf && state.facet) items = items.filter(it => facetOf(it) === state.facet);
  const q = state.filterText.toLowerCase();
  if (q) {
    items = items.filter(it =>
      it.id.toLowerCase().includes(q) ||
      Object.values(it.facts).some(v => v !== null && vstr(v).toLowerCase().includes(q)));
  }
  if (state.sortKey) {
    const k = state.sortKey, dir = state.sortDir;
    items = [...items].sort((a, b) => {
      const av = k === "id" ? a.id : a.facts[k];
      const bv = k === "id" ? b.id : b.facts[k];
      if (av === bv) return 0;
      if (av === null || av === undefined) return 1;
      if (bv === null || bv === undefined) return -1;
      return (typeof av === "number" && typeof bv === "number")
        ? (av - bv) * dir
        : naturalCompare(vstr(av), vstr(bv)) * dir;
    });
  }
  return items;
}

/* 2:0:10:0 belongs after 2:0:9:0 and slot 10 after slot 9 — digit runs
   compare as numbers, everything else as text. */
function naturalCompare(a, b) {
  const ax = String(a).split(/(\d+)/), bx = String(b).split(/(\d+)/);
  for (let i = 0; i < Math.max(ax.length, bx.length); i++) {
    const as = ax[i] ?? "", bs = bx[i] ?? "";
    if (as === bs) continue;
    if (/^\d+$/.test(as) && /^\d+$/.test(bs)) return Number(as) - Number(bs);
    return as.localeCompare(bs);
  }
  return 0;
}

let lookupHadFocus = false;

function renderGrid() {
  // Rebuilding the body destroys a focused lookup input; remember so the
  // rebuilt form can restore focus (its text survives in state.lookupDraft).
  lookupHadFocus = !!document.activeElement?.closest?.(".lookup-form");
  const cols = columnsFor();
  const head = $("grid-head");
  head.textContent = "";
  const hr = el("tr");
  for (const key of ["id", ...cols]) {
    const th = el("th", null, key === "id" ? "object" : key);
    if (state.sortKey === key) th.appendChild(el("span", "dir", state.sortDir > 0 ? "↑" : "↓"));
    th.onclick = () => {
      state.sortDir = state.sortKey === key ? -state.sortDir : 1;
      state.sortKey = key;
      renderGrid(); renderCrumb();
    };
    hr.appendChild(th);
  }
  head.appendChild(hr);

  const body = $("grid-body");
  body.textContent = "";
  const items = visibleItems();
  $("grid-empty").hidden = items.length > 0 || !!state.detailObs;
  $("grid-empty").textContent = emptyMessage();

  const treeable = !state.sortKey && !state.filterText && !state.facet;
  const anchorId = anchorRowId();
  let expansionPlaced = false;
  for (const item of items) {
    const tr = el("tr");
    tr.dataset.id = item.id;
    tr.classList.toggle("selected", item.id === anchorId);

    const idCell = el("td", "ident");
    if (treeable && typeof item.depth === "number" && item.depth > 0) {
      idCell.appendChild(el("span", "tree", NBSP.repeat((item.depth - 1) * 3) + "└ "));
    }
    idCell.appendChild(el("span", `dot ${item.worst_opinion_level || "info"}`));
    idCell.appendChild(document.createTextNode(item.native_id));
    idCell.title = item.id;
    // What runs on this piece of plumbing, when something can say so.
    const owner = state.owners?.[item.native_id];
    if (owner) {
      const wrap = el("span", "owner");
      // "on X" where the attribution reaches only the shared network and not
      // the workload — the hedge is a claim about what is known, not decoration.
      if (owner.hedge) wrap.appendChild(document.createTextNode("on "));
      owner.parts.forEach((part, i) => {
        // "network:container" — one shape, so which half is which never has to
        // be guessed, and each half goes to its own object.
        if (i) wrap.appendChild(document.createTextNode(":"));
        if (!part.href) {
          wrap.appendChild(document.createTextNode(part.label));
          return;
        }
        const link = el("a", "owner-part", part.label);
        link.href = part.href;
        link.onclick = (e) => e.stopPropagation();
        wrap.appendChild(link);
      });
      idCell.appendChild(wrap);
    }
    tr.appendChild(idCell);

    for (const key of cols) {
      const resolve = PSEUDO_COLUMNS[key];
      tr.appendChild(renderCell(key, resolve ? resolve(item) : item.facts[key], item));
    }
    tr.onclick = () => {
      if (item.id === anchorRowId()) {
        collapseDetail(); stripObjectFromHash();
      } else {
        goTo(state.subsystem, state.collection, item.id);
      }
    };
    body.appendChild(tr);

    if (item.id === anchorId && state.detailObs) {
      body.appendChild(renderExpansion(cols.length + 1));
      expansionPlaced = true;
    }
  }
  // A deep-linked object may not be among the visible rows (filtered out or
  // beyond the page); its observation still deserves a home.
  if (!expansionPlaced && state.selectedId && state.detailObs) {
    body.insertBefore(renderExpansion(cols.length + 1), body.firstChild);
  }
}

function renderCell(key, value, item) {
  const td = el("td");
  if (value === null || value === undefined || value === "" ||
      (Array.isArray(value) && value.length === 0)) {
    td.appendChild(el("span", "dim", "—"));
    return td;
  }
  // Snapshot weight doubles as the door to the snapshot list.
  if (key === "SnapshotUsedBytes" && typeof value === "number" && value > 0 && item) {
    const a = el("a", "fact-link", humanBytes(value));
    a.href = hashFor(state.subsystem, "lookups", "lookup:snapshots-of/" + item.native_id);
    a.title = `${value} bytes held by snapshots — click to list them`;
    a.onclick = (e) => e.stopPropagation();
    td.appendChild(a);
    return td;
  }
  if (key === "UsePercent" && typeof value === "number") {
    const wrap = el("span", `usebar${value >= 95 ? " crit" : value >= 90 ? " warn" : ""}`);
    const track = el("span", "track");
    const fill = el("span", "fill");
    fill.style.width = `${Math.min(100, value)}%`;
    track.appendChild(fill);
    wrap.append(track, el("span", "mono", `${value}%`));
    td.appendChild(wrap);
    return td;
  }
  if (key === "Priority" && typeof value === "number") {
    const cls = value <= 3 ? "crit" : value === 4 ? "warn" : "neutral";
    td.appendChild(el("span", `badge ${cls}`, PRIORITY_NAMES[value] ?? value));
    return td;
  }
  const unit = scalarText(key, value);
  if (unit !== null) {
    td.appendChild(el("span", "mono", unit));
    td.title = String(value);
    return td;
  }
  if (["ActiveState", "SubState", "State", "Health", "OperState", "LoadState"].includes(key)) {
    const cls = VALUE_CLASS[String(value).toLowerCase()] || "neutral";
    td.appendChild(el("span", `badge ${cls}`, String(value)));
    return td;
  }
  if (Array.isArray(value)) { td.className = "mono"; td.textContent = value.map(vstr).join(", "); return td; }
  if (typeof value === "boolean") { td.appendChild(el("span", "dim", value ? "true" : "false")); return td; }
  if (typeof value === "object") { td.className = "mono"; td.textContent = vstr(value); td.title = vstr(value); return td; }
  td.textContent = String(value);
  if (!["Description", "Message", "Status"].includes(key)) td.className = "mono";
  td.title = String(value);
  return td;
}

/* ── detail expansion ────────────────────────────────────── */

async function openDetail(objectId, { quiet = false } = {}) {
  const { subsystem, collection, epoch } = state;
  if (state.selectedId !== objectId) state.lookupDraft = null;
  state.selectedId = objectId;      // optimistic: j/k walks rows per keypress
  let obs;
  try {
    obs = await api(`/v1/${subsystem}/${collection}/${idPath(objectId)}`);
  } catch (err) {
    if (epoch === state.epoch && state.selectedId === objectId) {
      banner(`Failed to load ${objectId}: ${err.message}`);
    }
    return;
  }
  // Discard if the user navigated elsewhere while this was in flight.
  if (epoch !== state.epoch || state.selectedId !== objectId) return;
  state.detailObs = obs;
  if (!quiet) state.evidence = null;
  renderGrid();
  if (!quiet) {
    document.querySelector("tr.expand")?.previousSibling?.scrollIntoView({ block: "nearest" });
    // A lookup descriptor's next act is typing the input — hand it focus.
    const lookupInput = document.querySelector(".lookup-form input");
    if (lookupInput && !lookupInput.value) lookupInput.focus({ preventScroll: true });
  }
}

function collapseDetail() {
  state.selectedId = null;
  state.detailObs = null;
  state.evidence = null;
  state.lookupDraft = null;
  state.suppressAutoOpen = true;
  renderGrid();
}

function renderExpansion(colspan) {
  const obs = state.detailObs;
  const tr = el("tr", "expand");
  const td = el("td");
  td.colSpan = colspan;
  const box = el("div", "d-box");

  const head = el("div", "d-head");
  head.appendChild(el("span", "d-id", obs.object.id));
  head.appendChild(el("span",
    `badge ${obs.status === "ok" ? "ok" : obs.status === "partial" ? "warn" : "crit"}`, obs.status));
  head.appendChild(el("span", "d-sub", `${obs.object.type} · observed ${ageOf(obs.observed_at)}`));
  const close = el("button", "d-close", "✕");
  close.title = "Collapse (Esc)";
  close.onclick = (e) => { e.stopPropagation(); collapseDetail(); stripObjectFromHash(); };
  head.appendChild(close);
  box.appendChild(head);

  if (obs.object.type === "lookup") box.appendChild(renderLookupForm(obs));

  if (obs.errors?.length) {
    for (const msg of obs.errors) box.appendChild(el("div", "opinion critical", msg));
  }
  for (const op of obs.opinions || []) {
    const o = el("div", `opinion ${op.level}`);
    o.appendChild(el("div", "msg", op.message));
    const ev = el("div", "ev");
    for (const path of op.evidence) {
      const chip = el("span", "ev-chip", path);
      chip.onmouseenter = () => citeFacts(path, true);
      chip.onmouseleave = () => citeFacts(path, false);
      ev.appendChild(chip);
    }
    o.appendChild(ev);
    box.appendChild(o);
  }

  const cols = el("div", "d-cols");

  const factsSec = el("div", "d-section");
  factsSec.appendChild(el("h3", null, "Facts"));
  // Pools get a bespoke layout: scalar facts left, capacity meters in the
  // otherwise-dead space to their right, and the vdev table full-width
  // below — fullness readable at a glance, per top-level vdev.
  const isPool = obs.subsystem === "storage" && obs.object.type === "pool";
  const grid = el("div", "facts");
  for (const [key, value] of Object.entries(obs.facts)) {
    if (isPool && key === "Vdevs") continue;
    const k = el("div", "k", key);
    const v = el("div", `v${value === null || value === undefined ? " null" : ""}`);
    const unit = scalarText(key, value, true);
    if (unit !== null) {
      v.textContent = unit;
    } else {
      v.appendChild(renderFactValue(value));
    }
    k.dataset.fact = key; v.dataset.fact = key;
    grid.append(k, v);
  }
  if (isPool && typeof obs.facts.SizeBytes === "number") {
    const top = el("div", "pool-top");
    top.appendChild(grid);
    top.appendChild(capacityPanel(obs.facts));
    factsSec.appendChild(top);
  } else {
    factsSec.appendChild(grid);
  }
  if (isPool && obs.facts.Vdevs) {
    const vh = el("h3", null, "Vdevs");
    vh.style.marginTop = "14px";
    factsSec.appendChild(vh);
    const v = el("div", "v");
    v.dataset.fact = "Vdevs";
    v.appendChild(renderFactValue(obs.facts.Vdevs));
    factsSec.appendChild(v);
  }
  cols.appendChild(factsSec);

  const side = el("div", "d-side");
  if (obs.relationships?.length) {
    const sec = el("div", "d-section");
    sec.appendChild(el("h3", null, "Relationships"));
    const groups = {};
    for (const r of obs.relationships) (groups[`${r.type}/${r.direction}`] ??= []).push(r);
    for (const [key, rels] of Object.entries(groups)) {
      const [type, direction] = key.split("/");
      const g = el("div", "rel-group");
      g.appendChild(el("div", "rel-type", `${direction === "out" ? "→" : "←"} ${type}`));
      const chips = el("div", "rel-chips");
      const REL_CAP = 100;
      const addChips = (list) => {
        for (const r of list) {
          const targetId = r.target.id;
          const prefix = targetId.split(":", 1)[0];
          const routeTo = PREFIX_ROUTE[prefix];
          const node = el(routeTo ? "a" : "span", "rel");
          node.appendChild(el("span", "arrow", direction === "out" ? "→" : "←"));
          node.appendChild(document.createTextNode(targetId));
          if (routeTo) node.href = hashFor(routeTo[0], routeTo[1], targetId);
          chips.appendChild(node);
        }
      };
      addChips(rels.slice(0, REL_CAP));
      if (rels.length > REL_CAP) {
        const more = el("button", "rel dim", `+${rels.length - REL_CAP} more`);
        more.onclick = (e) => { e.stopPropagation(); more.remove(); addChips(rels.slice(REL_CAP)); };
        chips.appendChild(more);
      }
      g.appendChild(chips);
      sec.appendChild(g);
    }
    side.appendChild(sec);
  }

  const src = obs.source;
  const srcSec = el("div", "d-section");
  srcSec.appendChild(el("h3", null, "Source"));
  const line = el("div", "src-line");
  line.append(el("b", null, src.interface), src.method ? ` · ${src.method}` : "");
  srcSec.appendChild(line);
  for (const cmd of src.reference_commands || [])
    srcSec.appendChild(el("div", "src-line", `$ ${cmd}`));
  for (const note of src.notes || [])
    srcSec.appendChild(el("div", "src-line dim", note));
  side.appendChild(srcSec);
  cols.appendChild(side);
  box.appendChild(cols);

  if (obs.evidence_ref) box.appendChild(renderEvidenceSection(obs));

  td.appendChild(box);
  tr.appendChild(td);
  tr.onclick = (e) => e.stopPropagation();
  return tr;
}

/* ── lookup launcher ─────────────────────────────────────── */

/* Every subsystem that advertises a `lookups` collection contributes its
   questions; the launcher is how a lookup is reachable from any view. The
   catalog is discovered from the same public API, never hardcoded. */
async function lookupCatalog() {
  if (state.lookupCatalog) return state.lookupCatalog;
  const subs = Object.entries(state.capabilities?.subsystems || {})
    .filter(([, cap]) => (cap.collections || []).includes("lookups"))
    .map(([name]) => name);
  const entries = [];
  for (const sub of subs) {
    try {
      const page = await api(`/v1/${sub}/lookups`);
      for (const item of page.items)
        entries.push({ subsystem: sub, id: item.id, name: item.native_id, facts: item.facts });
    } catch { /* one subsystem failing does not take the launcher down */ }
  }
  state.lookupCatalog = entries;
  return entries;
}

function closePalette() {
  const pal = $("palette");
  pal.hidden = true;
  pal.textContent = "";
}

async function openPalette() {
  const pal = $("palette");
  if (!pal.hidden) return closePalette();
  pal.hidden = false;
  pal.textContent = "";
  pal.onclick = (e) => { if (e.target === pal) closePalette(); };
  const box = el("div", "pal-box");
  pal.appendChild(box);

  const entries = await lookupCatalog();
  if (pal.hidden) return;                       // closed while loading
  if (!entries.length) {
    box.appendChild(el("div", "pal-hint", "This host advertises no lookups."));
    return;
  }

  const chipRow = el("div", "pal-chips");
  const input = el("input", "pal-input");
  input.type = "text"; input.spellcheck = false; input.autocomplete = "off";
  const hint = el("div", "pal-hint");
  let sel = 0;

  const select = (i) => {
    sel = (i + entries.length) % entries.length;
    [...chipRow.children].forEach((c, j) => c.classList.toggle("on", j === sel));
    const entry = entries[sel];
    input.placeholder = entry.facts.Example ? `e.g. ${entry.facts.Example}` : "input…";
    hint.textContent = (entry.facts.Question || "") +
      (entry.facts.Available === false
        ? ` — unavailable here: ${entry.facts.Note || "no acquisition path"}` : "");
  };
  entries.forEach((entry, i) => {
    const chip = el("button", "chip", `${entry.subsystem} · ${entry.name}`);
    chip.onclick = () => { select(i); input.focus(); };
    chipRow.appendChild(chip);
  });

  input.onkeydown = (event) => {
    event.stopPropagation();
    if (event.key === "Escape") {
      closePalette();
    } else if (event.key === "Enter") {
      const value = input.value.trim();
      if (!value) return;
      const entry = entries[sel];
      closePalette();
      goTo(entry.subsystem, "lookups", `${entry.id}/${value}`);
    } else if (event.key === "Tab" || event.key === "ArrowDown") {
      event.preventDefault(); select(sel + 1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault(); select(sel - 1);
    }
  };

  box.append(chipRow, input, hint);
  select(0);
  input.focus();
}

/* ── lookups ─────────────────────────────────────────────── */

/* The input row for a lookup expansion. The descriptor observation invites
   the first input; a result keeps the form so the next query is one edit
   away. Running is navigation — the result is a deep-linkable observation. */
function renderLookupForm(obs) {
  const base = obs.object.id.split("/")[0];
  const fromId = obs.object.id.includes("/")
    ? obs.object.id.slice(base.length + 1) : "";

  const form = el("div", "lookup-form");
  const input = el("input");
  input.type = "text";
  input.spellcheck = false;
  input.autocomplete = "off";
  input.placeholder = obs.facts.Example ? `e.g. ${obs.facts.Example}` : "input…";
  input.value = state.lookupDraft ?? fromId;
  input.oninput = () => { state.lookupDraft = input.value; };

  const run = () => {
    const value = input.value.trim();
    if (value) goTo(state.subsystem, state.collection, `${base}/${value}`);
  };
  input.onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); run(); } };

  const btn = el("button", "lookup-run", "Look up");
  btn.onclick = (e) => { e.stopPropagation(); run(); };

  form.append(input, btn);
  if (obs.facts.Available === false) {
    form.appendChild(el("span", "src-line dim", obs.facts.Note || "unavailable on this host"));
  }
  if (lookupHadFocus) {
    input.focus({ preventScroll: true });
    input.setSelectionRange(input.value.length, input.value.length);
  }
  return form;
}

const INLINE_LIST_MAX = 64;

/* Capacity meters for a pool: one bar for the pool, one per top-level vdev.
   Status color only at the same thresholds the pool opinions use (>=80 warn,
   >=90 crit); the numbers are always printed, so color never stands alone. */
function capacityPanel(facts) {
  const panel = el("div", "cap-panel");
  panel.appendChild(el("h3", null, "Capacity"));
  const rows = [["pool", facts.AllocatedBytes, facts.SizeBytes, facts.CapacityPercent]];
  for (const vd of facts.Vdevs || []) {
    if (typeof vd.CapacityPercent === "number") {
      rows.push([vd.Name, vd.AllocatedBytes, vd.SizeBytes, vd.CapacityPercent]);
    }
  }
  for (const [label, alloc, size, pct] of rows) {
    if (typeof pct !== "number") continue;
    const row = el("div", "cap-row");
    row.appendChild(el("div", "cap-name", String(label)));
    const bar = el("div", "cap-bar");
    const fill = el("span", `cap-fill${pct >= 90 ? " crit" : pct >= 80 ? " warn" : ""}`);
    fill.style.width = `${Math.min(100, Math.max(0, pct))}%`;
    bar.appendChild(fill);
    row.appendChild(bar);
    row.appendChild(el("div", "cap-val",
      `${humanBytes(alloc)} / ${humanBytes(size)} · ${pct}%`));
    row.title = `${alloc} / ${size} bytes allocated`;
    panel.appendChild(row);
  }
  return panel;
}

/* Fact values that name another object ("block-device:sdc") become links,
   the same routing the relationship chips use. */
function factLeaf(value, short = false) {
  if (typeof value !== "string") return null;
  const sep = value.indexOf(":");
  if (sep <= 0) return null;
  const prefix = value.slice(0, sep);
  // lookup ids are subsystem-relative: every subsystem may carry a lookups
  // collection, and a fact naming one means "this subsystem's".
  const routeTo = prefix === "lookup"
    ? [state.subsystem, "lookups"] : PREFIX_ROUTE[prefix];
  if (!routeTo || !routeTo[0]) return null;
  const a = el("a", "fact-link", short ? value.slice(sep + 1) : value);
  a.title = value;
  a.href = hashFor(routeTo[0], routeTo[1], value);
  a.onclick = (e) => e.stopPropagation();
  return a;
}

/* Structured fact values earn structure: scalar lists stack when long,
   uniform object lists become mini-tables (NICs, LLDP neighbours, vdevs),
   plain objects become nested key/value grids (PerLinkDNS), and anything
   deeper falls back to readable JSON. A "Depth" key in a mini-table row is
   tree indentation (vdev trees), not a column. */
function renderFactValue(value, depth = 0) {
  if (value === null || value === undefined ||
      (Array.isArray(value) && value.length === 0) ||
      (typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === 0)) {
    return el("span", "null", "—");
  }
  if (Array.isArray(value)) {
    const scalars = value.every(v => typeof v !== "object" || v === null);
    if (scalars) {
      const joined = value.map(vstr).join(", ");
      if (joined.length <= INLINE_LIST_MAX) return el("span", null, joined);
      const ul = el("ul", "v-list");
      for (const v of value) ul.appendChild(el("li", null, vstr(v)));
      return ul;
    }
    const keys = [...new Set(value.flatMap(o => Object.keys(o || {})))]
      .filter(k => k !== "Depth").slice(0, 8);
    const flatRows = value.every(o => o && typeof o === "object" && !Array.isArray(o) &&
      keys.every(k => o[k] === undefined || o[k] === null || typeof o[k] !== "object" || Array.isArray(o[k])));
    if (flatRows && keys.length && depth < 2) {
      const table = el("table", "v-table");
      const thr = el("tr");
      for (const k of keys) thr.appendChild(el("th", null, k));
      table.appendChild(thr);
      for (const o of value) {
        const tr = el("tr");
        keys.forEach((k, idx) => {
          const cell = o[k];
          const td = el("td");
          if (idx === 0 && typeof o.Depth === "number" && o.Depth > 1) {
            td.appendChild(el("span", "tree", NBSP.repeat((o.Depth - 1) * 3) + "└ "));
          }
          if (cell === undefined || cell === null) {
            td.appendChild(el("span", "null", "—"));
          } else {
            const link = factLeaf(cell, true);
            const unit = link ? null : scalarText(k, cell);
            if (link) td.appendChild(link);
            else td.appendChild(document.createTextNode(unit ?? vstr(cell)));
          }
          tr.appendChild(td);
        });
        table.appendChild(tr);
      }
      return table;
    }
  }
  if (typeof value === "object" && !Array.isArray(value)) {
    if ("__bytes_base64__" in value) return el("span", null, vstr(value));
    if (depth < 2) {
      const kv = el("div", "v-kv");
      for (const [k, v] of Object.entries(value)) {
        kv.appendChild(el("div", "v-kv-k", k));
        const vd = el("div", "v-kv-v");
        const unit = scalarText(k, v);
        if (unit !== null) vd.textContent = unit;
        else vd.appendChild(renderFactValue(v, depth + 1));
        kv.appendChild(vd);
      }
      return kv;
    }
  }
  if (typeof value === "object") {
    return el("pre", "v-json", JSON.stringify(value, null, 2));
  }
  return factLeaf(value) || el("span", null, String(value));
}

function citeFacts(path, on) {
  const root = path.split(".")[0];
  document.querySelectorAll(`.facts [data-fact="${CSS.escape(root)}"]`)
    .forEach(n => n.classList.toggle("cited", on));
}

/* ── evidence ────────────────────────────────────────────── */

function renderEvidenceSection(obs) {
  const sec = el("div", "d-section d-evidence");
  const bar = el("div", "ev-bar");
  const btn = el("button", "evidence-btn",
    state.evidence ? "Hide native evidence" : "Show native evidence");
  btn.onclick = async () => {
    if (state.evidence) { state.evidence = null; renderGrid(); return; }
    btn.textContent = "Loading…";
    let data;
    try {
      data = await api(obs.evidence_ref);
    } catch (err) {
      if (state.detailObs === obs) { btn.textContent = `Evidence failed: ${err.message}`; }
      return;
    }
    if (state.detailObs !== obs) return;   // moved on; not our expansion any more
    state.evidence = { data, view: "text" };
    renderGrid();
  };
  bar.appendChild(btn);

  if (state.evidence) {
    for (const view of ["text", "json"]) {
      const tab = el("button",
        "ev-tab" + (state.evidence.view === view ? " on" : ""),
        view === "text" ? "command view" : "json");
      tab.onclick = () => { state.evidence.view = view; renderGrid(); };
      bar.appendChild(tab);
    }
    bar.appendChild(el("span", "src-line dim",
      `captured ${ageOf(state.evidence.data.captured_at)} · rendered from the captured payload — nothing was executed`));
  }
  sec.appendChild(bar);

  if (state.evidence) {
    const { data, view } = state.evidence;
    const text = data.error
      ? `evidence acquisition failed: ${data.error}`
      : view === "json" ? JSON.stringify(data, null, 2)
      : evidenceText(state.subsystem, data.payload);
    sec.appendChild(el("pre", "evidence", text));
  }
  return sec;
}

/* Command-style rendering of captured payloads — approximations of what the
   reference tools print, produced purely from the evidence JSON. */
function evidenceText(subsystem, payload) {
  if (payload === null || payload === undefined) return "(empty payload)";

  if (payload.domain_xml) {
    const info = Object.entries(payload.info || {})
      .filter(([k]) => k !== "ips_by_mac")
      .map(([k, v]) => `${k}: ${vstr(v)}`).join("\n");
    return `${info}\n\n${payload.domain_xml}`;
  }
  if (payload.__CURSOR) {
    const ts = payload.__REALTIME_TIMESTAMP
      ? new Date(Number(payload.__REALTIME_TIMESTAMP) / 1000).toISOString() : "";
    const head = `${ts} ${payload._HOSTNAME ?? ""} ${payload.SYSLOG_IDENTIFIER ?? payload._COMM ?? ""}` +
      `${payload._PID ? `[${payload._PID}]` : ""}: ${payload.MESSAGE ?? ""}`;
    const rest = Object.entries(payload)
      .filter(([k]) => k !== "MESSAGE")
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${vstr(v)}`).join("\n");
    return `${head}\n\n${rest}`;
  }
  if (payload.blockdevices) return treeText(payload.blockdevices,
    n => `${n.name}  ${n.size ?? ""}  ${n.type ?? ""}  ${n.fstype ?? ""}  ${(n.mountpoints || []).filter(Boolean).join(",")}`);
  if (payload.filesystems) return treeText(payload.filesystems,
    n => `${n.target}  ${n.source ?? ""}  ${n.fstype ?? ""}  ${n.options ?? ""}`);
  if (payload.route_get) {
    return payload.route_get.map(r =>
      [r.dst ?? "?", r.gateway ? `via ${r.gateway}` : "", r.dev ? `dev ${r.dev}` : "",
       r.prefsrc ? `src ${r.prefsrc}` : "", r.table ? `table ${r.table}` : "",
       r.uid !== undefined ? `uid ${r.uid}` : "", (r.flags || []).join(",")]
      .filter(Boolean).join(" ")).join("\n");
  }
  if (payload.ipv4 || payload.ipv6) {
    const lines = [];
    for (const fam of ["ipv4", "ipv6"]) {
      for (const r of payload[fam] || []) {
        lines.push([r.dst ?? "default", r.gateway ? `via ${r.gateway}` : "",
                    r.dev ? `dev ${r.dev}` : "", r.protocol ? `proto ${r.protocol}` : "",
                    r.scope ? `scope ${r.scope}` : "", r.prefsrc ? `src ${r.prefsrc}` : "",
                    r.metric !== undefined ? `metric ${r.metric}` : ""]
                   .filter(Boolean).join(" "));
      }
    }
    return lines.join("\n");
  }
  if (payload.ip_addr) {
    const blocks = payload.ip_addr.map(l => {
      const lines = [`${l.ifindex}: ${l.ifname}: <${(l.flags || []).join(",")}> mtu ${l.mtu} state ${l.operstate}`];
      if (l.address) lines.push(`    link/${l.link_type} ${l.address}`);
      for (const a of l.addr_info || [])
        lines.push(`    ${a.family === "inet6" ? "inet6" : "inet"} ${a.local}/${a.prefixlen}${a.scope ? ` scope ${a.scope}` : ""}`);
      return lines.join("\n");
    });
    const lldp = Object.entries(payload.lldp || {}).map(([ifname, ns]) =>
      `${ifname}:\n` + ns.map(n => `    ${n.SystemName ?? "?"}  ${n.PortDescription ?? ""}  ${n.ChassisID ?? ""}`).join("\n"));
    return blocks.join("\n") + (lldp.length ? `\n\nLLDP neighbours:\n${lldp.join("\n")}` : "");
  }
  if (payload.nftables) {
    const lines = [];
    let openTable = false, openChain = false;
    const closeChain = () => { if (openChain) { lines.push("  }"); openChain = false; } };
    const closeTable = () => { closeChain(); if (openTable) { lines.push("}"); openTable = false; } };
    for (const entry of payload.nftables) {
      if (entry.table) {
        closeTable();
        lines.push(`table ${entry.table.family} ${entry.table.name} {`);
        openTable = true;
      } else if (entry.chain) {
        closeChain();
        const c = entry.chain;
        lines.push(`  chain ${c.name} {` +
          (c.type ? ` type ${c.type} hook ${c.hook} priority ${c.prio};` : "") +
          (c.policy ? ` policy ${c.policy};` : ""));
        openChain = true;
      } else if (entry.rule) {
        lines.push(`    ${JSON.stringify(entry.rule.expr)}`);
      }
    }
    closeTable();
    return lines.join("\n");
  }
  if (typeof payload === "object" && !Array.isArray(payload)) {
    const flat = Object.values(payload).every(v => typeof v !== "object" || v === null ||
      Array.isArray(v) || "__bytes_base64__" in (v || {}));
    if (flat) {
      return Object.entries(payload).sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => `${k}=${vstr(v)}`).join("\n");
    }
    const sections = [];
    for (const [section, props] of Object.entries(payload)) {
      if (typeof props === "object" && props !== null && !Array.isArray(props)) {
        sections.push(`# ${section}\n` + Object.entries(props)
          .sort(([a], [b]) => a.localeCompare(b))
          .map(([k, v]) => `${k}=${vstr(v)}`).join("\n"));
      } else {
        sections.push(`# ${section}\n${vstr(props)}`);
      }
    }
    return sections.join("\n\n");
  }
  return JSON.stringify(payload, null, 2);
}

function treeText(nodes, lineOf, depth = 0) {
  const out = [];
  for (const n of nodes) {
    out.push(`${"  ".repeat(depth)}${depth ? "└ " : ""}${lineOf(n)}`);
    if (n.children) out.push(treeText(n.children, lineOf, depth + 1));
  }
  return out.join("\n");
}

/* ── chrome ──────────────────────────────────────────────── */

function banner(text) {
  const node = $("banner");
  node.hidden = !text;
  node.textContent = text || "";
}

function armAutoRefresh() {
  clearInterval(state.refreshTimer);
  state.refreshTimer = setInterval(() => {
    if (!document.hidden) loadCollection();
  }, 15000);
}

function initTheme() {
  const saved = localStorage.getItem("se-theme");
  if (saved) document.documentElement.dataset.theme = saved;
  $("theme-toggle").onclick = toggleTheme;
}

function toggleTheme() {
  const current = document.documentElement.dataset.theme
    || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  const next = current === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("se-theme", next);
}

function cycleCollection(step) {
  const routes = navRoutes();
  const idx = routes.findIndex(([s, c]) => s === state.subsystem && c === state.collection);
  const next = routes[(idx + step + routes.length) % routes.length];
  if (next) goTo(next[0], next[1], null);
}

document.addEventListener("keydown", (event) => {
  if (!$("palette").hidden) {           // palette input stops its own keys;
    if (event.key === "Escape") closePalette();   // this catches the rest
    return;
  }
  if (event.target.matches?.("input, textarea, select")) {
    if (event.key === "Escape") event.target.blur();
    return;
  }
  if (event.metaKey || event.ctrlKey || event.altKey) return;
  const rows = [...document.querySelectorAll("#grid-body tr:not(.expand)")];
  const idx = rows.findIndex(r => r.dataset.id === anchorRowId());
  switch (event.key) {
    case "/": event.preventDefault(); $("filter").focus(); break;
    case "j": case "ArrowDown": {
      if (event.key === "ArrowDown") event.preventDefault();
      const next = rows[Math.min(idx + 1, rows.length - 1)];
      if (next && next.dataset.id !== state.selectedId) {
        goTo(state.subsystem, state.collection, next.dataset.id, { replace: true });
        next.scrollIntoView({ block: "nearest" });
      }
      break;
    }
    case "k": case "ArrowUp": {
      if (event.key === "ArrowUp") event.preventDefault();
      const prev = rows[Math.max(idx - 1, 0)];
      if (prev && prev.dataset.id !== state.selectedId) {
        goTo(state.subsystem, state.collection, prev.dataset.id, { replace: true });
        prev.scrollIntoView({ block: "nearest" });
      }
      break;
    }
    case "[": cycleCollection(-1); break;
    case "]": cycleCollection(1); break;
    case "l": openPalette(); break;
    case "Escape": collapseDetail(); stripObjectFromHash(); break;
    case "r": loadCollection(); break;
    case "t": toggleTheme(); break;
    case "e": document.querySelector(".evidence-btn")?.click(); break;
  }
});

$("filter").addEventListener("input", (event) => {
  state.filterText = event.target.value.trim();
  renderGrid();
  renderCrumb();
});
$("refresh").onclick = () => loadCollection();
$("lookup-btn").onclick = () => openPalette();

boot();
