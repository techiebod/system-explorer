/* Executes the operator UI's chrome-rendering path against a stub DOM.
 *
 * This exists because a single null dereference in applyNavBadges blanked the
 * ENTIRE page — the TypeError killed renderNav, which killed loadHost, so the
 * router never ran and there were no rows, no panel and no error message to
 * diagnose from. Nothing in the repository could have caught it: conformance is
 * pytest and lints the UI's source text, the NixOS VM test curls the API, and
 * neither executes a line of JavaScript.
 *
 * Deliberately not a browser. It stubs the handful of DOM APIs the chrome path
 * uses and calls the real functions from the real app.js, which is enough to
 * catch the class of fault that actually happened: an assumption about element
 * structure that holds for every section but one.
 *
 * Run: node test/ui-smoke/nav-smoke.mjs
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import vm from "node:vm";

const here = dirname(fileURLToPath(import.meta.url));
const APP = join(here, "..", "..", "src", "system_explorer", "ui", "app.js");

/* ── the smallest DOM that can hold a nav ─────────────────────────────── */

class Node {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.children = [];
    this.className = "";
    this.dataset = {};
    this.style = {};
    this.hidden = false;
    this._text = "";
    this.title = "";
    this.value = "";
  }
  addEventListener() {}
  // Fidelity gap worth knowing: a real DOM concatenates a node's own text with
  // its children's, this one prefers the children. So a label built with text
  // and then given a child (a nav heading that grows a severity dot) reads as
  // "" here. Identify such nodes by route or class, not by their text.
  get textContent() {
    return this.children.length ? this.children.map(c => c.textContent).join("") : this._text;
  }
  // renderOverview counts childNodes to decide whether the KPI line has
  // anything in it; without this, exporting it throws on the first call.
  get childNodes() { return this.children; }
  set textContent(value) { this._text = String(value); this.children = []; }
  appendChild(child) { this.children.push(child); return child; }
  append(...nodes) { for (const n of nodes) this.appendChild(typeof n === "object" ? n : text(n)); }
  remove() { /* detached nodes are not tracked; removal is a no-op here */ }
  get classList() {
    return {
      add: (c) => { if (!this.className.split(" ").includes(c)) this.className = `${this.className} ${c}`.trim(); },
      remove: (c) => { this.className = this.className.split(" ").filter(x => x && x !== c).join(" "); },
      toggle: () => {},
      contains: (c) => this.className.split(" ").includes(c),
    };
  }
  _all(out = []) {
    for (const c of this.children) { out.push(c); c._all?.(out); }
    return out;
  }
  // Class selectors only, which is all the chrome path uses.
  querySelectorAll(sel) {
    const want = sel.trim().replace(/^\./, "");
    return this._all().filter(n => n.className.split(" ").includes(want));
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] ?? null; }
}

const text = (value) => Object.assign(new Node("#text"), { _text: String(value) });

function makeDocument(ids) {
  const byId = {};
  for (const id of ids) byId[id] = new Node("div");
  return {
    _byId: byId,
    createElement: (tag) => new Node(tag),
    createTextNode: (value) => text(value),
    getElementById: (id) => byId[id] ?? null,
    // app.js binds keyboard shortcuts and a theme toggle at load; the smoke
    // test never fires events, it just must not die registering the handlers.
    addEventListener() {},
    documentElement: new Node("html"),
    body: new Node("body"),
    querySelectorAll(sel) {
      // "#nav .nav-sub" — the one compound selector in the chrome path.
      const [root, child] = sel.split(/\s+/);
      const host = byId[root.replace("#", "")];
      return host ? host.querySelectorAll(child) : [];
    },
  };
}

/* ── realistic inputs, the shape a storage host actually serves ───────── */

const CAPABILITIES = {
  version: "0.4.0", revision: "abc1234",
  host: { hostname: "host-a", machine_id: "0123456789abcdef0123456789abcdef" },
  subsystems: {
    system: { available: true, collections: ["identity", "time", "boot", "overview"] },
    nix: { available: true, collections: ["generations", "packages"] },
    hardware: { available: true, collections: ["platform", "pci", "usb", "scsi", "nvme"] },
    units: { available: true, collections: ["units"] },
    storage: { available: true, collections: ["block-devices", "mounts", "arrays", "pools"] },
    vms: { available: false, reason: "no libvirt read-only socket" },
  },
};

const STATUS = {
  subsystems: {
    system: { identity: { worst: "info", counts: { none: 1 }, total: 1 },
              overview: { worst: "warn", counts: { warn: 1 }, total: 1 } },
    nix: { generations: { worst: "ok", counts: { ok: 68 }, total: 68 },
           packages: { worst: null, reason: "inventory; no severity semantics" } },
    // A collection that is overwhelmingly info: 115 rows the rulebook looked at
    // and had something unalarming to say about. It must earn no badge at all.
    units: { units: { worst: "ok", counts: { ok: 212, info: 115 }, total: 327 } },
    // The empty-hiding case, and the one that started all this. mounts carries
    // every level at once, so the badge has to pick and count correctly.
    storage: { arrays: { worst: null, counts: {}, total: 0 },
               mounts: { worst: "critical", counts: { critical: 1, warn: 2, ok: 3 }, total: 6 },
               pools: { worst: "warn", counts: { warn: 1 }, total: 1 } },
  },
};

/* An overview at the moment the ARC verdict fires: raw usage over the warn
   threshold, ARC-adjusted usage well under it. The rulebook's answer is an
   `info` opinion whose own sentence says this is not pressure. */
const OVERVIEW_ARC_INFO = {
  observed_at: "2026-08-11T19:31:17Z", status: "ok",
  object: { id: "overview:host", type: "overview", native_id: "host" },
  facts: {
    UptimeSeconds: 204242, MemTotalBytes: 33525432320,
    MemUsedBytes: 30500000000, MemAvailableBytes: 3000000000,
    MemUsedPercent: 91, ArcSizeBytes: 13492575664, SwapTotalBytes: 0,
    PsiCpuSomeAvg60: 4, PsiCpuSomeAvg10: 2, PsiCpuSomeAvg300: 5,
    PsiIoFullAvg60: 1, PsiIoFullAvg10: 0, PsiIoFullAvg300: 2,
  },
  opinions: [{
    key: "memory-available", level: "info",
    message: "Memory reads 91% used, but 51% outside the ZFS ARC — the cache "
           + "yields under demand, so this is occupancy, not pressure.",
    evidence: ["MemAvailableBytes", "MemTotalBytes", "ArcSizeBytes"],
  }],
};

/* ── run the real code ────────────────────────────────────────────────── */

const IDS = ["nav", "host-name", "host-meta", "host-select", "build", "banner",
             "grid-empty", "grid-head", "grid-body", "overview", "collection-pane",
             "facets", "filter", "crumb", "age", "refresh", "palette", "lookup-btn",
             "theme-toggle"];
const document = makeDocument(IDS);

const sandbox = {
  document,
  window: { addEventListener() {}, matchMedia: () => ({ matches: false }) },
  location: { hash: "#/system/overview" },
  history: { replaceState() {}, pushState() {} },
  localStorage: { getItem: () => null, setItem() {} },
  fetch: () => Promise.reject(new Error("no network in the smoke test")),
  setInterval: () => 0, clearInterval() {}, setTimeout: () => 0,
  console,
};
sandbox.globalThis = sandbox;

const context = vm.createContext(sandbox);
// Appended to the SAME script rather than run as a second one: app.js declares
// its state and helpers with const, which in a vm script are lexically scoped
// and never become properties of the sandbox. Only code inside that script can
// see them.
const EXPORTS = "\n;globalThis.__ui = { state, renderNav, applyNavBadges, renderBuild, navRoutes, navModel, cellValue, PSEUDO_COLUMNS, linkPanel, scalarText, factHelp, renderOverview, renderGrid, renderResources, factLabel, worstOpinionLevel, OPINION_LEVELS, ATTENTION_LEVELS };";
vm.runInContext(readFileSync(APP, "utf8") + EXPORTS, context, { filename: "app.js" });
const ui = sandbox.__ui;

const failures = [];
const check = (name, fn) => {
  try { fn(); console.log(`  PASS  ${name}`); }
  catch (err) { failures.push(name); console.log(`  FAIL  ${name}\n        ${err.message}`); }
};

console.log("operator UI chrome smoke test");

check("the views heading survives a section being promoted above it", () => {
  /* Regression, caught within the hour of causing it: the heading was keyed
     on sections.length ("am I first overall"), so promoting the headless
     overview above the loop made every view section headless too. */
  ui.state.capabilities = CAPABILITIES;
  ui.state.views = { views: [{ name: "a", title: "A" }, { name: "b", title: "B" }] };
  const model = ui.navModel();
  ui.state.views = null;
  const headed = model.filter((s) => s.heading === "views");
  if (headed.length !== 1)
    throw new Error(`expected exactly one "views" heading, got ${headed.length}`);
});

check("a headless section never renders under the heading above it", () => {
  /* Reported from the deployed UI: the host's own overview appeared beneath
     the "estate" heading and read as estate-scoped, which it is not. The
     section carries no heading deliberately, and a headless section inherits
     whatever heading precedes it — so its POSITION is load-bearing, and
     nothing may be inserted above it that carries one. */
  ui.state.capabilities = CAPABILITIES;
  ui.state.hub = true;                 // makes the estate section exist
  ui.state.views = { views: [{ name: "v", title: "A view" }] };
  const model = ui.navModel();
  ui.state.hub = false;
  ui.state.views = null;
  const first = model[0];
  if (!first) throw new Error("the nav built no sections");
  const overview = first.items.find((i) => i.route === "system/overview");
  if (!overview)
    throw new Error(`overview is not in the first section (got ${first.heading})`);
  for (let i = 0; i < model.length; i++) {
    if (model[i].heading) continue;
    const above = model.slice(0, i).reverse().find((s) => s.heading);
    if (above && model[i].items.some((it) => it.route === "system/overview"))
      throw new Error(`overview would render under "${above.heading}"`);
  }
});

/* ── the resources page ──────────────────────────────────────────────────
 *
 * Executed rather than eyeballed, for the reason this whole harness exists:
 * a render path nothing runs is exactly how the nav blanked. These build the
 * page from facts shaped like a real host's and assert the claims the page
 * makes about itself — every figure a fact, every row a link, and the
 * remainder present as a row rather than a footnote. */

const RES_ITEMS = [
  { id: "unit:-.slice", type: "slice", native_id: "-.slice",
    facts: { Depth: 0, CpuUsageUsec: 400_000_000, HostCpuBusyUsec: 500_000_000,
             UnattributedCpuUsec: 100_000_000, HostCpuStolenUsec: 18_500_000,
             PsiIoFullAvg60: 54.55,
             StallUnexplained: { PsiIoFullAvg60: "every member cgroup was read" } } },
  { id: "unit:system.slice", type: "slice", native_id: "system.slice",
    facts: { Depth: 1, Parent: "-.slice", CpuUsageUsec: 300_000_000,
             PsiIoFullAvg60: 5.14,
             StallExplainedBy: { PsiIoFullAvg60: "nix-daemon.service" } } },
  { id: "unit:user.slice", type: "slice", native_id: "user.slice",
    facts: { Depth: 1, Parent: "-.slice", CpuUsageUsec: 100_000_000 } },
  { id: "unit:nix-daemon.service", type: "service", native_id: "nix-daemon.service",
    facts: { Depth: 2, Parent: "system.slice", CpuUsageUsec: 250_000_000,
             MemoryCurrentBytes: 2_000_000_000, IoWrittenBytes: 9_000_000_000,
             IoReadBytes: 1_000_000, PsiIoFullAvg60: 33.4 } },
  { id: "unit:hungry.service", type: "service", native_id: "hungry.service",
    facts: { Depth: 2, Parent: "system.slice", CpuUsageUsec: 40_000_000,
             MemoryCurrentBytes: 500_000_000, MemoryOomKills: 3,
             CpuThrottledUsec: 12_000_000 } },
];

const resourcesPage = () => ({ items: RES_ITEMS.map((i) => ({ ...i, facts: { ...i.facts } })) });

const renderRes = () => {
  ui.state.subsystem = "resources";
  ui.state.collection = "workloads";
  ui.renderResources(resourcesPage(), new Map());
  return document.getElementById("collection-pane");
};

check("the resources page renders without throwing", () => {
  const pane = renderRes();
  if (!pane.textContent.length) throw new Error("the page rendered empty");
});

check("the unattributed remainder is a row, not a footnote", () => {
  const text = renderRes().textContent;
  if (!text.includes("(no slice)"))
    throw new Error("the remainder is missing from the ladder");
  if (!text.includes("in no slice"))
    throw new Error("the host total does not state its unattributed share");
});

check("stolen time is shown only where the host has any", () => {
  if (!renderRes().textContent.includes("stolen by the hypervisor"))
    throw new Error("stolen time was not surfaced");
  const bare = resourcesPage();
  delete bare.items[0].facts.HostCpuStolenUsec;
  ui.renderResources(bare, new Map());
  if (document.getElementById("collection-pane").textContent.includes("stolen"))
    throw new Error("bare metal was told about stolen time it does not have");
});

check("an OOM kill and a throttle are surfaced, with their reason", () => {
  const text = renderRes().textContent;
  if (!text.includes("3 killed")) throw new Error("OOM kills are not shown");
  if (!text.includes("leaves no trace anywhere else"))
    throw new Error("the panel does not say why an OOM kill matters here");
});

check("a slice whose stall a member explains is not listed again", () => {
  const text = renderRes().textContent;
  if (text.includes("5.14"))
    throw new Error("an explained slice was restated over its member");
  if (!text.includes("33.4")) throw new Error("the member that explains it is missing");
});

check("the root's unexplained stall keeps its note and its own sentence", () => {
  const pane = renderRes();
  // The stub matches by class, not by tag — which is why the selector is the
  // class the page actually puts on the note.
  const note = [...pane.querySelectorAll("row-note")]
    .find((d) => /nothing inside this slice accounts/.test(d.textContent || ""));
  if (!note) throw new Error("the unexplained stall lost its note");
  if (!/every member cgroup was read/.test(note.title || ""))
    throw new Error("the host's own sentence is not carried as the hover");
});

check("every row links back to the object the figure came from", () => {
  const labels = [...renderRes().querySelectorAll("lbl")];
  if (!labels.length) throw new Error("the page built no row labels");
  const links = labels.filter((n) => n.href);
  if (!links.length) throw new Error("no row is a link");
  for (const a of links) {
    if (!/resources\/workloads/.test(a.href))
      throw new Error(`a row links somewhere else: ${a.href}`);
  }
});

check("labels explain themselves out of the fact dictionary", () => {
  ui.state.factDict = { subsystems: { resources: { workloads: {
    CpuUsageUsec: "Total CPU time this workload has consumed." } } } };
  const node = ui.factLabel("val", "1s", "CpuUsageUsec");
  if (node.title !== "Total CPU time this workload has consumed.")
    throw new Error("the tooltip is not the agent's own sentence");
  ui.state.factDict = null;
  if (ui.factLabel("val", "1s", "CpuUsageUsec").title)
    throw new Error("a missing dictionary invented a tooltip");
});

check("the page states that every figure is a fact", () => {
  if (!renderRes().textContent.includes("every figure is a fact"))
    throw new Error("the page does not say where its numbers come from");
});

check("renderNav builds sections without throwing", () => {
  ui.state.capabilities = CAPABILITIES;
  ui.state.status = null;
  ui.renderNav();
  const boxes = document.getElementById("nav").querySelectorAll("nav-sub");
  if (!boxes.length) throw new Error("no nav sections were built");
});

check("the promoted overview section exists and is label-less", () => {
  const solo = document.getElementById("nav").querySelector("nav-solo");
  if (!solo) throw new Error("no .nav-solo section — overview was not promoted");
  if (solo.querySelector("sub-label")) throw new Error("promoted section grew a heading");
  const item = solo.querySelector("nav-item");
  if (item?.dataset.route !== "system/overview")
    throw new Error(`promoted route is ${item?.dataset.route}`);
});

// THE REGRESSION. applyNavBadges walks every .nav-sub and used to dereference
// .sub-label unconditionally; the promoted section has none.
check("applyNavBadges tolerates a section with no heading", () => {
  ui.state.status = STATUS;
  ui.state.subsystem = "system";
  ui.state.collection = "overview";
  ui.applyNavBadges();
});

check("overview is not listed a second time under system", () => {
  const routes = document.getElementById("nav").querySelectorAll("nav-item")
    .map(n => n.dataset.route);
  const overviews = routes.filter(r => r === "system/overview");
  if (overviews.length !== 1)
    throw new Error(`system/overview appears ${overviews.length} times: ${routes.join(", ")}`);
});

check("an honestly-empty collection is hidden, a declined one is not", () => {
  const items = document.getElementById("nav").querySelectorAll("nav-item");
  const arrays = items.find(n => n.dataset.route === "storage/arrays");
  const packages = items.find(n => n.dataset.route === "nix/packages");
  if (!arrays?.hidden) throw new Error("storage/arrays (total 0, no reason) should be hidden");
  if (packages?.hidden) throw new Error("nix/packages declines with a reason and must stay listed");
});

check("renderBuild stamps version and revision", () => {
  ui.renderBuild();
  const stamped = document.getElementById("build").textContent;
  if (!stamped.includes("0.4.0") || !stamped.includes("abc1234"))
    throw new Error(`build stamp reads ${stamped}`);
});

// The keyboard order MUST be the rendered order. It was not: navRoutes rebuilt
// itself from capabilities, so [ and ] walked overview in its old position under
// system/boot while the sidebar showed it promoted to the top. Same root cause as
// the blank page — a rendering variant added without updating what consumes the
// nav's structure.
check("[ and ] walk the nav in the order it is rendered", () => {
  const rendered = [];
  for (const box of document.getElementById("nav").querySelectorAll("nav-sub")) {
    if (box.hidden) continue;
    for (const link of box.querySelectorAll("nav-item")) {
      if (!link.hidden) rendered.push(link.dataset.route);
    }
  }
  const walked = ui.navRoutes().map(([s, c]) => `${s}/${c}`);
  if (walked.join(",") !== rendered.join(","))
    throw new Error(`keyboard order\n  ${walked.join(", ")}\nrendered order\n  ${rendered.join(", ")}`);
});

check("overview is FIRST in the keyboard order, not buried under system", () => {
  const walked = ui.navRoutes().map(([s, c]) => `${s}/${c}`);
  if (walked[0] !== "system/overview")
    throw new Error(`first route is ${walked[0]}, expected system/overview`);
  // The specific symptom: it must not sit immediately after system/boot.
  const afterBoot = walked[walked.indexOf("system/boot") + 1];
  if (afterBoot === "system/overview")
    throw new Error("overview still follows system/boot — the old capability order");
});

check("the keys skip a collection the nav hides as honestly empty", () => {
  const walked = ui.navRoutes().map(([s, c]) => `${s}/${c}`);
  if (walked.includes("storage/arrays"))
    throw new Error("storage/arrays is hidden in the nav but reachable by keyboard");
});

// The model is the structure, so assert over it directly — no DOM needed, which
// is the point: the three bugs all came from consumers re-deriving the shape.
check("navModel is the single structure both the sidebar and the keys use", () => {
  const model = ui.navModel();
  const fromModel = model.flatMap(s => s.items.map(i => i.route));
  const rendered = [];
  for (const box of document.getElementById("nav").querySelectorAll("nav-sub")) {
    for (const link of box.querySelectorAll("nav-item")) rendered.push(link.dataset.route);
  }
  if (fromModel.join(",") !== rendered.join(","))
    throw new Error(`model\n  ${fromModel.join(", ")}\nrendered\n  ${rendered.join(", ")}`);
  // A headless section is legal and must stay legal: that is the shape that
  // blanked the page when a consumer assumed every section has a heading.
  if (!model.some(s => s.solo && s.heading === null))
    throw new Error("no headless promoted section in the model");
});

// The "disks" heading groups collections from one subsystem under a label that
// is not a subsystem name. Presentation only: the routes must stay exactly what
// the API serves, because the whole point of a heading over a collection is that
// it costs no contract change.
check("the disks heading sits immediately after storage", () => {
  const headings = ui.navModel().map(s => s.heading);
  const storage = headings.indexOf("storage");
  const disks = headings.indexOf("disks");
  if (storage === -1) throw new Error(`no storage section: ${headings.join(", ")}`);
  if (disks !== storage + 1)
    throw new Error(`order is ${headings.join(", ")} — disks must follow storage`);
});

check("a disks heading groups scsi and nvme without touching their routes", () => {
  const model = ui.navModel();
  const disks = model.find(s => s.heading === "disks");
  if (!disks) throw new Error("no disks section in the model");
  const routes = disks.items.map(i => i.route);
  if (routes.join(",") !== "hardware/scsi,hardware/nvme")
    throw new Error(`disks holds ${routes.join(", ")}`);
  // And they must not ALSO appear under hardware, which is what a claimed-set
  // bug would produce — the same collection reachable twice.
  const hardware = model.find(s => s.heading === "hardware");
  const dupes = (hardware?.items || []).filter(i => routes.includes(i.route));
  if (dupes.length)
    throw new Error(`also listed under hardware: ${dupes.map(d => d.route).join(", ")}`);
  // hardware keeps what is genuinely not a disk.
  const kept = (hardware?.items || []).map(i => i.coll);
  if (!kept.includes("platform") || !kept.includes("pci"))
    throw new Error(`hardware lost its own collections: ${kept.join(", ")}`);
});

check("an observed Kind fact is not hidden by the derived one", () => {
  // network/links reports Kind from the kernel: bridge, veth, tun. Giving the
  // pseudo-column precedence rendered "link" on all 32 rows of a real host.
  const link = { id: "link:br-proxy", type: "link", facts: { Kind: "bridge" } };
  const got = ui.cellValue("Kind", link);
  if (got !== "bridge") throw new Error(`Kind resolved to ${got}, not the fact`);
});

check("a fact present with a null value is not replaced by the derived one", () => {
  /* The untested middle case, and the one an operator actually sees: on
     network/links every physical interface reports Kind: null, because the
     kernel names a kind only for software devices. `key in item.facts` is true
     for a null, so the derive is suppressed and the cell reads as absent —
     which is correct, since PSEUDO_COLUMNS.Kind can only ever yield the
     constant "link" here and that is the value the original complaint was
     about. Load-bearing in both directions: reinstating the fallback puts
     "link" back on those rows, and making the adapter omit Kind instead of
     nulling it would do the same by flipping the `in` test. */
  const nic = { id: "link:eth0", type: "link",
                facts: { Kind: null, LinkType: "ether" } };
  const got = ui.cellValue("Kind", nic);
  if (got !== null)
    throw new Error(`a null Kind resolved to ${JSON.stringify(got)}, not null`);
  if (ui.cellValue("LinkType", nic) !== "ether")
    throw new Error("LinkType, which every interface has, did not resolve");
});

check("a collection with no Kind fact still gets its object type", () => {
  // hardware/scsi is heterogeneous and carries no Kind fact; without the
  // fallback a controller renders as a disk with every disk column blank.
  const host = { id: "scsi:host0", type: "host", facts: { Vendor: "LSI" } };
  if (ui.cellValue("Kind", host) !== "host")
    throw new Error(`Kind fell back to ${ui.cellValue("Kind", host)}`);
});

check("a pseudo-column is sortable, not silently inert", () => {
  // The comparator read item.facts only, so ordering by Kind, Link, Changed or
  // Deployed did nothing whatever on the collections that define them.
  const a = { id: "a", type: "enclosure", facts: {} };
  const b = { id: "b", type: "disk", facts: {} };
  const values = [a, b].map(i => ui.cellValue("Kind", i));
  if (values.some(v => v === undefined))
    throw new Error(`sortable value missing: ${JSON.stringify(values)}`);
});

check("every pseudo-column yields undefined rather than throwing on a bare item", () => {
  // A pseudo-column runs against every row of whatever collection lists it, so
  // one that assumes a fact is present takes the whole grid down — which is how
  // a nav dereference once blanked the page.
  const bare = { id: "x:1", type: "thing", facts: {} };
  for (const key of Object.keys(ui.PSEUDO_COLUMNS)) {
    ui.cellValue(key, bare);
  }
});

/* ── severity: one ordering, three levels ─────────────────────────────────
   `info` is not a weak warn. It is what the rulebook says when a reading is
   explained rather than alarming — reclaimable ARC, an unwired spare NIC, a p3
   log line — and six hand-rolled binary comparisons in app.js each decided for
   themselves what it meant. Two decided wrongly, in opposite directions. */

const overviewRows = () =>
  document.getElementById("overview").querySelectorAll(".ov-row").map(r => ({
    label: r.querySelector(".lbl")?.textContent ?? "",
    title: r.querySelector(".lbl")?.title ?? "",
    meter: r.querySelector(".meter")?.className ?? null,
  }));

const drawOverview = (obs) => {
  ui.state.currentHost = CAPABILITIES.host.hostname;
  ui.state.status = null;              // no attention strip in these checks
  ui.state.ovPrev = null;
  ui.state.ovHistory = [];
  ui.state.ovHistoryHost = null;
  ui.renderOverview(obs);
  return overviewRows();
};

const withOpinions = (opinions) => ({ ...OVERVIEW_ARC_INFO, opinions });

check("the severity helper mirrors the rulebook and ranks nothing else", () => {
  const cases = [
    [["info", "warn"], "warn"], [["warn", "info"], "warn"],
    [["critical", "warn"], "critical"], [["info"], "info"],
    [[], null], [[null, undefined], null],
    // Row levels are not opinion levels: /v1/status ranks a vouched-for `ok`
    // row ABOVE a neutral `info` one, the opposite of OPINION_LEVELS, so one
    // table cannot serve both and these must not be rankable here.
    [["ok"], null], [["none"], null],
    // A closed enum's unknown member: abstain, never invent the loudest claim
    // in the vocabulary out of a string we cannot rank.
    [["catastrophic"], null], [["info", "catastrophic"], "info"],
  ];
  for (const [input, want] of cases) {
    const got = ui.worstOpinionLevel(input);
    if (got !== want)
      throw new Error(`worstOpinionLevel(${JSON.stringify(input)}) = ${got}, want ${want}`);
  }
});

// THE REGRESSION. An `info` opinion on a mapped overview key was coerced to
// warn, so the memory meter went yellow directly above a sentence saying the
// reading was occupancy, not pressure — the UI contradicting the rulebook it
// exists to render.
check("an info opinion leaves its meter neutral", () => {
  const used = drawOverview(OVERVIEW_ARC_INFO).find(r => r.label === "used");
  if (!used) throw new Error("no memory row was rendered");
  if (/\b(warn|critical)\b/.test(used.meter))
    throw new Error(`info painted the memory meter "${used.meter}"`);
  // Positively: the level REACHED the meter. Silently dropping it would also
  // satisfy the assertion above.
  if (!/\binfo\b/.test(used.meter))
    throw new Error(`the info level never reached the meter: "${used.meter}"`);
  // And the sentence is the reason the bar is calm, so it must be reachable.
  if (!used.title.includes("occupancy, not pressure"))
    throw new Error(`the opinion's sentence is not on the row: "${used.title}"`);
});

// The paired positive, without which a bug that stops colouring meters at all
// passes the check above.
check("a warn opinion still paints its meter", () => {
  const rows = drawOverview(withOpinions([{
    key: "memory-available", level: "warn",
    message: "MemAvailable is nearly exhausted.",
    evidence: ["MemAvailableBytes", "MemTotalBytes"] }]));
  const used = rows.find(r => r.label === "used");
  if (!/\bwarn\b/.test(used.meter)) throw new Error(`warn rendered "${used.meter}"`);
});

// Last-write-wins: the loop assigned instead of reducing, so two opinions on
// one meter meant the later one won regardless of severity.
check("the worst opinion on a meter wins whatever order it arrives in", () => {
  for (const order of [["critical", "info"], ["info", "critical"]]) {
    const rows = drawOverview(withOpinions(order.map(level => ({
      key: "memory-available", level, message: `${level} sentence`,
      evidence: ["MemTotalBytes"] }))));
    const used = rows.find(r => r.label === "used");
    if (!/\bcritical\b/.test(used.meter))
      throw new Error(`opinions in order ${order} yielded "${used.meter}"`);
    if (!used.title.startsWith("critical"))
      throw new Error(`the sentence did not follow the level: "${used.title}"`);
  }
});

// An unrankable level colours nothing rather than inventing a verdict — the
// enum is closed, so an unknown value means a bug, not an emergency.
check("an unrecognised level colours nothing", () => {
  const rows = drawOverview(withOpinions([{
    key: "memory-available", level: "catastrophic",
    message: "from a newer agent than this page", evidence: ["MemTotalBytes"] }]));
  const used = rows.find(r => r.label === "used");
  if (used.meter !== "meter")
    throw new Error(`an unknown level reached the meter as "${used.meter}"`);
});

// Absence of severity was rendered identically to a judged-neutral `info`.
// adapters/network.py omits the field for a quiet operstate specifically to
// avoid "a neutral dot two auditors misread as a verdict" — and this put it back.
check("a row with no severity is not drawn as a neutral verdict", () => {
  Object.assign(ui.state, {
    subsystem: "network", collection: "links",
    /* Kind is null and LinkType carries the layer, which is what the adapter
       really emits: the kernel names a Kind only for software devices, so every
       physical interface and loopback has none. An earlier version of this
       fixture invented Kind: "loopback" / "ether" — shapes no host produces. */
    page: { total: 2, next_cursor: null, status: "ok", items: [
      { id: "link:lo", type: "link", native_id: "lo",
        facts: { OperState: "unknown", Kind: null, LinkType: "loopback" } },  // no severity field
      { id: "link:enp2s0", type: "link", native_id: "enp2s0",
        facts: { OperState: "down", Kind: null, LinkType: "ether",
                 ParentBus: "pci", ParentDev: "0000:02:00.0" },
        worst_opinion_level: "info" },                                       // judged neutral
    ] },
    filterText: "", facet: null, sortKey: null, showHidden: false,
    owners: null, detailObs: null, selectedId: null, factDict: null,
  });
  ui.renderGrid();
  const dots = document.getElementById("grid-body").querySelectorAll(".dot");
  if (dots.length !== 2) throw new Error(`${dots.length} dots for 2 rows`);
  const [absent, judged] = dots.map(d => d.className);
  if (absent === judged)
    throw new Error(`absent and info render identically: ${absent} | ${judged}`);
  if (!absent.split(" ").includes("none"))
    throw new Error(`absent severity rendered "${absent}"`);
  if (!judged.split(" ").includes("info"))
    throw new Error(`info rendered "${judged}"`);
  // The recorded failure mode is a mark being misread, so the mark must speak.
  if (!dots[0].title.includes("nothing here is judged"))
    throw new Error(`the absent dot says "${dots[0].title}"`);
});

check("a tap or veth shows the workload's address, not just its name", () => {
  /* The row that prompted this: network/links on a VM host renders
     "vnet1 appliance  fe80::fc00:ff:fe00:80/64". The fe80 is genuinely all the
     TAP has — the guest's own address lives on the guest — so the reader
     concludes the VM has no IPv4. The join already knows the address; it just
     stopped at the name. Docker veths have the identical problem. */
  Object.assign(ui.state, {
    subsystem: "network", collection: "links",
    page: { total: 2, next_cursor: null, status: "ok", items: [
      { id: "link:vnet1", type: "link", native_id: "vnet1",
        facts: { OperState: "unknown", Kind: "tap", LinkType: "ether",
                 Addresses: ["fe80::fc00:ff:fe00:80/64"] } },
      { id: "link:vnet9", type: "link", native_id: "vnet9",
        facts: { OperState: "unknown", Kind: "tap", LinkType: "ether",
                 Addresses: ["fe80::dead/64"] } },
    ] },
    owners: {
      vnet1: { parts: [{ label: "appliance", href: "#/x", addrs: ["10.0.0.80"] }] },
      // libvirt saw no address for this one: no lease, no ARP entry. Silence
      // is the honest render — never another workload's address.
      vnet9: { parts: [{ label: "quiet-vm", href: "#/y", addrs: [] }] },
    },
    filterText: "", facet: null, sortKey: null, showHidden: false,
    detailObs: null, selectedId: null, factDict: null,
  });
  ui.renderGrid();
  const rows = document.getElementById("grid-body").querySelectorAll("ident");
  const text = rows.map(r => r.textContent);
  if (!text[0].includes("appliance"))
    throw new Error(`owner name missing: ${text[0]}`);
  if (!text[0].includes("10.0.0.80"))
    throw new Error(`the guest's address is not on the row: ${text[0]}`);
  // It must be the OWNER's address, marked as such — not folded into the
  // link's own Addresses column, which belongs to the interface.
  const marked = document.getElementById("grid-body").querySelectorAll("owner-addr");
  if (marked.length !== 1)
    throw new Error(`${marked.length} owner-addr spans, want exactly 1`);
  if (!marked[0].title.includes("not this interface"))
    throw new Error(`owner-addr does not attribute itself: ${marked[0].title}`);
  // And a workload whose address could not be observed shows none.
  if (/\d+\.\d+\.\d+\.\d+/.test(text[1]))
    throw new Error(`invented an address for a guest with none: ${text[1]}`);
});

check("info and ok rows earn no badge, and a badge counts only what it claims", () => {
  ui.state.capabilities = CAPABILITIES;
  ui.state.status = STATUS;
  ui.renderNav();
  ui.applyNavBadges();
  const nav = document.getElementById("nav");
  const items = nav.querySelectorAll("nav-item");
  const badgeOf = (route) =>
    items.find(n => n.dataset.route === route)?.querySelector("nav-badge") ?? null;

  // 327 rows, 115 of them info: a badge is an attention claim and info makes none.
  const units = badgeOf("units/units");
  if (units) throw new Error(`units/units badged "${units.textContent}" — info is not attention`);

  // 1 critical + 2 warn = 3. The 3 ok rows are counted by the roll-up, not here.
  const mounts = badgeOf("storage/mounts");
  if (mounts?.textContent !== "3")
    throw new Error(`storage/mounts badge reads ${mounts?.textContent}, want 3`);
  if (!mounts.className.split(" ").includes("critical"))
    throw new Error(`badge class "${mounts.className}" — the worst level must win`);
  if (mounts.title !== "1 critical, 2 warn")
    throw new Error(`badge title reads "${mounts.title}"`);

  // The subsystem dot is the worst BADGED level in the group: storage is walked
  // mounts (critical) then pools (warn), so a running maximum must not decay.
  // Found by route rather than by heading text, which is what navModel() is for
  // — and because this stub's textContent hides a node's own text once a child
  // is appended, so the label reads "" the moment it wears a dot.
  const storage = nav.querySelectorAll("nav-sub").find(box =>
    box.querySelectorAll("nav-item").some(n => n.dataset.route === "storage/mounts"));
  if (!storage) throw new Error("no nav section carries storage/mounts");
  const dot = storage.querySelector("sub-label")?.querySelector("dot")?.className ?? null;
  if (!dot?.split(" ").includes("critical"))
    throw new Error(`storage subsystem dot is "${dot}"`);
});

/* ── the link equation ────────────────────────────────────────────────────
   Speed × lanes = bandwidth, drawn. It exists because the four link facts read
   as four unrelated numbers: a reader asked what "x2 of x4" cost them, could
   not answer from the screen, and did the PCIe arithmetic by hand offline.
   Every branch below is a shape a real host actually produces, and each one
   must degrade rather than invent — the panel says less, never something
   untrue, when a fact it wants is absent. */

const flatten = (node) => {
  if (!node) return "";
  const own = node.textContent ?? "";
  const kids = (node.children || []).map(flatten).join(" ");
  return `${own} ${kids}`.replace(/\s+/g, " ").trim();
};
const marks = (panel) => {
  const found = [];
  const walk = (n) => {
    if (n.className === "eq-v eq-lanes") found.push(n.children.map(c => c.className));
    (n.children || []).forEach(walk);
  };
  walk(panel);
  return found[0] || [];
};

check("the link equation states speed, lanes and the product", () => {
  // An x4-capable card in an M.2 socket wired for two lanes.
  const panel = ui.linkPanel({
    LinkSpeed: "8.0 GT/s PCIe", LinkSpeedMax: "8.0 GT/s PCIe",
    LinkWidth: 2, LinkWidthMax: 4, SlotLinkWidthMax: 2,
    LinkBandwidthBytesPerSec: 1969230768, LinkBandwidthMaxBytesPerSec: 3938461536,
  });
  const shown = flatten(panel);
  for (const want of ["8.0 GT/s PCIe", "the rate of one lane", "×",
                      "x2 lanes of x4", "=", "2.0 GB/s", "each way",
                      "the slot provides x2", "3.9 GB/s"]) {
    if (!shown.includes(want)) throw new Error(`missing ${JSON.stringify(want)} in: ${shown}`);
  }
  const lanes = marks(panel);
  if (lanes.join(",") !== "on,on,off,off")
    throw new Error(`lane marks were ${lanes.join(",")}, expected two lit of four`);
});

check("a link at full width draws no dark lanes", () => {
  const panel = ui.linkPanel({
    LinkSpeed: "8.0 GT/s PCIe", LinkSpeedMax: "8.0 GT/s PCIe",
    LinkWidth: 4, LinkWidthMax: 4, SlotLinkWidthMax: 4,
    LinkBandwidthBytesPerSec: 3938461536, LinkBandwidthMaxBytesPerSec: 3938461536,
  });
  if (marks(panel).includes("off")) throw new Error("an unnarrowed link drew an unlit lane");
  // Drawn anyway: a healthy device is where the concept is cheapest to learn.
  if (!flatten(panel).includes("3.9 GB/s")) throw new Error("healthy link showed no bandwidth");
});

check("a SATA link is not given lanes it does not have", () => {
  const panel = ui.linkPanel({ LinkSpeed: "6.0 Gbps", LinkSpeedMax: "6.0 Gbps" });
  const shown = flatten(panel);
  if (shown.includes("lane")) throw new Error(`serial link claimed lanes: ${shown}`);
  if (!shown.includes("negotiated rate")) throw new Error(`no rate caption: ${shown}`);
  if (marks(panel).length) throw new Error("serial link drew lane marks");
});

check("an unrecognised PCIe generation yields no bandwidth term", () => {
  // The conversion table is exact-match: a generation it has not met must make
  // the panel say less, not guess a number.
  const shown = flatten(ui.linkPanel({
    LinkSpeed: "128.0 GT/s PCIe", LinkWidth: 2, LinkWidthMax: 4, SlotLinkWidthMax: 2,
  }));
  if (/GB\/s|MB\/s/.test(shown)) throw new Error(`invented a bandwidth: ${shown}`);
  if (!shown.includes("x2 lanes of x4")) throw new Error(`lost the lane count: ${shown}`);
});

check("an object with no link facts gets no panel at all", () => {
  if (ui.linkPanel({ Model: "256GB SSD" }) !== null)
    throw new Error("drew a link panel for something with no link");
});

check("lane counts and rates carry their units", () => {
  const cases = [["LinkWidth", 2, "x2 lanes"], ["SlotLinkWidthMax", 2, "x2 lanes"],
                 ["LinkBandwidthBytesPerSec", 1969230768, "2.0 GB/s"]];
  for (const [key, value, want] of cases) {
    const got = ui.scalarText(key, value, false);
    if (got !== want) throw new Error(`${key} rendered ${got}, expected ${want}`);
  }
  // Throughput is decimal where capacity is binary: 2.0 GB/s must not become
  // 1.8 GiB/s and disagree with every PCIe reference the reader checks.
  if (ui.scalarText("SizeBytes", 1969230768, false) === "2.0 GB/s")
    throw new Error("capacity and throughput are sharing a unit ladder");
});

check("a missing fact dictionary costs tooltips, not the page", () => {
  ui.state.factDict = null;
  if (ui.factHelp("LinkSpeed") !== null) throw new Error("invented help with no dictionary");
  ui.state.factDict = { subsystems: { hardware: { nvme: { LinkSpeed: "one lane's rate." } } } };
  if (ui.factHelp("LinkSpeed", "hardware", "nvme") !== "one lane's rate.")
    throw new Error("dictionary lookup missed a documented fact");
  if (ui.factHelp("LinkSpeed", "hardware", "scsi") !== null)
    throw new Error("nvme's sentence leaked onto scsi, where lanes do not exist");
});

if (failures.length) {
  console.log(`\n${failures.length} failed: ${failures.join(", ")}`);
  process.exit(1);
}
console.log("\nall chrome checks passed");
