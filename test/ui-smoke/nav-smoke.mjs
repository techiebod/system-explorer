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
  get textContent() {
    return this.children.length ? this.children.map(c => c.textContent).join("") : this._text;
  }
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

/* ── realistic inputs, matching what silo actually serves ─────────────── */

const CAPABILITIES = {
  version: "0.4.0", revision: "abc1234",
  host: { hostname: "silo", machine_id: "f0d5c28d8b5845a1bddbe46a87f9415a" },
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
    // The empty-hiding case, and the one that started all this.
    storage: { arrays: { worst: null, counts: {}, total: 0 },
               pools: { worst: "warn", counts: { warn: 1 }, total: 1 } },
  },
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
const EXPORTS = "\n;globalThis.__ui = { state, renderNav, applyNavBadges, renderBuild, navRoutes, navModel, cellValue, PSEUDO_COLUMNS };";
vm.runInContext(readFileSync(APP, "utf8") + EXPORTS, context, { filename: "app.js" });
const ui = sandbox.__ui;

const failures = [];
const check = (name, fn) => {
  try { fn(); console.log(`  PASS  ${name}`); }
  catch (err) { failures.push(name); console.log(`  FAIL  ${name}\n        ${err.message}`); }
};

console.log("operator UI chrome smoke test");

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

if (failures.length) {
  console.log(`\n${failures.length} failed: ${failures.join(", ")}`);
  process.exit(1);
}
console.log("\nall chrome checks passed");
