/* System Explorer — operator UI (SPEC §8).
   Vanilla, no build step. Consumes only the public /v1 API; renders only
   what is in the envelope. Deep links: #/subsystem/collection[/object-id] —
   behind the per-site hub (hub/server.py) a host name is the first segment
   (#/host/…) and every agent call is proxied through /agents/<host>. A
   machine served by several agent processes is ONE page, addressed by its
   primary member's name: the mates' subsystems merge into the nav, and
   api() re-aims each subsystem's fetches at the process that owns it.

   Detail is an inline expansion beneath the row that produced it. Evidence
   offers two views of one captured payload — a command-style rendering and
   raw JSON; nothing is ever executed to produce either.

   Concurrency: every fetch captures state.epoch (bumped on collection
   change) and its own target; responses that no longer match current state
   are discarded. The last *wanted* response wins, not the last to arrive. */

"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  views: null,          // se.views/1 from /hub/views; null = not a hub, or none
  hub: null,             // /hub/hosts payload when the hub serves us, else null
  currentHost: null,     // hub mode: the agent every api() call is proxied to
  capabilities: null,
  // Merged machine: which machine-mate answers for each subsystem the primary
  // does not serve itself. api() consults it at fetch time; absent (or empty)
  // means every ask goes to the current host. The primary's own subsystems
  // are deliberately never entered, which is what makes it win any collision
  // without a tie-break ever running.
  agentForSubsystem: {},
  status: null,          // /v1/status roll-up for the current host (nav badges)
  subsystem: null,
  collection: null,
  page: null,
  selectedId: null,
  detailObs: null,
  evidence: null,        // {data, view}
  sortKey: null,
  sortDir: 1,
  // A `look` link's arrival intent, armed on click and consumed once at the
  // route it names. Deliberately session state and not part of the URL: the
  // link's href is the destination collection's own address and must stay
  // copyable as that (see lookLinks).
  lookArrival: null,
  // {route, host, fact}: the ordering fact that arrival made visible, for
  // this visit only. Nothing about it is stored — see columnsFor. The host is
  // part of the key because the host dropdown keeps the route (see
  // takeLookArrival); it is null off-hub, where it never differs.
  lookColumn: null,
  filterText: "",
  facet: null,
  // Keys of the HIDDEN groups the reader has revealed on this route. A set,
  // not a flag: each group is revealed on its own and any number can be on.
  revealed: new Set(),
  colPicker: false,      // the columns dropdown in the facet bar
  lookupDraft: null,     // in-progress lookup input, preserved across refresh
  lookupCatalog: null,   // launcher entries, fetched once per host
  factDict: null,        // /v1/facts: what each fact MEANS, fetched once per host
  ovIdentity: null,      // overview KPI identity facts, cached per host
  ovPrev: null,          // overview's previous counter sample (client-side rates)
  owners: null,          // native_id -> owning workload, for the current list
  ovHistory: [],         // sparkline ring: derived cpu/mem samples, this session
  ovHistoryHost: null,   // which host that ring belongs to
  observedAt: null,
  refreshTimer: null,
  suppressAutoOpen: false,
  epoch: 0,
  hostGen: 0,            // bumped only by loadHost: identifies a load invocation
};

const COLUMNS = {
  "units/units": ["ActiveState", "SubState", "Description"],
  /* Utilisation and stall side by side, because they answer different
     questions and disagree in the interesting cases: a workload pegging a
     core with nothing contended stalls nobody, and one starved by somebody
     else's I/O stalls while consuming almost nothing. Parent leads so the
     ladder is readable down the page. */
  "network/listening": ["Protocol", "LocalAddress", "LocalPort", "Scope", "Uid"],
  /* The rendered rule leads, because it is the thing being read, and
     Comprehension sits beside it because it says how much of the rule that
     text actually is. Position is a column rather than a detail: nftables is
     first-match-wins, so order is meaning. */
  /* Family leads, because the same chain name in ip and ip6 is two chains
     and a rule admitting a port in one says nothing about the other — a
     column the estate needed the moment a host ran both stacks. Verdict
     sits beside Rendered rather than at the end: what a rule DOES is the
     second question after what it matches, and burying it behind
     Comprehension put the answer off the right-hand edge. */
  "network/nft-rules": ["Family", "Table", "Chain", "Position", "Rendered",
                        "Verdict", "JumpTarget", "Comprehension"],
  /* The shape of the ruleset, answers first: whether the kernel enters here
     at all, then where in the path, then what it falls back to. RuleCount
     last, because it is the one number on the row that says nothing about
     what any rule permits. */
  "network/nft-chains": ["Family", "Table", "Name", "BaseChain", "Hook",
                         "Priority", "Policy", "JumpedFrom", "RuleCount"],
  /* The two answers, not the socket's own description. Without a preset the
     table fell back to the first five facts and showed protocol, address,
     port, scope and a constant sentence — every column identical or already
     in the object name, and the closure answers this collection exists to
     give were off the right-hand edge. PathCoverage is deliberately NOT here:
     it is the same sentence on every row, which is right for an opened object
     and for a model reading one, and pure noise as a column. */
  "network/port-exposure": ["LocalPort", "Protocol", "Scope",
                            "AdmittedFromCertain", "AdmittedFromPossible",
                            "ClosureGap"],
  "resources/workloads": ["Parent", "CpuUsageUsec", "MemoryCurrentBytes",
                          "IoReadBytes", "IoWrittenBytes", "PsiIoFullAvg60",
                          "PsiCpuSomeAvg60", "PsiMemoryFullAvg60"],
  "logs/journal": ["Timestamp", "Priority", "SyslogIdentifier", "Message"],
  "docker/containers": ["State", "Status", "Image", "ComposeProject"],
  "docker/volumes": ["Driver", "Mountpoint", "ComposeProject"],
  "docker/networks": ["Driver", "BridgeInterface", "ComposeProject", "Internal"],
  "storage/mounts": ["Source", "FsType", "UsePercent", "SizeBytes", "AvailBytes"],
  "storage/block-devices": ["Type", "Transport", "Size", "FsType", "Mountpoints", "Model"],
  "storage/arrays": ["Status", "Level", "SyncPercent", "RaidDisks", "SizeBytes"],
  "storage/pools": ["State", "Redundancy", "DeviceFailuresTolerated",
                    "CapacityPercent", "ScanFunction", "Errors"],
  "storage/datasets": ["UsedBytes", "SnapshotUsedBytes", "AvailBytes", "UsePercent", "Mountpoint", "ReadOnly", "Mounted"],
  "nix/generations": ["NixosVersion", "Kernel", "ConfigurationRevision", "Changed", "Deployed", "Created", "Current", "Booted", "Profile"],
  "packages/packages": ["Name", "Version", "Manager", "Architecture", "StorePath"],
  "system/overview": ["LoadAvg1", "LoadPerCpu1", "MemUsedPercent", "MemAvailableBytes", "SwapUsedPercent", "UptimeSeconds"],
  "hardware/platform": ["ProductName", "CPUModel", "CPUs", "MemoryTotalBytes", "BiosVersion"],
  "hardware/pci": ["Class", "Vendor", "Model", "Driver"],
  "hardware/usb": ["Vendor", "Product", "SpeedMbps", "USBVersion"],
  "hardware/scsi": ["Kind", "Transport", "Vendor", "Model", "SizeBytes", "Link", "State", "Block", "Devices", "EnclosureSlot", "SmartTemperatureC"],
  "hardware/nvme": ["Link", "Model", "FirmwareRev", "Serial", "State", "SmartTemperatureC", "Namespaces"],
  /* Three columns answer "what is this device", because no one field does and
     none of them can be synthesised into another without inventing a value.
     Kind is the software device type, blank on anything the kernel gives no
     linkinfo. LinkType is the link layer, present on everything. ParentBus is
     the bus behind it, present only where there is hardware — and it says pci
     on a real NIC but virtio on a VM's, which is exactly the distinction a
     synthesised "physical" would have destroyed. Each cell is read; the reader's
     eye does the join, losslessly. */
  "network/links": ["OperState", "Kind", "LinkType", "ParentBus", "MTU",
                    "MACAddress", "Addresses"],
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
  /* Speed and width are independent dimensions that MULTIPLY into bandwidth —
     8.0 GT/s is the per-lane rate, x2 is the lane count, so Gen3 x2 carries half
     of Gen3 x4 at the same "speed". Shown as four separate facts, an identical
     speed pair sat next to a differing width pair and the warning looked
     self-contradictory. One string makes the comparison a single glance. */
  Link: (item) => {
    const f = item.facts;
    if (!f.LinkSpeed && !f.LinkWidth) return null;
    const now = [f.LinkSpeed, f.LinkWidth ? `x${f.LinkWidth}` : null]
      .filter(Boolean).join(" ");
    const max = [f.LinkSpeedMax, f.LinkWidthMax ? `x${f.LinkWidthMax}` : null]
      .filter(Boolean).join(" ");
    return max && max !== now ? `${now}  (capable of ${max})` : now;
  },
  /* A generation's delta is a table of {Kind, Name, From, To} rows — unreadable
     in a grid cell, and the whole point of the row is to be scanned. Count it
     here, by kind, and render the rows themselves in the expansion. Null when
     the generation records no manifest, so the column stays empty rather than
     claiming "0 changes" about something never measured. */
  Changed: (item) => {
    const counts = item.facts.DeltaCounts;
    if (!counts || typeof counts !== "object") return null;
    const entries = Object.entries(counts);
    if (!entries.length) return "no change";
    return entries.map(([kind, n]) => `${n} ${kind}${n === 1 ? "" : "s"}`).join(", ");
  },
  /* How this generation came to be, in one cell. An expected-but-absent receipt
     is what the deployment-unattested opinion is about, so say it plainly here
     rather than leaving the cell blank and the dot unexplained. */
  Deployed: (item) => {
    const f = item.facts;
    if (f.Deployment === undefined) return null;
    if (f.Deployment === null) return "no receipt";
    return [f.Deployment.Mode, f.Deployment.Outcome].filter(Boolean).join(" · ") || null;
  },
};

/* THE resolution rule for a column's value, used by the grid and the sort alike.
   Those two disagreed. The cell gave a pseudo-column unconditional precedence, so
   network/links — whose Kind is a real fact from the kernel, bridge or veth or
   tun — rendered "link" on every row, the derived value hiding the observed one.
   The sort read item.facts only, so ordering by Kind, Link, Changed or Deployed
   silently did nothing at all.

   An observed fact always wins; a pseudo-column supplies only what the item does
   not carry. That is what makes Kind able to mean both things: hardware/scsi has
   no Kind fact and wants its object type, network/links reports one and must keep
   it. */
function cellValue(key, item) {
  if (item.facts && key in item.facts) return item.facts[key];
  const derive = PSEUDO_COLUMNS[key];
  return derive ? derive(item) : undefined;
}

const FACETS = {
  "units/units": (item) => item.type,
  "logs/journal": (item) => item.facts.SyslogIdentifier,
  "docker/containers": (item) => item.facts.State,
  "hardware/pci": (item) => item.facts.Class,
  "hardware/scsi": (item) => item.type,
};

/* Rows hidden by default, systemctl-status style: the default view is what
   is running (plus anything failed — that is never hidden). A toggle chip
   in the facet bar reveals the rest; the API always returns everything.

   SEVERAL groups per route, each revealed on its own, because one route's
   rows can be quiet for unrelated reasons and a reader wants them back one
   reason at a time. Order is meaningful: a row belongs to the FIRST group
   that claims it and to no other, so the chip counts partition what is
   hidden and add up to the difference the crumb states. Two chips whose
   numbers overlap would be a filtered view that cannot be audited by
   arithmetic, which is the same defect as not announcing the filter at all.

   `key` is what state.revealed holds; keep it stable, it is the identity of
   a group across renders.

   ONE GROUP PER KIND, never a shared "mounts & timers" chip. A shared chip
   would still name what it holds and how much of it, and the arithmetic
   would still close — it fails on the third property only. A reader chasing
   a mount would have to take the timers back to see it, and there would be
   no step smaller than all-or-nothing. That independence is the whole
   difference between hiding as a presentation choice and hiding as a loss,
   and a line of bar width is not worth trading for it; the run in
   renderFacets() is how the width was paid for instead. */

/* A group that hides a whole KIND of unit. Four of the five groups below are
   of this shape, so the rule they share is stated once here rather than four
   times: `LoadState === "loaded"` narrows each group to units this host
   actually has.

   A not-found unit is the opposite statement — something here declares a
   dependency on a unit that is NOT installed — and no argument about what a
   kind of unit DOES covers that. systemd reports such a unit inactive, so in
   practice the inactive group claims it and one chip brings it back; the
   narrowing is what stops a kind rule swallowing it silently should it ever
   arrive in some other state, which for `.device` is not hypothetical: that
   kind's resting state is `activating` forever.

   The key is the type name — already stable, and already what the type facet
   calls the same rows, which is what makes the ghost chip legible as the way
   back to a facet chip that hiding removed. */
const kindGroup = (type, label) => ({
  key: type, label,
  match: (item) => item.type === type && item.facts.LoadState === "loaded",
});

const HIDDEN = {
  "units/units": [
    { key: "inactive", label: "inactive",
      match: (item) => item.facts.ActiveState === "inactive" },
    /* Half of a busy host's unit list is `.device` — 410 of 808 rows on the
       busiest host measured, 51% of the page. They are not hidden for being
       quiet: a device unit's resting state is ActiveState `activating`,
       SubState `tentative`, forever, so no rule about what is running or
       should be running will ever catch one. They are hidden for what they
       ARE. A `.device` unit is systemd's record that a device exists; it
       starts nothing, and a reader after the device inventory has the whole
       hardware subsystem, which observes the devices themselves rather than
       systemd's shadow of them.

       `LoadState === "loaded"` — the narrowing kindGroup() applies to every
       group of this shape, argued there — keeps it to exactly that record.

       TARGETS ARE DELIBERATELY NOT IN THIS GROUP (~35 rows). The argument
       for including them is real: a target is a synchronisation point, it
       runs nothing either, and by the "does it do something" test it fails
       exactly as a device does. It is refused for two reasons. First, a
       target's ActiveState is load-bearing where a device's is not —
       "reached" is what active MEANS for a target, and an unreached
       multi-user.target or an active emergency.target is a fact about this
       boot that an admin reads directly. Second, and because of that, the
       inactive group above ALREADY does the right thing to targets: the
       unreached ones fall out, the reached ones stay, which is the
       operator's rule applied to them rather than an exemption from it.
       Devices needed a new group precisely because no state rule can reach
       them. The operator has since asked for three more kinds and still not
       for this one; devices carried a measured argument and targets do not,
       so targets keep the treatment they have until someone asks. */
    kindGroup("device", "device units"),

    /* mount, timer, socket — asked for by the operator, whose reason was the
       page rather than the rows: "whilst they're useful we need the default
       to be more workable with and it's really long". Mounts and timers were
       the instruction. Sockets were "I'm tempted to say sockets too", which
       is a question, not a decision, so it is answered with the measurement
       below and left one deletable line away from gone.

       These do NOT inherit the device argument and must not be written as if
       they did. A device unit is hidden because it says nothing AND because
       another subsystem observes the same things properly. Of the three only
       `mount` has both halves: its resting state is `active (mounted)`
       forever, and storage/mounts observes the mount table itself — source,
       target, fs type, options — which is strictly more than the three
       columns this row shows. A timer and a socket each genuinely start
       something, and neither has a second home anywhere in the product:
       there is no timers collection and no listeners collection. They are
       hidden for VOLUME, and saying so is the point.

       Volume is a legitimate reason only because of what the mechanism
       guarantees, so the guarantees ARE the justification: a failed one is
       never hidden (structurally, in hidingGroup); each kind's count sits on
       its own chip; the chips sum to the total the run announces and that
       total closes against the crumb; and one click brings any one kind back
       without the others. If a later edit breaks one of those, these are the
       groups to delete — not the invariant to weaken.

       WHAT IT COSTS, measured against the 808-row page (169 service, 80
       socket, 40 mount, 40 timer, 35 target, 20 scope, 14 slice, 410
       device): mounts+timers take the default from 260 rows to 190, and
       sockets take it to 130. The socket-shaped caveat the operator is owed
       before keeping that last group: a socket-activated service sits
       `inactive (dead)` between connections, so the inactive group already
       hides the service half of it; hiding sockets removes the other half,
       and such a service then has no trace at all on the default page.
       Timers and the services they trigger have the same shape. The trace
       comes back with one chip, and it is the true price of the instruction
       rather than an argument against it.

       Note the ordering consequence, which the chip numbers make visible:
       the inactive group runs first and claims the quiet ones, so these
       chips read 40 mounts, 30 timers, 60 sockets rather than 40/40/80. A
       chip counts what toggling it reveals, which is the property worth
       keeping; the missing 10 and 20 are on the inactive chip, and no row is
       counted twice. */
    kindGroup("mount", "mounts"),
    kindGroup("timer", "timers"),
    /* ── to drop the socket group, delete this one line. Nothing else knows
          about it: chip, count, crumb hover and run total are all derived. */
    kindGroup("socket", "sockets"),
  ],
  "hardware/scsi": [
    { key: "empty-hosts", label: "empty hosts",
      match: (item) => item.type === "scsi-host" && !item.facts.Devices },
  ],
};

/* Which group hides this row, or null if it stays. The one exemption is
   structural rather than left to each predicate: a row the rulebook called
   critical is never suppressed, whatever the group matches on. The old
   single group got that for free — nothing whose ActiveState is `inactive`
   is a failed unit — but a group that matches on KIND has no such luck, and
   "the default view never swallows a failure" is the promise the toggle
   rests on. It cannot be re-derived correctly in every predicate anyone
   adds later, so it is enforced once, here.

   It reaches the inactive group too, which formerly hid a critical inactive
   row if one ever existed. Nothing emits that today (unit-health is critical
   only for ActiveState `failed`), so the widening is unobservable — but the
   contract was already claiming it, and a promise honoured by coincidence is
   one waiting to be broken by an unrelated edit to the rulebook.

   Critical only, not warn: the inactive group hides a unit carrying a
   restart-churn warning today, and widening the exemption to `warn` would
   quietly change what that group has always meant. That is a separate call
   for whoever wants it, not a side effect of adding a second group. */
function hidingGroup(item, route) {
  if (item.worst_opinion_level === "critical") return null;
  for (const group of HIDDEN[route] || []) if (group.match(item)) return group;
  return null;
}

/* The rows the hide rules leave on the page, before the facet and the text
   filter narrow it further. What the facet counts describe, and what the
   crumb calls "shown". */
function afterHiding(items, route) {
  if (!HIDDEN[route]) return items;
  return items.filter(it => {
    const group = hidingGroup(it, route);
    return !group || state.revealed.has(group.key);
  });
}

/* What each group answers for on this page: [group, n] pairs in HIDDEN's
   order, groups holding nothing omitted. Counts what hidingGroup() ASSIGNS
   rather than what match() alone would claim, so a chip's number is exactly
   the set of rows toggling it reveals — critical rows, and rows an earlier
   group took, belong to somebody else. Independent of what is revealed: the
   number beside a chip must not change when the chip is pressed. */
function hiddenCounts(items, route) {
  const groups = HIDDEN[route] || [];
  const n = new Map(groups.map(g => [g.key, 0]));
  for (const item of items) {
    const group = hidingGroup(item, route);
    if (group) n.set(group.key, n.get(group.key) + 1);
  }
  return groups.map(g => [g, n.get(g.key)]).filter(([, count]) => count > 0);
}

/* Where an object id opens — SERVED BY THE AGENT, never a table in here.

   This was a hand-kept map of 31 prefixes until 2026-08-14, and it is the
   fourth-copy failure the fact dictionary exists to prevent, caught in the
   act: the entire application tier was missing from it, so every app-tier
   relationship chip and every fact value naming an app object rendered as
   dead text. Nothing in the browser could have noticed, because nothing in
   the browser mints ids.

   /v1/capabilities now carries object_prefixes, narrowed to the collections
   the host actually answers, as an ORDERED list per prefix: the first entry
   is the canonical home and any further entries are the same object seen by
   another collection. Five prefixes are claimed twice — units/units and
   resources/workloads publish the same `unit:` ids, network/listening and
   network/port-exposure the same `socket:` ones — which is why resolution
   takes a hint and why a bare fallback is the LAST resort, not the rule.

   An agent predating the field publishes nothing, and then nothing links.
   That is deliberate: a stale local table is how the last one went wrong. */
function idHomes(objectId) {
  const sep = String(objectId ?? "").indexOf(":");
  if (sep <= 0) return [];
  const prefix = objectId.slice(0, sep);
  return state.capabilities?.object_prefixes?.[prefix] || [];
}

/* [subsystem, collection] for an id, or null if nothing here serves it.

   `hint` is the subsystem a relationship declared for its target — the only
   thing that can disambiguate `unit:` between the systemd view and the
   cgroup one, and the reason env.rel() takes a subsystem= at all. Failing
   that, STAY WHERE THE READER IS: a `unit:` value on a resources page means
   the resources row, and jumping to units would be the same wrong answer
   the old global table gave for every one of these. */
function routeForId(objectId, hint = null) {
  const homes = idHomes(objectId);
  if (!homes.length) return null;
  const pick = (hinted) => homes.find(h => h.subsystem === hinted);
  const home = (hint && pick(hint)) || pick(state.subsystem) || homes[0];
  return [home.subsystem, home.collection];
}

/* State badges. One table, several vocabularies — `dead` is a normal systemd
   SubState and a warned-about docker container; `down` is a fault on a NIC
   carrying addresses and correct on an empty bridge — so the badge may only
   colour a word whose severity does NOT depend on which collection said it.

   The rule this settles on: the badge may never claim MORE than the rulebook
   can. Under-claiming is safe, because the row's dot carries the verdict and
   comes from rules/ per collection; over-claiming puts a warning beside a row
   the rulebook deliberately declined to judge, which is how a table in the
   browser becomes a second opinion nobody wrote down.

   Two words used to over-claim, and both re-asserted a judgement the rulebook
   had specifically removed:

   `down` — rules/network.py calls a down link INFO in three of its four
   shapes: a veth (its health is the container's), an empty bridge (down by
   design, the docker0 false positive of 2026-08-10), and a link with nothing
   configured on it (an unwired spare NIC — "inventory, not trouble", an
   operator call). Only a down link carrying addresses warns. Ambering all four
   is the cry-wolf that call was made to stop.

   `exited` — rules/docker.py warns only when the exit code is not 0 or absent.
   A cleanly-exited container earns no opinion at all and the adapter gives its
   row `info`, so an amber badge sat beside its own faint info dot. */
const VALUE_CLASS = {
  active: "ok", running: "ok", up: "ok", online: "ok", loaded: "ok", enabled: "ok",
  // Unambiguous across every collection that can emit them.
  failed: "crit", crashed: "crit", unhealthy: "crit", degraded: "crit",
  paused: "warn", blocked: "warn", restarting: "warn",
  // Context-dependent: the dot says whether these are trouble.
  down: "neutral", exited: "neutral",
  inactive: "neutral", shutoff: "neutral", dead: "neutral", unknown: "neutral",
};

const PRIORITY_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"];
// The one syslog priority the rulebook trusts as severity from the number alone
// (rules/logs.py PRIORITY_CRITICAL). Everything below it is a label, not a
// verdict — err is where plenty of applications write routine output.
const PRIORITY_CRITICAL = 2;
const NBSP = "\u00a0";

/* The rulebook's severity order, mirrored from agent/rules/__init__.py
   (OPINION_LEVELS). The ONE ordering in this file: six hand-rolled binary
   comparisons lived here instead, and one of them painted an `info` opinion
   warn-yellow while the sentence directly beneath it said the reading was
   occupancy, not pressure. Conformance lints this literal against the agent's
   tuple, so the copy this file is forced to keep cannot drift silently.

   OPINION levels only. Row levels ("ok") and absent severity ("none") are
   deliberately outside it: /v1/status ranks a vouched-for `ok` row ABOVE a
   neutral `info` one (agent/main.py tests ok before info), which is the
   opposite of the order below, so no single table can serve both. Row levels
   are membership-tested against ATTENTION_LEVELS, never ranked. */
const OPINION_LEVELS = ["info", "warn", "critical"];

/* Which levels earn a place in an attention channel: a nav badge, a subsystem
   dot, an overview chip, a storage row's dot. Deliberately NOT every level the
   rulebook emits. `info` exists precisely to say "recorded, explained, not
   claiming your attention" \u2014 an unwired spare NIC, a p3 log line, memory that
   is ZFS ARC occupancy \u2014 and badging it rebuilds the cry-wolf noise the
   three-level taxonomy was built to escape (rules/logs.py records the audit:
   one cosmetic message was 72 of 72 p<=3 entries for a day).

   This is a POLICY about which levels may speak, not an ordering:
   worstOpinionLevel derives a level from a set, this decides which levels are
   allowed to. Fusing the two is what produced every defect it now prevents. */
const ATTENTION_LEVELS = ["warn", "critical"];

/* The worst level in a set, or null when the set says nothing rankable.
   Tolerates null/undefined members so a running maximum can seed itself.

   An unrecognised level is IGNORED, not promoted and not floored. The enum is
   closed (SPEC section 5.1, rule 6), so an unknown value is a bug or a broken
   agent, and colouring from a string we cannot rank would invent the loudest
   claim in the vocabulary out of something we do not understand \u2014 the opposite
   of every hedge in this file. Nothing is lost by declining: the opinion's TEXT
   prints verbatim regardless of level, in both the overview box and the detail
   pane, landing on the base `.opinion` faint border. Colour abstains; the
   sentence always survives. (That property is why `.opinion.info` restates the
   base border rather than moving it out of `.opinion`.) */
function worstOpinionLevel(levels) {
  let rank = -1;
  for (const level of levels) {
    const at = OPINION_LEVELS.indexOf(level);
    if (at > rank) rank = at;
  }
  return rank < 0 ? null : OPINION_LEVELS[rank];
}

/* ── helpers ─────────────────────────────────────────────── */

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

/* One sentence saying what a fact MEANS, from the host's own dictionary.

   Native property names are the contract (SPEC section 5) and they are not
   self-explanatory: LinkSpeed beside LinkWidth read as two ways of saying the
   same thing to the first person who met them, and no renaming would have
   fixed that — the reader needed the concept, once, where they were looking.

   The sentence comes from the adapter that emits the fact, over /v1/facts, and
   deliberately not from a table in here. Three severity tables in this file
   already drifted from the rulebook; a fourth copy of anything the agent knows
   is a fourth thing to disagree with it. */
function factHelp(fact, subsystem = state.subsystem, collection = state.collection) {
  return state.factDict?.subsystems?.[subsystem]?.[collection]?.[fact] || null;
}

/* WHICH KIND OF CLAIM a fact makes — from the same dictionary, for the same
   reason it lives there rather than here.

   Three kinds and only two are ever written down. `measured` is the default
   and is stated by omission, because saying it on three hundred entries
   would bury the forty that matter. So an absent kind means measured, an
   absent COLLECTION means nobody has classified it yet, and both look
   identical from here — which is exactly why the ratchet that closes the
   gap lives in conformance and not in a badge in this file. */
const KIND_NOTE = {
  measured: "read from the kernel, systemd or an API — reproducible with this collection's reference commands",
  derived: "computed by System Explorer from the facts above; no command reproduces it",
  declared: "asserted by a person in a document this host reads — true because it was written, not because it was checked",
};

function factKind(fact, subsystem = state.subsystem, collection = state.collection) {
  return state.factDict?.kinds?.[subsystem]?.[collection]?.[fact] || "measured";
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
  // WHICH agent answers is decided here, at fetch time, from the subsystem
  // the path names. A merged machine serves one nav from several agent
  // processes, and resolving at the fetch is what keeps every caller — grid,
  // detail, evidence, lookups, views, keyboard cycling — safe by
  // construction: routes stay plain subsystem/collection and nothing
  // upstream ever holds a cross-process URL to leak. (The previous design
  // put mate hrefs into the nav itself, and the key-cycler walked into
  // them.)
  //
  // The site is named in the URL because the hub is stateless: a host at a
  // sibling site is forwarded to the hub that owns it, and without the site in
  // the path that hub would have to ask every sibling who owns the host on
  // every single request. The browser already knows, from /hub/hosts.
  const res = await fetch(state.hub ? `${hubBaseFor(agentFor(path))}${path}` : path);
  if (!res.ok) {
    const body = await res.text().then(t => t.slice(0, 140));
    // The status rides on the error because ONE of these is not a failure.
    // A 404 from an object route means the agent looked and the object is
    // not there — an answer, and on a resolved finding usually the right
    // one. Callers that can say something better than "request failed"
    // need to be able to tell it apart, and parsing it back out of the
    // message string is how that goes wrong later.
    const err = new Error(`${res.status} ${body}`);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return res.json();
}

/* The agent a /v1 path is asked of: the machine-mate that owns the subsystem
   the path names, else the current host — which also covers the host-scoped
   routes (capabilities, status, facts) that name no subsystem at all.
   Evidence paths (/v1/evidence/<subsystem>/…) name their subsystem in the
   SECOND segment, so the prefix is skipped — safe because the server
   guarantees "evidence" is never a subsystem name. */
function agentFor(path) {
  const named = /^\/v1\/(?:evidence\/)?([^/?]+)/.exec(path)?.[1];
  return state.agentForSubsystem[named] ?? state.currentHost;
}

function humanBytes(n) {
  if (typeof n !== "number") return String(n);
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0, v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

/* Throughput, in the decimal units every link reference uses — deliberately
   NOT humanBytes' binary ladder. Storage capacity is conventionally GiB and
   link rate conventionally GB/s; a PCIe 3.0 x2 link rendered as "1.8 GiB/s"
   would disagree with every table the reader goes on to check. */
function humanRate(n) {
  if (typeof n !== "number") return String(n);
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)} GB/s`;
  if (n >= 1e6) return `${Math.round(n / 1e6)} MB/s`;
  return `${Math.round(n / 1e3)} kB/s`;
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
  // Before *Bytes, which it does not match today but would the moment someone
  // adds a suffix check that is not an exact endsWith.
  if (key.endsWith("BytesPerSec")) return withExact(humanRate(value));
  if (key.endsWith("Bytes")) return withExact(humanBytes(value));
  if (key.endsWith("Seconds")) return withExact(humanSeconds(value));
  if (key.endsWith("Hours")) return withExact(humanHours(value));
  // PCIe lane counts. A bare "2" beside a bare "4" did not read as the cause of
  // a warning; "x2 lanes" beside "x4 lanes" does — and says which of the two
  // dimensions it is, which "x2" alone did not: the first person shown it read
  // it as a speed. Same wording the rule settled on, for the same reason.
  if (/LinkWidth(Max)?$/.test(key)) return `x${value} lanes`;
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
  if (state.hub) {
    // Views are hub-served operator projections (SPEC 6.2); an agent 404s
    // the route and the section simply never exists. Failure here is a
    // missing feature, never a broken page.
    try {
      const res = await fetch("/hub/views");
      if (res.ok) {
        const body = await res.json();
        if (body?.schema === "se.views/1") state.views = body;
      }
    } catch { /* hub without views; nothing to show */ }
  }
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

/* Agents sharing this host's machine_id — the per-process split (one
   machine, several agent processes: the host agent plus credential-scoped
   app instances). The split is a deployment fact and it now stops at the
   deployment: the UI shows ONE machine as ONE page, fronted by the
   machine's primary member. The earlier projection — two dropdown entries,
   cross-linking nav sections — was withdrawn on the operator's verdict
   ("too confusing visually as you move between them", 2026-08-13).

   Mateship requires the SAME SITE: a machine's agent processes register at
   one site's hub by construction, so the legitimate per-process split always
   shares a site, while two physical machines at different sites that share a
   machine_id (a cloned /etc/machine-id, the classic VM-clone artifact) must
   never be presented as one machine. Two entries both lacking a site (an
   older hub) still mate via undefined === undefined — the same mixed-version
   degradation hubBaseFor documents. */
function machineMates(name) {
  const me = state.hub?.hosts?.[name];
  const mine = me?.host?.machine_id;
  if (!mine) return [];
  return Object.entries(state.hub.hosts)
    .filter(([other, probe]) => other !== name
            && probe.host?.machine_id === mine
            && probe.site === me.site)
    .map(([other]) => other);
}

/* The member that fronts a machine everywhere the machine reads as one
   thing: the dropdown's single entry, the URL the merged page lives at, the
   process whose own subsystems win a collision. It is the member whose name
   matches the hostname it reports, else the first alphabetically — computed
   over the sorted membership so every member names the same primary. A solo
   host (or a name the hub does not know) is its own primary. */
function machinePrimary(name) {
  const members = [name, ...machineMates(name)].sort((a, b) => a.localeCompare(b));
  return members.find(m => m === (state.hub?.hosts?.[m]?.host?.hostname || m))
      ?? members[0];
}

function defaultHost() {
  const names = Object.keys(state.hub.hosts);
  // Primaries before mates: landing on a machine's app process by accident
  // of listing order would open the page the dropdown deliberately does not
  // offer. A reachable mate still beats an unreachable everything.
  const primaries = names.filter(n => machinePrimary(n) === n);
  return primaries.find(n => state.hub.hosts[n].reachable)
      ?? names.find(n => state.hub.hosts[n].reachable)
      ?? names[0];
}

/* Fetch the current host's capabilities and rebuild the chrome around them.
   Everything host-scoped resets here; in-flight responses from the previous
   host die on the epoch bump. */
async function loadHost() {
  const epoch = ++state.epoch;
  const gen = ++state.hostGen;   // this load invocation's identity, see below
  state.lookupCatalog = null;
  state.status = null;
  state.ovPrev = null;         // counter deltas never span two hosts
  state.owners = null;         // and neither does attribution
  state.capabilities = null;   // stale caps must not describe the new host
  state.factDict = null;       // and vocabulary belongs to the host that served it
  state.agentForSubsystem = {}; // the merge rebuilds per machine; empty = solo
  state.mateMergeDone = null;   // resolves when the mates' answers have merged
  renderHostCard();
  /* Started alongside capabilities rather than in front of them, and never
     awaited on the failure path: an agent too old to serve /v1/facts (or a hub
     proxying one) simply has no fact tooltips. Missing help must never be the
     difference between a page that renders and one that does not. */
  const dictionary = api("/v1/facts").catch(() => null);
  /* The machine's other agent processes, asked for capabilities and facts IN
     PARALLEL with the host's own fetches above. Only the machine's PRIMARY
     merges its mates: a mate browsed directly (#/<mate-agent>/…) stays a
     standalone page — the debugging escape hatch the dropdown deliberately
     does not offer. Every member failure resolves to null; a machine never
     loses its page to a sibling process being down. */
  const mateHost = state.currentHost;
  const mates = state.hub && machinePrimary(mateHost) === mateHost
    ? machineMates(mateHost) : [];
  const mateFetch = Promise.all(mates.map(mate => Promise.all([
    fetch(`${hubBaseFor(mate)}/v1/capabilities`)
      .then(res => res.ok ? res.json() : null).catch(() => null),
    fetch(`${hubBaseFor(mate)}/v1/facts`)
      .then(res => res.ok ? res.json() : null).catch(() => null),
  ]).then(([caps, dict]) => ({ mate, caps, dict }))));
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
  state.factDict = await dictionary;
  if (epoch !== state.epoch) return false;
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
  // The mates' answers LAND after the first paint, on purpose: this host's
  // own nav must never wait on a sibling process. Guarded on the LOAD
  // INVOCATION (hostGen), not the host name: revisiting the same host runs
  // loadHost again, and a straggler continuation from the earlier visit must
  // not replay against the new visit's state. The collection epoch still
  // cannot be the guard: route() bumps it synchronously after loadHost
  // returns, so an epoch guard would discard every response before it could
  // land (the refreshStatus arrangement) — hostGen is bumped only here.
  if (mates.length) {
    state.mateMergeDone = mateFetch.then(async results => {
      if (gen !== state.hostGen || !state.capabilities) return;
      for (const { mate, caps: mateCaps, dict } of results)
        adoptMate(mate, mateCaps, dict);
      // AWAITED before the merged sections first paint, for the same reason
      // loadHost awaits its own: offering a mate's honestly-empty collection
      // and withdrawing it when the status lands is the nav shrinking under
      // the pointer again.
      await refreshStatus();   // now covers the mates' subsystems too
      if (gen !== state.hostGen || !state.capabilities) return;
      try { renderNav(); } catch { /* the merged sections are additive */ }
      // A deep link straight into a mate's subsystem raced this merge and
      // asked the primary, which honestly 404ed. The owner is known now:
      // re-route from the hash, so the collection (and any deep-linked
      // object) loads again — from the right process this time.
      if (state.agentForSubsystem[state.subsystem]) {
        // This re-route lands on the SAME address, so an arrival already
        // spent here has to be re-armed: route() clears sortKey on the way
        // in, while lookColumn survives it, which would leave the destination
        // wearing the ordering fact as a column with no ordering. Re-armed
        // rather than restored afterwards, so takeLookArrival still sets the
        // order BEFORE loadCollection paints — the page arrives sorted
        // instead of resorting under the reader. Address means host AND
        // route, tested rather than argued; the arrival itself carries route
        // and fact only, being host-free by contract, and takeLookArrival
        // stamps the host again when it lands.
        const here = `${state.subsystem}/${state.collection}`;
        if (state.lookColumn?.route === here
            && state.lookColumn.host === state.currentHost)
          state.lookArrival = { route: here, fact: state.lookColumn.fact };
        state.subsystem = null;
        state.collection = null;
        route();
      }
    });
  }
  return true;
}

/* Proxy prefix for an agent, by name. Falls back to the unscoped route when
   the hub reports no site for it — an older hub, or one started without
   SE_HUB_SITE — so a mixed-version estate degrades to today's behaviour
   rather than 404ing. */
function hubBaseFor(name) {
  const site = state.hub?.hosts?.[name]?.site;
  return site ? `/sites/${encodeURIComponent(site)}/agents/${name}`
              : `/agents/${name}`;
}

/* Fold one mate's capabilities and fact dictionary into the merged
   projection. The primary wins every collision by construction: a subsystem
   it already serves is never re-pointed, and a fact vocabulary it already
   carries is never overwritten. Pure bookkeeping on state, factored out of
   loadHost so the smoke harness can drive the merge without a DOM. */
function adoptMate(mate, caps, dict) {
  const subsystems = (state.capabilities.subsystems ??= {});
  for (const [sub, cap] of Object.entries(caps?.subsystems || {})) {
    if (sub in subsystems) continue;
    subsystems[sub] = cap;
    state.agentForSubsystem[sub] = mate;
  }
  if (!dict?.subsystems) return;
  const mine = (state.factDict ??= { subsystems: {} });
  mine.subsystems ??= {};
  for (const [sub, colls] of Object.entries(dict.subsystems)) {
    if (!(sub in mine.subsystems)) mine.subsystems[sub] = colls;
  }
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
    // ONE MACHINE = ONE ENTRY (operator verdict, 2026-08-13): members
    // sharing a machine_id collapse into a single option naming the
    // machine's primary — their subsystems merge into its page, so a second
    // entry would be a second door into the same room. Solo hosts are
    // exactly as before, and the list reads alphabetically by what it
    // SHOWS: a machine sorts by its primary's name, never by machine_id hex.
    const entries = bySite.get(site);
    const byMachine = new Map();
    for (const [name, probe] of entries) {
      const key = probe.host?.machine_id || `solo:${name}`;
      if (!byMachine.has(key)) byMachine.set(key, []);
      byMachine.get(key).push([name, probe]);
    }
    const options = [];
    for (const members of byMachine.values()) {
      const primary = members.find(([name]) => name === machinePrimary(name))
        ?? members[0];
      options.push(primary);
      // A mate browsed directly (#/<mate-agent>/…) is never OFFERED here, but
      // the select must still be able to SAY it: while it is the current
      // host it rides along as an option, gone once navigation moves on.
      const current = members.find(([name]) => name === state.currentHost);
      if (current && current !== primary) options.push(current);
    }
    options.sort((a, b) => a[0].localeCompare(b[0]));
    for (const [name, probe] of options) {
      // Unreachable hosts stay listed and selectable — picking one shows the
      // error banner rather than silently hiding the host.
      const opt = el("option", null,
                     probe.reachable ? name : `${name} — unreachable`);
      opt.value = name;
      (group || select).appendChild(opt);
    }
    if (group) select.appendChild(group);
  }

  select.value = state.currentHost;
  const probe = state.hub.hosts[state.currentHost];
  const machineId = state.capabilities?.host?.machine_id ?? probe?.host?.machine_id;
  // The host's OWN site. Three answers in preference order, and the first is
  // the only one the HOST states: agent_site comes from its /health, `site`
  // is whichever hub fronts it, and the hub's own is the last resort. A
  // cloud host registered with a home hub read as living at home until the
  // first of these existed (2026-08-14).
  const hostSite = probe?.agent_site || probe?.site || state.hub.site;
  // A merged machine names its member processes where the machine is named:
  // "host + apps" says who answers on this page without resurrecting the
  // two-entry split the dropdown gave up. Short labels shed the primary's
  // own prefix (host-apps → apps); a mate sharing no separator-delimited
  // prefix keeps its whole name — a label must never manufacture ambiguity.
  const mates = machinePrimary(state.currentHost) === state.currentHost
    ? machineMates(state.currentHost).sort((a, b) => a.localeCompare(b)) : [];
  const shortLabel = (mate) => {
    const rest = mate.startsWith(state.currentHost)
      ? mate.slice(state.currentHost.length) : "";
    return /^[-_.]/.test(rest) ? rest.replace(/^[-_.]+/, "") || mate : mate;
  };
  $("host-meta").textContent = [
    hostSite || null,
    mates.length ? [state.currentHost, ...mates.map(shortLabel)].join(" + ") : null,
    machineId ? machineId.slice(0, 12) + "…" : "unreachable",
  ].filter(Boolean).join(" · ");
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

/* THE nav taxonomy: headings, their order, and what goes under each.

   Presentation only, and that is what makes it cheap. Routes, object ids,
   status keys, opinion keys and stored history all keep their subsystem
   names; nothing here reaches the wire. What it changes is the ONE thing
   the wire cannot: which question a reader is browsing by.

   `subsystem` is an ACQUISITION boundary. It answers "which interface did we
   read this from" — D-Bus, the engine API, cgroupfs, nft -j — which is the
   right way to organise adapters and no way at all to look for anything. The
   nav had already conceded this twice, in two tables that did the same job
   for different halves of the surface: `disks` pulled hardware/scsi and
   hardware/nvme together because hardware is organised by TRANSPORT and an
   operator is not (scsi holds SAS, SATA and USB drives; NVMe has its own),
   and `media`/`ingress`/`documents` grouped the app subsystems after
   "bazarr is one of the *arr apps, why is it not in with them?".

   Between those two fixes sat twelve host-OS subsystems in whatever order
   Object.entries happened to yield. Reviewed 2026-08-14, and the ordering
   is an argument rather than an alphabet: what is running, then where its
   data is, then how that data is protected, then how it is reached, then
   what the box underneath is, then what happened.

   THE RULE THIS TABLE IS BUILT ON, and it is worth stating because it
   settled two disagreements: IF A HEADING NEEDS `subsystem · collection`
   LABELS TO BE READABLE, IT HAS MERGED THINGS WHOSE NAMES DO NOT SURVIVE
   THE MERGE. The prefix is the smell, not the price. A draft with one
   `machine` heading held eight items, six of them prefixed; split into
   `hardware` and `os` it needs none, and reads better as two questions than
   it did as one — what this box is made of and what it is running as an
   operating system are not the same question. The same rule moved docker's
   networks and volumes out of `running`, where they were both prefixed and
   wrong: a network and a volume are not things that run, and a bare
   `networks` would have collided with the `network` heading below.

   `label` overrides a member's name where the collection's own is not the
   informative half. It is declared per member rather than derived, because
   `vms` beats `domains` while `workloads` beats `resources` and no rule
   picks correctly for both. The subsystem-name fallback for a one-collection
   subsystem is the same behaviour the app domains already had — which is why
   bazarr/instance has always rendered as `bazarr` and not as a second
   `instance` — now applied to the host-OS half, where it retires
   `units › units`, `packages › packages` and `nix › generations`.

   A subsystem this table does not name keeps its own heading, so a future
   adapter is never hidden, merely ungrouped until someone files it. One tree,
   stable across machines: a heading with nothing on this host renders not at
   all (the honest-empty rule, again). */
const GROUPS = [
  // Leads the content, which is why it carries `lead` rather than an
  // `after`: there is no section above it to name, and anchoring it to
  // whatever happens to be first would make the top of the nav depend on
  // whether the hub serves views today.
  { heading: "running", lead: true, members: [
      ["units", "units", "units"],
      ["docker", "containers", "containers"],
      ["vms", "domains", "vms"],
      ["resources", "workloads", "workloads"],
  ] },
  { heading: "docker", after: "running", members: [
      ["docker", "networks"], ["docker", "volumes"],
  ] },
  // Placed after storage rather than at the top: physical disks are the
  // substrate the filesystems, arrays and pools above them are built on, so
  // reading downward goes from what is mounted to what it sits on. `after`
  // names the section it follows, so position is declared here with the
  // grouping instead of falling out of the order the loops happen to run in.
  { heading: "disks", after: "storage",
    members: [["hardware", "scsi"], ["hardware", "nvme"]] },
  // network's nine collections split along a seam that already existed:
  // addressing on one side, what can reach in on the other. The firewall
  // collections belong with the sockets they bear on, not with the routes.
  { heading: "exposure", after: "network", members: [
      ["network", "listening"], ["network", "port-exposure"],
      ["network", "nft-tables"], ["network", "nft-chains"],
      ["network", "nft-rules"],
  ] },
  { heading: "hardware", after: "exposure", members: [
      ["hardware", "platform"], ["hardware", "pci"], ["hardware", "usb"],
  ] },
  { heading: "os", after: "hardware", members: [
      ["system", "identity"], ["system", "time"], ["system", "boot"],
      ["nix", "generations", "generations"],
      ["packages", "packages", "packages"],
  ] },
];

/* Whole SUBSYSTEMS grouped by operator domain — the app tier, where the
   subsystem IS the app and grouping it collection by collection would say
   nothing. Kept separate from GROUPS above because the membership unit
   differs: these claim everything a subsystem serves, present and future, so
   an app that grows a collection appears under its domain without an edit. */
const DOMAINS = [
  { heading: "media", members: ["servarr", "bazarr", "downloaders", "plex"] },
  { heading: "ingress", members: ["traefik"] },
  { heading: "documents", members: ["paperless"] },
  { heading: "dns & dhcp", members: ["kea", "unbound"] },
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

  // FIRST, and that ordering is the whole point. This section carries no
  // heading — it is separated by space rather than by a label it does not
  // need — and a headless section renders under whatever heading precedes
  // it. Built after the estate section, the host's own overview appeared
  // beneath "estate" and read as estate-scoped, which it is not: it is one
  // host's landing view (reported from the deployed UI, 2026-08-14). Leading
  // the nav, there is nothing above it to be mistaken for.
  for (const [sub, coll, label] of STANDALONE) {
    if (!listed(sub, coll)) continue;
    claimed.add(`${sub}/${coll}`);
    sections.push({ solo: true, heading: null, available: true,
                    items: [{ sub, coll, label, route: `${sub}/${coll}` }] });
  }

  // Operator-authored views lead the nav when the hub serves any: they are
  // the curated front doors, and the person they were written for should
  // meet them before the raw subsystem list. Absent entirely otherwise —
  // an empty heading would be a lie about what is here (same rule as
  // groups below). The route shape is view/<name>; "view" is not a
  // subsystem and the router dispatches it before capabilities are asked.
  //
  // A view that names its hosts appears only on them: a dashboard is
  // composed FOR somewhere, and rendering the ZFS view against a host
  // with no ZFS turned a curated page into a wall of error strips
  // (reported live, 2026-08-12 — the composable-dashboard idea deployed
  // as an accidental estate-wide default). On a host a view DOES name,
  // failures stay loud; that half was right.
  let viewsHeaded = false;
  for (const doc of state.views?.views || []) {
    if (doc.hosts && state.currentHost && !doc.hosts.includes(state.currentHost))
      continue;
    // The FIRST view section carries the heading and the rest join it. Keyed
    // on whether one has been emitted, not on sections.length — that read as
    // "am I first overall", and the moment a headless section was promoted
    // above this loop the heading silently vanished (introduced and caught
    // within the hour, 2026-08-14). A heading that depends on what else
    // happens to be in the nav is a heading waiting to disappear.
    const heading = viewsHeaded ? null : "views";
    viewsHeaded = true;
    sections.push({ solo: false, heading,
                    available: true,
                    items: [{ sub: "view", coll: doc.name, label: doc.title,
                              route: `view/${doc.name}` }] });
  }

  // The estate attention surface (SPEC section 6.3): hub mode only,
  // because /hub/findings is the hub's registry — a directly-browsed
  // agent has /v1/findings but no lifecycle to show for it.
  if (state.hub) {
    sections.push({ solo: false, heading: "estate", available: true,
                    items: [{ sub: "estate", coll: "findings",
                              label: "findings", route: "estate/findings" }] });
  }

  // Where the chrome ends and the host's own surface begins. A leading group
  // splices HERE rather than at index 0, so it sits under the overview,
  // views and estate without having to name whichever of them happens to
  // exist on this host today.
  const contentAt = sections.length;

  // Group membership is claimed BEFORE the subsystem sections are built, so a
  // grouped collection cannot also appear under its own subsystem — the same
  // collection reachable twice is what the smoke test guards.
  const groups = [];
  for (const group of GROUPS) {
    const items = group.members
      .filter(([sub, coll]) => listed(sub, coll) && !claimed.has(`${sub}/${coll}`))
      // The third element overrides the label where the collection's own
      // name is not the informative half — `vms` for vms/domains, and the
      // end of `units › units`, which is what a reader clicking through a
      // container's scope had been landing in.
      .map(([sub, coll, label]) => ({ sub, coll, label: label || coll,
                                      route: `${sub}/${coll}` }));
    // An empty group is not a heading, it is a lie about what is here.
    if (!items.length) continue;
    items.forEach(item => claimed.add(item.route));
    groups.push({ solo: false, heading: group.heading, available: true,
                  grouped: true, after: group.after ?? null,
                  lead: !!group.lead, items });
  }

  const domainOf = {};
  for (const domain of DOMAINS)
    for (const member of domain.members) domainOf[member] = domain.heading;
  const domainItems = new Map(DOMAINS.map(domain => [domain.heading, []]));

  for (const [name, cap] of Object.entries(subsystems)) {
    const items = (cap.collections || [])
      .filter(coll => !claimed.has(`${name}/${coll}`))
      .map(coll => ({ sub: name, coll, label: coll, route: `${name}/${coll}` }));
    // The nav lists what this host ANSWERS, nothing else. The dimmed
    // unavailable-entries experiment lasted exactly one deploy: on a host
    // with no ZFS it rendered three grey storage rows and a
    // "not yet implemented" placeholder, which the operator read — rightly
    // — as clutter and roadmap leaking into the product ("no placeholders
    // in the UI", 2026-08-12). The where-did-it-go question the dimming
    // was built for is answered at the API instead: /v1/capabilities
    // names every absence with its reason, one call away, and the
    // original vanishing act (resolver) is gone at the root — it answers
    // on every host now (SPEC rule 16). An unavailable subsystem
    // likewise contributes no section: a heading over nothing is not
    // information, it is furniture.
    if (!items.length || !cap.available) continue;
    if (domainOf[name]) {
      // A domained subsystem's items lead with the app's name, because that
      // is how the operator says them: "bazarr" is an app that happens to
      // expose one collection, and "servarr · queue" says whose queue where
      // a bare "queue" — or a second "instance", a second "daemon" — says
      // nothing. The route underneath is untouched.
      domainItems.get(domainOf[name]).push(...items.map(item => ({
        ...item,
        label: items.length === 1 ? name : `${name} · ${item.coll}`,
      })));
      continue;
    }
    sections.push({ solo: false, heading: name, available: true, items });
  }

  /* Splice each group in after the section it names, IN TABLE ORDER — a
     group may anchor to another group, so `os` after `hardware` after
     `exposure` only resolves if each is placed before the next looks for it.

     An unplaceable group goes last rather than vanishing: its collections
     must stay reachable even where the subsystem it wanted to follow is
     absent from this host — which is the ordinary case on a machine with no
     ZFS, and on every guest in the VM lab. */
  for (const group of groups) {
    if (group.lead) { sections.splice(contentAt, 0, group); continue; }
    const at = group.after
      ? sections.findIndex(section => section.heading === group.after)
      : -1;
    if (at === -1) sections.push(group);
    else sections.splice(at + 1, 0, group);
  }

  // The domains, in their declared order, AFTER the host-OS sections: the
  // mates' subsystems land asynchronously, and appending keeps the top of
  // the nav where the eye left it rather than reflowing under the pointer —
  // "the nav bar can't bounce around" is the verdict this whole shape
  // answers. Within a domain the members keep the table's order (stable
  // sort, so a subsystem's own collection order survives). A domain with
  // nothing on this machine renders no heading at all.
  for (const domain of DOMAINS) {
    const items = domainItems.get(domain.heading);
    if (!items.length) continue;
    items.sort((a, b) =>
      domain.members.indexOf(a.sub) - domain.members.indexOf(b.sub));
    sections.push({ solo: false, heading: domain.heading, available: true,
                    domain: true, items });
  }
  return sections;
}

function renderNav() {
  const nav = $("nav");
  nav.textContent = "";
  for (const section of navModel()) {
    const box = el("div", "nav-sub"
      + (section.solo ? " nav-solo" : "")
      + (section.domain ? " domain" : "")
      + (section.available ? "" : " unavailable"));
    if (section.heading) {
      const label = el("div", "sub-label", section.heading);
      if (!section.available) label.title = section.reason || "unavailable";
      box.appendChild(label);
    }
    for (const item of section.items) {
      const link = el("a", "nav-item" + (item.unavailable ? " unavailable" : ""),
                      item.label);
      link.href = hashFor(item.sub, item.coll);
      link.dataset.route = item.route;
      if (item.unavailable) link.title = item.reason || "unavailable";
      // On a merged machine, the hover answers "which process serves this" —
      // the one home of the subsystem→process mapping the fetches route by.
      else if (state.agentForSubsystem[item.sub])
        link.title = `served by ${state.agentForSubsystem[item.sub]}`;
      box.appendChild(link);
    }
    nav.appendChild(box);
  }
  applyNavBadges();
}

/* ── status badges ───────────────────────────────────────── */

/* The nav's attention layer (ROADMAP slice 1). Failures clear the badges
   rather than freeze them — a stale count is worse than none.

   On a merged machine every member answers for its own subsystems: the
   pages merge per-subsystem, the primary winning any collision, so badges
   and the hide-empty rule work across the whole machine. The mate list
   derives from agentForSubsystem — a mate whose capabilities never landed
   has no nav entries to badge, so its status is not asked for. A member
   that fails to answer simply contributes nothing: its subsystems keep
   their nav entries (capabilities said they exist) and navigating to one
   reports the failure in the banner, never a silently vanished machine. */
async function refreshStatus() {
  const gen = state.hostGen;   // answers belong to this load invocation only
  const mates = [...new Set(Object.values(state.agentForSubsystem))];
  const asks = mates.map(mate =>
    fetch(`${hubBaseFor(mate)}/v1/status`)
      .then(res => res.ok ? res.json() : null)
      .catch(() => null));
  let primary = null;
  try { primary = await api("/v1/status"); }
  catch { /* no roll-up (old agent, dead host) → no badges for its rows */ }
  const matePages = await Promise.all(asks);
  if (gen !== state.hostGen) return;   // the host reloaded mid-flight
  state.status = mergeMemberStatuses(primary, matePages);
  applyNavBadges();
}

/* Per-subsystem union of the members' roll-ups, folded in OWNERSHIP order —
   the primary first, then mates in adoption order, first claim winning —
   mirroring adoptMate's capability merge exactly, so a badge can never
   describe a collection a click would fetch from a different process. Null
   in, null out when nobody answered: no roll-up means the nav must offer
   everything rather than guess at emptiness. */
function mergeMemberStatuses(primary, matePages) {
  let merged = null;
  for (const page of [primary, ...matePages]) {  // first claim wins — adoptMate's rule
    if (!page?.subsystems) continue;
    merged ??= { subsystems: {} };
    for (const [sub, entry] of Object.entries(page.subsystems))
      if (!(sub in merged.subsystems)) merged.subsystems[sub] = entry;
  }
  return merged;
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
        // ok and info rows are counted by the roll-up and deliberately not
        // badged here — see ATTENTION_LEVELS. The badge's number counts only
        // what the badge claims, so it can never exceed what a reader finds.
        const present = ATTENTION_LEVELS.filter((level) => entry.counts[level]);
        if (!present.length) continue;
        const total = present.reduce((sum, level) => sum + entry.counts[level], 0);
        const badge = el("span", `nav-badge ${worstOpinionLevel(present)}`, String(total));
        badge.title = [...present].reverse()
          .map((level) => `${entry.counts[level]} ${level}`).join(", ");
        link.appendChild(badge);
        subLevel = worstOpinionLevel([subLevel, ...present]);
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
                           revealed: new Set(), colPicker: false, owners: null });
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

  /* After the reset above (which clears sortKey), so the arrival survives it;
     before the rows land, so the destination ARRIVES sorted rather than
     resorting under the reader a moment later. A collection that did not
     change loads nothing and must be repainted here instead. */
  if (takeLookArrival() && !changedCollection) {
    renderGrid();
    renderCrumb();
  }
}

/* The host changed under the route. Rebuild the host-scoped chrome, then
   re-route: the subsystem/collection carries over when the new host serves
   it, else falls back to that host's default. */
async function switchHost(host, rest) {
  state.currentHost = host;
  clearInterval(state.refreshTimer);   // no polls of the old route mid-switch
  const loading = loadHost();  // bumps state.hostGen synchronously
  const gen = state.hostGen;
  const ok = await loading;
  if (gen !== state.hostGen) return;   // superseded by a newer load
  if (!ok) {
    // Unreachable host: the banner (set by loadHost) plus an emptied grid;
    // the select still lists it, so recovery is one change event away.
    // This branch IS a route change and it is the one that never reaches
    // route(), so takeLookArrival never runs: spend the arrival here by hand
    // or it stays armed and reorders whatever host the reader picks next —
    // and this branch keeps the very route it is keyed to, so the next
    // selection is exactly where it would fire. The transient column goes
    // with it for the same reason: it belongs to the rows that justified it,
    // and there are none here.
    state.lookArrival = null;
    state.lookColumn = null;
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
  const isView = rest[0] === "view" &&
    (state.views?.views || []).some(doc => doc.name === rest[1]);
  const isEstate = rest[0] === "estate" && rest[1] === "findings";
  // A machine with mates cannot judge an unknown subsystem bogus yet — the
  // mates' capabilities land after first paint, and bouncing the route to
  // the default here would eat a deep link into a subsystem a mate serves.
  const merging = !!rest[0] && machinePrimary(host) === host
    && machineMates(host).length > 0;
  if (!isView && !isEstate
      && (!rest[0] || !(rest[1] ? cols.includes(rest[1]) : cols.length))) {
    if (merging) {
      // The mates may own this route; their answer, not a guess, decides.
      // First paint already happened inside loadHost — this wait only
      // postpones the route verdict, never the page. A route NO member
      // serves still bounces to the default, as the solo contract promises.
      await state.mateMergeDone;
      if (gen !== state.hostGen) return;   // switched again while waiting
      const merged = state.capabilities.subsystems[rest[0]]?.collections || [];
      if (!(rest[1] ? merged.includes(rest[1]) : merged.length))
        history.replaceState(null, "", hashFor(...defaultRoute()));
    } else {
      history.replaceState(null, "", hashFor(...defaultRoute()));
    }
  }
  state.subsystem = null;                   // force a reload on the new host
  state.collection = null;
  route();
}

/* `host` names a machine OTHER than the one on screen, and only the estate
   surfaces need it: a finding states its condition on its own agent's
   machine, so resolving its links against the selected host would send the
   reader to the wrong box entirely. The machine's PRIMARY fronts the URL,
   because that is where the merged page lives and where a mate's subsystems
   are served from — the same rule the findings row itself follows. */
function hashFor(subsystem, collection, objectId, host = null) {
  const path = objectId
    ? `${subsystem}/${collection}/${idPath(objectId)}`
    : `${subsystem}/${collection}`;
  const at = host ? machinePrimary(host) : state.currentHost;
  return state.hub ? `#/${at}/${path}` : `#/${path}`;
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

/* ── an opinion's onward step (`look`) ───────────────────────
   An opinion MAY carry `look`: route hints naming where the diagnosis it
   summarises actually lives. "This host is I/O bound" is a true sentence the
   reader cannot act on — the attribution sits one route away on units/units,
   and until now they had to know that. The rulebook knows it, so it says it,
   and this is the only place in the UI that turns one into a link.

   Real anchors with real hrefs, for the reason the pipeline rows already
   insist on: a destination that cannot be middle-clicked or copied is not a
   route, it is a sentence about one.

   `host` is the machine the OPINION belongs to, not the one on screen —
   null everywhere a host speaks about itself, and the finding's own agent on
   the estate panel. An opinion with no `look` returns null and grows nothing:
   no empty row, no dangling separator. */
function lookLinks(opinion, host = null) {
  const hints = opinion?.look || [];
  if (!hints.length) return null;
  const box = el("div", "look");
  for (const hint of hints) {
    const href = hashFor(hint.subsystem, hint.collection, null, host);
    const link = el("a", "look-link",
                    hint.label || `${hint.subsystem}/${hint.collection}`);
    link.href = href;
    if (hint.fact) link.title = `ordered by ${hint.fact}, worst first`;
    link.onclick = (event) => {
      // A modified click belongs to the browser: a new tab is a fresh load
      // with no session to carry the arrival intent, and it still lands on
      // the right collection, which is the part that must never depend on us.
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
      armLookArrival(hint);
      // Already at exactly this address: no hashchange will fire, so route()
      // has to be asked. Same shape as goTo's own no-op guard.
      if (location.hash === href) route();
    };
    box.appendChild(link);
  }
  return box;
}

/* `fact` names the fact that ORDERS the answer at the far end, so the culprit
   is row one instead of something to hunt for. It is carried, never stored:
   a click is navigation, and navigation must not rewrite what the reader has
   saved. "I followed a warning last week and my columns changed" is an
   annoyance nobody can trace back to its cause. */
function armLookArrival(hint) {
  state.lookArrival = hint.fact
    ? { route: `${hint.subsystem}/${hint.collection}`, fact: hint.fact }
    : null;
}

/* One shot, and only at the route that asked for it: a reader who went
   somewhere else instead must not find that page reordered under them, so
   the intent is spent on the first route change either way. Returns whether
   it applied, because a route that did not otherwise change still has to
   repaint.

   The order is state.sortKey/sortDir — the very pair a column header click
   sets, because a second ordering path that could disagree with the header's
   is exactly the fourth-copy failure this file names elsewhere.

   lookColumn outlives the intent by one thing: it lasts while the reader
   stays on the route AND the host that asked for it, since opening a row is
   not leaving but changing machine is. Cleared here, the one place that sees
   every route change, so no visit can inherit the previous one's extra
   column. The host has to be part of that test: the dropdown deliberately
   keeps the route, so without it the column follows the reader onto another
   machine — where a kernel with no PSI carries the fact on no row, prints a
   column of dashes that reads as "none here", and offers no tick to untick,
   because the picker only lists facts the loaded rows actually carry.

   `want` stays host-free on purpose and must not be qualified: a findings
   link is armed on the host the reader is looking FROM and consumed after
   switchHost on the host it names. Stamping state.currentHost at the moment
   the intent is TAKEN is what binds the column to the machine whose rows
   justified it. */
function takeLookArrival() {
  const want = state.lookArrival;
  state.lookArrival = null;
  const here = `${state.subsystem}/${state.collection}`;
  if (state.lookColumn &&
      (state.lookColumn.route !== here || state.lookColumn.host !== state.currentHost))
    state.lookColumn = null;
  if (!want || want.route !== here) return false;
  state.sortKey = want.fact;
  state.sortDir = -1;          // descending: worst first is the whole point
  state.lookColumn = { ...want, host: state.currentHost };
  return true;
}

/* ── resources: what is eating this machine ──────────────────────────────
 *
 * A purpose-built page rather than the generic table, because the question
 * has a shape the table cannot take: a total, a decomposition of it, a
 * remainder, and two different measurements that must sit side by side.
 *
 * INDEXED BACK INTO THE FACTS, without exception. Every number here is a
 * fact from resources/workloads and nothing else; every label carries that
 * fact's own sentence from /v1/facts as its tooltip, so the page explains
 * itself out of the agent's dictionary rather than out of a copy in here;
 * and every row links to the object it came from. Nothing on this page is
 * computed that the collection does not already carry, except the shares —
 * which are ratios of two facts on the same row and say so.
 *
 * The shares are cumulative, not rates, and the wording says so. These are
 * counters since boot; a percentage of them is "of all the CPU this host has
 * spent, this much went here", which needs no window and is honest without
 * one. A live rate would need two samples and a stated interval, and that is
 * a different feature — see SPARK_SAMPLES for where the browser does keep
 * its own history and says as much. */

const RESOURCE_METRICS = [
  { key: "CpuUsageUsec", label: "CPU", format: (v) => humanSeconds(v / 1e6) },
  { key: "MemoryCurrentBytes", label: "memory", format: humanBytes },
  { key: "IoWrittenBytes", label: "written", format: humanBytes },
  { key: "IoReadBytes", label: "read", format: humanBytes },
];

/* A label that explains itself out of the agent's dictionary. The tooltip is
   never written here — a second copy of what a fact means is the drift the
   fact dictionary exists to prevent. */
function factLabel(cls, text, fact) {
  const node = el("span", cls, text);
  const help = factHelp(fact, "resources", "workloads");
  if (help) node.title = help;
  return node;
}

function resourceRow(label, valueText, pct, fact, href, cls) {
  const row = el("div", "ov-row");
  const lbl = href ? el("a", "lbl wide", label) : el("span", "lbl wide", label);
  if (href) lbl.href = href;
  lbl.title = label;
  row.appendChild(lbl);
  // "aux" is a SEGMENT style, not a meter style — styles.css paints
  // `.meter .seg.aux`, so passing it as a class produced an unstyled bar.
  row.appendChild(cls === "aux"
    ? meter(0, null, [], [{ pct, aux: true }])
    : meter(pct, cls));
  const val = factLabel("val", valueText, fact);
  row.appendChild(val);
  return row;
}

async function loadResources() {
  const { epoch } = state;
  $("overview").hidden = true;
  $("views-pane").hidden = true;
  $("collection-pane").hidden = false;
  $("refresh").classList.add("spin");
  const subs = state.capabilities?.subsystems || {};
  const has = (s, c) => subs[s]?.available && (subs[s].collections || []).includes(c);
  let page, containers = new Map();
  try {
    page = await api("/v1/resources/workloads?limit=1000");
    // Only to put a human name on a container scope, and only where this host
    // serves docker at all. A failure here costs names, never the page.
    if (has("docker", "containers")) {
      try { containers = containerNames(await api("/v1/docker/containers?limit=200")); }
      catch { containers = new Map(); }
    }
  } catch (err) {
    $("refresh").classList.remove("spin");
    banner(`Failed to load resources: ${err.message}`);
    return;
  }
  if (epoch !== state.epoch) return;
  $("refresh").classList.remove("spin");
  renderResources(page, containers);
}

function renderResources(page, containers) {
  const host = $("collection-pane");
  host.textContent = "";
  const items = page.items || [];
  const byName = new Map(items.map((i) => [i.native_id, i]));
  const root = byName.get("-.slice");
  const grid = el("div", "ov-grid");
  const link = (id) => hashFor("resources", "workloads", id);

  /* ── the host total, and the part of it that is nobody's ── */
  if (root) {
    const f = root.facts || {};
    const busy = f.HostCpuBusyUsec;
    const unattributed = f.UnattributedCpuUsec;
    const p = el("div", "ov-panel");
    p.appendChild(el("h3", null, "This host, since boot"));
    if (typeof busy === "number" && busy > 0) {
      const share = (100 * (unattributed || 0)) / busy;
      p.appendChild(resourceRow(
        "in no slice", `${share.toFixed(1)}%`, share, "UnattributedCpuUsec",
        link(root.id), share >= 50 ? "warn" : null));
      p.appendChild(el("div", "ov-sub",
        `${humanSeconds((unattributed || 0) / 1e6)} of ${humanSeconds(busy / 1e6)}` +
        " of this host's CPU is in no top-level slice — kernel threads, an md" +
        " resync, a scrub. No workload row below accounts for it."));
    }
    if (typeof f.HostCpuStolenUsec === "number") {
      p.appendChild(el("div", "ov-sub",
        `${humanSeconds(f.HostCpuStolenUsec / 1e6)} stolen by the hypervisor —` +
        " time this machine wanted and did not get. Neither busy nor idle, and" +
        " deliberately outside the total above."));
    }
    grid.appendChild(p);
  }

  /* ── the ladder: where the attributed total went ── */
  const top = items.filter((i) => i.facts?.Depth === 1
                                  && typeof i.facts?.CpuUsageUsec === "number");
  if (top.length) {
    const total = top.reduce((n, i) => n + i.facts.CpuUsageUsec, 0)
                  + (root?.facts?.UnattributedCpuUsec || 0);
    const p = el("div", "ov-panel");
    p.appendChild(el("h3", null, "The ladder · CPU"));
    for (const item of [...top].sort((a, b) => b.facts.CpuUsageUsec - a.facts.CpuUsageUsec)) {
      const value = item.facts.CpuUsageUsec;
      p.appendChild(resourceRow(
        item.native_id, humanSeconds(value / 1e6), total ? (100 * value) / total : 0,
        "CpuUsageUsec", link(item.id)));
    }
    if (root && typeof root.facts?.UnattributedCpuUsec === "number") {
      // The remainder as a row of the same list, because it is a share of the
      // same total — a footnote would let the bars above read as the whole.
      const value = root.facts.UnattributedCpuUsec;
      p.appendChild(resourceRow(
        "(no slice)", humanSeconds(value / 1e6), total ? (100 * value) / total : 0,
        "UnattributedCpuUsec", link(root.id), "aux"));
    }
    grid.appendChild(p);
  }

  /* ── the leaves, ranked, one panel per resource ── */
  const leaves = items.filter((i) => i.type !== "slice");
  for (const metric of RESOURCE_METRICS) {
    const ranked = leaves
      .filter((i) => typeof i.facts?.[metric.key] === "number" && i.facts[metric.key] > 0)
      .sort((a, b) => b.facts[metric.key] - a.facts[metric.key])
      .slice(0, 6);
    if (!ranked.length) continue;
    const worst = ranked[0].facts[metric.key];
    const p = el("div", "ov-panel");
    p.appendChild(el("h3", null, `Most ${metric.label}`));
    for (const item of ranked) {
      const value = item.facts[metric.key];
      p.appendChild(resourceRow(
        stallingName(item, containers), metric.format(value),
        worst ? (100 * value) / worst : 0, metric.key, link(item.id)));
    }
    grid.appendChild(p);
  }

  /* ── things that happened to a workload and left no other trace ── */
  const oom = leaves.filter((i) => (i.facts?.MemoryOomKills || 0) > 0);
  const throttled = leaves.filter((i) => (i.facts?.CpuThrottledUsec || 0) > 0);
  if (oom.length || throttled.length) {
    const p = el("div", "ov-panel");
    p.appendChild(el("h3", null, "Killed and held back"));
    for (const item of oom) {
      p.appendChild(resourceRow(
        stallingName(item, containers), `${item.facts.MemoryOomKills} killed`,
        100, "MemoryOomKills", link(item.id), "warn"));
    }
    for (const item of throttled) {
      p.appendChild(resourceRow(
        stallingName(item, containers),
        humanSeconds(item.facts.CpuThrottledUsec / 1e6),
        100, "CpuThrottledUsec", link(item.id), "aux"));
    }
    p.appendChild(el("div", "ov-sub",
      "An OOM kill leaves no trace anywhere else — systemd restarts the" +
      " service and its unit returns to active. Throttling is a workload" +
      " stopped by its own quota rather than by contention, which no pressure" +
      " reading reports."));
    grid.appendChild(p);
  }

  /* ── who is suffering, which is a different question ── */
  const stalling = items
    .filter((i) => (i.facts?.PsiIoFullAvg60 ?? 0) > 0)
    .filter((i) => !(i.facts?.StallExplainedBy || {}).PsiIoFullAvg60)
    .sort((a, b) => (b.facts.PsiIoFullAvg60 ?? 0) - (a.facts.PsiIoFullAvg60 ?? 0))
    .slice(0, 5);
  const p = el("div", "ov-panel");
  p.appendChild(el("h3", null, "Waiting on I/O · last 60s"));
  if (!stalling.length) {
    p.appendChild(el("div", "ov-sub", "No workload reports an I/O stall."));
  } else {
    for (const item of stalling) {
      const share = item.facts.PsiIoFullAvg60;
      p.appendChild(resourceRow(
        stallingName(item, containers), `${share}%`, share,
        "PsiIoFullAvg60", link(item.id), share >= 20 ? "warn" : null));
      const unexplained = (item.facts.StallUnexplained || {}).PsiIoFullAvg60;
      const unsettled = (item.facts.StallAttributionUnobservable || {}).PsiIoFullAvg60;
      if (unexplained || unsettled) {
        // The same two classes, and the same two SUBJECTS, the units page
        // uses: the finding speaks about the slice, the hedge about the
        // reading. The host's own sentence stays a hover — this panel
        // prints no sentence it did not write.
        const note = el("div",
          `ov-sub row-note ${unexplained ? "note-finding" : "note-unsettled"}`,
          unexplained
            ? "nothing inside this slice accounts for it"
            : "part of this slice could not be read — neither ruled in nor out");
        note.title = unexplained || unsettled;
        p.appendChild(note);
      }
    }
  }
  p.appendChild(el("div", "ov-sub",
    "Utilisation says who is causing load; this says who is suffering from" +
    " it. They disagree in the interesting cases — a workload pegging a core" +
    " with nothing contended stalls nobody."));
  grid.appendChild(p);

  host.appendChild(grid);
  const foot = el("div", "ov-sub",
    `${items.length} workloads · every figure is a fact on` +
    " resources/workloads, and every row opens the object it came from.");
  host.appendChild(foot);
}

/* ── collection view ─────────────────────────────────────── */

const PAGE_LIMIT = 500;
const MAX_ROWS = 2000;   // client-side ceiling; the crumb says when it's hit

async function loadCollection(deepLinkId = null) {
  if (state.subsystem === "system" && state.collection === "overview")
    return loadOverview();
  if (state.subsystem === "view")
    return loadView(state.collection);
  if (state.subsystem === "estate" && state.collection === "findings")
    return loadFindings();
  if (state.subsystem === "resources" && state.collection === "workloads")
    return loadResources();
  $("overview").hidden = true;
  $("views-pane").hidden = true;
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
      // Name the owning process when a mate serves this subsystem: "which
      // member is down" must be answerable from the failure itself. A solo
      // host's banner is unchanged (no owner recorded).
      const owner = state.agentForSubsystem[subsystem];
      banner(`Failed to load ${subsystem}/${collection}${owner ? ` (agent ${owner})` : ""}: ${err.message}`);
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
  /* A facet with nothing under it is normally a filter that matched nothing.
     It can also be a facet whose every row is held back by a hide group —
     pick `mount`, then hide mounts — and there "nothing matches" would be a
     lie: the rows are on this page, one chip away. Rare before, easy now
     that four kinds have groups and the type facet is keyed by kind, so name
     the group instead. Only when no text filter is also in play: with both,
     either could be the reason and neither can be shown to be. */
  if (state.facet && !state.filterText) {
    const route = `${state.subsystem}/${state.collection}`;
    const facetOf = FACETS[route];
    const held = new Map();
    if (facetOf) for (const item of state.page?.items || []) {
      if (facetOf(item) !== state.facet) continue;
      const group = hidingGroup(item, route);
      if (group && !state.revealed.has(group.key)) held.set(group, (held.get(group) || 0) + 1);
    }
    if (held.size)
      return `No ${state.facet} row is on the page right now: `
           + [...held].map(([g, n]) => `${n} held back as ${g.label}`).join(", ")
           + ". Reveal it from the bar above — nothing was dropped.";
  }
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
   a host on I/O and the operator could not tell which workload it was.

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
      //
      // The guest's address rides along, because the row without it actively
      // misleads: a tap's own Addresses are its link-local and nothing else, so
      // "vnet1 appliance  fe80::fc00:ff:fe00:80/64" reads as a VM with no IPv4
      // when the VM is sitting on 192.168.200.80. The address belongs to the
      // guest, not the link, so it renders inside the attribution rather than
      // in the link's own Addresses column. Absent when libvirt could not see
      // one (bridged guests leased externally often have no lease or ARP entry
      // to read) — silence there is honest, and better than the wrong owner's
      // address.
      for (const d of doms?.items || [])
        for (const tap of d.facts.HostTaps || [])
          owners[tap] = { parts: [{ label: d.native_id,
                                    href: hashFor("vms", "domains", d.id),
                                    addrs: d.facts.IPAddresses || [] }] };
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
      // The same payload carries IPv4Address per endpoint, and a veth has the
      // identical problem a tap does: its own Addresses are link-local, so the
      // container's address is the one the reader wants and the only one that
      // is not on screen.
      for (const obs of inspected)
        for (const ep of obs?.facts?.ContainerEndpoints || [])
          if (ep.MACAddress)
            containerByMac[ep.MACAddress.toLowerCase()] =
              { name: ep.Name, addrs: [ep.IPv4Address].filter(Boolean) };
      for (const item of rows) {
        if (item.facts.Kind !== "veth") continue;
        const via = byBridge[item.facts.Master];
        if (!via) continue;
        const net = { label: via.label, href: hashFor("docker", "networks", via.id) };
        const found = (item.facts.PeerMACAddresses || [])
          .map(m => containerByMac[String(m).toLowerCase()]).find(Boolean);
        if (found) {
          owners[item.native_id] = { parts: [net, {
            label: found.name,
            href: hashFor("docker", "containers", `container:${found.name}`),
            addrs: found.addrs,
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

/* ── fact names other adapters own, in one block ──
   The stalling panel below joins across subsystems, and every fact name it
   needs to do that belongs to an adapter this file does not own. They live
   here, once: a rename upstream is then a one-line change instead of a panel
   that quietly stops explaining itself. The ones landed alongside this work
   are matched by SHAPE rather than by spelling — the wording of a fact that
   another adapter owns is not this file's to depend on, and a panel that goes
   silent on a rename is worse than one that never joined at all.

   CONTAINER_ID  — the short container id, emitted under this one name by the
                   units adapter (read off a docker scope's own name) and by
                   the docker adapter (read off the container). A shared value
                   meant to be joined on, so it needs no shape matching.
   MACHINE_NAME  — the VM domain behind a machine scope, which the units
                   adapter recovers from the escaped scope name.
   DOCKER_SCOPE  — on a container row, the systemd scope that runs it. Matched
                   on the VALUE, because docker's scope name identifies itself
                   and nothing else on a container row looks like one. A
                   path-shaped value (a cgroup path) joins on its last segment.
   STALL_CLAIMS  — a slice row states, per pressure reading, exactly one of
                   three things: a member accounts for it, nothing inside does,
                   or it could not be ruled in or out. All three are stated
                   POSITIVELY by the adapter, so this panel reads a claim and
                   never infers one from an absence — a row saying none of the
                   three is a row this panel adds nothing to. Written against
                   StallExplainedBy / StallUnexplained /
                   StallAttributionUnobservable, each holding {reading: value};
                   matched on the verb in the key, so the surrounding words are
                   free to change.
   UNIT_NAME     — what an explanation's value has to look like to be read as a
                   member: this panel drops no row on a value it cannot read as
                   a unit name.
   RESOURCE_WORDS — the resources pressure is measured per. Used to refuse a
                   memory claim as an I/O one; see ioClaim. */
const CONTAINER_ID = "ContainerID";
const MACHINE_NAME = "MachineName";
const DOCKER_SCOPE = /(?:^|\/)(docker-[0-9a-f]{12,}\.scope)$/;
const STALL_CLAIMS = {
  explained: (w) => w.some((x) => x.startsWith("explain")),
  unexplained: (w) => w.some((x) => x.startsWith("unexplain")),
  unobservable: (w) => w.some((x) => x.startsWith("unobserv")),
};
const UNIT_NAME =
  /\.(service|scope|slice|mount|automount|socket|swap|target|timer|path|device)$/;
const RESOURCE_WORDS = ["io", "memory", "cpu"];

/* Fact names are camel case; this splits one into words so a verb or a
   resource can be matched as a whole word. Substring matching finds "io"
   inside "Attribution" and would read a memory claim as an I/O one — and
   finds "explain" inside "unexplained", which inverts the meaning outright. */
function factWords(key) {
  return String(key)
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/* What this row claims about its I/O stall under one of the three verbs, or
   null where it makes no such claim. Two spellings are accepted because the
   naming is not this file's: one key holding a per-reading map, and one key
   per reading with the resource in its own name. A key naming another
   resource is never read as I/O. */
function ioClaim(item, verb) {
  for (const [key, value] of Object.entries(item?.facts || {})) {
    const words = factWords(key);
    if (!STALL_CLAIMS[verb](words)) continue;
    if (value && typeof value === "object" && !Array.isArray(value)) {
      for (const [reading, claim] of Object.entries(value))
        if (factWords(reading).includes("io") && typeof claim === "string") return claim;
      continue;
    }
    if (words.includes("io") || !words.some((w) => RESOURCE_WORDS.includes(w))) {
      const claim = Array.isArray(value) ? value.find((v) => typeof v === "string") : value;
      if (typeof claim === "string") return claim;
    }
  }
  return null;
}

/* The member unit named as accounting for this row's I/O stall. Only a value
   that reads as a unit name counts: dropping a row is the one irreversible
   thing this panel does, and it does it on a name it could hand to systemctl,
   not on any string that happened to sit under the key. */
function ioExplainedBy(item) {
  const member = ioClaim(item, "explained");
  return member && UNIT_NAME.test(member) ? member : null;
}

/* Container name by every handle a unit row can offer: the scope that runs it
   (stated on the container row, matched by shape) and the short container id
   (stated by both adapters under one name, on purpose). Empty when docker is
   not served, declined, or paged past — and an empty map means every label
   falls back, never that a label is wrong. */
function containerNames(page) {
  const byHandle = new Map();
  for (const item of page?.items || []) {
    const name = item.name || item.native_id;
    if (!name) continue;
    if (item.facts?.[CONTAINER_ID]) byHandle.set(item.facts[CONTAINER_ID], name);
    for (const value of Object.values(item.facts || {})) {
      const scope = typeof value === "string" && DOCKER_SCOPE.exec(value);
      /* Keyed by BOTH the container id and the scope unit's full name. The
         id serves a row that carries ContainerID as a join key; the unit name
         serves one whose native id simply IS the scope, which is every row in
         resources/workloads. Same map, same source, no fact duplicated to
         make the join work. */
      if (scope) { byHandle.set(scope[1], name); byHandle.set(scope[0].replace(/^\//, ""), name); break; }
    }
  }
  return byHandle;
}

/* The name a unit row leads with — never an invented one. A container's own
   name where this row is the scope running it, the domain where it is a VM's
   machine scope (the units adapter already recovers that from the scope name),
   the row's own `name` where the collection carries one distinct from the
   native id, and otherwise exactly what printed before: the native id. Every
   step is something a host stated; a join that cannot be made falls through
   rather than guessing. */
function stallingName(item, containers) {
  const joined = containers.get(item.native_id)
    || (item.facts?.[CONTAINER_ID] && containers.get(item.facts[CONTAINER_ID]));
  if (joined) return joined;
  if (item.facts?.[MACHINE_NAME]) return item.facts[MACHINE_NAME];
  return item.name || item.native_id;
}

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

/* ── views (SPEC 6.2): operator-authored projections ─────────

   A view defers truth, never hides it: every panel is a real collection
   fetched through the same host-scoped api() the grid uses, every row
   links to its full observation, and every fact name resolves its meaning
   through factHelp() — nothing here re-states what an agent knows. Panels
   render for the CURRENTLY SELECTED host, deliberately: an estate-wide
   panel would need the roll-up the findings phase owns, and a quiet
   per-host view that switches hosts honestly beats a clever aggregation
   the hub contract forbids. */

/* ── estate findings (SPEC section 6.3) ───────────────────
   The registry's read side, rendered in three honest bands: current
   (derived this sweep), unobservable (nobody could look — lifecycle
   frozen, no `current` claim to render), and resolved (an agent that
   could look stopped deriving it). Acknowledgement STYLES a row and
   never removes it — the one power the design refuses is suppression,
   and this renderer holds that line by construction: every finding in
   the envelope gets a row, unconditionally. */

async function loadFindings() {
  const { epoch } = state;
  $("overview").hidden = true;
  $("collection-pane").hidden = true;
  const pane = $("views-pane");
  pane.hidden = false;
  // Repaint in the BACKGROUND: the previous render stays on screen while
  // the sweep runs (a full estate acquisition, honestly seconds), and the
  // new content lands in one replaceChildren swap. Blanking to a loading
  // line on every poll made the panel strobe in the foreground (reported
  // live, 2026-08-12). Only a first visit has nothing better to show.
  const firstLoad = pane.dataset.findings !== "1";
  if (firstLoad) pane.textContent = "sweeping the estate…";
  $("refresh").classList.add("spin");
  let body;
  try {
    const res = await fetch("/hub/findings");
    body = await res.json();
  } catch (err) {
    if (state.epoch !== epoch) return;
    if (firstLoad) {
      pane.textContent = "";
      banner(`The hub's findings surface did not answer: ${err}`);
    }
    return;
  } finally {
    $("refresh").classList.remove("spin");
  }
  if (state.epoch !== epoch) return;
  banner("");
  // The age shown is the SWEEP's, not the read's: the read is instant by
  // design and its timestamp would claim a freshness the data does not
  // have. swept_at is the honesty stamp.
  state.observedAt = body.swept_at || body.observed_at || null;

  const next = [];
  const head = el("div", "vw-head");
  head.appendChild(el("h2", "vw-title", "Estate findings"));
  if (body.site) head.appendChild(el("div", "vw-audience", `site ${body.site}`));
  next.push(head);

  for (const note of body.errors || [])
    next.push(el("div", "vw-error", note));
  const unswept = Object.entries(body.hosts || {})
    .filter(([, entry]) => !entry.swept);
  for (const [name, entry] of unswept)
    next.push(el("div", "vw-error",
      `${name} could not be swept: ${entry.error || "no answer"} — its findings below are frozen, not resolved`));

  const bands = [
    ["current", "Needs attention", (f) => f.current === true],
    ["frozen", "Unobservable right now", (f) => f.observable === false],
    ["resolved", "Resolved — condition no longer derived", (f) => f.current === false],
  ];
  const findings = body.findings || [];
  if (!findings.length) {
    next.push(el("div", "vw-note",
      "No findings anywhere the estate can currently see."));
  }
  for (const [, title, match] of bands) {
    const rows = findings.filter(match);
    if (!rows.length) continue;
    const card = el("section", "vw-card");
    card.appendChild(el("h3", "vw-panel-title", `${title} (${rows.length})`));
    for (const finding of rows) {
      card.appendChild(findingRow(finding));
      /* The finding's own agent, not the selected host: every link an estate
         finding offers belongs to the machine the finding is about.

         A SIBLING of the row, never a child of it — the row is itself an
         anchor and an anchor inside an anchor is not a link any browser will
         honour. Findings with no `look` add nothing here, which is also what
         keeps `.fnd-row:first-of-type` (the card's missing top border) still
         picking the first row: these are divs among the anchors. */
      const onward = lookLinks(finding.opinion, finding.agent);
      if (onward) card.appendChild(onward);
    }
    next.push(card);
  }
  pane.replaceChildren(...next);
  pane.dataset.findings = "1";
}

function findingRow(finding) {
  const row = el("a", "fnd-row");
  // Cross-host deep link. The registry names which AGENT last stated the
  // finding; the link leads with that agent's machine primary, because the
  // merged page serves the mate's subsystems and landing there keeps the
  // one nav — the agent name still decides which machine. An agent the hub
  // no longer lists passes through unchanged.
  row.href = `#/${machinePrimary(finding.agent)}/${finding.subsystem}/`
    + `${finding.collection}/` + idPath(finding.object.id);
  row.appendChild(el("span", `dot ${finding.opinion.level}`));
  const where = [finding.host?.hostname || finding.agent,
                 finding.host?.container, finding.host?.app]
    .filter(Boolean).join(" · ");
  const main = el("div", "fnd-main");
  main.appendChild(el("div", "fnd-title",
    `${finding.object.name || finding.object.native_id} — ${finding.opinion.message}`));
  const parts = [where, `${finding.subsystem}/${finding.collection}`,
                 finding.opinion.key];
  if (finding.first_seen) parts.push(`first seen ${ageOf(finding.first_seen)}`);
  if (finding.current === false && finding.last_seen)
    parts.push(`last seen ${ageOf(finding.last_seen)}`);
  main.appendChild(el("div", "fnd-meta", parts.join("  ·  ")));
  row.appendChild(main);
  if (finding.acknowledged) {
    const last = (finding.transitions || []).at(-1);
    const chip = el("span", "fnd-ack", "acknowledged");
    if (last?.by) chip.title = `by ${last.by}${last.note ? ` — ${last.note}` : ""}`;
    row.appendChild(chip);
  }
  return row;
}


async function loadView(name) {
  const { epoch } = state;
  const doc = (state.views?.views || []).find(v => v.name === name);
  $("overview").hidden = true;
  $("collection-pane").hidden = true;
  const pane = $("views-pane");
  pane.hidden = false;
  pane.textContent = "";
  // The findings panel's keep-content-while-sweeping marker must not
  // survive into a view render, or navigating back to findings would
  // show this view's stale content for the seconds the sweep takes.
  delete pane.dataset.findings;
  if (!doc) {
    // A stale bookmark for a view the operator since removed: say so and
    // stay useful, exactly the unreachable-host shape.
    banner(`No view named ${name} is served by this hub.`);
    return;
  }
  banner("");
  const head = el("div", "vw-head");
  head.appendChild(el("h2", "vw-title", doc.title));
  if (doc.audience) head.appendChild(el("div", "vw-audience", doc.audience));
  pane.appendChild(head);
  // Malformed sibling documents are part of the envelope, and an operator
  // editing views deserves to see the refusal where they look first.
  for (const bad of state.views?.errors || []) {
    pane.appendChild(el("div", "vw-error",
      `${bad.file}: ${bad.error} — this document is not being served`));
  }
  for (const panel of doc.panels) {
    pane.appendChild(panel.kind === "pipeline"
      ? renderPipelinePanel(panel, epoch)
      : renderViewPanel(panel, epoch));
  }
}

/* A pipeline panel: authored STAGES rendered as columns in flow order,
   with the flow itself derived — never drawn — from the join facts the
   rows carry. Clicking a row lights every row it relates to in the
   neighbouring stages (the DownloadId a manager states matching the
   transfer id a client states), because an arrow that cannot say which
   rows it connects is decoration, and these can. Case-insensitive on
   the join value: the estate's keys cross APIs that disagree on case. */
function renderPipelinePanel(panel, epoch) {
  const card = el("section", "vw-card");
  card.appendChild(el("h3", "vw-panel-title", panel.title));
  if (panel.note) card.appendChild(el("div", "vw-note", panel.note));
  const flow = el("div", "pl-flow", "loading…");
  card.appendChild(flow);
  const stages = panel.stages || [];
  Promise.all(stages.map(stage => {
    const query = new URLSearchParams(stage.filters || {});
    query.set("limit", String(PAGE_LIMIT));
    return api(`/v1/${stage.subsystem}/${stage.collection}?${query}`)
      .then(page => page.items || [])
      .catch(err => ({ error: String(err) }));
  })).then(results => {
    if (state.epoch !== epoch) return;
    flow.textContent = "";
    const rowNodes = stages.map(() => []);
    const joinValue = (item, fact) =>
      String(fact === "native_id" ? item.native_id
             : fact === "id" ? item.id
             : item.facts?.[fact] ?? "").toLowerCase();
    const clearLinks = () => rowNodes.forEach(nodes =>
      nodes.forEach(node => node.classList.remove("linked", "picked")));
    for (const [at, stage] of stages.entries()) {
      const column = el("div", "pl-stage");
      const items = results[at];
      const count = Array.isArray(items) ? items.length : "—";
      column.appendChild(el("div", "pl-stage-title",
                            `${stage.title} (${count})`));
      if (!Array.isArray(items)) {
        column.appendChild(el("div", "vw-error", items.error));
        flow.appendChild(column);
        continue;
      }
      if (!items.length)
        column.appendChild(el("div", "pl-empty", "nothing here right now"));
      for (const item of items) {
        const row = el("a", "pl-row");
        row.href = hashFor(stage.subsystem, stage.collection, item.id);
        if (item.worst_opinion_level)
          row.appendChild(el("span", `dot ${item.worst_opinion_level}`));
        row.appendChild(el("span", "pl-label",
          (stage.label && item.facts?.[stage.label])
            || item.name || item.native_id));
        row.onclick = (event) => {
          if (event.metaKey || event.ctrlKey) return; // real navigation
          event.preventDefault();
          clearLinks();
          row.classList.add("picked");
          // Forward join: this stage declares how it relates to the next.
          const forward = stage.join;
          if (forward && at + 1 < stages.length) {
            const value = joinValue(item, forward.fact);
            if (value) rowNodes[at + 1].forEach(node => {
              if (node.dataset.back === value) node.classList.add("linked");
            });
          }
          // Backward join: the previous stage declared how it reaches us.
          const backward = at > 0 ? stages[at - 1].join : null;
          if (backward) {
            const mine = joinValue(item, backward.targetFact);
            if (mine) rowNodes[at - 1].forEach(node => {
              // Previous rows carry the TARGET value they forward to us.
              if (node.dataset.fwd === mine) node.classList.add("linked");
            });
          }
        };
        // EVERY row registers — clearing and the backward scan must reach
        // rows in stages nobody joins into (stage 0 included), and several
        // rows sharing one join value (a season pack's queue records) must
        // all light, so the values ride as data attributes, never map keys.
        const backward = at > 0 ? stages[at - 1].join : null;
        if (backward) {
          const back = joinValue(item, backward.targetFact);
          if (back) row.dataset.back = back;
        }
        if (stage.join)
          row.dataset.fwd = joinValue(item, stage.join.fact);
        rowNodes[at].push(row);
        column.appendChild(row);
      }
      flow.appendChild(column);
    }
  });
  return card;
}

function renderViewPanel(panel, epoch) {
  const card = el("section", "vw-card");
  card.appendChild(el("h3", "vw-panel-title", panel.title));
  if (panel.note) card.appendChild(el("div", "vw-note", panel.note));
  const body = el("div", "vw-body", "loading…");
  card.appendChild(body);
  const query = new URLSearchParams(panel.filters || {});
  query.set("limit", String(PAGE_LIMIT));
  api(`/v1/${panel.subsystem}/${panel.collection}?${query}`)
    .then(page => {
      if (state.epoch !== epoch) return;
      body.textContent = "";
      if (page.status === "error") {
        // The agent's reason, verbatim — a declined collection on this host
        // is a true statement the audience can read.
        body.appendChild(el("div", "vw-error", (page.errors || []).join("; ")));
        return;
      }
      if (!page.items.length) {
        body.appendChild(el("div", "empty", "nothing here right now"));
        return;
      }
      body.appendChild(viewTable(panel, page.items));
      if (page.total > page.items.length) {
        const more = el("a", "vw-more",
          `showing ${page.items.length} of ${page.total} — open the full collection`);
        more.href = hashFor(panel.subsystem, panel.collection);
        body.appendChild(more);
      }
    })
    .catch(exc => {
      if (state.epoch !== epoch) return;
      body.textContent = "";
      body.appendChild(el("div", "vw-error", String(exc.message || exc)));
    });
  return card;
}

function viewTable(panel, items) {
  const table = el("table", "vw-table");
  const thead = el("thead");
  const hrow = el("tr");
  hrow.appendChild(el("th", null, ""));   // severity dot column
  for (const key of panel.columns || []) {
    const th = el("th", null, key);
    const help = factHelp(key, panel.subsystem, panel.collection);
    if (help) th.title = help;
    hrow.appendChild(th);
  }
  thead.appendChild(hrow);
  table.appendChild(thead);
  const tbody = el("tbody");
  for (const item of items) {
    const row = el("tr");
    row.className = "vw-row";
    const dotCell = el("td");
    const dot = el("span", `dot ${item.worst_opinion_level || "none"}`);
    dot.title = item.worst_opinion_level || "no severity claim";
    dotCell.appendChild(dot);
    row.appendChild(dotCell);
    for (const key of panel.columns || []) {
      row.appendChild(el("td", "vw-cell", viewCellText(key, item)));
    }
    // The whole row is the drill: one click from any panel to the full
    // observation, which is what "defers, never hides" means in pixels.
    row.onclick = () => goTo(panel.subsystem, panel.collection, item.id);
    tbody.appendChild(row);
  }
  table.appendChild(tbody);
  return table;
}

function viewCellText(key, item) {
  const value = cellValue(key, item);
  if (value === undefined || value === null) return "";
  if (typeof value === "number" && /Bytes$/.test(key)) return humanBytes(value);
  if (Array.isArray(value)) return value.map(String).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}


async function loadOverview() {
  const { epoch } = state;
  $("views-pane").hidden = true;
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
    // The KPI needs only the total, but the stalling panel needs these rows to
    // put a name on a docker scope — so this asks for the page instead of a
    // second, near-identical request. Still one ask, still guarded: a host that
    // serves no docker makes no docker call at all, and the panel then labels
    // exactly as it did before.
    asks.call = api("/v1/docker/containers?limit=200");
  }
  if (has("vms", "domains")) {
    asks.vrun = api("/v1/vms/domains?State=running&limit=1");
    asks.vall = api("/v1/vms/domains?limit=1");
  }
  if (has("units", "units")) asks.ufail = api("/v1/units/units?ActiveState=failed&limit=1");
  // The stalled-workload list beside the pressure meter. Cheap because the PSI
  // numbers already ride on the row (that was the point of putting them there),
  // so this is one page rather than a walk of every object. It reads
  // resources/workloads rather than units/units because consumption moved
  // there with the cgroup walk — and the collection now carries the ROOT
  // slice, which is what lets the panel say a host stall belongs to no
  // workload at all instead of leaving the meter unreconciled.
  if (has("resources", "workloads"))
    asks.stalled = api("/v1/resources/workloads?limit=800");
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

/* `title` is the opinion's own sentence, on the label that names the reading.
   The memory panel already explains itself in place — the ARC rides as its own
   dimmed segment with "… available · ARC n GiB" beneath — but the pressure and
   swap rows do not, and an `info` verdict there leaves a neutral bar with no
   visible reason. The sentence is the reason, so it goes one hover from the
   number, in the dotted-underline idiom this UI already uses for a fact the
   host can explain. No new colour, no new mark. */
function ovRow(label, meterNode, value, side, { title = null } = {}) {
  const row = el("div", "ov-row");
  const lbl = el("span", "lbl", label);
  if (title) lbl.title = title;
  row.appendChild(lbl);
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
  /* Meter severity is the agent's, not ours (SPEC rule 14): one opinion per
     resource area, all three levels honoured. `info` is a level, not a weak
     warn — it is what the rulebook says when a reading is explained rather than
     alarming (memory that is ARC occupancy, not pressure) — so it leaves the bar
     at the neutral accent while the sentence itself prints below and on hover.
     Reduced rather than assigned: two opinions can land on one meter, and the
     last one read is not necessarily the worst one. */
  const levels = {};
  const notes = {};
  for (const op of obs.opinions || []) {
    const target = OPINION_METER[op.key];
    if (!target) continue;
    const worst = worstOpinionLevel([levels[target], op.level]);
    if (worst === null) continue;          // a level we cannot rank colours nothing
    // The sentence follows the level: whichever opinion is now the worst owns
    // the row's hover text. First one wins a tie, keeping the agent's order.
    if (worst !== levels[target] || notes[target] === undefined) notes[target] = op.message;
    levels[target] = worst;
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
      // Attention only, and `worst` can also be ok / info / null — none of which
      // this strip is for (ATTENTION_LEVELS). The count matches: it totals the
      // levels the chip claims, not every row the collection holds.
      if (!ATTENTION_LEVELS.includes(v.worst)) continue;
      const n = ATTENTION_LEVELS.reduce((sum, level) => sum + (v.counts?.[level] || 0), 0);
      attention.push({ sub, coll, worst: v.worst, n });
    }
  }
  if (attention.length) {
    const strip = el("div", "ov-attention");
    // Critical first. Safe to rank because the filter above already narrowed
    // `worst` to opinion levels; ok and null are not on this scale.
    attention.sort((a, b) =>
      OPINION_LEVELS.indexOf(b.worst) - OPINION_LEVELS.indexOf(a.worst));
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
      p.appendChild(ovRow("busy", meter(cpu.busy, levels.cpu), `${cpu.busy}%`,
                          undefined, { title: notes.cpu }));
      // Shown as its own row, not folded into busy: a core waiting on a disk
      // is available, and lumping the two is how a storage problem gets read
      // as a CPU problem. Its scale is the same 0..100 so the eye can compare.
      p.appendChild(ovRow("io wait", meter(cpu.iowait, levels["psi-io"]),
                          `${cpu.iowait}%`, undefined, { title: notes["psi-io"] }));
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
                        `${f.MemUsedPercent}%`, undefined, { title: notes.mem }));
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
                          `${f.SwapUsedPercent ?? 0}%`, undefined, { title: notes.swap }));
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
      p.appendChild(ovRow(name, meter(v60, levels[key]), `${v60}%`, `${v10}%`,
                          { title: notes[key] }));
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
    p.appendChild(el("h3", null, "Stalling most · workload, 60s"));
    // Names for the scopes that carry an id instead of one. The container rows
    // are the ones the containers KPI already asked for, so a host that serves
    // no docker pays nothing here and simply gets no map.
    const containers = containerNames(got.call);
    const stalling = got.stalled.items.filter(u => (u.facts.PsiIoFullAvg60 ?? 0) > 0);
    // A slice cannot out-stall its own worst member: PSI "full" is time in
    // which EVERY non-idle task in the cgroup was blocked, and a parent's tasks
    // are its children's — so an explained slice makes the same statement as
    // the member that explains it, less specifically and with a smaller number,
    // while costing that member one of five rows. Dropped, but only where the
    // adapter names the member; the number itself is never the reason.
    const worst = stalling
      .filter(u => ioExplainedBy(u) === null)
      .sort((a, b) => (b.facts.PsiIoFullAvg60 ?? 0) - (a.facts.PsiIoFullAvg60 ?? 0))
      .slice(0, 5);
    if (!worst.length) {
      p.appendChild(el("div", "ov-sub", stalling.length
        ? "every workload reporting an I/O stall is a slice its own members explain"
        : "no workload reports an I/O stall"));
    } else {
      for (const u of worst) {
        const share = u.facts.PsiIoFullAvg60;
        const row = el("div", "ov-row");
        // The name a human chose, where anything states one — a container id
        // written out in full names nothing, and it is not a truncated name
        // that a wider column would fix. The native id stays the link target
        // and the hover, because it is the string systemctl takes and the
        // container name is not.
        const named = stallingName(u, containers);
        const lbl = el("a", "lbl wide", named);
        lbl.href = hashFor("resources", "workloads", u.id);
        lbl.title = named === u.native_id ? u.native_id : `${named} — ${u.native_id}`;
        row.appendChild(lbl);
        row.appendChild(meter(share, share >= 20 ? "warn" : null));
        row.appendChild(el("span", "val", `${share}%`));
        p.appendChild(row);
        // Why a slice is still here, in the two cases where the row says: one
        // is the finding — a stall belonging to the slice as a whole, which no
        // member's row will ever state — and the other is the reading that
        // could not settle it, which must not read as the first.
        const unexplained = ioClaim(u, "unexplained");
        const unsettled = unexplained ? null : ioClaim(u, "unobservable");
        if (unexplained || unsettled) {
          // Two notes in one slot, and the difference between them is the
          // difference between a result and the absence of one — so it must
          // not rest on the wording, which is all that separated them: both
          // opened "nothing inside", one class, one weight. A reader taking
          // the hedge for the finding skips the row no member will ever
          // state; one taking the finding for the hedge acts on a slice
          // nobody measured. Each gets a modifier class (styles.css breaks
          // the unsettled one's rule and slants its face) and a different
          // SUBJECT: the finding speaks about the slice, the hedge about the
          // reading. Neither takes a severity — both rules state info, and
          // a gap in the measurement is not a fault of the slice.
          const note = el("div",
            `ov-sub row-note ${unexplained ? "note-finding" : "note-unsettled"}`,
            unexplained
              ? "nothing inside this slice accounts for it"
              : "part of this slice could not be read — neither ruled in nor out");
          // Which members went unread is the host's sentence to make, and it
          // stays a hover: this panel prints no sentence it did not write.
          note.title = unexplained || unsettled;
          p.appendChild(note);
        }
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
      // `name` is the human one where a collection carries both; the native id
      // is the handle a command line takes, so it keeps the hover. Titled only
      // where the two differ — a tooltip repeating the label teaches nothing
      // and this UI dots-underlines anything titled.
      const lbl = el("a", "lbl wide", item.name || item.native_id);
      if (item.name && item.name !== item.native_id) lbl.title = item.native_id;
      lbl.href = hashFor("storage", "pools", item.id);
      row.appendChild(lbl);
      if (ATTENTION_LEVELS.includes(lvl)) row.appendChild(el("span", `dot ${lvl}`));
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
      // Unlike a pool, mount_opinions is capacity-only, so the row's level IS a
      // verdict on this meter's own magnitude and may colour it.
      const lvl = ATTENTION_LEVELS.includes(m.worst_opinion_level)
        ? m.worst_opinion_level : null;
      const row = el("div", "ov-row");
      const lbl = el("a", "lbl wide", m.name || m.native_id);
      // The title already carried the native id, which is what makes leading
      // with a name safe here.
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
    for (const op of obs.opinions) {
      // The strip an operator meets first, and the one that started this: a
      // pressure verdict with nowhere to click was the whole complaint.
      const line = el("div", `opinion ${op.level}`, `${op.key} — ${op.message}`);
      const onward = lookLinks(op);
      if (onward) line.appendChild(onward);
      box.appendChild(line);
    }
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
    const count = el("span", "count", shown === total ? `${total}` : `${shown} of ${total}`);
    /* "260 of 808" already refuses to pass a subset off as the whole, and
       that is the load-bearing half. What it cannot say in two numbers is
       WHO took the other 548 — a hide rule, a facet, or something typed in
       the filter. The chips name the hide rules beside their counts; this
       puts the same arithmetic on the number the reader is looking at, so
       the two can be checked against each other rather than believed. */
    const withheld = hiddenCounts(p.items, `${state.subsystem}/${state.collection}`)
      .filter(([group]) => !state.revealed.has(group.key));
    if (withheld.length) {
      count.title = `${shown} of ${total} rows shown. Hidden by default: `
        + withheld.map(([group, n]) => `${n} ${group.label}`).join(", ")
        + " — reveal from the bar below. Every row the host reported is here;"
        + " a failed row is never hidden.";
    }
    crumb.appendChild(count);
    if (p.next_cursor) crumb.appendChild(el("span", "count", `(first ${p.items.length} loaded; history continues)`));
  }
  $("age").textContent = state.observedAt ? `observed ${ageOf(state.observedAt)}` : "";
}

function renderFacets() {
  const bar = $("facets");
  const route = `${state.subsystem}/${state.collection}`;
  const facetOf = FACETS[route];
  // The overview is a designed panel with no rows to facet; its pseudo-page
  // must not resurrect the bar.
  bar.hidden = !state.page || route === "system/overview";
  bar.textContent = "";
  if (bar.hidden) return;
  // Facet counts describe what is on screen, so they respect the hide rules.
  const base = afterHiding(state.page.items, route);
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
  /* One chip per group that is holding something back, in HIDDEN's order so
     the bar reads the same on every visit. A group matching nothing shows no
     chip: a control that reveals an empty set is noise, and worse, it implies
     rows are being withheld when none are.

     Five of them on units/units is more than a bar should carry loose, and
     the answer is NOT to fold them into a menu: a page that must click to
     say what it is withholding has stopped saying it. The clutter was never
     the count, it was that two different kinds of control ran together in
     one undifferentiated line — facet chips narrow what you see, ghost chips
     restore what was removed. So the ghosts become one run behind a seam,
     with a lead-in stating the total currently held back. Every chip keeps
     its own label, its own number and its own click, and the run's total is
     the sum of the chips beside it, which puts the closing arithmetic on
     screen instead of only in the crumb's hover.

     From two groups up, only. A route holding something back under a single
     group — hardware/scsi has exactly one — has no sum to state that its one
     chip is not already stating, and a heading that restates its only member
     is the same noise as a control that reveals an empty set. Such a route
     renders exactly as it did before the run existed. */
  const withheld = hiddenCounts(state.page.items, route);
  const run = withheld.length > 1 ? el("div", "hidden-run") : bar;
  if (withheld.length > 1) {
    const held = withheld.filter(([g]) => !state.revealed.has(g.key))
                         .reduce((sum, [, n]) => sum + n, 0);
    const lead = el("span", "hidden-lead", held ? `holding back ${held}` : "nothing held back");
    lead.title = held
      ? `Of ${state.page.items.length} rows collected, ${base.length} survive`
        + ` the hide rules and ${held} are held back — the number beside each`
        + " chip to the right, and they sum to this one. Nothing was dropped;"
        + " a failed row is never hidden by any of them."
      : "Every group on this route is revealed: nothing is being held back.";
    run.appendChild(lead);
    bar.appendChild(run);
  }
  for (const [group, n] of withheld) {
    const on = state.revealed.has(group.key);
    const chip = el("button", "chip ghost" + (on ? " on" : ""));
    chip.append(`${on ? "hide" : "show"} ${group.label}`,
                el("span", "chip-n", String(n)));
    // The chip's label says what and how many; the hover says which way the
    // page is currently leaning, because "show inactive 138" read quickly
    // does not by itself tell you the 138 are missing right now.
    chip.title = on
      ? `Revealed: ${n} ${group.label}. Click to hide them again.`
      : `Hidden right now: ${n} ${group.label}. Click to reveal them —`
        + " nothing was dropped, the page holds every row the host reported,"
        + " and a failed row is never hidden by any rule.";
    chip.onclick = () => {
      if (on) state.revealed.delete(group.key); else state.revealed.add(group.key);
      renderFacets(); renderGrid(); renderCrumb();
    };
    run.appendChild(chip);
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
        // An arrival's transient column ticks like any other, so unticking it
        // must actually drop it — the stored preferences hold nothing to
        // remove. Clicking it again then adds it for good, which is the
        // deliberate choice the transient one deliberately is not.
        if (state.lookColumn?.fact === key) state.lookColumn = null;
        if (current.has(key)) {
          if (preset.includes(key)) prefs.remove = [...(prefs.remove || []), key];
          prefs.add = (prefs.add || []).filter(k => k !== key);
        } else {
          prefs.remove = (prefs.remove || []).filter(k => k !== key);
          if (!preset.includes(key)) prefs.add = [...(prefs.add || []), key];
        }
        setColPrefs(route, prefs);
        // Dropping the sorted column drops the sort with it. An order no
        // header shows and no header click can reproduce explains nothing —
        // the same rule the arrival's transient column exists to satisfy,
        // read the other way round. `current.has(key)` scopes this to the
        // untick branch, and a key comes from the preset or from prefs.add
        // but never both, so unticking always removes the column. sortDir is
        // left alone: the header path reads it only as
        // `state.sortKey === key ? -state.sortDir : 1`, so it is inert
        // beside a null key.
        if (current.has(key) && state.sortKey === key) state.sortKey = null;
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
  /* The fact a `look` link arrived ordering by, unioned in for THIS VISIT
     ONLY and stored nowhere. A sort by a column nobody can see explains
     nothing — PsiIoFullAvg60 is not among units/units' presets — but the
     answer to that is one transient column, not an edit to the reader's saved
     layout: leaving the route restores exactly what they chose. Making it
     permanent is the picker's job, and theirs to decide. */
  const arrived = state.lookColumn?.fact;
  if (arrived && !cols.includes(arrived)) cols.push(arrived);
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
  let items = afterHiding(state.page?.items ?? [], `${state.subsystem}/${state.collection}`);
  const facetOf = FACETS[`${state.subsystem}/${state.collection}`];
  if (facetOf && state.facet) items = items.filter(it => facetOf(it) === state.facet);
  const q = state.filterText.toLowerCase();
  if (q) {
    // The filter matches everything the ROW can show, not a subset of it:
    // identity members, every fact, derived (pseudo) columns, and the
    // cross-subsystem attributions loadOwners() paints beside the row.
    // Typing a docker network's name on network/links found nothing while
    // that exact name sat rendered on the bridge's row (reported live,
    // 2026-08-12) — "my eyes can see it, the filter cannot" is the whole
    // class this closes.
    const contains = (v) =>
      v !== null && v !== undefined && vstr(v).toLowerCase().includes(q);
    items = items.filter(it => {
      if ([it.id, it.name, it.native_id, it.type].some(contains)) return true;
      if (Object.values(it.facts).some(contains)) return true;
      for (const derive of Object.values(PSEUDO_COLUMNS)) {
        let value;
        try { value = derive(it); } catch { continue; }
        if (contains(value)) return true;
      }
      const owner = state.owners?.[it.native_id];
      return (owner?.parts || []).some(part =>
        contains(part.label) || (part.addrs || []).some(contains));
    });
  }
  if (state.sortKey) {
    const k = state.sortKey, dir = state.sortDir;
    items = [...items].sort((a, b) => {
      const av = k === "id" ? a.id : cellValue(k, a);
      const bv = k === "id" ? b.id : cellValue(k, b);
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
    // A column header is where a reader first meets a native name — often
    // before they open anything. Pseudo-columns name no fact and get none.
    const help = factHelp(key);
    if (help) th.title = help;
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
    /* "none", not "info": an absent level and a neutral verdict are different
       statements and must not share a mark. adapters/network.py omits the field
       for a quiet operstate precisely so no dot is drawn — "no judgment is
       derivable, so the severity field is omitted rather than drawing a neutral
       dot two auditors misread as a verdict (audit 2026-08-10)" — and the old
       `|| "info"` fallback put that dot straight back. The failure mode recorded
       there is a mark being misread, so the mark now says what it means. */
    const dot = el("span", `dot ${item.worst_opinion_level || "none"}`);
    dot.title = item.worst_opinion_level
      ? `worst opinion on this row: ${item.worst_opinion_level}`
      : "this row carries no severity — nothing here is judged";
    idCell.appendChild(dot);
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
        // The workload's own address, not the interface's. Marked as the
        // owner's so the two are never read as one set: the Addresses column
        // stays the link's facts and this stays the join.
        if (part.addrs?.length) {
          const at = el("span", "owner-addr", ` ${part.addrs.join(" ")}`);
          at.title = `${part.label} reports ${part.addrs.join(", ")}`
                   + " — the workload's address, not this interface's";
          wrap.appendChild(at);
        }
      });
      idCell.appendChild(wrap);
    }
    tr.appendChild(idCell);

    for (const key of cols) {
      tr.appendChild(renderCell(key, cellValue(key, item), item));
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

/* Facts whose value IS a sentence in another language, and which a reader
   has to read every word of. Everywhere else an ellipsis costs a detail; a
   truncated firewall rule costs the CONDITION — `meta iifname tailscale0 tcp
   dport 22 counter accept` clipped at the column edge reads as a rule
   admitting sshd from anywhere, which is the same inversion the renderer
   goes to such lengths to prevent, reintroduced by CSS. */
const WRAPPING_FACTS = new Set(["Rendered", "Residue", "AdmittingRules"]);

function renderCell(key, value, item) {
  const td = el("td");
  if (WRAPPING_FACTS.has(key)) td.className = "wrap";
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
    /* The badge is the priority's LABEL; only emerg/alert/crit is also a
       verdict. This read `<= 3 ? crit : === 4 ? warn`, which painted every err
       row red and every warning row amber — while the rulebook calls p3 `info`
       ("err alone is not attention-worthy — applications log routine output at
        err") and says nothing whatever about p4 and below. So a red badge sat
       on the same row as a faint info dot, all day, on the densest collection
       here. Colour is semantic only (SPEC section 8); it cannot claim more than
       the rulebook does. PRIORITY_CRITICAL mirrors rules/logs.py and conformance
       lints the number. */
    const cls = value <= PRIORITY_CRITICAL ? "crit" : "neutral";
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
  // Title, like every other long-value branch below: cells are capped at
  // min(380px, 55vw) and ellipsised, and an array is the one shape that
  // routinely exceeds it — a link with an IPv4 and three IPv6 addresses runs to
  // 177 characters, of which about 55 are visible. Without this the remainder
  // is unreachable: the grid does not scroll horizontally, so the value is not
  // merely clipped, it is gone.
  if (Array.isArray(value)) {
    td.className = "mono";
    td.textContent = value.map(vstr).join(", ");
    if (value.length > 1) td.title = value.map(vstr).join("\n");
    return td;
  }
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
    if (epoch !== state.epoch || state.selectedId !== objectId) return;
    // A 404 is an ANSWER, not a failure, and rendering it as one was the
    // reported bug: 16 of 63 findings opened onto a red "Failed to load"
    // banner, every one of them a resolved finding whose object had gone.
    // The condition cleared because the container was removed, the unit
    // stopped being generated, the disk was pulled — which is exactly what
    // the reader wanted to know and precisely what the banner hid.
    if (err.status === 404) {
      state.detailObs = { gone: true, id: objectId, subsystem, collection,
                          checked_at: new Date().toISOString() };
      renderGrid();
      return;
    }
    const owner = state.agentForSubsystem[subsystem];
    banner(`Failed to load ${objectId}${owner ? ` (agent ${owner})` : ""}: ${err.message}`);
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

/* An object the agent looked for and did not find.

   Stated as an observation, because that is what it is: this host was asked
   just now and this object is not among the things it has. The old
   behaviour — a red "Failed to load" banner — reported the product as
   broken when the product had worked, and reported nothing about the one
   thing the reader had come to find out.

   Reached almost entirely from a resolved finding. The condition cleared
   BECAUSE the object went, so the 404 is very often the answer to "what
   happened here" rather than an obstacle in front of it. The wording says
   that without asserting it: this host, right now, does not have it. */
function renderGoneExpansion(obs, colspan) {
  const tr = el("tr", "expand");
  const td = el("td");
  td.colSpan = colspan;
  const box = el("div", "d-box");

  const head = el("div", "d-head");
  head.appendChild(el("span", "d-id", obs.id));
  head.appendChild(el("span", "d-sub", `not present · checked ${ageOf(obs.checked_at)}`));
  const close = el("button", "d-close", "✕");
  close.title = "Collapse (Esc)";
  close.onclick = (e) => { e.stopPropagation(); collapseDetail(); stripObjectFromHash(); };
  head.appendChild(close);
  box.appendChild(head);

  const host = state.currentHost || "this host";
  const note = el("div", "opinion info");
  note.appendChild(el("div", "msg",
    `${host} has no ${obs.subsystem}/${obs.collection} object with this id. `
    + "It was there when the observation that named it was made, and it is "
    + "not there now — which is usually why a finding about it resolved."));
  box.appendChild(note);

  // The one onward move that is certainly here: what the collection holds
  // NOW. No link to a changes view, because this UI has no changes route —
  // offering one would be the same class of mistake as the banner.
  const onward = el("div", "look");
  const link = el("a", "look-link", `what ${obs.subsystem}/${obs.collection} holds now`);
  link.href = hashFor(obs.subsystem, obs.collection);
  link.onclick = (e) => { e.stopPropagation(); collapseDetail(); };
  onward.appendChild(link);
  box.appendChild(onward);

  td.appendChild(box);
  tr.appendChild(td);
  return tr;
}

function collapseDetail() {
  state.selectedId = null;
  state.detailObs = null;
  state.evidence = null;
  state.lookupDraft = null;
  state.suppressAutoOpen = true;
  renderGrid();
}

/* The same object, seen by another collection.

   One real thing routinely has more than one row in this product, and until
   now nothing said so. A running container is `container:radarr` under
   docker, `unit:docker-<id>.scope` under units, THE SAME `unit:` id again
   under resources/workloads, and a row in port-exposure if it publishes a
   port. The ids genuinely join — resources publishes the identical ids units
   does, and port-exposure reuses the listening socket's — but a reader
   clicking between them had no way to know they were looking at one thing
   twice, which is the substance of "the taxonomy needs a rethink".

   Drawn from the agent's own prefix map, so there is nothing here to keep in
   step: a collection that stops sharing ids stops appearing, and one that
   starts appears without an edit. The current page is excluded, because
   telling a reader they are where they are is furniture. */
function alsoAppearsIn(objectId) {
  const others = idHomes(objectId).filter(
    h => !(h.subsystem === state.subsystem && h.collection === state.collection));
  if (!others.length) return null;
  const box = el("div", "d-also");
  box.appendChild(el("span", "d-also-label", "also seen as"));
  for (const home of others) {
    const link = el("a", "d-also-link", `${home.subsystem}/${home.collection}`);
    link.href = hashFor(home.subsystem, home.collection, objectId);
    link.title = `the same object, ${home.collection === "workloads"
      ? "as resource accounting sees it"
      : `as ${home.subsystem}/${home.collection} sees it`}`;
    link.onclick = (e) => e.stopPropagation();
    box.appendChild(link);
  }
  return box;
}

/* A fact the head has already said.

   Part of "think of the poor admin here" (reported 2026-08-14, of a page
   where nearly half the rows repeated something): a protection job opens
   with `job:media-archive` across the top and then leads its facts with
   `Job  media-archive`. The name is on screen twice before the reader has
   learned anything.

   Value equality only, against the two strings the head actually renders —
   never the fact's NAME, because a fact called Name whose value differs from
   the object's name is the interesting case and must survive. And never a
   value the head merely contains: `ContainerID c06407a40a94` is a prefix of
   the scope in the head and is a different fact about a different thing. */
function restatesTheHead(value, object) {
  if (typeof value !== "string" || !value) return false;
  return value === object?.native_id || value === object?.name;
}

/* The facts, grouped by WHAT KIND OF CLAIM they make.

   One flat table rendered `UsedBytes` — go and check it with zfs list — in
   the same plain cell as `AdmittedFromCertain`, a two-closure computation
   over a firewall ruleset that was wrong five times in a single review
   pass. A reader had no way to tell which was which, and a model reading
   the same table over MCP restates the second with the confidence of the
   first.

   Blocks, not a badge on every row. Most facts are measured, so per-row
   marks would be three hundred pieces of noise carrying the same word; the
   heading says it once, for everything under it. An object whose facts are
   all measured looks exactly as it always did — one grid, no heading — so
   the structure appears only where there is something to say.

   Order is measured, derived, declared: what the machine said, then what
   this product worked out from it, then what a person asserted. Reading
   down is reading outwards from the ground truth. */
const FACT_KIND_ORDER = ["measured", "derived", "declared"];

function factBlocks(entries, subsystem, collection) {
  const byKind = new Map(FACT_KIND_ORDER.map(kind => [kind, []]));
  for (const entry of entries) {
    const kind = factKind(entry[0], subsystem, collection);
    (byKind.get(kind) || byKind.get("measured")).push(entry);
  }
  const used = FACT_KIND_ORDER.filter(kind => byKind.get(kind).length);
  const box = el("div", "facts-box");
  for (const kind of used) {
    // A single kind needs no heading: naming the only category present
    // tells the reader nothing they can act on, and it is furniture on the
    // great majority of objects in the product.
    if (used.length > 1) {
      const head = el("div", `fact-kind ${kind}`);
      head.appendChild(el("span", "dot"));
      head.appendChild(el("span", "name", kind));
      head.appendChild(el("span", "note", KIND_NOTE[kind]));
      box.appendChild(head);
    }
    const grid = el("div", "facts");
    for (const [key, value] of byKind.get(kind)) {
      const k = el("div", "k", key);
      const help = factHelp(key, subsystem, collection);
      if (help) k.title = help;
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
    box.appendChild(grid);
  }
  return box;
}

function renderExpansion(colspan) {
  const obs = state.detailObs;
  if (obs?.gone) return renderGoneExpansion(obs, colspan);
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

  const elsewhere = alsoAppearsIn(obs.object.id);
  if (elsewhere) box.appendChild(elsewhere);

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
      // The chips are the facts the opinion reasoned from, so they are exactly
      // the names a reader most needs explained.
      const help = factHelp(path.split(".")[0]);
      if (help) chip.title = help;
      chip.onmouseenter = () => citeFacts(path, true);
      chip.onmouseleave = () => citeFacts(path, false);
      ev.appendChild(chip);
    }
    o.appendChild(ev);
    // Below the evidence, because the evidence is what this opinion read and
    // the link is where the reader goes next. This host speaks about itself
    // here, so no host is named.
    const onward = lookLinks(op);
    if (onward) o.appendChild(onward);
    box.appendChild(o);
  }

  const cols = el("div", "d-cols");

  const factsSec = el("div", "d-section");
  factsSec.appendChild(el("h3", null, "Facts"));
  // Above the facts it explains, below the opinion that judges them.
  const link = linkPanel(obs.facts);
  if (link) factsSec.appendChild(link);
  // Pools get a bespoke layout: scalar facts left, capacity meters in the
  // otherwise-dead space to their right, and the vdev table full-width
  // below — fullness readable at a glance, per top-level vdev.
  const isPool = obs.subsystem === "storage" && obs.object.type === "pool";
  /* Same treatment as a pool's vdevs, for the same reason: a list of rows is a
     table, and a table squeezed into the right-hand column of a key/value grid
     is neither. */
  const isGeneration = obs.subsystem === "nix" && obs.object.type === "generation";
  const deltaRows = isGeneration && Array.isArray(obs.facts.DeltaFromPrevious)
    && obs.facts.DeltaFromPrevious.length ? obs.facts.DeltaFromPrevious : null;
  const shown = Object.entries(obs.facts).filter(([key, value]) =>
    !(isPool && key === "Vdevs") && !(deltaRows && key === "DeltaFromPrevious")
    && !restatesTheHead(value, obs.object));
  const grid = factBlocks(shown, obs.subsystem, obs.collection);
  if (isPool && typeof obs.facts.SizeBytes === "number") {
    const top = el("div", "pool-top");
    top.appendChild(grid);
    top.appendChild(capacityPanel(obs.facts));
    factsSec.appendChild(top);
  } else {
    factsSec.appendChild(grid);
  }
  if (deltaRows) {
    const compared = obs.facts.ComparedWithGeneration;
    const dh = el("h3", null, compared === undefined || compared === null
      ? "Changed in this generation"
      : `Changed from generation ${compared}`);
    dh.style.marginTop = "14px";
    factsSec.appendChild(dh);
    const d = el("div", "v");
    d.dataset.fact = "DeltaFromPrevious";
    d.appendChild(renderFactValue(deltaRows));
    factsSec.appendChild(d);
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
          // The edge's own subsystem decides where it lands. It is the only
          // thing that can tell `unit:` in the systemd sense from `unit:` in
          // the cgroup-accounting sense, which is why env.rel() takes it.
          const routeTo = routeForId(targetId, r.target.subsystem);
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
/* Speed × width = bandwidth, drawn as that equation.

   The facts were six unrelated rows, and the reasonable reading of "8.0 GT/s"
   beside "2" is that speed and width say the same thing twice. They do not:
   speed is the rate of ONE lane, width is how many of them are active, and the
   product is the only figure anyone actually wants. Asked what "x2 of x4" had
   cost them, a reader could not answer from this screen — they left it, did
   PCIe arithmetic by hand, and came back to explain it to us.

   Drawn on every link, not only capped ones. A healthy x4 device is where the
   idea is cheapest to learn, and nobody should have to find a degraded device
   to be taught it.

   Lanes are drawn rather than counted because a lane is a physical, countable
   thing and four marks say "four of these exist, two are dark" faster than
   "2" beside "4" ever did. CSS boxes, not glyph characters: a monospace font
   without U+25B0 would render the whole explanation as tofu. Every mark is
   also stated in words underneath, so the drawing carries no information alone.

   Reads facts only — the GT/s-to-bytes conversion lives in the adapter, one
   place and conformance-tested. A copy here would be the second rulebook. */
function linkPanel(facts) {
  const speed = facts.LinkSpeed, lanes = facts.LinkWidth;
  const hasLanes = typeof lanes === "number" && lanes > 0;
  if (!speed && !hasLanes) return null;

  const panel = el("div", "link-eq");
  const row = el("div", "eq-row");
  const term = () => { const t = el("div", "eq-term"); row.appendChild(t); return t; };

  if (speed) {
    const t = term();
    t.appendChild(el("div", "eq-v", speed));
    // A SATA or SAS link has one serial connection and no lanes, so the
    // per-lane wording would be a lie there.
    t.appendChild(el("div", "eq-c", hasLanes ? "the rate of one lane" : "negotiated rate"));
  }
  if (hasLanes) {
    if (speed) row.appendChild(el("div", "eq-op", "×"));
    const t = term();
    const max = typeof facts.LinkWidthMax === "number"
      ? Math.max(lanes, facts.LinkWidthMax) : lanes;
    const marks = el("div", "eq-v eq-lanes");
    for (let i = 0; i < max; i++) marks.appendChild(el("span", i < lanes ? "on" : "off"));
    marks.title = `${lanes} of ${max} lanes active`;
    t.appendChild(marks);
    t.appendChild(el("div", "eq-c",
      `x${lanes} lane${lanes === 1 ? "" : "s"}${max > lanes ? ` of x${max}` : ""}`));
  }
  const now = facts.LinkBandwidthBytesPerSec;
  if (typeof now === "number") {
    row.appendChild(el("div", "eq-op", "="));
    const t = term();
    t.appendChild(el("div", "eq-v", humanRate(now)));
    t.appendChild(el("div", "eq-c", "each way"));
  }
  panel.appendChild(row);

  /* What the marks mean and what the ceiling would be — stated, never implied
     by the drawing. No causal claim: whether a dark lane is the slot's doing
     or a link that trained down is the opinion's judgement, above, and it
     needs the slot fact to make it. */
  const notes = [];
  if (facts.LinkSpeedMax && facts.LinkSpeedMax !== speed) {
    notes.push(`the device supports ${facts.LinkSpeedMax}`);
  }
  if (typeof facts.LinkWidthMax === "number" && facts.LinkWidthMax !== lanes) {
    notes.push(`the device supports x${facts.LinkWidthMax} lanes`);
  }
  if (typeof facts.SlotLinkWidthMax === "number") {
    notes.push(`the slot provides x${facts.SlotLinkWidthMax}`);
  }
  const best = facts.LinkBandwidthMaxBytesPerSec;
  if (typeof best === "number" && best !== now) {
    notes.push(`at the device's own maximum it would carry ${humanRate(best)}`);
  }
  if (notes.length) panel.appendChild(el("div", "eq-note", notes.join(" · ")));
  return panel;
}

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
   the same routing the relationship chips use.

   No hint to pass: a fact value is a bare string with no room to carry a
   subsystem, so routeForId's stay-where-the-reader-is rule is what resolves
   the ambiguous prefixes. That rule was originally a special case for
   `lookup` here — every subsystem may carry a lookups collection, so a fact
   naming one means this subsystem's — and generalising it turned out to be
   the correct behaviour for `unit` and `socket` too. */
function factLeaf(value, short = false) {
  if (typeof value !== "string") return null;
  const sep = value.indexOf(":");
  if (sep <= 0) return null;
  const routeTo = routeForId(value);
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
  // The estate findings sweep is a full acquisition on every agent — it
  // COSTS seconds, honestly (statelessness means fresh capture, not a
  // cache going stale). Polling it at the collection cadence meant the
  // panel spent a third of its life mid-sweep (reported live,
  // 2026-08-12); attention lifecycle does not change in 15 s.
  const interval = state.subsystem === "estate" ? 60000 : 15000;
  state.refreshTimer = setInterval(() => {
    if (!document.hidden) loadCollection();
  }, interval);
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
