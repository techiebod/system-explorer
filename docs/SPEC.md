# System Explorer — Specification

**Version:** 0.6
**Status:** Accepted for build
**Supersedes:** SE-001 through SE-006 — the predecessor design suite,
condensed into this document; per-document disposition in Appendix A
**Direction:** [ROADMAP.md](ROADMAP.md) — status, priorities, and the estate/portability tracks

0.6 (2026-08-13) adds rule 16 — the mechanism is a fact — settles the
findings write posture (§6.3: a grant, appended transitions, no
suppression, resolution observed not declared) before the findings layer
exists, and decides
the composite locator in writing before its
schema: optional `container` and `app` members join the `host` block and
rule 15's finding-identity tuple — identity, not provenance — with
`relationships[].target` gaining the same members and off-host subjects
explicitly deferred. Implementation follows in the same version: rows
carry the warn/critical subset of their evaluated opinions (rule 14 made
structural — one builder derives the severity and the subset from one
list), agents grow `GET /v1/findings` (`se.findings/1`, whose `unobserved`
member is what stops an unevaluable collection reading as all of its
findings resolving), and the hub grows the §6.3 registry: `/hub/findings`
(`se.hub-findings/1`) with first_seen/last_seen under the hub's state
directory and the grant-gated transition route. The app tier's flow-edge
vocabulary (§3: `dispatches-to`, `provisions`, `tracks`; `routes-via`
and `backs` reused for ingress) is decided before the first app adapter
emits one — and the app tier then lands whole: paperless, traefik, the
servarr fleet, downloaders, the plex family and bazarr as app-scoped
explorers, kea and unbound as host-scoped socket explorers, the first
emitted flow edges (tracks, dispatches-to, routes-via), pipeline view
panels whose stages are authored and whose relations are the rows' own
join keys, view host-targeting, the two filter operators (`!`, `*`),
and the hub findings sweep moved to its own cadence with `swept_at` as
the read's honesty stamp.

0.5 (2026-08-12) amends §6.1 rule 4 — the hub holds metadata, never
observations — and adds views (§6.2, `se.views/1`), the evidence envelope's
schema (`se.evidence/1`), the prefix evidence route, the 422 near-miss
filter refusal, and three relationship types. The observation shape itself
is unchanged; every addition is additive under §5.1.

0.4 (2026-08-09) records the passed success gate, adds the shared rule
evaluators (rule 14) and finding identity (rule 15), amends the §7 trust
boundary to the deployed reality plus the DNS-rebinding defence, and
tightens conformance rules 5 and 8. No envelope shape changed.

---

## 1. What this is

System Explorer is the read-only half of a reconciled infrastructure model. It
observes the actual state of Linux hosts and presents it as a graph of native
objects with provenance, so that an expert operator or an AI agent can
understand what is true on a host — and, later, what changed and why — without
opening an SSH session.

The product ladder is:

> **observe → explain → recommend → reconcile**

This specification covers **observe** in full and seeds **explain**
(evidence-linked opinions, snapshot history). Recommend and reconcile are out
of scope and must not leak into the design: no component defined here has a
write path to the operating system.

### Two consumers, one contract

| Consumer | Surface | Renders |
|---|---|---|
| AI agent | MCP tools / HTTP JSON | the observation envelope, verbatim |
| Expert operator | state-browser UI (§8) | the same envelope, designed |

Both consumers read the same JSON from the same endpoints. There is no
UI-private API and no agent-private API; if the two ever need different data,
the envelope is wrong and the envelope gets fixed.

### Success criterion

A real issue on a real host is diagnosed through System Explorer alone — by
a Claude session over MCP, or by the operator in the UI — without SSH.
**Passed 2026-08-09**: a genuine health question was answered end-to-end
through se-mcp, and the finding was one no dashboard had surfaced — a
redundant pool that had gone months without a scrub, root-caused to a
freshly-installed scrub timer that had never once fired, from
`LastTrigger: null` against a `NextElapse` weeks away.
The gate had blocked phases beyond Phase 2 of the [roadmap](ROADMAP.md); it
re-arms for each later capability the roadmap gates the same way.

---

## 2. Design rules

Carried forward from the SE-00x suite:

1. **Read-only by design.** No mutating endpoint exists. (SE-001 §3)
2. **Native concepts before abstractions.** Objects keep native names, native
   identifiers, native terminology. The product presents Linux consistently;
   it does not simplify it. (SE-001 §2.1, SE-005 §3)
3. **Evidence before opinion** — now enforced, not aspirational: every opinion
   carries an `evidence` list citing the fact paths it derives from, and
   conformance rejects an opinion whose citations do not resolve. (SE-001 §8)
4. **Semantic representation and native evidence are separate.** The envelope
   carries structured facts; raw payloads are fetched on demand via
   `evidence_ref` and are captured fresh, never cached. (SE-004 §9)
5. **Reference commands are documentation, never execution.** Every source
   block names at least one command an administrator could run to reproduce
   the observation. The agent never runs them. Enforced by adapter lint
   (rule 5, §11). (SE-004 §6)
6. **Source attribution on every observation**: adapter, native interface,
   method, time. (SE-004 §6)
7. **Partial success over total failure; absence is not an error.** A missing
   capability is reported in capability discovery with a reason. A failed
   adapter degrades one subsystem, not the service. (SE-004 §12)

   This applies at three scales, and the shape at each is fixed so a consumer
   learns it once. A **subsystem** or **collection** that cannot be answered
   carries a `reason` in capability discovery, and its route answers with an
   error envelope carrying that same reason — never an empty page (§6). An
   individual **fact** that cannot be observed is *omitted*, not null, when it
   does not apply to this host; a null fact reads as "unknown", and "not
   applicable" is a different statement. Where a fact is genuinely
   unobservable rather than inapplicable — the value exists but this agent
   cannot see it — the fact is null and a sibling `<Fact>Unobservable` carries
   the prose reason, so the reader learns both that a value exists and why it
   is out of reach. One convention, one name shape, no per-adapter dialect.
8. **Acquisition hierarchy** (SE-003 §2), tightened: D-Bus / varlink → native
   libraries → kernel interfaces (netlink, procfs, sysfs) → structured CLI
   output (`-j`/`-J`/`-o json` only). Parsing human-readable command output is
   **forbidden**, not discouraged. A domain with no structured source waits.

New in 0.2:

9. **Objects are graph nodes.** Every observation is about an object with a
   stable identity and typed, directed relationships to other objects —
   including across subsystems. The graph, its identity rules, and its
   provenance model are the durable asset; everything else is replaceable.
10. **Snapshot-on-demand only.** No deltas, no invalidation protocol, no
    subscriptions, no WebSocket. Agents pull; the UI polls. (The v0.1
    prototype's WebSocket was already a 5-second full-snapshot loop —
    evidence that nothing needed more.)
11. **History is stored snapshots plus diff-on-read**, not an event stream.
    "What changed" is computed by comparing stored envelopes.
12. **Unprivileged by construction.** The agent runs as a dynamic user with
    the narrow grants in §7. If a proposed observation needs root, the
    acquisition path is wrong — or the acquisition is isolated behind a
    narrow root helper with a fixed command set that the agent only reads
    (the SMART collector is the precedent: root runs one fixed `smartctl`
    per device on a timer; the agent reads the snapshots and reports their
    age). The agent process itself never gains the privilege.

New in 0.3:

13. **Lookups are the only parameterised surface.** A lookup answers a
    diagnostic question about one operator-supplied input — which route the
    kernel chooses for an address, what the resolver answers for a name
    (§6). The input is a single typed value, validated before use, passed
    as one argv token or one D-Bus argument; it never reaches a shell and
    never selects which command runs. Lookups mutate nothing; at most they
    place the same query traffic on the wire their reference command would.

New in 0.4:

14. **One rule evaluator, two severity surfaces.** Collection-row
    `worst_opinion_level` and full-object opinions derive from the same
    pure rule functions (`src/system_explorer/agent/rules/`, one module per subsystem). A rule
    fires only when the facts it needs are present, so a summary that
    deliberately omits an expensive fact simply does not evaluate that rule
    — divergence by acquisition-cost decision is allowed and documented per
    rule; divergence by drifted thresholds is a conformance failure.
    Since 0.6 the rule is structural rather than a convention at every
    call site: the row builder takes the evaluated list itself and derives
    both the severity and the row's carried warn/critical subset
    (`opinions` on `se.collection/1` items) in one place, so the red dot
    and its explanation cannot disagree — and `/v1/findings` is a third
    surface reading the same evaluation, never re-running it.
15. **Findings have stable identity.** The composite
    `(host.machine_id, container?, app?, object.id, opinion.key)`
    identifies a condition across observations: object IDs are stable for
    unchanged objects (rule 7, §11) and opinion keys are stable kebab-case
    slugs that never rename casually. An unchanged condition yields the
    same key on every evaluation. This is the identity the findings layer
    (hub, roadmap slice 2) will attach lifecycle to; agents stay stateless.

    The optional members are the **composite locator** (0.6, decided in
    writing before any schema changed — the sequencing that mattered,
    because this tuple is the primary key findings will persist under, and
    re-keying it after they exist would orphan every finding in flight).
    Three decisions, each closing a question an adversarial review showed
    the first draft had left open:

    - **They are identity, not provenance.** One `machine_id` now runs
      several agent processes, and an app-scoped process can front several
      instances of one application — two readarr instances speak one API
      and both emit `indexer:3`. Sibling `container` and `app` members on
      the envelope's `host` block are what keep those conditions distinct.
      Absent means host-native — never a zero value, because an invented
      identity is worse than an admitted absence. What keeps the change
      one day rather than ten: *within a single collection on a single
      process, object ids remain unique*, so route addressing,
      `evidence_ref`, page uniqueness, snapshot diffing and the MCP tool
      signatures are untouched by envelope-root members.
    - **`relationships[].target` gains the same optional members**, or an
      app-scoped object could not express an edge to a host-scoped one —
      the exact edge a cross-app trace (indexer → download → library)
      walks.
    - **Off-host subjects stay out of scope until the locator answers
      them.** An adapter observing a subject that lives on no agent host
      would silently change `host.machine_id` from "where this lives" to
      "who looked", against §3's definition of host as the observation
      boundary. That contradiction is deferred with the non-Linux adapter
      case (§12), and this locator deliberately does not claim to solve
      it.

New in 0.6:

16. **The mechanism is a fact.** Where a capability can be served by more
    than one native mechanism, which one answered is part of the
    observation — a fact with a glossary sentence, never only a source
    note — because consumers filter facts and columns render facts, and
    "which one is in use?" is a question, not metadata. `packages` set the
    pattern (`Manager`: nix, dpkg or rpm — the question is universal and
    only the answer is not); `resolver` is the second conformer
    (`ResolverService`: systemd-resolved, or glibc reading resolv.conf
    directly — both are resolvers, and a host was wrongly declined for
    running the older one). Candidates owing compliance as they are next
    touched: SMART's depth order and the mounts namespace fallback, both
    of which currently say which mechanism spoke only in source notes.

Explicitly dropped from the SE-00x suite: the SE-005 UI framework (replaced by
the one-page contract in §8), the WebSocket message protocol, placeholder
domains, the `/api/info` command-runner endpoint, and the delta/invalidation/
sequence-number machinery of SE-004 §7–8.

---

## 3. Conceptual model

```
Host  →  Subsystem  →  Collection  →  Object  →  Observation
```

- **Host** — the observation boundary, identified by `machine-id`. One agent
  observes exactly one host (SE-004's single-host scoping is kept; multi-host
  is the MCP aggregator's job, §9).
- **Subsystem** — a navigation grouping matching an administrator's mental
  model (§4). Not an ownership boundary; objects may be reachable from more
  than one subsystem via relationships.
- **Collection** — the current set of objects of one kind, filterable and
  paginated.
- **Object** — a native OS entity. Identity: `<collection-singular>:<native-id>`,
  e.g. `unit:sshd.service`, `dataset:tank/photos`, `container:traefik`.
  IDs are stable across observations of an unchanged object (conformance
  rule 7). Cross-host references prefix the machine-id.
- **Observation** — one envelope (§5) describing one object at one moment.

### Relationship types

A small closed set, extended deliberately rather than ad hoc:

| Type | Example |
|---|---|
| `requires` / `wants` / `after` | unit → unit (from systemd properties) |
| `member-of` | container → compose project; dataset → pool |
| `mounts` | container → volume; mount → block device |
| `attached-to` | container → docker network; VM NIC → bridge link |
| `backs` | block device → pool vdev; qcow2 file → VM disk |
| `routes-via` | route → link |
| `runs` | unit → machine (a `machine-*.scope` hosting a VM or container) |
| `plumbed-onto` | docker network → bridge link |
| `owns` | VM domain → its host tap link (the edge that attributes a `vnet` to a workload) |

Cross-subsystem edges are the point: `unit:compose-stack-web.service` →
`member-of` ← `container:web-frontend` is what makes "why is this container
down" answerable from the graph.

**Flow edges (0.6, decided before any adapter emits one).** The app tier
turns the graph into a pipeline — a request enters at the ingress and work
moves between applications — and "show the flow between them" is answered
by edges, never by a hand-drawn picture. Three additions, each with the
refusal that shaped it, plus two deliberate reuses:

| Type | Example |
|---|---|
| `dispatches-to` | an app sends selected work to another (a media manager → its download client; a request portal → the manager it files requests with) |
| `provisions` | an app supplies configuration into another (an indexer manager syncing indexers into each manager; a config templater writing quality profiles) |
| `tracks` | this object and the target are the same underlying work item seen by two apps (a queue item → the transfer it created, joined on the download id BOTH sides state) |

Ingress hops need nothing new: a proxy router `routes-via` its service
(the existing conduit semantics), and a backend `backs` the service that
balances onto it.

**Protection hops need nothing new either**, and the reuse is the point —
a chain of promises is the same shape as a chain of work:

| Type | Example |
|---|---|
| `dispatches-to` | protection target → each destination it declares, *including the hops nothing implements*; protection job → the destination it delivers to |
| `backs` | protection job → the target whose hop it is the stated implementation of |
| `runs` | protection job → the systemd unit it runs as (`in`, as everywhere) |
| `tracks` | protection target → the object it protects, where the declaration named one as an id rather than as prose |

A cross-host hop emits **no** edge. The manifest qualifies implementations
as `<host>:<job>` because execution splits by verb, so `job:x` minted from
another host's reference would address this host's object of that name —
a link to the wrong machine's work, which is worse than no link. The fact
still names the host in full.

The refusals: no generic `related-to` (an edge that cannot say what it
means is decoration); no inferred edges — every flow edge derives from a
member the SOURCE app's own API states (its configured client, its sync
target, its download id), cited like any fact, so the pipeline picture
can only ever show what the apps themselves claim; and path-overlap
edges (a manager's root folder against a media server's library) are
deferred until path-identity semantics are decided — filesystem
coincidence is not an API statement.

---

## 4. Subsystems v1

Chosen for real diagnostic demand (systemd, ZFS, Docker, VMs,
routing/firewall), not for coverage symmetry.

| Subsystem | Collections | Acquisition | Privilege needed | First validated on |
|---|---|---|---|---|
| `system` | `identity`, `time`, `boot`, `overview` | hostname1 / timedate1 / timesync1 D-Bus; `/etc/machine-id`; procfs (uptime, loadavg, meminfo, pressure, ZFS arcstats) | none | any systemd host |
| `nix` | `generations` | `/nix/var/nix/profiles` + the metadata files every system closure carries, plus optional deployment provenance (§4.1); pure filesystem reads, no subprocess | none | NixOS only — declines as a whole subsystem with one reason elsewhere |
| `packages` | `packages` | whichever manager can answer: the `/run/current-system/sw` link farm on NixOS, else `dpkg-query -W -f` or `rpm -qa --qf` with a format string this agent supplies | none | any host with one of the three; declines with a reason where none is present |
| `hardware` | `platform`, `pci`, `usb`, `scsi`, `nvme` | sysfs (DMI, pci/usb/nvme, scsi/sas/enclosure classes); udev hwdb via `udevadm --json=short`; `lscpu -J`; udisks2 D-Bus for SMART | none | any systemd host; scsi depth needs SAS/enclosure hardware |
| `units` | `units` (filter by type/state) | `org.freedesktop.systemd1` ListUnits + properties | none | any systemd host |
| `logs` | `journal` (bounded query only) | `journalctl -o json` (allow-listed) or libsystemd reader | `systemd-journal` group | any systemd host |
| `storage` | `pools`, `datasets`, `block-devices`, `mounts`, `arrays`, `lookups` | `zpool`/`zfs` JSON output; `lsblk -J`; `findmnt -J` | none (verify `/dev/zfs` mode) | blocks/mounts on any host; ZFS needs a pool |
| `docker` | `containers`, `volumes`, `networks` | Engine API over unix socket, GET only | `docker` group (caveat §7) | any host running Docker |
| `vms` | `domains` | libvirt read-only socket (`virConnectOpenReadOnly`) | ro-socket access | any host running libvirt |
| `network` | `links`, `routes`, `resolver`, `listening`, `nft-tables`, `nft-chains`, `nft-rules`, `port-exposure`, `tailscale`, `conntrack-summary`, `lookups` | `ip -j` (rtnetlink); resolve1 D-Bus; `nft -j list ruleset`; `/proc/net/{tcp,tcp6,udp,udp6}`; `tailscale status --json` snapshots via root collector | `CAP_NET_ADMIN` (nft, conntrack); none for links/routes/listening | any systemd host; tailscale needs the snapshot collector |
| `resources` | `workloads` | cgroup v2 under `/sys/fs/cgroup`: `cpu.stat`, `memory.current`/`peak`/`events`, `io.stat` and the `{io,cpu,memory}.pressure` files, plus `/proc/stat` for the host total the remainder is measured against | none | any host presenting a unified cgroup v2 hierarchy; declines with a reason on cgroup v1 |
| `protection` | `targets`, `jobs`, `destinations` | three documents the host already publishes: a rendered declaration under `/etc`, per-job receipts, and an hourly staleness verdict. The repositories those jobs write to are deliberately never opened | none | a host whose configuration renders a protection manifest |
| `paperless` | `instance` | Paperless-ngx REST API over HTTP | API token (`SE_PAPERLESS_TOKEN`) | a host running paperless |
| `traefik` | `overview`, `routers`, `services` | Traefik API over HTTP, GET only | API reachable (the estate publishes it loopback-only) | a host running Traefik |
| `servarr` | `apps`, `health`, `queue`, `history` | Servarr API v3 — one implementation, several instances | per-instance API key | a host running any Servarr application |
| `downloaders` | `clients`, `transfers` | Transmission RPC and the SABnzbd API | per-client credentials | a host running either |
| `plex` | `server`, `libraries`, `sessions`, `requests` | Plex, Tautulli and Overseerr HTTP APIs | per-service token | a host running the media tier |
| `bazarr` | `instance` | Bazarr API over HTTP | API key | a host running bazarr |
| `kea` | `daemon`, `subnets`, `reservations`, `leases` | Kea control socket (`config-get`, `statistic-get-all`, `lease4-get-all`) | socket group | a host running Kea DHCP |
| `unbound` | `daemon` | `unbound-control` over its socket | socket group | a host running unbound |

Every subsystem an adapter serves appears above, and every collection it
declares appears in its row. That is held by conformance rather than by
review: ten subsystems and three collections had shipped without a row here
before the check existed, which is the drift this table is supposed to
prevent in the code and could not prevent in itself.

Notes:

- `logs` is deliberately bounded-query only (`unit=`, `since=`, `limit=`).
  Follow-mode is a non-goal (§12).
- `conntrack-summary` is current flow state (counts by state, top talkers
  now). Flow *history* is a different product and a non-goal.
- The v0.1 `storagectl` domain is deleted; the tool does not exist. Storage
  observations come from the sources above.

### 4.1 Optional deployment provenance

`nix/generations` reports what changed between generations, and how each one came
to be, from two things it reads and never computes.

**`se-generation.json`, inside the closure.** Any generation may carry this file
alongside `nixos-version`. nixpkgs knows nothing about it — whatever builds the
closure writes it — so it is absent far more often than present, and absence
means only that the generation does not record this.

```json
{"schema": 2, "revision": "<vcs revision>", "receiptsExpected": true,
 "inputs": {"<name>": {"revision": "...", "narHash": "...",
                       "lastModified": 1786089803}}}
```

**The closures themselves.** Two more comparisons need no manifest at all, so they
work on every generation including ones built before manifests existed:
`<generation>/sw` is a buildEnv link farm, and `<generation>/etc` is a tree of
symlinks into the store plus a few tiny files recording ownership and mode. A
symlink's target and a small file's content hash are exact identities, so both
compare by reading.

Together they yield `DeltaFromPrevious`, a list of uniform
`{Kind, Name, From, To}` rows — `revision`, `input`, `etc`, `package` — plus
`ComparedWithGeneration` naming which generation it was compared against: the
previous one still *present*, which is not necessarily N−1 once older ones are
collected. `DeltaCounts` carries the per-kind totals and is present on both
surfaces; the rows themselves are carried only on an opened object, because a
nixpkgs bump moves hundreds of packages and a collection page is asked for a
hundred generations at a time. That is a payload decision, not an acquisition one.

`etc` rows name **one changed path each**. An earlier version reported a single
row carrying the two /etc store paths, which is a true statement an administrator
can do nothing with: it says something under /etc moved and refuses to say what.
What changed *inside* a file is a further question, and a config-diff tool
answers it against a candidate.

Where a generation carries a manifest but its predecessor does not,
`DeltaFromPreviousPartial` says so precisely: the package and /etc halves are
complete, and only the revision and inputs could not be compared.

No comparison here diffs two closures with a tool. `nvd` and `nix store
diff-closures` have no structured output, so an adapter running one would be
executing a reference command and parsing its prose, which rule 5 forbids and no
allow-list entry could make correct. Whatever built the closures already knew
what went into them, and the closures still say so.

**Deployment receipts, outside it.** `SE_DEPLOYMENT_RECEIPTS` (module option
`services.systemExplorer.deploymentReceipts`) names a directory of
`<generation>.json` files describing how each generation was activated. The agent
reads a documented subset — `activation.mode`, `activation.outcome`,
`activation.verified_at`, `risks`, `source.git_revision` — and ignores the rest,
so an estate is free to record more.

There is no default path, and `ReceiptsExpected`/`Deployment` appear only when
the closure says receipts are expected **and** a directory is configured. Both
conditions are load-bearing: a generation predating the workflow, or a host that
keeps no receipts, must not be reported as having bypassed anything. Where both
hold and no receipt exists, `Deployment` is null and `deployment-unattested`
fires — something activated that closure outside the workflow, and what was
previewed or verified for it is recorded nowhere.

---

## 5. Observation envelope

Authoritative definition: [`schema/observation.schema.json`](../schema/observation.schema.json)
and [`schema/collection.schema.json`](../schema/collection.schema.json).
The prose here explains semantics; the schemas win on shape.

```json
{
  "schema": "se.observation/1",
  "host": { "machine_id": "0123456789abcdef0123456789abcdef", "hostname": "host-a" },
  "subsystem": "units",
  "object": { "id": "unit:sshd.service", "type": "service", "native_id": "sshd.service" },
  "observed_at": "2026-08-07T15:04:05Z",
  "status": "ok",
  "source": {
    "adapter": "systemd-dbus",
    "interface": "org.freedesktop.systemd1",
    "method": "org.freedesktop.DBus.Properties.GetAll",
    "reference_commands": ["systemctl status sshd.service", "systemctl show sshd.service"]
  },
  "facts": {
    "LoadState": "loaded",
    "ActiveState": "active",
    "SubState": "running",
    "UnitFileState": "enabled",
    "MainPID": 812,
    "NRestarts": 0
  },
  "relationships": [
    { "type": "after", "direction": "out", "target": { "id": "unit:network-online.target" } },
    { "type": "wants", "direction": "in",  "target": { "id": "unit:multi-user.target" } }
  ],
  "evidence_ref": "/v1/evidence/units/units/unit:sshd.service"
}
```

Field semantics:

- **`facts`** carry native property names (`ActiveState`, not `active_state`)
  and native types. The v0.1 `{key, label, value}` list is gone — labels are
  presentation and belong to clients. Per-subsystem fact schemas may tighten
  `facts` later; v1 requires only that it is an object.
  - Native names are the contract, and they are not self-explanatory: what a
    fact MEANS is served separately by `/v1/facts` (§6), one sentence per
    name, owned by the adapter that emits it. Never a `description` beside the
    value — an agent paging a collection would pay for the same prose on every
    row.
  - A fact is normally READ. A **derived** fact is permitted where the
    derivation is exact arithmetic over facts already in the envelope plus a
    fixed published constant, and it is absent (never guessed, never null)
    whenever any input is missing or unrecognised. `LinkBandwidthBytesPerSec`
    is the first: `LinkSpeed` is the rate of one PCIe lane and `LinkWidth` is
    how many, and no reader was deriving the product for themselves — the one
    who tried had to leave the screen to do it. It is a fact rather than prose
    so an opinion can CITE it (rule 3), a client can render it without carrying
    a PCIe table of its own, and an agent consumer gets the same arithmetic the
    screen shows. The bar is deliberately high: an estimate, a threshold or a
    judgement is an opinion, not a fact.
- **`status`** is `ok` | `partial` | `error`, with `errors[]` listing what
  failed. `partial` means some facts are present and trustworthy; `error`
  means the envelope documents a failed acquisition. Errors are observations.
- **`opinions`** are the only place interpretation is allowed, and each must
  cite the facts it derives from. Opinion levels: `info`, `warn`, `critical`.
  A healthy object has none — the example above is a running unit and carries no
  `opinions` key at all, which is why the field is absent there rather than
  holding an affirmative "all is well" entry; see
  [`observation-pool-degraded.json`](../schema/examples/observation-pool-degraded.json)
  for the populated shape. `info` is not a weak `warn`: it is what a rule says
  when a reading is explained rather than alarming (reclaimable ARC counted as
  used memory, a PCIe card limited by its slot, an unwired spare link), and it
  earns a neutral mark rather than an attention badge.
  - **`look`** is the optional other half of `evidence`: evidence cites facts
    on THIS object, `look` names collection routes elsewhere on the same agent
    that carry the attribution this object cannot. A host PSI warning states
    that every non-idle task was waiting on I/O and offers nowhere to go, while
    `units/units` already carries the same kernel accounting per unit — the
    condition and its next step were on two screens with nothing joining them.
    Each entry is `{subsystem, collection, fact?, label}`: the route, the fact
    that ORDERS the answer there, and the phrase to word the link with. Pure
    routing data; the agent resolves none of it, and it travels verbatim into
    `/v1/findings` and the hub roll-up, where the routes stay agent-relative
    exactly as `evidence_ref` does. Deliberately not a filter — the fact-filter
    language (§6) is string equality, negation and prefix, so "greater than
    zero" is inexpressible and a filter that silently kept every row would
    claim a narrowing it never performed. Ordering asserts no threshold and is
    therefore the honest primitive.
- **`evidence_ref`** fetches the raw native payload as `se.evidence/1` —
  formerly the one undeclared surface on the wire, now schema'd like
  every sibling (the discriminator and host are stamped at the route, so
  an adapter cannot forget what it never had to remember) (D-Bus reply, JSON
  document, netlink dump) captured fresh at request time.
- Freshness is the client's judgment from `observed_at`; the envelope does
  not claim it.

### 5.1 Envelope evolution (additive fields)

The `N` in `se.<name>/N` is a compatibility contract, not a build number.
Hosts deploy at different times, so at any moment a hub or aggregator is
fanning out across several agent versions at once. Eight rules make that safe.

1. **Every response body carries a `schema` discriminator.** A response
   without one cannot be versioned at all, and is a defect.
2. **Additive changes keep `N`.** Adding an optional field, adding a key to an
   open map, or relaxing a constraint does not change the version: a consumer
   written against `se.observation/1` last month keeps working against
   `se.observation/1` today.
3. **Consumers must ignore unknown fields**, and the published schemas must
   make that legal — they may not say `additionalProperties: false` on
   anything an agent fills. A consumer that rejects an envelope for carrying
   a member it does not know is not conformant.
4. **`N` changes only on a break:** removing or renaming a field, changing its
   type or units, adding a required field, making a required field optional,
   redefining an existing field's meaning, or removing an enum value. A break
   ships as a new schema id, and the old id keeps being served until every
   host has moved.
5. **A rename is an addition followed by a removal, never an edit:** emit
   both, document the old one deprecated, switch consumers, remove one release
   later. Two releases, not one.
6. **New enum members are additive only where the consumer already has a
   fallback.** `opinions[].level` is closed at three values by §2 rule 3 — a
   fourth is a break. `relationships[].type` is a closed set extended
   deliberately (§3): adding a member is additive, because a consumer renders
   an unknown type as itself rather than dropping the edge. `status` values
   and roll-up `worst` values are closed.
7. **Absence is documented at the point of addition.** A new optional field
   states what its absence means — "not a NixOS host", "this agent predates
   the field" — because during a rollout both are true somewhere. Skew is
   discoverable, never guessed: every agent reports `version` in `/health`
   and `/v1/capabilities`.
8. **Strictness moves to the producer.** Losing `additionalProperties: false`
   on the wire does not license the agent to emit whatever it likes. The
   conformance suite validates this project's own fixtures against a *strict
   profile* of the same schemas — every declared object closed — so an
   undeclared or misspelt field still fails CI. The published schema is the
   consumer contract; the strict profile is the producer contract.

One exception, closed on purpose: `se.status/1`'s `counts` map. Its keys *are*
the severity levels, so an unknown key there is a new level, which rule 6
makes a break. It stays closed in both profiles and fails loudly.

This was overdue rather than hypothetical: with the roots closed, an envelope
from a newer agent carrying one added field was rejected outright by a
consumer validating against this version — mid-rollout, across five hosts.
Rules 3 and 8 are executable in [conformance/test_schemas.py](../conformance/test_schemas.py).

---

## 6. API

Base path `/v1`. All responses are envelopes or envelope pages.

| Endpoint | Returns |
|---|---|
| `GET /health` | liveness |
| `GET /v1/capabilities` | per-subsystem availability (`se.capabilities/1`), with a `reason` for anything absent |
| `GET /v1/facts` | the fact dictionary (`se.facts/1`): what each fact means |
| `GET /v1/{subsystem}/{collection}` | collection page (`se.collection/1`) |
| `GET /v1/{subsystem}/{collection}/{object_id}` | one observation (`se.observation/1`) |
| `GET /v1/evidence/{subsystem}/{collection}/{object_id}` | native evidence, fresh. Prefix-first because `{object_id}` is a path parameter that may itself contain slashes (`dataset:tank/photos`, lookup inputs): a trailing `/evidence` segment made any object whose id ended in `/evidence` unreachable, answering with its parent's evidence instead of a 404. |
| `GET /v1/changes?since=…&subsystem=…` | what-changed diff (`se.changes/1`, §10) |
| `GET /v1/findings` | every warn/critical opinion currently derivable from row facts (`se.findings/1`), with the rule-15 identity and an `unobserved` list naming every collection the sweep could not evaluate — the estate roll-up costs one request per host, and absence can only mean resolution where the envelope says the agent could look (§6.3) |

Collection behaviour (carried from SE-004 §11, unchanged in spirit):

- Filtering by fact value: `?type=service&ActiveState=failed`. Equality is
  the default; two operators on the VALUE extend it — a leading `!` negates
  (`?ActiveState=!active`), a trailing `*` prefix-matches
  (`?Mountpoint=/run*`), and they compose (`?Mountpoint=!/run*`). An absent
  fact matches only negated filters — absence is not equal to anything, but
  it is honestly not-equal to everything. No escape syntax exists: exact
  equality against a value that itself begins with `!` or ends with `*`
  cannot be expressed through the query string. Operators belong on the
  value, never the key — a key wearing one (`?!ActiveState=failed`) is
  refused as the near-miss it is. A key that is a case or underscore
  near-miss of a carried fact (`activestate`, `active_state`) is refused
  with HTTP 422 naming the real fact — the same status a malformed `limit`
  gets — because a typo and a healthy zero used to be byte-identical, which
  is rule 7's lie arriving through the query string. Refusal stops at
  provable near-misses: the fact vocabulary is open (the glossary is
  partial, and rule 7 makes omission a legitimate shape for any fact), so an
  unknown key with no near-miss returns the honest empty page —
  `?RuntimeSynthesised=True` on a host with no synthesised mounts is a
  correct query whose answer is nothing, and refusing it would make the same
  query flip between ok and error as host state drifts.
- Pagination is explicit: `?limit=` and `?cursor=`; responses always carry
  `applied_limit` and `next_cursor` (nullable). **The server never silently
  truncates; the client never infers truncation.**
- Small collections (pools, links, domains) return whole by default.

Capability discovery (`se.capabilities/1`) reports absence at **two levels**,
which is the shape SE-004 §12 was reaching for. A subsystem carries
`available: true` and names its `collections`, or `available: false` and a
`reason` — "no docker socket on this host", "not a NixOS host", or a capability
probe that failed, since a broken adapter is itself a capability fact. An
available subsystem may still decline individual collections through
`unavailable_collections`, a map of collection name to reason: hardware without
an NVMe controller, network without the `nft` grant. Those keys are not a subset
of `collections` — a collection may be declined that the subsystem does not
otherwise list.

Two members exist beyond that shape and are declared rather than tolerated:
`manager` on the packages subsystem, naming what this host resolves to, and a
top-level `site` carrying the hub URL. `site` is a **display hint the deployment
supplies, never discovery** — the agent does not find its hub and never talks to
one, because aggregation must never be a precondition for observation (§7).

### 6.1 Federation: the site hub

`se-hub` fronts the agents of one site with the same UI and the same `/v1`
contract, and it is the reason an operator running several hosts sees one page
rather than several. It is deployed, it drives the UI's host switcher, and until
now this specification did not mention it.

| Endpoint | Returns |
|---|---|
| `GET /hub/hosts[?local=1]` | every host this site can reach, plus each sibling site's own view (`se.hub-hosts/1`) |
| `GET /hub/views` | the site's view documents (`se.views/1`), read from the configured directory — see §6.2 |
| `GET /agents/{name}/v1/{path}` | one agent's route, proxied verbatim |
| `GET /sites/{site}/agents/{name}/v1/{path}` | the same, for a host this hub may not own |

Four rules, each load-bearing:

1. **Verbatim pass-through, no summarisation layer.** The hub returns the
   agent's bytes and status untouched, so an error envelope arrives exactly as
   sent. `/hub/hosts` is the single exception and the only route that
   aggregates anything; it aggregates reachability, never observations.
2. **Federation is exactly one hop, enforced by which URL is used.** A sibling's
   host is handed to that sibling's own *local* `/agents/…` route, which cannot
   forward again. That is a rule about addressing rather than a hop counter or a
   header, so no estate wiring can produce a loop.
3. **Unreachable is data.** A dark agent is a host entry saying so; a dark
   sibling is a *site* entry saying so, because "no hosts there" and "cannot see
   there" are different statements and only one is a problem. A site whose
   siblings are dark keeps working alone (ROADMAP §6).
4. **The hub holds metadata, never observations.** Amended 0.5 — the rule was
   "stateless: no cache, no polling, no persistence", and the property it
   protected survives intact: **no observation is ever served from hub state**,
   so nothing the hub holds can go stale against a host and be passed off as
   current, and an unreachable host stays a *statement of unreachability*
   rather than a last-known-good masquerading as now. What 0.5 admits is the
   other kind of state, which the founding vision always sanctioned ("writes…
   to hub-owned metadata… never translated into host actions"): documents the
   operator authored — view definitions (§6.2), read fresh from a configured
   directory on every request — and, when the findings model lands, finding
   lifecycle records, each gated by its own written reconciliation before any
   code. The boundary a reviewer should check is mechanical: every byte of
   every observation still arrives through rule 1's verbatim proxy, and
   deleting the hub's state directory loses convenience, never data and never
   truth.

The configuration contract is four environment variables — `SE_HUB_AGENTS`,
`SE_HUB_SITE`, `SE_HUB_SIBLINGS`, `SE_HUB_ALLOWED_HOSTS` — and the host URLs a
hub hands out are **site-internal**: a URL from one site's directory is not
necessarily dialable from another, which is why a cross-site consumer goes
through the owning hub's proxy rather than dialling agents itself.

The hub's own surface is deliberately **not** under `/v1`. `/v1` is the agent's
contract, which the hub proxies unchanged; `se.hub-hosts/1` and `se.views/1`
version independently of it.

### 6.2 Views: one graph, several projections

A **view** is an operator-authored projection of the graph for a stated
audience: which collections appear, which facts surface at which level, and
where each row drills to. The principle is ROADMAP §2's — one graph, several
projections, one public contract — and the placement follows the fact
dictionary's precedent exactly: deciding *which facts an audience sees* is a
judgement about the facts, so it is served from an endpoint both consumers
read, never a table inside one client (a fourth copy of anything the agent
knows is a fourth thing to disagree with it).

- **A view never hides the truth; it defers it.** Every row links to its full
  observation, every panel to its full collection. The novice's three panels
  and the expert's full graph are the same data at different depths, not two
  products.
- **A view references facts; it does not restate them.** Documents carry fact
  *names*; meaning stays in `/v1/facts`, labels stay native (§5). A view
  schema field that duplicated a glossary sentence would be the drift this
  product keeps hunting.
- **The schema is public contract; the documents are estate configuration.**
  `se.views/1` and its conformance guards live in this repository; the JSON
  documents live wherever the estate keeps configuration, deployed to the
  directory `SE_HUB_VIEWS` names (the deployment-receipts pattern: a path
  option with no default, because views are the operator's judgement and an
  empty directory honestly means none were made). Malformed documents are an
  *input*: the hub validates each against the published schema on read and
  serves a per-document error entry rather than dropping it silently or
  serving garbage.
- **se-mcp serves the same documents** through its `get_views` tool, pointed
  at the same deployed directory (`SE_MCP_VIEWS`). Parity is by shared
  configuration, not by a hub dependency: the MCP surface must keep working
  when the hub is down, so it reads the directory itself.
- The agent knows nothing of views. An agent-only deployment simply has none,
  and the UI shows the section only where `/hub/views` answers.

### 6.3 Findings at the hub — the write posture, decided before the route

Slice 2's findings layer gives conditions a lifecycle: the rule-15 key
`(host.machine_id, container?, app?, object.id, opinion.key)` gains
first_seen, last_seen, and operator acknowledgement, persisted at the hub
under §6.1's metadata rule. Acknowledgement is a WRITE — the first this
product has ever accepted — and its posture is settled here, in writing,
before any code, because §6.1's read posture is licensed by "read-only by
construction" and that licence does not stretch to cover a mutation
nobody wrote down. Four decisions:

1. **Writes are a grant, default off.** The transition route exists only
   when the deployment enables it (`findingsWrites` in the hub module —
   the `grantDiskAccess` idiom: an explicit, documented, per-deployment
   yes). The posture caveat is stated where the grant is: until
   authentication exists (a hard prerequisite of the actions phase), an
   enabled write route trusts the network the hub is bound to, so it
   belongs behind loopback or a tailnet bind, not a LAN the operator does
   not control.
2. **A transition is appended, attributed, and reversible — never a
   deletion.** POST adds a record carrying the transition, a mandatory
   free-text `by` (honest attribution without pretending it is
   authentication), an optional note, and the hub's timestamp. Un-
   acknowledging is another appended transition; the history is the
   record and nothing rewrites it.
3. **Acknowledgement never removes a finding from anything.** The
   condition is still true on the host — the agent re-derives it on every
   status poll, and hub state cannot say otherwise. Roll-ups keep
   acknowledged findings in their counts, marked; projections (views, the
   home-automation surface) may STYLE acknowledged differently and may
   never drop it. Suppression is the one power this design refuses to
   create, because a suppressed truth is the absence-as-health shape with
   a signature on it.
4. **Resolution is observed, not declared.** A finding leaves the roll-up
   when the condition stops being derived — the host stopped saying it —
   never because an operator marked it done. last_seen stops advancing;
   the record remains; reappearance within the record's retention is the
   same finding recurring, not a new one.

The read side needs no grant: GET routes serve the registry (every
finding, its lifecycle, its transitions) the way /hub/views serves
documents — hub metadata, honestly distinct from the live observations it
was derived from, each finding carrying the evidence_ref-style pointer
back to the object that can prove or refute it right now.

Landed in 0.6, one addition the decisions above forced into the open:
**absence only resolves where the host could look.** The agent's
`/v1/findings` envelope carries `unobserved` — every collection the sweep
could not evaluate, with its reason — and the hub freezes those findings
(lifecycle untouched, `current` honestly unstated) instead of resolving
them, because an adapter failure that read as "all of its findings
cleared at once" would be the absence-as-health shape written into
history. The same freeze applies to a whole agent that could not be
swept. The hub parses these envelopes, deliberately and exceptionally:
the registry is metadata DERIVED from findings under §6.1's amended rule
4, and every observation behind them still travels rule 1's verbatim
proxy. One clock — the hub's — stamps first_seen and last_seen, so
lifecycle never depends on comparing host clocks. The sweep runs on the
hub's own background cadence rather than inline per request: a fresh
estate acquisition costs seconds by design, and the read side serves the
registry plus the latest completed sweep instantly, with `swept_at` on
the envelope saying exactly how old that sweep is — the founding rule's
"last-known-good belongs with findings", done literally and nowhere
else.

### The fact dictionary — what a native name means

Rule 2 keeps native terminology, and native terminology is not
self-explanatory. A reader looking at `LinkSpeed` "8.0 GT/s PCIe" beside
`LinkWidth` 2 reasonably asked whether lanes and speed were the same thing;
they are not, and nothing on the screen said so. No renaming fixes that — the
reader needs the concept, once, where they are looking.

`GET /v1/facts` returns `se.facts/1`: subsystem → collection → fact name → one
sentence. Its shape follows from constraints already in this document:

- **An endpoint, not a client-side table.** Rule 14 exists because duplicated
  knowledge drifts. A map of fact meanings in the UI would be a second one, and
  the UI is not where the fact is emitted.
- **An endpoint, not a `description` beside every value.** §5 keeps `facts` a
  flat map of native names; a consumer paging ten thousand rows must not pay
  for the same prose ten thousand times. Fetched once, cached, and equally
  available to an agent as to the UI — the two-consumers rule of §1.
- **Owned by the emitting adapter**, so the sentence cannot drift from the
  thing it describes, and enforced as such: conformance rejects a documented
  name that no longer appears in that adapter, and rejects a fact an opinion
  CITES that carries no sentence and no reviewed exemption.
- **Descriptions, never labels.** Presentation belongs to clients (§5), so the
  name itself is never restated — the client already has it.
- **Coverage is partial by design.** An undocumented fact is absent from the
  document. That says no sentence has been written yet, which is a statement,
  not an error (rule 7).

### Lookups — parameterised read-only questions

A lookup is a diagnostic question the host can answer only when given an
input: which route the kernel chooses for a destination, what the resolver
returns for a name. Lookups are a collection like any other (`lookups`), so
discovery, browsing, deep links and evidence need no new machinery:

| Endpoint | Returns |
|---|---|
| `GET /v1/{subsystem}/lookups` | available lookups; each item's facts are its documentation (`Question`, `Input`, `Example`) |
| `GET /v1/{subsystem}/lookups/lookup:{name}` | one lookup's descriptor, including a `Usage` fact |
| `GET /v1/{subsystem}/lookups/lookup:{name}/{input}` | the answer, as a normal `se.observation/1` |
| `GET /v1/evidence/{subsystem}/lookups/lookup:{name}/{input}` | the raw native payload, captured fresh (the lookup re-runs) |

Rules, tightening rule 13 rather than relaxing anything:

- **Never mutating.** A lookup that would generate probe traffic beyond
  what its reference command sends (ping, port probes, packet generation)
  is not a lookup; it stays a non-goal (§12).
- **Input is data.** One typed value per lookup, validated before use
  (an IP address literal, a hostname). Invalid input is an error
  *envelope* — errors are observations, not HTTP failures.
- **Negative answers are answers.** NXDOMAIN and "network unreachable"
  come back `status: ok` with the verdict in facts and a `warn` opinion
  citing it; the lookup succeeded in establishing them.
- **Same acquisition hierarchy.** D-Bus first (resolve1), structured CLI
  only from the §11 allow-list (`ip -j route get`).

v1 network lookups: `route-get` (kernel FIB decision, with a `routes-via`
relationship into the links graph) and `resolve` (forward or reverse via
resolve1, capability-gated like the `resolver` collection). Other adapters
may add lookups by the same pattern — the obvious next candidate is
storage `mount-of` (`findmnt -J --target <path>`).

---

## 7. Security model

The v0.1 prototype ran as root on `0.0.0.0` because it shelled out to
privileged tools. The rebuild inverts this: acquisition paths are chosen so
the service needs no root at all.

```ini
# systemd unit sketch — the authoritative version lives in the NixOS module
DynamicUser=yes
SupplementaryGroups=systemd-journal docker
AmbientCapabilities=CAP_NET_ADMIN     # nft ruleset + conntrack dumps only
CapabilityBoundingSet=CAP_NET_ADMIN
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
StateDirectory=system-explorer
```

Trust boundary, v1 (amended 0.4 to match the deployed reality): the agent
binds loopback by default. Widening the bind is a per-host decision that
must be justified in a comment where it is made, and an operator-trusted
LAN bind is a legitimate outcome of that rule. There is no authentication
in v1 — the network the operator chose to bind **is**
the trust boundary, and that is a documented decision, not an omission.

Two consequences are handled explicitly:

- **DNS rebinding**: an unauthenticated API trusts its network, but a
  browser on that network can be steered by any website into requests the
  same-origin policy attributes to the attacker's hostname. Agents
  therefore reject requests whose `Host` header is not in a per-host
  allow-list (`allowedHosts` / `SE_ALLOWED_HOSTS`) of the names and
  addresses the agent is legitimately dialled by. Unset disables the check;
  deployed hosts set it.
- **Sensitive reads**: the API exposes the full journal, package inventory,
  and (with `grantNetAdmin`) the nftables ruleset. A LAN bind hands those
  to every device on that LAN. Where the LAN is not operator-controlled
  (a guest network, a friend's site), the honest options are a tailnet-only
  bind or waiting for authentication — application auth is the roadmap's
  concern, deliberately not bolted on here.

The MCP path (§9) carries the same model: bind narrowly by default, front
with an authenticated edge (Cloudflare Access or tailnet) before any
publication beyond the trusted network. Adding per-request identity is a
v2 concern.

**Known caveat — docker group.** Membership of `docker` is root-equivalent on
that host. The agent only issues GET requests by construction, but the
credential itself is powerful. Accepted for v1 (the agent runs no untrusted
code and takes no mutating input); if it starts to itch, the mitigation is a
GET-only socket proxy in front of `docker.sock`.

**Structural consequence:** the v0.1 prototype ran a privileged observer
that needed hardening; this design closes that gap rather than patching it —
no root, no `0.0.0.0`, no journald exposure beyond group membership.
Request parameters never select
or compose commands: the only parameterised surface is lookups (§6), whose
single input is validated, typed, and passed as data — the v0.1 `/api/info`
command-runner has no successor.

---

## 8. UI contract

The operator UI is a first-class product surface — one of the two consumers
the product exists for — and visual quality is a requirement, not a polish
pass. This replaces SE-005 in its entirety.

Architectural rules:

- Consumes only the public API, and never displays information that is not
  in the envelope. If the UI needs it, the envelope grows, and the agent
  gets it too.
- Self-contained static assets served by the agent: no CDN, no runtime
  external requests. An asset build step is permitted only inside the Nix
  package build — never a toolchain on the operating machine.
- **Deep-linkable:** the URL encodes host/subsystem/collection/object.
- **Live-ness:** poll on an interval with visible `observed_at` age. No
  WebSocket.

Design direction (binding; detail iterates with the implementation):

- **Calm density.** An expert's state browser: information-dense collection
  tables, quiet chrome, generous detail panes. No dashboard kitsch — no
  gauges, no donut charts, no decorative color.
- **Native identifiers are always monospace**: unit names, object IDs,
  dataset paths, digests.
- **A native name the host can explain says so.** Facts keep their native
  spelling, and the meaning arrives from `/v1/facts` (§6) — never a table in
  the client. Help nobody knows is there helps nobody, so a fact with a
  sentence behind it is marked as hoverable rather than left looking like
  plain text. Absent help degrades to today's behaviour and nothing else.
- **Facts that multiply are shown multiplying.** Where two facts combine into
  the number a reader actually wants — a per-lane rate and a lane count into
  bandwidth — the relationship is displayed, not left as adjacent rows for the
  reader to spot. Composition of envelope facts only: the arithmetic itself
  belongs to the agent (§5), never to a table in the browser.
- **Color is semantic only**: opinion levels (info/warn/critical), envelope
  status (ok/partial/error), and later diff states (added/removed/changed).
  Everything else stays neutral — a raw native value the rules decline to judge
  is a label, never a verdict.
- **The absence of a level is drawn as absence, never as a level.** A row with no
  `worst_opinion_level` carries no severity claim, which is a different statement
  from a neutral `info` verdict; it gets an unfilled mark, not the neutral fill an
  `info` verdict gets. An adapter omits the field deliberately (a quiet operstate
  is carrier-detection absence, not health), and a UI that renders absence as
  neutrality re-asserts the judgement the agent withheld.
- **Dark and light themes from one token set**; dark is the primary design
  target.
- **Keyboard-first**: subsystem switching, filtering, and object navigation
  without the mouse; the mouse always works too.
- **Progressive disclosure** (SE-001's rule survives here): summary → facts →
  relationships → evidence, with evidence hidden until asked for.
- **Layout:** subsystem nav → collection table (filter, sort, count) → object
  detail pane: facts, opinions with their evidence highlighted, clickable
  relationships, evidence reveal.

---

## 9. MCP surface

A separate small component, `se-mcp` ([src/system_explorer/mcp/server.py](../src/system_explorer/mcp/server.py)),
deployable beside an existing MCP broker or standalone. Host agents stay
single-host;
`se-mcp` aggregates them, configured by environment (`SE_MCP_AGENTS` as
name=url pairs) and shipped by the flake as `packages.se-mcp` +
`nixosModules.mcp`. Transports: streamable-http (`/mcp`, default) or
legacy sse (`/sse` + `/messages/`, the broker layout):

| Tool | Maps to |
|---|---|
| `list_hosts()` | configured agent endpoints + their capabilities |
| `get_status(host?)` | `GET /v1/status` — one host, or every configured host |
| `get_fact_dictionary(host)` | `GET /v1/facts` — what each native fact name means |
| `get_collection(host, subsystem, collection, filters?, limit?, cursor?)` | `GET /v1/...` |
| `get_object(host, subsystem, collection, id)` | `GET /v1/.../{id}` |
| `get_evidence(host, subsystem, collection, id)` | `GET /v1/evidence/{subsystem}/{collection}/{id}` |
| `lookup(host, name, input, subsystem?)` | `GET /v1/{subsystem}/lookups/lookup:{name}/{input}` |
| `what_changed(host, since, subsystem?)` | `GET /v1/changes` (§10) |

Tool responses are envelopes verbatim — no summarisation layer. The agent
consuming them decides what matters. Unknown hosts and unreachable agents
return structured errors (with the known-host list), never exceptions.

**Every route the agent serves gets a tool in the same commit.** The
roll-up shipped HTTP-only and the drift was found the embarrassing way —
by the agent consumer reaching for curl instead (2026-08-10).
Two consumers, one contract, means this table is part of the route's
definition of done.

---

## 10. History and what-changed (shipped 2026-08-10)

History is stored snapshots plus diff-on-read (rule 11), not an event
stream. Authoritative envelope shape:
[`schema/changes.schema.json`](../schema/changes.schema.json).

- An in-process task — not a systemd timer; it needs the adapters anyway,
  and this way history stops with the service — snapshots every collection
  except `logs/journal` (a bounded query result, not object state) and
  every `lookups` catalog (documentation, not observed objects) to SQLite
  at `$STATE_DIRECTORY/history.db`. One snapshot row per
  (snapshot, subsystem, collection) holds that collection's item summaries,
  all pages, plus the `boot_id` at capture. Cadence: a startup snapshot
  only when the newest stored one is missing or already stale (a redeploy
  does not stack extras), then every `SE_SNAPSHOT_INTERVAL_SECONDS`
  (default 900). Retention rides every write: snapshots older than
  `SE_SNAPSHOT_RETENTION_DAYS` (default 30 days) are pruned. A collection
  the host cannot serve is simply absent from that snapshot; a failed
  store never breaks serving. Without `STATE_DIRECTORY` (the NixOS module
  sets it) history is off, and `/v1/changes` says so in an error envelope —
  errors are observations, never a 500.
- `GET /v1/changes?since=` (UTC ISO 8601 or relative like `-24h`; omitted
  means since history began) picks the newest stored snapshot at-or-before
  `since` — falling back to the oldest one, flagged `baseline.fallback`,
  when nothing stored is that old — live-collects the same collections
  now, and answers `se.changes/1`: added/removed object ids and changed
  objects with the dotted paths that differ, per collection, empty
  sections omitted. Changed paths use the evidence-path language, so a
  change entry cites facts the way an opinion does. The baseline's
  `boot_id` is compared with the current boot (`rebooted`), so boot
  boundaries are explicit. A collection that fails to collect live
  degrades the envelope to `partial`, one entry at a time (rule 7).
- `what_changed(host, since, subsystem?)` is the same envelope over MCP
  (§9).

The target capability: explaining actual incidents. "This host runs a
closure no generation records" was diagnosable only from live state plus git
archaeology; with history it is one `what_changed` call.

---

## 11. Conformance

The contract is executable. A pytest suite enforces, for every adapter, on
every collection it exposes:

1. Every envelope validates against the schemas — twice: the published
   schemas, which permit members a newer agent might add, and a strict
   profile of them with every declared object closed, which is what stops
   this agent inventing a field (§5.1 rule 8).
2. Every `opinions[].evidence` path resolves to an existing fact, and every
   `opinions[].look` entry names a collection an adapter really serves,
   ordered by a fact that collection really emits. Checked here rather than
   raised in the builder: a dead link must degrade to a missing link, never
   to the error envelope a raise inside an adapter would produce.
3. Every relationship target is a well-formed object reference.
4. Every `source` has ≥ 1 `reference_command`.
5. **Adapter lint:** subprocess use is permitted only for allow-listed
   commands, enforced by extracting argv list literals from the AST —
   every extracted argv head must be allow-listed and carry its
   structured-output token in the same literal (`zpool … -j`, `lsblk -J`,
   `journalctl -o json`, `smartctl --json=c`, …). A subprocess-using file
   from which no argv can be extracted fails: dynamically built commands
   are unlintable and therefore forbidden. (Tightened 2026-08-09: the
   previous some-command-appears check let unlisted commands ride along
   in files that already invoked an allow-listed one.)
6. All timestamps are UTC ISO 8601 with `Z`.
7. Two consecutive collections yield identical IDs for unchanged objects.
8. **Rule purity and coverage** (0.4): `src/system_explorer/agent/rules/` modules import
   nothing beyond the stdlib and the envelope builders, tolerate absent
   facts, and are exercised directly — characteristic inputs must fire the
   documented keys at the documented levels, and every emitted opinion's
   evidence must resolve into the input facts.
9. **Every declared surface is published** (0.4): every `se.<name>/<n>`
   discriminator emitted anywhere in the package has a schema in `schema/` and
   a fixture, and every published schema is emitted by something. An envelope
   naming a schema nobody wrote is unversioned in practice, and a schema
   nothing emits is contract a consumer implements against and never receives.
10. **Evidence redacts what it should** (0.4): every adapter serving
    `evidence_ref` either routes its payload through a redactor or carries a
    written, reviewed reason why its native payload has no credential surface.
    A redactor declares the paths where it actually withheld something —
    announcing a redaction that did not happen inverts the provenance contract
    as surely as performing one silently.

---

## 12. Non-goals (v1)

Explicit, so scope creep has to argue with a list:

- Writeback / reconciliation of any kind (later rungs of the ladder).
- Deltas, subscriptions, WebSocket, invalidation protocol.
- Log follow-mode; flow history; packet capture.
- Metrics time-series (beszel exists) and alerting. The boundary in one
  sentence: System Explorer owns identity, current truth, correlation and
  explanation; specialised providers own high-volume retention and
  delivery (ROADMAP "The line").
- Non-Linux adapters (UniFi APs, switches) — the first true adapter case,
  after the host graph is proven.
- Multi-host awareness inside the host agent (aggregation lives in `se-mcp`).
- Authentication beyond the network trust boundary.

Not a non-goal, to be explicit about it: **portability beyond NixOS**. The
agent targets systemd-based Linux distributions; NixOS is the first-class
deployment today, not the definition of the product. The packaging path
lives in the roadmap's portability track.

---

## Appendix A — Disposition of SE-001…006

SE-001 through SE-006 were this project's original design suite, plus a
long-form vision document. They are not published: everything of theirs that
still holds is *in* this specification (the `(SE-00x §y)` citations above mark
where) or in ROADMAP.md §2, and what did not hold is recorded below. This
table is the condensation, and it is deliberately the only trace they leave.

| Doc | Disposition |
|---|---|
| SE-001 Product Philosophy | Carried: read-only, native-first, evidence-before-opinion, progressive disclosure. Reframed: primary consumer is agent + expert operator; success criterion is a diagnosed real issue, not browser-completeness. |
| SE-002 Conceptual Model | Carried nearly whole: Host→Subsystem→Collection→Object, native identity, objects in multiple subsystems. Extended with explicit relationship types and ID format. |
| SE-003 Interface Catalogue | Carried: acquisition hierarchy, reference-tool vs native-interface split. Tightened: tier-7 parsing forbidden. Corrected: `storagectl` does not exist; storage sources are ZFS/lsblk/findmnt JSON. |
| SE-004 Architecture & Protocol | Carried: evidence model, source attribution, capabilities, partial success, pagination rules, errors-as-observations. Dropped: continuous observation (deltas/invalidation/subscriptions), stateless-host emphasis (history now requires state). |
| SE-005 UI Framework | Replaced by §8 (one page, same JSON as agents). The interaction skeleton survives; the 867-line framework does not. |
| SE-006 Backlog | Superseded by the original implementation plan, itself condensed into [ROADMAP.md](ROADMAP.md). Its §3 runtime contract became the schemas; its clean-break policy is retained. |
