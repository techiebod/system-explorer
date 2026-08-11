# System Explorer — Specification

**Version:** 0.4
**Status:** Accepted for build
**Supersedes:** SE-001 through SE-006 — the predecessor design suite,
condensed into this document; per-document disposition in Appendix A
**Direction:** [ROADMAP.md](ROADMAP.md) — status, priorities, and the estate/portability tracks

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
15. **Findings have stable identity.** The composite
    `(host.machine_id, object.id, opinion.key)` identifies a condition
    across observations: object IDs are stable for unchanged objects
    (rule 7, §11) and opinion keys are stable kebab-case slugs that never
    rename casually. An unchanged condition yields the same key on every
    evaluation. This is the identity the findings layer (hub, roadmap
    slice 2) will attach lifecycle to; agents stay stateless.

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

Cross-subsystem edges are the point: `unit:compose-stack-web.service` →
`member-of` ← `container:web-frontend` is what makes "why is this container
down" answerable from the graph.

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
| `network` | `links`, `routes`, `resolver`, `nft-tables`, `tailscale`, `conntrack-summary`, `lookups` | `ip -j` (rtnetlink); resolve1 D-Bus; `nft -j list ruleset`; `tailscale status --json` snapshots via root collector | `CAP_NET_ADMIN` (nft, conntrack) | any systemd host; tailscale needs the snapshot collector |

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

Comparing two of these yields `DeltaFromPrevious`, a list of
`{Kind, Name, From, To}` rows, plus `ComparedWithGeneration` naming which
generation it was compared against — the previous one still *present*, which is
not necessarily N−1 once older ones are collected.

The comparison is of two recorded manifests, never of two closures. `nvd` and
`nix store diff-closures` have no structured output, so an adapter running one
would be executing a reference command and parsing its prose, which rule 5
forbids and no allow-list entry could make correct. Whatever built the closures
already knew what went into them.

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
  "opinions": [
    { "key": "unit-health", "level": "info",
      "message": "Unit is active and running.",
      "evidence": ["ActiveState", "SubState"] }
  ],
  "relationships": [
    { "type": "after", "direction": "out", "target": { "id": "unit:network-online.target" } },
    { "type": "wants", "direction": "in",  "target": { "id": "unit:multi-user.target" } }
  ],
  "evidence_ref": "/v1/units/units/unit:sshd.service/evidence"
}
```

Field semantics:

- **`facts`** carry native property names (`ActiveState`, not `active_state`)
  and native types. The v0.1 `{key, label, value}` list is gone — labels are
  presentation and belong to clients. Per-subsystem fact schemas may tighten
  `facts` later; v1 requires only that it is an object.
- **`status`** is `ok` | `partial` | `error`, with `errors[]` listing what
  failed. `partial` means some facts are present and trustworthy; `error`
  means the envelope documents a failed acquisition. Errors are observations.
- **`opinions`** are the only place interpretation is allowed, and each must
  cite the facts it derives from. Opinion levels: `info`, `warn`, `critical`.
- **`evidence_ref`** fetches the raw native payload (D-Bus reply, JSON
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
| `GET /v1/capabilities` | per-subsystem availability, with a `reason` for anything absent |
| `GET /v1/{subsystem}/{collection}` | collection page (`se.collection/1`) |
| `GET /v1/{subsystem}/{collection}/{object_id}` | one observation (`se.observation/1`) |
| `GET /v1/{subsystem}/{collection}/{object_id}/evidence` | native evidence, fresh |
| `GET /v1/changes?since=…&subsystem=…` | what-changed diff (`se.changes/1`, §10) |

Collection behaviour (carried from SE-004 §11, unchanged in spirit):

- Filtering by fact equality: `?type=service&ActiveState=failed`.
- Pagination is explicit: `?limit=` and `?cursor=`; responses always carry
  `applied_limit` and `next_cursor` (nullable). **The server never silently
  truncates; the client never infers truncation.**
- Small collections (pools, links, domains) return whole by default.

Capabilities response distinguishes, per SE-004 §12: `available`,
`unsupported` (with reason: "no docker socket on this host"), and
`error` (with the failure).

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
| `…/{input}/evidence` | the raw native payload, captured fresh (the lookup re-runs) |

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
- **Color is semantic only**: opinion levels (info/warn/critical), envelope
  status (ok/partial/error), and later diff states (added/removed/changed).
  Everything else stays neutral.
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
| `get_collection(host, subsystem, collection, filters?, limit?, cursor?)` | `GET /v1/...` |
| `get_object(host, subsystem, collection, id)` | `GET /v1/.../{id}` |
| `get_evidence(host, subsystem, collection, id)` | `GET /v1/.../evidence` |
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
2. Every `opinions[].evidence` path resolves to an existing fact.
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
