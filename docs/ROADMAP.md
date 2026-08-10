# System Explorer — Roadmap

**Status:** Accepted direction
**Date:** 2026-08-09
**Contract:** [SPEC.md](SPEC.md) — authoritative for current behaviour

The demand signal behind this roadmap is a running backlog of questions the
observer could not yet answer. It is kept privately with the deployment that
raised them, because each entry cites a specific host and its evidence;
findings graduate into this file once they are general.

This file is the single statement of where the product is and where it goes
next. It condenses and supersedes the original implementation plan and the
long-form vision; when this roadmap and the code disagree, fix whichever is
wrong the same day.

## 1. Where the product is

Verified against the code at the date above — deliberately structural, so it
stays true longer than an inventory would (the predecessor vision document's
"today" snapshot was stale within three hours of being committed):

- **Observe is built and deployed.** Eight native adapters behind one
  envelope contract, agents running on a multi-site fleet of NixOS hosts, a
  designed single-host UI served by each agent, and a per-site MCP
  aggregator so no site's visibility depends on an inter-site path.
- **The success gate is passed** (2026-08-09): a genuine health question
  answered end-to-end through se-mcp with an evidence chain and no SSH — and
  the product gaps that session exposed went straight into the backlog,
  which is the loop working as designed.
- **Severity is one logic.** Collection rows and full-object opinions derive
  from the same pure rule modules (`src/system_explorer/agent/rules/`, SPEC rule 14), and
  finding identity is declared (SPEC rule 15) so a findings layer can attach
  lifecycle without re-plumbing the agents.
- **The conformance suite covers** schema validity, fixture invariants,
  AST-level source lint (subprocess argv extraction, UI HTML-sink ban) and
  direct rule-evaluator tests. It does **not** yet prove adapter behaviour
  against mocked acquisitions — the known, logged gap.
- **Slice 1 is delivered and deployed (2026-08-09, same day):**
  `GET /v1/status` per-collection severity roll-up (`se.status/1`,
  nullable with reasons), nav badges on a 60s cadence, the
  `system/overview` procfs snapshot as the landing view, and per-site
  hubs (one `se-hub` per site) — one URL per site, host dropdown,
  `#/<host>/…` routes with legacy-link migration.
  Its first hour surfaced a genuinely crash-looping container that the
  pre-unification severity logic would have shown as a calm warn row.
- **Slice 2's history core is delivered (2026-08-10):** per-agent SQLite
  snapshot store (in-process task, 15-min cadence, 30-day retention),
  `GET /v1/changes` diff-on-read (`se.changes/1`) and the `what_changed`
  MCP tool. Placement stays per-agent as the SPEC accepted; the
  hub-central question re-opens when findings land. The overview also
  became a designed panel: opinion-coloured meters (load, memory with ARC
  as a reclaimable segment, swap, PSI) and an attention strip from the
  roll-up — the UI holds scales, never thresholds.
- **Not built:** findings with lifecycle (the remaining slice-2 piece —
  diffing opinion sets over the now-existing snapshots); expected-state
  policy (deliberately-down links warn until it exists);
  provider integrations; hub last-known-good cache and staleness. Every
  one of these is a slice below, none is accidental.
- **Security posture:** read-only by construction, unprivileged agent with
  narrow per-host grants, loopback bind by default, any wider bind
  justified where it is made, Host-header allow-list against DNS
  rebinding. There is no application authentication; on any network the
  operator does not control, that remains the standing risk — tracked in the
  backlog, honestly stated in SPEC §7.

## 2. The line

The durable boundary, carried from the vision:

> System Explorer owns estate identity, current truth, expected-versus-
> observed state, relationships, resource attribution, health findings and
> diagnostic explanation. Specialised providers may own high-volume
> collection, retention and delivery, but their information is correlated
> and presented through the System Explorer graph and its single operator
> surface.

Providers, when their slices arrive: Beszel for metric history, a UniFi
controller adapter for network inventory, a dedicated NetFlow/IPFIX store
for flow history, an advisory source for security evaluation, Healthchecks
for dead-man state. System Explorer never becomes the storage engine for
any of them, and none of them becomes the canonical source of object
identity.

Principles that survive from the vision (the rest of it was elaboration):
evidence before opinion at every scale; native concepts before abstractions;
one graph, several projections; one public contract for humans and agents;
read-only toward the estate; partial truth labelled (unknown is never
green); expected state explicit (absence is a problem only when something
says the object should exist); short diagnostic state and long telemetry
are different workloads; privilege follows the acquisition path; calm
density.

## 3. From opinions to findings

Five concepts, kept separate:

| Concept | Meaning | Owner |
|---|---|---|
| Observation status | Was acquisition complete and trustworthy? | Agent |
| Opinion | What does this one observation mean? | Agent (rules modules) |
| Finding | A stable, current condition requiring attention | Hub (slice 2) |
| Notification | Delivery of a finding outside the product | External, much later |
| Incident | Related findings grouped under one cause | Hub, later still |

A finding is `(machine_id, object.id, opinion.key)` — SPEC rule 15 — plus
what only a stateful layer can add: first/last seen, active/recovered/
unknown, acknowledgement. Severity stays three-valued (critical: availability
or data at risk now; warn: action needed soon or resilience reduced; info:
worth understanding). No opaque health score, ever.

## 4. Delivery slices

Each slice is independently useful and earns the next; the ordering after
slice 2 may change in response to real diagnostic demand, recorded in
the backlog. The standing rule: **no new collection unless it closes a
demonstrated diagnostic gap or improves a finding or explanation visible
from the estate surface.**

| # | Slice | Contents | Proof it earned the next |
|---|---|---|---|
| 1 | Attention and overview — **delivered 2026-08-09** | Per-collection severity roll-up (`/v1/status`, nullable — logs has no honest status), nav badges with counts; `system/overview` observation (loadavg, PSI, meminfo, ARC when present — kernel-precomputed rates only); per-site hub (`se-hub`): one UI fronting each site's agents, host-aware routes with deep-link migration | Proven same day: a crash-looping container surfaced from the roll-up without knowing where to look; each site navigable from a single URL |
| 2 | Findings and history | Snapshot store + diff-on-read (`/v1/changes`, `what_changed`) — placement decided then (per-agent StateDirectory per SPEC §10 vs hub-central as the predecessor design proposed); findings with lifecycle derived by diffing opinion sets; health inbox | A past incident is explainable from stored state; known faults surface and clear correctly without browsing |
| 3 | Expected state | Nix-generated expected-inventory manifest (hosts, key units, pools, mounts, stacks, domains) related to observations by explicit edges; drift and absence become findings | "Down" and "missing" are policy-grounded, not guesses |
| 4 | Resources and attribution | cgroup-v2 resource model, workload attribution (stack → container → process, lazily), Beszel history provider spike | A resource spike traces host → workload → process without SSH; host totals reconcile with an explicit unattributed remainder |
| 5 | Network estate and beyond | UniFi controller provider, device/client inventory, conntrack summary; then flows, advisories, notifications — each gated on the graph and findings model already existing | A client traces through AP/switch/VLAN/gateway; device loss is a finding |

## 5. Portability track

**Decision (2026-08-09): portability beyond NixOS is a goal, not an
afterthought.** A NixOS-only product limits the audience to a niche and
starves the project of feedback from other hardware and use-cases; the
packaging discipline portability forces (one dependency truth, a real CLI,
an installable service contract) pays off even inside the estate. NixOS
remains the first-class deployment — it is where the hardening contract is
already executable — but it is not the definition of the product.

The boundary: **systemd-based Linux distributions, x86-64 and arm64.** The
agent's essential acquisitions are systemd D-Bus, journald, udev, util-linux
and iproute2; Alpine/OpenRC or generic Unix would be a different project and
is not claimed.

### What the lab has already proven (2026-08-10)

Measured in [test/vm-lab](../test/vm-lab) guests, not predicted:

| | Debian 13 | Ubuntu 24.04 | Ubuntu 26.04 | Fedora 44 |
|---|---|---|---|---|
| python3 | 3.13.5 | 3.12.3 | 3.14.4 | 3.14.3 |
| anyio · httpx · uvicorn · fastapi · starlette · dbus-fast · libvirt | all packaged | all packaged | all packaged | all packaged |
| `python3-mcp` | absent | absent | absent | 1.26.0 |

**The agent needs no vendoring on any target.** It imported and served
`/v1/capabilities` from distro packages alone at both ends of the version
spread — Ubuntu 24.04's fastapi 0.101 / dbus-fast 2.21 and Fedora 44's
0.136 / 2.45 — which was the one compatibility risk research could not
settle. systemd D-Bus, journald, udev and procfs all worked unmodified:
units, logs, system identity/time/boot/overview live on both.

Degradation is honest where it matters: `/v1/status` returned 200 with
`status: ok`, zero acquisition errors and 14 collections rolled up, and
each absence named itself — no NVMe controller, no docker socket, no
libvirt socket, no zpool, nft without CAP_NET_ADMIN, and
`generations`/`packages` saying *"not a NixOS host?"*.

Two things the lab falsified or found:

- **The `.deb`/RPM ordering was wrong.** Nothing about Debian is harder
  than Fedora; Fedora is *easier* (it is the only target that packages the
  MCP SDK, and its `%pyproject_` macros read the same metadata). Build both
  from one tarball rather than sequencing them.
- **A confirmed lie by omission**, reproduced on a real Ubuntu host:
  `GET /v1/system/generations` returns `status: ok, items: 0, total: 0,
  errors: None`. Capabilities, `/v1/status`, the UI and the snapshot task
  all decline it correctly; only the raw collection route claims a clean
  empty answer, and that is the one an MCP client hits. This is now a
  blocker rather than a nicety — it is the first thing a non-Nix user sees.

### The plan of attack

**Phase 1 — make the tree a Python distribution. SHIPPED 2026-08-10.**
Nothing else could start until this landed, and every blocker was structural
rather than packaging-specific. What shipped: `pyproject.toml` as the single
dependency truth (`requires-python = ">=3.10"`; the measured floor is 3.12,
so this is comfortable) consumed by `nix/package.nix` via
`buildPythonApplication`, so nixpkgs' `pythonRuntimeDepsCheckHook`
*enforces* that the two lists agree; a `system_explorer.*` namespace under
`src/`, because top-level `agent`/`hub`/`mcp` are taken on PyPI and a
top-level `mcp/` shadows the SDK it imports; `ui/` as package data, since
`parent.parent` found it in a checkout and silently 404s from a wheel or
`/usr/lib`; console entry points preserving `--host`/`--port`, so the NixOS
units' `ExecStart` lines did not change; one `__version__`; libvirt behind a
`[vms]` extra; `mcp>=1,<2` pinned as the `[mcp]` extra.

Three things worth recording from doing it:

- **The namespace rename was the cheap part**, not the expensive one. Every
  intra-package import was already relative (`from .. import envelope`), so
  the whole tree moved with four `git mv`s. What actually needed editing was
  the conformance suite: its absolute imports, its path constants, and one
  dynamic `importlib.import_module(f"agent.rules.{name}")` that no
  `from`-line grep would have found.
- **One distribution, three closures.** `nix/package.nix` takes `withVms` /
  `withMcp` and `mainProgram`, so the hub and the aggregator keep lean
  closures while all three builds verify the same metadata. Extras are only
  checked by the runtime-deps hook when requested, which is exactly what
  makes this legal.
- **`nix build` now runs the conformance suite** via `pytestCheckHook`
  inside the package, so `flake.checks` is the package rather than a second
  pytest invocation against a different `sys.path` than the installed
  package sees.

**Phase 2 — fix what a non-Nix user sees first. SHIPPED 2026-08-10.** The
generations/packages lie and the null Nix facts. Cheap, and they are the
difference between "degrades honestly" as a claim and as an experience.

The fix for the first is deliberately *not* NixOS-specific. The root cause is
that an absent directory and an empty directory both glob to zero items, so
the lie was never only about Nix: `hardware/nvme` on a host with no NVMe
controller and `hardware/scsi` with no SCSI hosts told exactly the same one.
`_unavailable_reason()` in `main.py` therefore gates the collection, object
and evidence routes on `capability()` — reusing the reason string
`/v1/status` already produced, so a collection added later cannot forget to
do it. Cost: one capability probe per request (logged in the backlog).

For individual facts the honest form of absence is to omit the fact, not to
emit `null`: a null `NixosVersion` on Debian reads as *unknown* when the
truth is *not applicable*. `_is_nixos()` gates the two identity facts and the
four boot pointer facts, and the boot envelope drops its `readlink` reference
command and its pointer note along with them. The rule evaluators needed no
change — they already guarded with `facts.get(...)`.

**Phase 3 — the service contract, both formats together.** `debian/` and a
`.spec` from one tarball. The findings that shape them: swap `DynamicUser`
for a `sysusers.d` static user (Debian does not install `libnss-systemd`,
and it sidesteps the SELinux interaction class); one `EnvironmentFile`
rather than TOML, which costs **zero** application code since everything is
already env-driven and systemd expands `${VAR}` in `ExecStart`; the
`docker` group only ever in an admin-enabled drop-in, because
`SupplementaryGroups=docker` hard-fails the unit on hosts without Docker;
`Depends` on util-linux/iproute2/systemd/udev, `Recommends` udisks2 and
smartmontools, `Suggests` nftables, and ZFS unexpressible on both (it is
Debian contrib and third-party on Fedora) — which the `shutil.which` gates
already handle. **Ship no SELinux policy**: a service in `/usr/bin` with no
policy of its own runs as `unconfined_service_t`, which permits everything
here; install to `/usr/bin`, then `setenforce 1` and read `ausearch`.
AppArmor needs nothing.

**Phase 4 — assert it, don't hope.** The assertion that matters is the one
this lab was built for: *every adapter returns data or an explicit
unavailable-with-reason — never a 500, never a silent empty.* Write it as
`autopkgtest` (`debian/tests`, `isolation-machine`) so one script serves
local runs here, CI, and Debian's archive CI. Add the cheap high-value
container checks too: dependency-closure resolution per release,
`systemd-analyze verify` on the units, and an import smoke test against
distro packages — the canary that caught nothing today but would catch the
next dbus-fast API break.

**Phase 5 — distribute.** OBS builds `.deb` and `.rpm` for this exact
matrix from one tarball, signs the repos, and makes `apt upgrade` work,
which GitHub Releases cannot. Host a `python3-mcp` backport in the same
project for Debian/Ubuntu; it retires itself when Debian 14 ships. Releases
need annotated tags and a generated changelog (`gbp dch`, `rpmautospec`)
— native packaging makes the version a user-visible upgrade key, so the
four-way drift above stops being cosmetic.

**Not now:** official Debian/Fedora inclusion (a freeze would pin users to
a snapshot of a moving envelope schema; revisit Fedora first at 1.0), and
an OCI image for anything but the hub — a containerised agent would need
host proc/sys, D-Bus, journal, sockets and devices, which is near-host
privilege pretending to be isolation.

## 6. Deployment shape this design assumes

Not prescriptive — but these are the constraints the components were shaped
around, and they explain choices that would otherwise look arbitrary:

- **Sites are independent.** Where hosts span networks with no routing
  between them, each site runs its own aggregator and hub, so no site's
  visibility depends on an inter-site path. This is why the aggregator is a
  separate deployable rather than a single central service, and why an MCP
  client is expected to carry one connector per site.
- **A host may be reachable by nobody but its operator.** The agent is
  useful standalone and joins an aggregator only if the network allows it,
  so aggregation is never a precondition for observation.
- **Publication beyond the trusted network goes behind an authenticated
  edge** (Cloudflare Access, a tailnet), never bare — there is no
  application authentication yet, and SPEC §7 states that plainly.
