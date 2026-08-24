# AGENTS.md — System Explorer

Guidance for AI coding agents installing or working on System Explorer.
Humans: start with [README.md](README.md).

## The model — reason THROUGH this, not merely near it

Every concept-level mistake of 2026-08-24 was made by an agent operating in
the code's vocabulary while the design's sat unread; each violated one line
of the glossary below, and each felt like a small local choice at the moment
it was made. So the model lives here, in the file every session loads, and
three working rules make it load-bearing:

1. **The trigger rule.** Any change that touches an **id, a name, a key, a
   prefix, a collection name, or any merge/split of objects** is an ontology
   decision wearing a small one's clothes. Before making it, quote the
   glossary line(s) it operates under — in the commit message. No quote, no
   change.
2. **State it back first.** A conceptual move — anything that decides what a
   thing IS — gets a two-sentence model reading to the owner BEFORE work
   builds on it. Every correction this week cost the owner one sentence;
   spent after artifacts instead of before, each cost hours of rework.
3. **The design is edited by the owner only.** Agents propose design changes
   as diffs to the adjudication queue; they never write into DESIGN.md. A
   ruling was once invented and written in — it governed real work before it
   was caught.

**Ratified by the owner, 2026-08-24, in the owner's own words** (from the
corrections that forced this section into existence):

- *"Isn't this the confusion between identity and an observation? Multiple
  collectors will observe attributes and potentially different aliases of
  the same identity."* — Two collections observing one thing yield
  **observations to join through identity**, never two objects and never a
  rename.
- *"Overview is not an identity. Overview is a view on an identity's
  attributes."* — A collection is a **question asked of things** (§15). Its
  objects are observations; the thing observed has exactly one identity per
  scope (§10 layer 2), minted at one site — never from the question asked
  about it.

### The glossary (DESIGN §37, verbatim — the nouns you must think in)

- **collector** — a program that reads one native interface, writes what it saw, and exits
- **collator** — one service per host: schedules collectors, mints ids and relations, joins, judges, records, serves
- **hub** — one service per site: holds intent, judges across hosts, projects
- **object** — a thing with an id that survives re-observation
- **relation** — an edge carrying facts of its own, assembled from directed assertions, keyed on source id, type, discriminator and target name; the assembly states whether it is confirmed, asserted or contradicted
- **assertion** — one vantage's directed claim about a relation, carrying the names it saw. Stored beneath the assembly, never rendered as the relation
- **name** — what a native interface called something. Observed, never minted
- **id** — minted by a collator or a hub, carrying its scope — including the instance, where a collector fronts one of several
- **fact** — a non-judgmental, provenance-bearing assertion about an object, carrying five axes
- **kind** — observed, derived or declared — where the assertion came from
- **temperament** — existence, configuration, state, counter or gauge — how a fact changes and whether anything can watch it
- **type · unit** — the value's shape, and the dimension it is measured in
- **origin** — which collector observed it, and which tier derived it
- **batch** — one collect run, committed per collection. A committed collection is authoritative; an uncommitted one is authoritative for nothing
- **generation** — a monotonic number the collator issues per collection, so an older commit arriving late is refused rather than applied
- **name class** — stable or ephemeral. Only stable names may be joined through
- **verdict** — what the evidence says about the system: healthy, degraded or critical
- **epistemic status** — how much of the question the evidence covered: complete, partial, unknown or conflicted. Never merged with the verdict
- **evidence** — the raw native payload a fact was read from, captured fresh on request, never stored — only digested
- **opinion** — a levelled judgement over facts, naming the facts it read. Self-evident or intent-relative
- **finding** — an opinion at warn or above, with a lifecycle across time
- **declaration** — a collector's static account of what it serves and what it means
- **corpus** — captured reference answers per native source, versioned and in variant states, that declarations are written against
- **intent** — the estate's account of what should be true, held only by hubs
- **coverage** — the identity lists an estate answer carries — declared, discovered-but-not-declared, unclassified — plus which discovery sources were readable. Host reachability travels in reach
- **reach** — what an answer consulted, what declined, and what was dark
- **problem domain** — a question, as an object: answer, verdict, basis, reach
- **projection** — a selection and shaping of the graph for an audience; a screen is an instance

> **Read this before writing any code.** A three-tier rewrite — collector,
> collator, hub — is under way in `go/`, `harness/` and `contract/`.
> **[docs/DESIGN.md](docs/DESIGN.md) is the record of intent and outranks every
> other artefact in this repository, including the code and this file**;
> [docs/PLAN.md](docs/PLAN.md) holds the phases and their gates. Silence in
> DESIGN is a blocker, not a licence to choose: if it does not say, the answer
> is queued in its appendix C and the work stops until it is ruled.
>
> The document below describes the product **shipping today**, which the
> rewrite replaces at the cut. It stays normative for what is deployed, and it
> is the wrong thing to build against. The specific trap DESIGN's appendix B
> names: SPEC describes an agent that accepts inbound HTTP, the rewrite
> reverses that connection, and an agent following SPEC would build a port the
> new architecture exists to remove.

## What this is

A **read-only** infrastructure observation service. Three deployables, all
from one Python distribution:

- **se-agent** — per-host agent. HTTP API serving observations
  (systemd units, journal, storage/ZFS, network, docker, libvirt VMs) as
  `se.observation/1` envelopes. No mutations, no auth. (The distribution
  is `system-explorer`; all three binaries share the `se-` prefix.)
- **se-hub** — per-site hub. One URL fronting a site's agents: proxies
  their GETs verbatim and serves the same operator UI. Stateless.
- **se-mcp** — MCP aggregator. Fronts one or more agents for AI clients.
  Eight read-only tools: `list_hosts`, `get_status`, `get_fact_dictionary`,
  `get_collection`, `get_object`, `get_evidence`, `lookup`, `what_changed`.
  Runs on one host, reaches agents over HTTP.

Trust model: **the API is unauthenticated by design** (SPEC section 7).
Keep `listenAddress` on `127.0.0.1` unless every host on the network is
operator-trusted, and say why in a comment when you widen it.

## Install on NixOS (the supported path)

Add the flake input and import the module. Minimal agent install:

```nix
# flake.nix
inputs.system-explorer.url = "github:techiebod/system-explorer";
# Self-hosted or other git hosting works the same:
#   inputs.system-explorer.url = "git+https://git.example.com/you/system-explorer.git";

# in a nixosConfiguration's modules
imports = [ inputs.system-explorer.nixosModules.default ];
services.systemExplorer.enable = true;   # loopback:8091 by default
```

Supported systems: `x86_64-linux`, `aarch64-linux`. The module pins
`services.systemExplorer.package` to this flake's build; override only if
you know why.

### Agent options (`services.systemExplorer`)

| Option | Default | Notes |
|---|---|---|
| `enable` | `false` | |
| `listenAddress` | `"127.0.0.1"` | widen only on an operator-trusted network |
| `port` | `8091` | |
| `openFirewall` | `false` | pair with a non-loopback `listenAddress` |
| `allowedHosts` | `[ ]` | Host-header allow-list (DNS-rebinding defence); list every name/IP clients dial, or leave empty to disable |
| `enableDockerAdapter` | `false` | joins the `docker` group — root-equivalent on the host (SPEC section 7); enable only where docker runs |
| `grantNetAdmin` | `false` | CAP_NET_ADMIN, needed only for the nftables collection |
| `grantDiskAccess` | `false` | root smartctl snapshot collector on a timer; agent reads (and ages) the snapshots |
| `grantTailscaleAccess` | `false` | root `tailscale status --json` snapshot collector on a timer; surfaces tailnet identity, key expiry, DERP home, per-peer reachability |
| `extraPackages` | `[ ]` | extra tools on the agent's PATH |
| `instances.<name>` | `{ }` | additional agent processes, each running a SELECTED adapter set (`adapters`, `port`, `environmentFile`, loopback by default) and none of the main agent's host grants — credential isolation as a deployment decision |

Subsystems degrade gracefully: no zfs on PATH means the pools/datasets
collections report unavailable with a reason — that is normal, not a
failure. Fix by installing the tool (e.g. `boot.supportedFilesystems`
or the relevant service), not by patching the agent.

### Aggregator options (`services.systemExplorerMcp`)

Import `inputs.system-explorer.nixosModules.mcp` on ONE host:

```nix
services.systemExplorerMcp = {
  enable = true;
  agents.myhost = "http://localhost:8091";   # name -> agent base URL
  # more agents join this attrset as hosts gain the agent; use names
  # the aggregator host can actually resolve, not raw IPs
};
```

Options: `enable`, `agents` (attrset, name → URL), `listenAddress`
(default loopback), `port`, `transport`, `openFirewall`, `package`.

### Hub options (`services.systemExplorerHub`)

Import `inputs.system-explorer.nixosModules.hub` on one host per site. The
hub proxies each agent's GETs verbatim and serves the same UI, so a site is
navigable from one address:

```nix
services.systemExplorerHub = {
  enable = true;
  site = "site-a";                           # label surfaced in /hub/hosts
  agents.myhost = "http://localhost:8091";
};
```

Options: `enable`, `agents`, `site`, `listenAddress` (default loopback),
`port` (default 8090), `openFirewall`, `allowedHosts` (same DNS-rebinding
defence as the agent), `package`. Stateless — losing the hub loses
convenience, never data.

### Classic (non-flake) NixOS

```nix
imports = [
  "${fetchTarball "https://github.com/techiebod/system-explorer/archive/main.tar.gz"}/nix/module.nix"
];
```

The module's own default builds the package, so `services.systemExplorer.package`
needs setting only to override it — and note it is
`pkgs.python3Packages.callPackage <repo>/nix/package.nix { }`, not
`pkgs.callPackage`: the package is a `buildPythonApplication` and names its
dependencies individually. The flake path is less fragile; prefer it.

### Not NixOS?

Portability to systemd-based Linux distributions is a stated goal
(ROADMAP.md §5: pyproject as the single dependency truth, then a hardened
`.deb`), but those steps have not landed yet — today there is no supported
bare pip/systemd install. The agent is a Python/uvicorn app whose runtime
closure is defined by [nix/package.nix](nix/package.nix) — on other
distros, use Nix the package manager
(`nix profile add <flake-url>#system-explorer`) and write your own service
unit mirroring [nix/module.nix](nix/module.nix)'s hardening. If you find
yourself vendoring requirements.txt, stop and ask the operator instead —
that file becoming necessary is what the roadmap's pyproject step is for.

## Verify the install

```sh
systemctl status system-explorer.service        # active (running)
curl -s http://127.0.0.1:8091/v1/capabilities | head -c 400
```

The capabilities response is `se.capabilities/1`: every subsystem, its
collections, and a stated reason for anything unavailable. For the
aggregator, the MCP `list_hosts` tool returns the same per configured
agent. An agent that starts but reports subsystems unavailable is
usually missing a tool or a grant (docker group, CAP_NET_ADMIN) — read
the reason string; it names the cause.

Facts keep the names Linux itself uses, and those do not explain themselves:
`GET /v1/facts` (`se.facts/1`, MCP `get_fact_dictionary`) is one sentence per
fact name, grouped by subsystem and collection. Fetch it once when reasoning
about an unfamiliar subsystem rather than inferring meaning from a name —
`LinkSpeed` beside `LinkWidth` does not say that one is a per-lane rate and
the other a lane count. Coverage is partial: an absent fact has no sentence
written yet.

## Working on the code

- Layout: one Python distribution under `src/system_explorer/` —
  `agent/` (host agent), `hub/` (per-site hub), `mcp/` (aggregator),
  `ui/` (operator UI, package data so an installed agent can find it).
  Outside the package: `schema/` (envelope JSON Schemas — the published
  contract, not shipped in the wheel because nothing serves it),
  `conformance/` (the executable contract), `nix/` (packages + NixOS
  modules), `test/vm-lab/` (disposable multi-distro guests),
  `docs/SPEC.md` (normative — cite section numbers in code comments when
  a constraint comes from it).
- `pyproject.toml` is the single dependency truth. `nix/package.nix`
  feeds that same list to `buildPythonApplication`, so nixpkgs'
  `pythonRuntimeDepsCheckHook` fails the build if the two disagree.
  Adding an import means adding it there, not in a derivation.
- The version lives once, in `src/system_explorer/__init__.py`;
  `pyproject.toml` and `nix/version.nix` both read it.
- Tests: `nix flake check` runs both — the conformance suite inside the
  package build, and a NixOS VM that installs via `nixosModules.default` and
  asserts the documented install path ([nix/tests/module.nix](nix/tests/module.nix)).
  Locally, `pytest -q` from the repo root: `pyproject.toml` puts `src/` and
  `conformance/` on the path, so no install is needed. Install the `test`
  extra — it carries the adapters' third-party imports so their pure helpers
  can be tested without a live host.
- The agent is read-only by construction. Do not add mutating endpoints,
  shell-outs assembled from request input, or auth-gated write paths —
  that is a different product. New collections follow SPEC section
  structure: facts, evidence-cited opinions, typed relationships.
- This is the canonical repo. To develop against a working tree rather than
  a published revision, override the flake input with a local path:
  `nixos-rebuild switch --override-input system-explorer path:/path/to/this/repo`.
