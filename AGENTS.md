# AGENTS.md — System Explorer

Guidance for AI coding agents installing or working on System Explorer.
Humans: start with [README.md](README.md); the contract is
[docs/SPEC.md](docs/SPEC.md).

## What this is

A **read-only** infrastructure observation service. Three deployables, all
from one Python distribution:

- **system-explorer** — per-host agent. HTTP API serving observations
  (systemd units, journal, storage/ZFS, network, docker, libvirt VMs) as
  `se.observation/1` envelopes. No mutations, no auth.
- **se-hub** — per-site hub. One URL fronting a site's agents: proxies
  their GETs verbatim and serves the same operator UI. Stateless.
- **se-mcp** — MCP aggregator. Fronts one or more agents for AI clients.
  Seven read-only tools: `list_hosts`, `get_status`, `get_collection`,
  `get_object`, `get_evidence`, `lookup`, `what_changed`. Runs on one host,
  reaches agents over HTTP.

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
