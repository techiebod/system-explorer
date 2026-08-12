# System Explorer

Read-only observation for Linux hosts: systemd, storage/ZFS, Docker, VMs,
network, hardware and the NixOS deployment itself, presented as a graph of
native objects with provenance — consumed by AI agents over HTTP/MCP and by
the operator through a designed UI. One contract for both.

| | |
|---|---|
| Specification | [docs/SPEC.md](docs/SPEC.md) — authoritative for current behaviour |
| Roadmap | [docs/ROADMAP.md](docs/ROADMAP.md) — status, direction, portability track |
| Contract | [schema/](schema/) — JSON Schemas plus example envelopes |
| Conformance suite | [conformance/](conformance/) — the spec's teeth |
| VM test matrix | [test/vm-lab/](test/vm-lab/) — disposable Fedora/Debian/Ubuntu/NixOS guests for packaging tests |

This repository is the canonical source and a self-contained Nix flake. The
author's own hosts consume it the same way you would — as a flake input
using [nix/module.nix](nix/module.nix) — so the documented install path is
the one running in production, not a second-class path nobody exercises.

The backlog that drives this — every question the observer could not yet
answer — is kept privately alongside the deployment it came from, because
each entry cites the host and evidence that raised it. Findings graduate
into [docs/ROADMAP.md](docs/ROADMAP.md) once they are general.

## Running it on your NixOS host

```nix
{
  inputs.system-explorer.url = "github:techiebod/system-explorer";

  outputs = { nixpkgs, system-explorer, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      modules = [
        system-explorer.nixosModules.default
        {
          services.systemExplorer = {
            enable = true;
            # loopback by default; widen deliberately (the trust boundary is
            # yours — SPEC section 7):
            # listenAddress = "0.0.0.0"; openFirewall = true;
            # per-adapter grants, each a documented decision:
            # enableDockerAdapter = true;   # docker group is root-equivalent
            # grantNetAdmin = true;         # nftables ruleset
            # extraPackages = [ pkgs.zfs ]; # pools/datasets on ZFS hosts
          };
        }
      ];
    };
  };
}
```

The UI is served by the agent at `http://<host>:8091/`; the same envelopes
are available to agents under `/v1/…` (see SPEC section 6).

## MCP

`se-mcp` (SPEC section 9) aggregates one or more host agents for MCP
clients — same envelopes, eight read-only tools (`list_hosts`,
`get_status`, `get_fact_dictionary`, `get_collection`, `get_object`,
`get_evidence`, `lookup`, `what_changed`). Enable it via `nixosModules.mcp`:

```nix
services.systemExplorerMcp = {
  enable = true;
  agents = { myhost = "http://localhost:8091"; };
  # transport = "sse";  # for legacy /sse + /messages/ broker layouts
};
```

Then point a client at `http://<host>:8092/mcp` (streamable-http), e.g.:

```sh
claude mcp add --transport http system-explorer http://<host>:8092/mcp
```

There is no authentication in the server itself; put your edge in front of
it (Cloudflare Access, tailnet, or loopback-only), exactly as with the
agent.

## Per-site hub

`se-hub` fronts several agents at one address: it proxies their GETs verbatim
and serves the same UI, with a host selector. Stateless — no polling, no
cache — so losing it costs convenience, never data. Enable it via
`nixosModules.hub`:

```nix
services.systemExplorerHub = {
  enable = true;
  site = "site-a";
  agents = { host-a = "http://localhost:8091"; host-b = "http://host-b:8091"; };
};
```

Then browse `http://<host>:8090/`.

Ad-hoc run without the module: `nix run .# -- --port 8091` then browse
localhost:8091 (the default is 127.0.0.1:8091; capabilities degrade honestly
for anything the process cannot reach). `--host`, `--port` and `--log-level`
each also read an environment variable — `SE_HOST`, `SE_PORT`, `SE_LOG_LEVEL`
— so a single `EnvironmentFile` configures the service on any init system.

Outside Nix it is an ordinary Python distribution:

```sh
pip install .            # or .[vms] on a libvirt host, .[mcp] for se-mcp
se-agent --host 0.0.0.0 --port 8091
```

## Conformance

```sh
nix flake check   # builds the package, which runs the suite inside it
# or, with pytest + jsonschema available, from the repo root:
pytest -q
```

The suite exercises the schemas, the example fixtures, the adapter sources
(the subprocess allow-list and the UI no-HTML-sink lint are armed and
enforced), and the severity rule modules under
`src/system_explorer/agent/rules/` directly. Fixtures under
`schema/examples/` are also the UI design track's sample data.

## Portability

NixOS is the first-class deployment, not the boundary of the product: the
target is systemd-based Linux distributions on x86-64/arm64, and the
packaging path (pyproject as the one dependency truth, then a hardened
`.deb`) is laid out in [docs/ROADMAP.md](docs/ROADMAP.md) §5. Until those
steps land, non-NixOS installs use Nix-the-package-manager as described in
[AGENTS.md](AGENTS.md).

## License

GPL-3.0-or-later. Copyright © 2026 techiebod <henry@techiebod.com>.
