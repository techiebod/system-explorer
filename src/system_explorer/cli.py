"""Console entry points for the agent and the hub.

These replace `makeWrapper uvicorn --add-flags "agent.main:app --app-dir …"`.
The wrapper worked only because the source tree sat next to the wrapper in
the nix store; a distro package installs an importable module and no
`--app-dir` to point at, so starting the service has to be a real command.

The accepted flags are deliberately the ones the existing NixOS units
already pass — `--host` and `--port` — so nix/module.nix and
nix/hub-module.nix keep their ExecStart lines unchanged across this move.
Each also falls back to an environment variable, which is what makes the
planned single EnvironmentFile (ROADMAP section 5, phase 3) cost no
application code.
"""

from __future__ import annotations

import argparse
import os

from . import __version__


def _serve(app: str, prog: str, description: str, env_prefix: str, default_port: int) -> None:
    parser = argparse.ArgumentParser(prog=prog, description=description)
    parser.add_argument(
        "--host",
        default=os.environ.get(f"{env_prefix}_HOST", "127.0.0.1"),
        help="bind address (default: %(default)s, or $" + env_prefix + "_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get(f"{env_prefix}_PORT", default_port)),
        help="bind port (default: %(default)s, or $" + env_prefix + "_PORT)",
    )
    parser.add_argument(
        "--log-level",
        default=os.environ.get("SE_LOG_LEVEL", "info"),
        choices=["critical", "error", "warning", "info", "debug", "trace"],
        help="uvicorn log level (default: %(default)s, or $SE_LOG_LEVEL)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args()

    # Imported here, not at module scope: --help and --version must work even
    # where the server extras are absent, and this keeps `--version` cheap.
    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level=args.log_level)


def agent() -> None:
    _serve(
        "system_explorer.agent.main:app",
        "system-explorer-agent",
        "System Explorer host agent: read-only observation over HTTP.",
        "SE",
        8091,
    )


def hub() -> None:
    _serve(
        "system_explorer.hub.server:app",
        "se-hub",
        "System Explorer per-site hub: one URL over a site's agents, one UI.",
        "SE_HUB",
        8090,
    )
