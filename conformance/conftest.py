import functools
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from common import SRC_DIR, example_files, load_example

# The rules evaluators are pure (stdlib + system_explorer.agent.envelope
# only), so test_rules.py imports them directly on any platform — including
# the macOS workstation this is developed on. Adapters stay unimportable
# off-host; only the rulebook needs the package importable.
#
# pyproject.toml's [tool.pytest.ini_options] pythonpath already does this for
# any pytest run rooted at the repo; the insert keeps a bare
# `pytest conformance/` from another cwd working too.
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


@pytest.fixture(params=example_files(), ids=lambda p: p.name)
def example(request):
    """Each fixture file under schema/examples/, parsed, with its path."""
    return request.param, load_example(request.param)


# ── which command is the reference for a variant ─────────────────────────
#
# The Python shim (harness/bin/se-reference-collector) is the reference for
# the adapters that are still Python; a PORTED collector is its own
# reference — the shim's docstring says it retires collector by collector,
# and this table is where a retirement lands. Two test modules resolve
# through here (corpus replay, staged-variant discrimination), which is why
# it lives in conftest rather than in either of them.

GO_DIR = Path(__file__).resolve().parent.parent / "go"

# collector name -> package path under go/, one entry per ported collector
GO_COLLECTORS = {
    "system": "./cmd/se-collect-system",
    "storage": "./cmd/se-collect-storage",
    "network": "./cmd/se-collect-network",
    "vms": "./cmd/se-collect-vms",
    "packages": "./cmd/se-collect-packages",
    "unbound": "./cmd/se-collect-unbound",
    "docker": "./cmd/se-collect-docker",
    "bazarr": "./cmd/se-collect-bazarr",
    "traefik": "./cmd/se-collect-traefik",
}


def _find_go() -> str | None:
    """The Go toolchain, or None on a machine that has none.

    PATH first; the Homebrew prefix second, because the workstation's pytest
    is often started from an environment that never sourced a shell profile.
    """
    found = shutil.which("go")
    if found:
        return found
    fallback = Path("/opt/homebrew/bin/go")
    return str(fallback) if fallback.exists() else None


@functools.cache
def go_collector_binary(collector: str) -> str:
    """Build one ported collector, once per pytest session, host-native.

    No toolchain: SKIP on a workstation — a machine without Go can still run
    the rest of the suite — but FAIL under CI, because a skip there would be
    the system variant silently dropping out of the gate it exists to hold
    (the subset-guard shape: a green run reporting success about what it
    never reached). A build failure is a defect on any machine, never a
    skip: the code is broken, not the environment.

    functools.cache is what makes this once-per-session: pytest.skip raises,
    exceptions are not cached, so a later test on a machine where Go appears
    mid-session (it cannot) would simply retry.
    """
    go = _find_go()
    if go is None:
        reason = (
            f"the {collector} collector is Go, and no Go toolchain is on "
            "PATH or at /opt/homebrew/bin/go"
        )
        if os.environ.get("CI"):
            pytest.fail(f"{reason} — CI must build it, never skip it: "
                        "extend the workflow's setup-go step")
        pytest.skip(reason)
    out = Path(tempfile.mkdtemp(prefix="se-go-build-")) / f"se-collect-{collector}"
    proc = subprocess.run(
        [go, "build", "-o", str(out), GO_COLLECTORS[collector]],
        cwd=GO_DIR,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if proc.returncode != 0:
        pytest.fail(
            f"go build {GO_COLLECTORS[collector]} exited {proc.returncode}:\n"
            f"{proc.stderr[:2000]}"
        )
    return str(out)


def reference_command(variant) -> list[str]:
    """The command that IS the reference implementation for this variant."""
    collector = variant.meta["collector"]
    if collector in GO_COLLECTORS:
        return [go_collector_binary(collector)]
    from se_harness import replay

    return replay.reference_binary()
