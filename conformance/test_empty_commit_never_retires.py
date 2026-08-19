"""An empty commit is not available to a collector that could not read.

RULED 2026-08-19 (DESIGN appendix C, "a configuration gap must never retire an
object"): `absent` and an empty commit are both authoritative-empty and both
RETIRE, so neither may stand for a reading that did not happen.

This pins the case the ruling was first written against, because it is the one
that is silent in the retiring direction and therefore invisible without a test.
`packages._items` dispatches on the detected manager through three branches —
nix, dpkg, rpm — and fell through all of them returning `[]` for anything else.
`acquire` handed that on as a successful reading, so a host whose manager this
code does not recognise had its ENTIRE package inventory retired on the strength
of a word nobody understood, with no decline record anywhere to say so.

Measured both ways on 2026-08-19 against a staged `pacman`:

    before   exit 0, records: begin, commit objects:0, end
    after    exit 2, records: begin

The seam is what makes this testable at all. `manager.json` is a captured
payload, so a manager nobody has can be staged without one being installed —
and the live host is never touched, which is the whole point of the replay
shim.

STATED COVERAGE: this checks the REFERENCE, through the replay shim. The Go
port answers the same condition by exiting non-zero and is covered by its own
suite; what neither can check is a manager that this collector reads WRONGLY
rather than not at all, which no staging reaches because it would need a real
`pacman` database to disagree about.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SHIM = REPO / "harness" / "bin" / "se-reference-collector"


def _run(manager: str, tmp_path: Path) -> tuple[int, list[dict]]:
    """Replay `packages` against a staged manager, returning (exit, records)."""
    (tmp_path / "manager.json").write_text(json.dumps(manager))
    env = dict(os.environ)
    env["SE_REPLAY_DIR"] = str(tmp_path)
    env["SE_REFERENCE_COLLECTOR"] = "packages"
    env["PYTHONPATH"] = os.pathsep.join(
        [str(REPO / "src"), str(REPO / "harness"), env.get("PYTHONPATH", "")]
    )
    proc = subprocess.run(
        [sys.executable, str(SHIM)],
        input="collect packages:1\n",
        capture_output=True, text=True, env=env, timeout=120,
    )
    records = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    return proc.returncode, records


def test_an_unreadable_manager_commits_nothing(tmp_path: Path) -> None:
    """The retiring half, which is the dangerous one.

    A commit — of any size, including zero — claims authority over the
    collection. Nothing was established here, so there is no authority to
    claim, and a zero commit would delete every package row a previous batch
    published.
    """
    code, records = _run("pacman", tmp_path)
    kinds = [r.get("record") for r in records]
    assert "commit" not in kinds, (
        "a manager this collector cannot read produced a COMMIT, which is "
        f"authoritative-empty and retires the whole inventory: {records}"
    )
    assert code != 0, (
        "exit 0 says the collector ran and established something; it did not, "
        f"and 'I could not run' is the honest answer. Records: {records}"
    )


def test_the_check_can_see_a_manager_it_does_read(tmp_path: Path) -> None:
    """Anti-vacuity: the staging mechanism must be able to reach a reading.

    Without this, a `packages` collector that failed on EVERY manager would
    satisfy the test above, and the guard would be asserting that the collector
    is broken rather than that it is honest.
    """
    # The payload shape is the corpus's own — rows of
    # [name, version, architecture, status] — read off
    # corpus/packages/healthy rather than invented here, because a staging this
    # test made up could stop matching the seam without either side noticing.
    (tmp_path / "dpkg.json").write_text(json.dumps([
        ["example", "1.0", "amd64", "installed"],
    ]))
    code, records = _run("dpkg", tmp_path)
    assert code == 0, f"a manager this collector reads must run: {records}"
    commits = [r for r in records if r.get("record") == "commit"]
    assert commits and commits[0].get("objects", 0) >= 1, (
        "the staged dpkg database must produce a reading, or the test above "
        f"passes over a collector that cannot read anything: {records}"
    )


@pytest.mark.parametrize("manager", ["pacman", "apk", "portage", ""])
def test_no_unreadable_manager_slips_through(manager: str, tmp_path: Path) -> None:
    """Deny-by-default over the shape rather than over one spelling.

    `pacman` is the one the queue item named, and naming only it would leave
    the next unrecognised manager to be found the same way — by somebody
    noticing an inventory had silently emptied.
    """
    _, records = _run(manager, tmp_path)
    assert "commit" not in [r.get("record") for r in records], (
        f"manager {manager!r} committed rather than refusing: {records}"
    )
