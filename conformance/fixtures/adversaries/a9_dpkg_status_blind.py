#!/usr/bin/env python3
"""Adversary fixture — status-blind: every row dpkg remembers, reported installed.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. `dpkg-query -W` answers for packages that were
REMOVED with their configuration left behind — `rc` in `dpkg -l`,
`config-files` in the status field adapters/packages.py asks for by name — and
"which packages are installed" is not "which packages dpkg has a record of". A
port that reads the first three fields and never looks at the fourth publishes
software the machine does not have, which is the direction that matters: an
operator reading an inventory acts on what is in it.

Expected verdict: GREEN on every committed pair, forever — and that green is the
point, not a gap. Every one of the 963 rows in corpus/packages/healthy is
`installed`, so ignoring the status column changes nothing the replay judge can
see. This is DESIGN 20's third trap: replay equivalence proves a collector right
about the machines the corpus holds and nothing else, and a filter that no
capture exercises is a filter a port can simply not have. The subject's RED
lives in conformance/test_differential.py, where the `dpkg-removed-config-row`
operator inserts an `rc ifupdown` row into the seed and the reference drops it.

**Why this delegates.** The packages derivation is small but it is not the
artefact; the artefact is one column never read. A hand-rolled second port would
disagree on sort order, on the absent channel, on the Manager fact, and prove
nothing about the defect. So this IS the reference, run against a payload whose
status column has been rewritten to `installed` before the reference ever reads
it: the output is byte-for-byte what a genuinely status-blind port emits — a
fully consistent stream that simply keeps every row — and the difference from a
correct port is therefore precisely the rows it should have dropped. On a
capture where every row is already installed the rewrite is a no-op, which is
what makes the green on the committed corpus honest rather than an accident of
agreement.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# fixtures/adversaries/ -> fixtures/ -> conformance/ -> the repository root.
REF = Path(__file__).resolve().parents[3] / "harness" / "bin" / "se-reference-collector"

# The payload whose rows carry a status, and the field this port never reads.
# rpm reports only installed packages and its format string asks for no status
# at all, so there is nothing to be blind to there — the blindness is dpkg's
# alone, and naming the payload keeps the rewrite from touching anything else.
BLIND_PAYLOAD = "dpkg.json"
STATUS_FIELD = 3
INSTALLED = "installed"


def _blind_rows(document: object) -> object:
    """Every row's status rewritten to `installed`, which is what a port that
    never read the column had in hand. Rows too short to carry the field are
    left alone: a short row is missing the status, not claiming one."""
    if not isinstance(document, list):
        return document
    for row in document:
        if isinstance(row, list) and len(row) > STATUS_FIELD:
            row[STATUS_FIELD] = INSTALLED
    return document


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)

    # Copy the payloads into a private directory and rewrite the status column
    # before the reference reads it. Every file is copied, not just the one
    # rewritten: manager.json is what tells the seam which interface answered,
    # and a directory missing it is a broken capture rather than a blind port.
    with tempfile.TemporaryDirectory(prefix="se-status-blind-") as sealed:
        directory = Path(sealed)
        for payload in sorted(Path(replay_dir).iterdir()):
            if not payload.is_file() or payload.name.startswith("."):
                continue
            if payload.name == BLIND_PAYLOAD:
                document = _blind_rows(json.loads(payload.read_text()))
                (directory / payload.name).write_text(json.dumps(document, indent=1))
            else:
                shutil.copy(payload, directory / payload.name)
        env = dict(os.environ)
        env["SE_REPLAY_DIR"] = str(directory)
        proc = subprocess.run(
            [sys.executable, str(REF)],
            input=sys.stdin.read(),
            capture_output=True,
            text=True,
            env=env,
        )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(proc.returncode)
    sys.stdout.write(proc.stdout)


if __name__ == "__main__":
    main()
