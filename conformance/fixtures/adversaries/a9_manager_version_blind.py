#!/usr/bin/env python3
"""Adversary fixture — manager-version-blind: an instance row that never says what it is wired to.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. `/api/system/status` reports the sonarr and
radarr this bazarr fetches its metadata from, and adapters/bazarr.py lifts each
one only when it is TRUTHY — because the interface spells "wired to nothing" as
an empty string rather than as a missing member. A port that never implemented
either fact publishes an instance row that answers only "which release is this",
and never "which managers does it serve", which is the question a subtitle
manager exists to have an answer to.

Expected verdict: GREEN on every committed pair, forever — and that green is the
point, not a gap. The instance in corpus/bazarr/healthy is wired to NEITHER
manager, so both members are present and empty and the reference drops both:
reading them or not reading them gives the same row. This is DESIGN 20's third
trap — replay equivalence proves a collector right about the machines the corpus
holds and nothing else, and a distinction no capture draws is a distinction a
port can simply not make. The subject's RED lives in
conformance/test_differential.py, where the `bazarr-wired-managers` operator
wires this instance to both and the two members stop being empty.

**Why this delegates.** The bazarr derivation is small but it is not the
artefact; the artefact is two facts never lifted. A hand-rolled second port
would disagree about the health fold, the bounding of an issue sentence, the
row's name — and prove nothing about the defect. So this IS the reference, run
against a payload whose two manager members have been blanked before the
reference ever reads it: the output is byte-for-byte what a genuinely
manager-blind port emits, and the difference from a correct port is therefore
precisely the two facts it failed to lift. On a capture wired to neither manager
the blanking is a no-op, which is what makes the green on the committed corpus
honest rather than an accident of agreement.
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

# The document that carries the wiring. The health document says nothing about
# either manager — it is the app's complaints about itself — so there is nothing
# to be blind to there, and naming the payload keeps the rewrite from touching
# anything else.
BLIND_PAYLOAD = "api-system-status.json"
BLIND_MEMBERS = ("sonarr_version", "radarr_version")


def _blank_managers(document: dict) -> dict:
    """Both manager members set to the empty string the interface uses.

    Which is what a port that never implemented the facts had in hand: the
    reference's gate is truthiness, so an empty member and an unread one
    produce the same row. Blanked rather than deleted, because an unwired
    bazarr answers with the members PRESENT — a deletion would make this
    fixture a specimen of a document bazarr does not produce, and it would
    stop being a no-op on the committed capture.
    """
    data = document.get("data")
    if isinstance(data, dict):
        for member in BLIND_MEMBERS:
            if member in data:
                data[member] = ""
    return document


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)

    # Copy the payloads into a private directory and blank the members before
    # the reference reads them. Every file is copied, not just the one
    # rewritten: the health document is what HealthIssues comes from, and a
    # directory missing it is a broken capture rather than a blind port.
    with tempfile.TemporaryDirectory(prefix="se-manager-blind-") as sealed:
        directory = Path(sealed)
        for payload in sorted(Path(replay_dir).iterdir()):
            if not payload.is_file() or payload.name.startswith("."):
                continue
            if payload.name == BLIND_PAYLOAD:
                document = _blank_managers(json.loads(payload.read_text()))
                (directory / payload.name).write_text(json.dumps(document))
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
