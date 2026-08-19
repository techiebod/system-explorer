#!/usr/bin/env python3
"""Adversary fixture — inverse-property-enum: the reverse properties its author met.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. The units collection reports what a unit file
asks for and does not get, and it can afford to because systemd stores every
dependency together with its inverse: the walk runs BACKWARDS, from each name
systemd could not load, over the seven reverse properties that carry a
consequence — RequiredBy, RequisiteOf, BoundBy, UpheldBy, WantedBy, Before and
After.

Four of those seven are empty on every unit of every committed capture. An
ordinary distribution accumulates ordering references to software it no longer
ships and almost never a hard one; DESIGN 20's own measurement is zero hard
references on five hosts. So a port that read Before, After and WantedBy and
stopped is right about every machine the corpus holds — and blind in exactly
the inverted direction: it sees every reference that costs nothing and none of
the three that stop a start job before the unit runs.

Expected verdict: GREEN on every committed pair, forever — and that green is
the point, not a gap. This is DESIGN 20's third trap: replay equivalence proves
a collector right about the machines the corpus holds and nothing else, and a
property no capture populates is a property a port can simply not read. The
subject's RED lives in conformance/test_differential.py, where the
`systemd-hard-reference` operator gives the alphabetically first absent name a
RequiredBy and the reference publishes MissingRequirements on the unit that
wrote it.

**Why this delegates.** The units derivation is large — a tree walk, a
ListUnitFiles cross-check, two scope-name derivations — but none of that is the
artefact; the artefact is four keys missing from one map. A hand-rolled second
port would disagree about the tail ordering, about which mounts are
synthesised, about the empty-string Slice, and prove nothing about the defect.
So this IS the reference, run against payloads whose four unexercised reverse
properties have been emptied before the reference ever reads them: the output
is byte-for-byte what a genuinely enum-blind port emits, and the difference
from a correct port is therefore precisely the references it failed to walk. On
a capture where all four are already empty the rewrite is a no-op, which is
what makes the green on the committed corpus honest rather than an accident of
agreement.

The rewrite is on the PAYLOAD rather than on the output, unlike its
machine-scope sibling: these properties are read, not derived, so emptying them
at the source is exactly what a port that never looked at them had in hand —
and it also proves the point the operator makes, that the four are empty in
every committed capture and the rewrite therefore changes nothing there.
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

# The payload that carries a not-found unit's reverse properties. ListUnits
# says WHICH names systemd could not load and carries no dependency members at
# all, so there is nothing to be blind to there, and naming the payload keeps
# the rewrite from touching anything else.
BLIND_PAYLOAD = "unit-properties.json"

# The four this port never learned to read. Together they are the two
# consequence classes an operator acts on — a hard dependency that fails the
# start job, and the Upholds= half of the soft one — which is what makes the
# blindness worth a fixture rather than a footnote.
BLIND_PROPERTIES = ("RequiredBy", "RequisiteOf", "BoundBy", "UpheldBy")


def _blind(document: object) -> object:
    """Every unexercised reverse property emptied, which is what a port that
    never read them had in hand. The member stays present and becomes an empty
    list rather than being deleted: systemd answers GetAll with all of them, so
    a document missing one is not a document this interface produces."""
    if not isinstance(document, dict):
        return document
    for reply in document.values():
        if not isinstance(reply, dict):
            continue
        for values in reply.get("data") or []:
            if not isinstance(values, dict):
                continue
            for name in BLIND_PROPERTIES:
                if name in values:
                    values[name] = {"type": "as", "data": []}
    return document


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)

    # Copy the payloads into a private directory and empty the four properties
    # before the reference reads them. Every file is copied, not just the one
    # rewritten: the listing is where the unit rows come from and the slice
    # replies are where the cgroup tree comes from, and a directory missing
    # either is a broken capture rather than a blind port.
    with tempfile.TemporaryDirectory(prefix="se-hard-reference-blind-") as sealed:
        directory = Path(sealed)
        for payload in sorted(Path(replay_dir).iterdir()):
            if not payload.is_file() or payload.name.startswith("."):
                continue
            if payload.name == BLIND_PAYLOAD:
                document = _blind(json.loads(payload.read_text()))
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
