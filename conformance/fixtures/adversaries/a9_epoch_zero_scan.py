#!/usr/bin/env python3
"""Adversary fixture — epoch-zero-timestamp: a scan date invented out of a zero.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. adapters/plex.py publishes ScannedAt and
UpdatedAt only for an int GREATER THAN ZERO, because Plex spells "this section
has never been scanned" as 0 rather than by omitting the member. A port that
converted the zero faithfully publishes 1970-01-01T00:00:00Z — a value that
sorts oldest, reads as catastrophically stale, and is not a reading at all.

Absence is the honest answer there, and the `> 0` gate exists to give it.

Expected verdict: GREEN on every committed pair, forever — and the green is the
point. Both sections in corpus/plex/healthy have been scanned, so no captured
`scannedAt` is zero, the gate never fires, and treating 0 as a date or refusing
to give the same rows. This is DESIGN 20's third trap: replay equivalence proves
a collector right about the machines the corpus holds and nothing else. The
subject's RED lives in conformance/test_differential.py, where the
`plex-never-scanned-section` operator sets the first section's scannedAt to 0.

**Why this delegates.** The plex derivation is small but it is not the artefact;
the artefact is a zero read as a timestamp. A hand-rolled second port would
disagree about the per-section count request, the sessions collection's
authoritative emptiness, the row's name — and prove nothing about the defect. So
this IS the reference, run against a payload whose zero has been nudged past the
gate before the reference ever reads it: the reference then publishes a scan
date in 1970, exactly as a zero-blind port does, and the difference from a
correct port is precisely that one fact appearing where silence belongs. On a
capture whose sections have all been scanned the nudge is a no-op, which is what
makes the green honest rather than an accident.

The nudge is to 1 rather than to 0, because the reference's own gate would
otherwise drop the value and the fixture would be indistinguishable from a
correct port. 1970-01-01T00:00:01Z and 1970-01-01T00:00:00Z are the same claim
about a library that has never been scanned, and the one this fixture can
actually make the reference say.
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

# The document that carries the section list. The per-section `all` documents
# carry only the item count, and the root document carries no timestamps a
# library row reads, so naming the payload keeps the rewrite from touching
# anything else.
BLIND_PAYLOAD = "library-sections.json"
BLIND_MEMBERS = ("scannedAt", "updatedAt")


def _zero_is_a_date(document: dict) -> dict:
    """A never-scanned section's zero pushed just past the reference's gate.

    Which is what a port with no `> 0` test had in hand: it reads the member,
    converts it, and publishes an epoch date. Only zeroes are touched, so a
    section that HAS been scanned keeps the reading it was captured with —
    that is what keeps this a no-op on the committed pair.
    """
    directory = (document.get("MediaContainer") or {}).get("Directory")
    if isinstance(directory, list):
        for section in directory:
            if not isinstance(section, dict):
                continue
            for member in BLIND_MEMBERS:
                if section.get(member) == 0:
                    section[member] = 1
    return document


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)

    # Every file is copied, not just the one rewritten: the per-section
    # documents are where ItemCount comes from and the sessions document is
    # read by two collections, so a directory missing either is a broken
    # capture rather than a blind port.
    with tempfile.TemporaryDirectory(prefix="se-epoch-zero-scan-") as sealed:
        directory = Path(sealed)
        for payload in sorted(Path(replay_dir).iterdir()):
            if not payload.is_file() or payload.name.startswith("."):
                continue
            if payload.name == BLIND_PAYLOAD:
                document = _zero_is_a_date(json.loads(payload.read_text()))
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
