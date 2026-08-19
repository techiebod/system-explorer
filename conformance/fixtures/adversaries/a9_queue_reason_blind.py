#!/usr/bin/env python3
"""Adversary fixture — stuck-reason-blind: the verdict published without its why.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. A servarr queue record carries the app's own
verdict on a download — `trackedDownloadStatus: warning` on the completed
transfer that will not import — and, beside it, the sentences that say WHY:
`statusMessages`, the app's per-item lines, and `errorMessage`. A port that
publishes the verdict and never reads the two message members leaves an
operator holding the word `warning` and nothing to act on, which is the same
distance from an answer as no row at all.

Expected verdict: GREEN on every committed pair, forever — and that green is the
point, not a gap. The fleet in corpus/servarr/healthy has never downloaded
anything: its queue holds no records at all, so there is nothing to explain and
both implementations emit the same empty collection. This is DESIGN 20's third
trap in its purest form — the two collections that answer this collector's
sharpest question are the two with nothing in them — and the subject's RED lives
in conformance/test_differential.py, where the `servarr-grab-in-flight` operator
puts one real acquisition through the fleet and the messages appear.

**Why this delegates.** The queue derivation is small but it is not the
artefact; the artefact is two members never read. A hand-rolled second port
would disagree about the id minting, the include-unknown walk, the fan-out
order and the App handle — and prove nothing about the defect. So this IS the
reference, run against payloads whose queue records have had their two message
members removed before the reference ever reads them: the output is
byte-for-byte what a genuinely reason-blind port emits, and the difference from
a correct port is therefore precisely the explanation it failed to publish.

**Why those two members and not the verdict itself.** `trackedDownloadStatus`
and `trackedDownloadState` are written to the facts dict UNCONDITIONALLY by
adapters/servarr.py, so a payload that removed them would make the reference
publish `null` fact values — refused by the contract's recursive fact_value and
by the replay judge, which would make the run a REFUSED verdict about the
reference rather than a disagreement about the port. The two message members
are conditional, so removing them is a blindness a lawful stream can express.
That constraint is the null-fact defect showing through, and it is reported
with the port rather than worked around silently.
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

# The payloads whose records carry an explanation, and the members this port
# never reads. A queue document is named for the instance and the path that
# answers it, so the blind rewrite is applied to whichever of them a variant
# staged — there is one queue per app that has one, and prowlarr has none.
BLIND_SUFFIX = "-queue.json"
BLIND_MEMBERS = ("statusMessages", "errorMessage")


def _blind_records(document: object) -> object:
    """Every queue record with its explanation removed, which is what a port
    that never read the two members had in hand. Records that carry neither are
    left exactly as they are: a download with nothing wrong with it has no
    explanation to lose, and rewriting one would make this fixture wrong about
    a second thing."""
    if not isinstance(document, dict):
        return document
    for record in document.get("records") or []:
        if not isinstance(record, dict):
            continue
        for member in BLIND_MEMBERS:
            record.pop(member, None)
    return document


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)

    # Copy the payloads into a private directory and rewrite the queue records
    # before the reference reads them. Every file is copied, not just the ones
    # rewritten: instances.json is what names the fleet at all, and a directory
    # missing it is a broken capture rather than a blind port.
    with tempfile.TemporaryDirectory(prefix="se-reason-blind-") as sealed:
        directory = Path(sealed)
        for payload in sorted(Path(replay_dir).iterdir()):
            if not payload.is_file() or payload.name.startswith("."):
                continue
            if payload.name.endswith(BLIND_SUFFIX):
                document = _blind_records(json.loads(payload.read_text()))
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
