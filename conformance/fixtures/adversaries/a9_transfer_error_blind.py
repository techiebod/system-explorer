#!/usr/bin/env python3
"""Adversary fixture — error-text-blind: the error code without the client's words.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. adapters/downloaders.py publishes a transfer's
`Error` code unconditionally and its `ErrorString` only where the code is
non-zero AND the client stored a line beside it — and ErrorString is the only
fact in this subsystem that says WHAT went wrong. A port that implemented the
code and stopped there, or that treated the empty-string member as the whole of
the error channel, publishes rows that say a transfer is failing and never say
why. That is the invisible middle this collector was built to close, reopened
one fact in.

Expected verdict: GREEN on every committed pair, forever — and that green is the
point, not a gap. Every torrent in corpus/downloaders/healthy reports `error: 0`
with `errorString: ""`, because the staged torrents announce to a tracker host
that does not resolve and therefore never get a reply to be refused by. So the
reference's own guard never fires, the fact is absent from both implementations'
rows, and there is nothing for the judge to compare. This is DESIGN 20's third
trap: replay equivalence proves a collector right about the machines the corpus
holds and nothing else, and a distinction no capture draws is a distinction a
port can simply not make. The subject's RED lives in
conformance/test_differential.py, where the `transmission-errored-transfer`
operator gives the first torrent a tracker that answers 404 and the two stop
agreeing.

**Why this delegates.** The downloaders derivation is not small — two clients,
two vocabularies, a percentage, three unit conversions — and none of it is the
artefact. The artefact is one arm never taken. A hand-rolled second port would
disagree about the megabyte floats, the disk conversion, the status enum's
spelling, and prove nothing about the defect. So this IS the reference, run
against a payload whose torrents' `errorString` members have been blanked before
the reference ever reads them: the output is byte-for-byte what an
error-text-blind port emits, and the difference from a correct port is therefore
precisely the line it failed to publish. On a capture where every errorString is
already empty the rewrite is a no-op, which is what makes the green on the
committed corpus honest rather than an accident of agreement.
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

# The one document that carries a transfer's error channel. sabnzbd's queue
# states a slot's status and no error line at all — there is nothing to be blind
# to there — so naming the payload keeps the rewrite from touching anything
# else, and keeps this fixture wrong about exactly one thing.
BLIND_PAYLOAD = "torrent-get.json"


def _without_error_text(document: object) -> object:
    """Every torrent's `errorString` emptied, and nothing else touched.

    Emptied rather than deleted, because that is what the defect looks like
    from the inside: the member is present on every torrent transmission
    reports, and a port that reads the code and never the text produces exactly
    the row the reference produces when the text is blank. Deleting it would
    also exercise the missing-member path, which is a second defect.
    """
    if not isinstance(document, dict):
        return document
    for torrent in document.get("torrents") or []:
        if isinstance(torrent, dict) and "errorString" in torrent:
            torrent["errorString"] = ""
    return document


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)

    # Copy the payloads into a private directory and blank the error lines
    # before the reference reads them. Every file is copied, not just the one
    # rewritten: the client rows come from session-get, session-stats and the
    # sabnzbd queue, and a directory missing any of them is a broken capture
    # rather than a blind port.
    with tempfile.TemporaryDirectory(prefix="se-error-blind-") as sealed:
        directory = Path(sealed)
        for payload in sorted(Path(replay_dir).iterdir()):
            if not payload.is_file() or payload.name.startswith("."):
                continue
            if payload.name == BLIND_PAYLOAD:
                document = _without_error_text(json.loads(payload.read_text()))
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
