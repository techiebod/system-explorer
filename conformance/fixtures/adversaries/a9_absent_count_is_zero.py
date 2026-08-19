#!/usr/bin/env python3
"""Adversary fixture — absent-count-is-zero: an archive reported empty because
the API said nothing about it.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. adapters/paperless.py publishes DocumentCount
only when `documents_total` is an INT, so a paperless that does not answer the
member produces a row carrying no count at all. A port that reached for a
zero default instead emits `DocumentCount: 0` — which the rules judge CRITICAL,
because zero documents is the emptied-archive shape this subsystem was written
after two real incidents to catch.

That is the inversion worth having a fixture for. The incident was a real 38 -> 0
going unseen; this defect manufactures the same alarm out of an API that simply
never mentioned the number, on every paperless older than its collector.

Expected verdict: GREEN on every committed pair, forever — and the green is the
point. corpus/paperless/healthy answers `documents_total: 3`, so the member is
present, the default is never consulted, and reading it or defaulting it give
the same row. This is DESIGN 20's third trap: replay equivalence proves a
collector right about the machines the corpus holds and nothing else. The
subject's RED lives in conformance/test_differential.py, where the
`paperless-count-absent` operator removes the member.

**Why this delegates.** The paperless derivation is small but it is not the
artefact; the artefact is one fact defaulted instead of omitted. A hand-rolled
second port would disagree about the component-check tuple, the redaction of the
connection URLs, the row's name — and prove nothing about the defect. So this IS
the reference, run against a payload whose missing count has been filled in with
the zero before the reference ever reads it: the output is byte-for-byte what a
zero-defaulting port emits, and the difference from a correct port is therefore
precisely that one fact. On a capture that answers the member the fill is a
no-op, which is what makes the green honest rather than an accident.
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

# The inventory document. The status document carries the component checks and
# says nothing about how many documents exist, so there is nothing to default
# there, and naming the payload keeps the rewrite from touching anything else.
BLIND_PAYLOAD = "api-statistics.json"
BLIND_MEMBER = "documents_total"


def _default_to_zero(document: dict) -> dict:
    """The count defaulted to 0 when the API did not answer it.

    Which is what a port reaching for `raw.get("documents_total", 0)` had in
    hand. Filled rather than deleted-and-rebuilt, because a paperless that DOES
    answer must be left exactly as captured — that is what keeps this a no-op
    on the committed pair.
    """
    if isinstance(document, dict) and BLIND_MEMBER not in document:
        document[BLIND_MEMBER] = 0
    return document


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)

    # Every file is copied, not just the one rewritten: the status document is
    # where the component checks come from, and a directory missing it is a
    # broken capture rather than a blind port.
    with tempfile.TemporaryDirectory(prefix="se-absent-count-") as sealed:
        directory = Path(sealed)
        for payload in sorted(Path(replay_dir).iterdir()):
            if not payload.is_file() or payload.name.startswith("."):
                continue
            if payload.name == BLIND_PAYLOAD:
                document = _default_to_zero(json.loads(payload.read_text()))
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
