#!/usr/bin/env python3
"""Adversary fixture — receiptless-job-dropped: a registered job that vanishes
because it has never written anything.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. adapters/protection.py builds one row per job
in the staleness VERDICT, and reads the receipts only to fill that row in. A
port that reversed the two — treating the receipt as the row's source rather
than as its detail — drops any job that has never written one.

The row it drops is the most alarming this collection can carry. A registered
job with no receipt at all has never run: the verdict still states its state,
its basis, its age and its threshold, and the absence of Unit, LastFinishedAt,
ExitStatus and LastSuccessAt is the finding rather than a gap. A promise nothing
has ever kept disappearing from the collection is the estate's own
absence-as-health failure wearing a backup's clothes.

Expected verdict: GREEN on every committed pair, forever — and the green is the
point. Every job in corpus/protection/healthy has at least one readable receipt
(`runtime-state` has a `last` and no `last-success`, which is still one), so
reading the verdict first and reading the receipts first give the same seven
rows. This is DESIGN 20's third trap: replay equivalence proves a collector
right about the machines the corpus holds and nothing else. The subject's RED
lives in conformance/test_differential.py, where the
`protection-receiptless-job` operator empties both of that job's receipts.

**Why this delegates.** The protection derivation is large, and none of it is
the artefact; the artefact is one row that does not appear. A hand-rolled second
port would disagree about the receipt-outranks-the-verdict rule, the
ownerHost scoping, the five states — and prove nothing about the defect. So this
IS the reference, run against a payload whose receiptless jobs have been struck
from the verdict before the reference ever reads it: the reference then emits
the same rows a receipt-first port emits, and the difference from a correct port
is precisely the row that is missing. On a capture where every job has written
something the strike is a no-op, which is what makes the green honest rather
than an accident.
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

STATUS_PAYLOAD = "var-lib-homelab-protection-status.json.json"
RECEIPT_PREFIX = "var-lib-homelab-protection-receipts-"


def _has_a_receipt(replay_dir: Path, job: str) -> bool:
    """Whether either of a job's two receipts holds a document.

    Every payload here is the (document, why-not) PAIR the adapter's _load
    returns, so a receipt that is absent is `[null, null]` and one that will not
    parse is `[null, "reason"]`. Only the first member is asked about: a receipt
    that exists and is unreadable IS something the job wrote, and a port that
    dropped the row for it would be making a different mistake than this one.
    """
    for suffix in ("last", "last-success"):
        payload = replay_dir / f"{RECEIPT_PREFIX}{job}.{suffix}.json.json"
        if not payload.is_file():
            continue
        try:
            pair = json.loads(payload.read_text())
        except ValueError:
            continue
        if isinstance(pair, list) and pair and pair[0] is not None:
            return True
    return False


def _strike_receiptless_jobs(replay_dir: Path, document: list) -> list:
    """Every job with no receipt at all removed from the verdict's job list.

    Which is what a receipt-first port produces: no receipt, no row. The
    document is the pair, so the verdict itself is member 0.
    """
    if not (isinstance(document, list) and document and isinstance(document[0], dict)):
        return document
    jobs = document[0].get("jobs")
    if not isinstance(jobs, list):
        return document
    document[0]["jobs"] = [
        row for row in jobs
        if not isinstance(row, dict)
        or not row.get("job")
        or _has_a_receipt(replay_dir, str(row["job"]))
    ]
    return document


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)
    source = Path(replay_dir)

    # Every file is copied, not just the one rewritten: the manifest is what
    # the targets and destinations collections are built from, and a directory
    # missing it is a broken capture rather than a blind port.
    with tempfile.TemporaryDirectory(prefix="se-receiptless-job-") as sealed:
        directory = Path(sealed)
        for payload in sorted(source.iterdir()):
            if not payload.is_file() or payload.name.startswith("."):
                continue
            if payload.name == STATUS_PAYLOAD:
                document = _strike_receiptless_jobs(
                    source, json.loads(payload.read_text()))
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
