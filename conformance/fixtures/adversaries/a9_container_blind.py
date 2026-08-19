#!/usr/bin/env python3
"""Adversary fixture — container-blind: a log line that cannot be attributed to
what wrote it.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. systemd's journal carries `CONTAINER_NAME` on
every entry a container runtime forwards, and adapters/logs.py publishes it as
`Container` — the fact that answers "which of the twenty-three things on this
host said that". A port that never implemented it emits a row that names a
message, a priority and a time, and cannot say what wrote it.

Expected verdict: GREEN on every committed pair, forever — and the green is the
point. The guest behind corpus/logs/healthy ran no containers, so no captured
entry carries the member, and reading it or never reading it give the same
hundred rows. This is DESIGN 20's third trap: replay equivalence proves a
collector right about the machines the corpus holds and nothing else, and a
journal from a host running nothing is exactly the machine on which this
blindness is invisible. The subject's RED lives in
conformance/test_differential.py, where the `logs-containerised-entry` operator
puts one containerised line into the page.

**Why this delegates.** The logs derivation is small but it is not the artefact;
the artefact is one fact never lifted. A hand-rolled second port would disagree
about the priority string-to-integer conversion, the microsecond-to-ISO stamp,
the page-scoped repeat counters, the row's name — and prove nothing about the
defect. So this IS the reference, run against a page whose container members
have been stripped before the reference ever reads them: the output is
byte-for-byte what a container-blind port emits, and the difference from a
correct port is therefore precisely that one fact. On a page from a host running
no containers the stripping is a no-op, which is what makes the green on the
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

# The journal page. Its name is the seam's own addressing rather than a label
# somebody chose: _run_journalctl is dispatched on its ARGUMENT, so the document
# is keyed on slug(["-r", "-n", "100"]).
BLIND_PAYLOAD = "r---n--100.json"
BLIND_MEMBER = "CONTAINER_NAME"


def _strip_container(page: list) -> list:
    """The container member removed from every entry that carries one.

    Which is what a port that never implemented the fact had in hand. Removed
    rather than blanked: the journal OMITS the member on a line no runtime
    forwarded, so an empty string would be a specimen of a document systemd
    does not produce — the opposite of bazarr's empty-string case, and the
    reason each fixture states which spelling its interface uses.
    """
    if isinstance(page, list):
        for entry in page:
            if isinstance(entry, dict):
                entry.pop(BLIND_MEMBER, None)
    return page


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)

    with tempfile.TemporaryDirectory(prefix="se-container-blind-") as sealed:
        directory = Path(sealed)
        for payload in sorted(Path(replay_dir).iterdir()):
            if not payload.is_file() or payload.name.startswith("."):
                continue
            if payload.name == BLIND_PAYLOAD:
                page = _strip_container(json.loads(payload.read_text()))
                (directory / payload.name).write_text(json.dumps(page))
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
