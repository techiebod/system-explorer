#!/usr/bin/env python3
"""Adversary fixture — oom-counter-blind: an OOM event reported as an OOM kill.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. `memory.events` keeps two counters that read
almost the same and mean entirely different things — `oom` is how many times a
workload hit its limit and had to reclaim or block, `oom_kill` is how many of
its processes the kernel then killed — and adapters/resources.py lifts them
separately, by name, into MemoryOomEvents and MemoryOomKills. A port that keyed
the row on the first record whose name starts `oom`, or that took the two for
one reading, publishes killings that never happened. It is wrong in the
direction that matters: MemoryOomKills is the only trace an OOM kill leaves —
systemd restarts the service, the unit returns to active, and every other fact
on the row goes back to looking healthy.

Expected verdict: GREEN on every committed pair, forever — and that green is the
point, not a gap. Every one of the 73 memory.events documents in
corpus/resources/healthy reads `oom 0` beside `oom_kill 0`, because the guest
was at rest, so lifting either under the other's name changes nothing the replay
judge can see. This is DESIGN 20's third trap: replay equivalence proves a
collector right about the machines the corpus holds and nothing else, and a
distinction no capture draws is a distinction a port can simply not make. The
subject's RED lives in conformance/test_differential.py, where the
`cgroup-oom-kill` operator gives one workload three OOM events and one kill and
the two stop being the same number.

**Why this delegates.** The resources derivation is large — a walk, a collision
rule, a delegation boundary, a stall attribution — but none of it is the
artefact; the artefact is two counters one name apart. A hand-rolled second port
would disagree about the walk order, the remainder, the attribution slack, and
prove nothing about the defect. So this IS the reference, run against payloads
whose `oom_kill` record has been rewritten to its `oom` twin before the
reference ever reads them: the output is byte-for-byte what a genuinely
oom-blind port emits, and the difference from a correct port is therefore
precisely the two counters it failed to tell apart. On a capture where both are
already zero the rewrite is a no-op, which is what makes the green on the
committed corpus honest rather than an accident of agreement.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# fixtures/adversaries/ -> fixtures/ -> conformance/ -> the repository root.
REF = Path(__file__).resolve().parents[3] / "harness" / "bin" / "se-reference-collector"

# The transcription commits one payload per path the collector read, so the
# documents to rewrite are named by their SUFFIX rather than listed: every
# cgroup on the machine has a memory.events, and a fixture that rewrote one
# named cgroup's would be blind about one workload rather than about a rule.
BLIND_SUFFIX = "-memory.events.txt"
EVENTS = "oom"
KILLS = "oom_kill"


def _kills_from_events(text: str) -> str:
    """`oom_kill` rewritten to the value of its `oom` twin, which is what a
    port that could not tell them apart had in hand. A document carrying no
    `oom` record is left exactly as it is: there is nothing there to have been
    read for the other."""
    values = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2:
            values[fields[0]] = fields[1]
    if EVENTS not in values:
        return text
    out = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[0] == KILLS:
            line = f"{KILLS} {values[EVENTS]}"
        out.append(line)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)

    # Copy the payloads into a private directory and rewrite the counters before
    # the reference reads them. Every file is copied, not just the ones
    # rewritten: the walk transcription is what tells the seam which cgroups
    # exist at all, and a directory missing any path the walk names is a broken
    # capture rather than a blind port.
    with tempfile.TemporaryDirectory(prefix="se-oom-blind-") as sealed:
        directory = Path(sealed)
        for payload in sorted(Path(replay_dir).iterdir()):
            if not payload.is_file() or payload.name.startswith("."):
                continue
            if payload.name.endswith(BLIND_SUFFIX):
                (directory / payload.name).write_text(
                    _kills_from_events(payload.read_text())
                )
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
