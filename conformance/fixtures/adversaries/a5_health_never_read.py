#!/usr/bin/env python3
"""Adversary fixture — fleet round a5, defects S1–S5: health never read.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. Expected verdict: RED on storage/degraded,
forever — and GREEN on storage/healthy, which is the half that makes the red
mean something and is the whole reason the deferral stood for as long as it
did. A hardcoded-healthy collector is RIGHT about a healthy pool.

Round a5's collector carried these defects (`a5_hardcoded_healthy.py`,
S1–S5): the pool's State is the struct default "ONLINE", StatusMessage is
never read because the pools it was written against had none, Errors is 0 by
initialisation, UnhealthyVdevs and VdevsWithErrors are stubs returning empty
slices, and every member row's State and error counters are ONLINE and zero.
Every committed storage variant was healthy, so all of it was true, and the
defect was declared a deferral. corpus/storage/degraded closed it — a pool
faulted on purpose, on two different members, in two different ways — so the
deferral is now a fixture instead.

**The round's own collector cannot serve this purpose.** It predates the
tokenised `<collection>:<generation>` request line, so it publishes under the
collection name `pools:100` and every anchor fails with "no object named
host-2f5789 in 'pools'" — a red that would survive deleting
corpus/storage/degraded entirely, which is vacuity rather than a catch. Its
own row in the expectation table is bound to what actually kills it, the
stubbed envelope; this file is bound to the facts.

**Why this delegates.** The storage derivation is large — capacity properties,
scan stats, device alias resolution, the absent and unobservable channels —
and none of it is the artefact. A hand-rolled second port of all that would go
red on storage/degraded for a dozen porting reasons and the anchors would
prove nothing about the defect. So acquisition is delegated to the reference
and exactly the members S1–S5 name are overwritten with the struct defaults a
subject that never read them would carry. The difference between this subject
and a correct one is therefore precisely the defect, which is what makes the
green on storage/healthy meaningful: the overwrite is a no-op there, because
that pool really is online with no message, no errors and no unhealthy
members.

StatusMessage goes to the absent channel rather than to null: a fact value is
never null (DESIGN 19), and a subject that never reads a member reports it
absent — which on a healthy pool is what the reference itself emits, and on
the degraded one hides catalogue prose that names an unrecoverable error.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# fixtures/adversaries/ -> fixtures/ -> conformance/ -> the repository root.
REF = Path(__file__).resolve().parents[3] / "harness" / "bin" / "se-reference-collector"

# S1/S3/S4: the struct defaults, never overwritten from the status document.
DEFAULT_POOL = {"State": "ONLINE", "Errors": 0,
                "UnhealthyVdevs": [], "VdevsWithErrors": []}
# S5: the same, one level down, per member row.
DEFAULT_VDEV = {"State": "ONLINE", "ReadErrors": 0, "WriteErrors": 0,
                "ChecksumErrors": 0}
# S2: never read at all, so reported absent.
NEVER_READ = "StatusMessage"


def hardcode(record: dict) -> dict:
    facts = dict(record.get("facts") or {})
    for member, default in DEFAULT_POOL.items():
        if member in facts:
            facts[member] = default
    facts.pop(NEVER_READ, None)
    if isinstance(facts.get("Vdevs"), list):
        facts["Vdevs"] = [
            {**vdev, **{k: v for k, v in DEFAULT_VDEV.items() if k in vdev}}
            if isinstance(vdev, dict)
            else vdev
            for vdev in facts["Vdevs"]
        ]
    out = {**record, "facts": facts}
    out["absent"] = sorted({*(record.get("absent") or []), NEVER_READ})
    return out


def main() -> None:
    if os.environ.get("SE_REFERENCE_COLLECTOR") != "storage":
        print("this subject collects pools only", file=sys.stderr)
        raise SystemExit(2)
    proc = subprocess.run([sys.executable, str(REF)], input=sys.stdin.read(),
                          capture_output=True, text=True, env=dict(os.environ))
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(proc.returncode)
    for raw in proc.stdout.splitlines():
        if not raw.strip():
            continue
        record = json.loads(raw)
        # pools records only: the reference seam serves the R3b collections
        # too now, and this subject's declared wrongness is about pool
        # health — touching any other collection would make it wrong in a
        # second, undeclared way.
        if record.get("record") == "object" and record.get("collection") == "pools":
            record = hardcode(record)
        print(json.dumps(record, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
