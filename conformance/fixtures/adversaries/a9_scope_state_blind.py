#!/usr/bin/env python3
"""Adversary fixture — scope-state blind: a scope only a RUNNING container gets.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. adapters/docker.py declares the closed set
_SCOPED_STATES — the container states that HAVE processes and therefore a live
systemd scope cgroup — and it has three members: running, restarting, paused. A
port whose rule is `state == "running"`, which is the simplification anybody
writes first, is right about every container in every committed capture and
wrong about the two an operator most wants to find.

ScopeUnit is not decoration. It is the only handle that turns a
`docker-6abfe5….scope` row in units/units — where the kernel's CPU, memory and
I/O pressure per cgroup is reported — back into a container name a person
recognises, because cgroupfs holds no name and dockerd's own scope Description
is the same hexadecimal id again. A restarting container is burning CPU right
now; a paused one is frozen with every process still resident. Dropping the
scope on exactly those two removes the edge at the moment somebody is following
it.

Expected verdict: GREEN on every committed pair, forever — and that green is
the point, not a gap. Every container in corpus/docker/healthy is `running` or
`exited`, and the two rules agree on both: running keeps its scope under either,
and exited keeps none under either. So the blindness changes nothing the replay
judge can see. This is DESIGN 20's third trap: replay equivalence proves a
collector right about the machines the corpus holds and nothing else, and a
branch no capture exercises is a branch a port can simply not have. The
subject's RED lives in conformance/test_differential.py, where the
`docker-restarting-container` and `docker-paused-container` operators mint the
two remaining members of the declared set and the reference names the scope this
port drops.

**Why this delegates.** The docker derivation is not the artefact — the port
mappings alone carry a dual-stack collapse, an exposed-port rendering and a
four-key sort, and a hand-rolled second port would disagree on all of it and
prove nothing about the defect. So this IS the reference, with one member
removed from the rows where the blindness lands.

And the removal is applied to the STREAM rather than to the payload, which is
where this fixture differs from its siblings. a8_l2cache_blind cuts a subtree
and a9_dpkg_status_blind rewrites a column, because in both the blindness is a
field never read. Here it is a DERIVATION: State is read, and read correctly,
for the State fact itself — a payload rewrite that changed the state to hide the
scope would change the State fact too, and the disagreement would then name two
members and be attributable to neither. Removing ScopeUnit from the rows a
running-only rule would leave it off is byte-for-byte what such a port emits,
and every other byte is the reference's own.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# fixtures/adversaries/ -> fixtures/ -> conformance/ -> the repository root.
REF = Path(__file__).resolve().parents[3] / "harness" / "bin" / "se-reference-collector"

# The one state this port believes has a scope, and the fact it drops
# everywhere else. Named once, so the blindness is a single character to widen
# and a reviewer can see exactly how narrow it is.
BLIND_STATE = "running"
BLIND_FACT = "ScopeUnit"
COLLECTION = "containers"


def _blind(record: dict) -> dict:
    """One row as a running-only port would have built it.

    Only the containers collection carries the fact, and only a row whose own
    State says otherwise loses it — a row with no State stated says nothing
    about whether it has processes, and this port's rule fails that test the
    same way it fails `paused`.
    """
    if record.get("record") != "object" or record.get("collection") != COLLECTION:
        return record
    facts = record.get("facts") or {}
    if BLIND_FACT in facts and facts.get("State") != BLIND_STATE:
        facts.pop(BLIND_FACT)
    return record


def main() -> None:
    if not os.environ.get("SE_REPLAY_DIR"):
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)

    proc = subprocess.run(
        [sys.executable, str(REF)],
        input=sys.stdin.read(),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(proc.returncode)

    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        before = json.dumps(record, sort_keys=True, separators=(",", ":"))
        after = json.dumps(_blind(record), sort_keys=True, separators=(",", ":"))
        # Untouched records go back out as the reference wrote them. The
        # re-serialisation is the same call the reference makes, so a record
        # this port did not change is byte-identical either way — but passing
        # the original line through keeps that true by construction rather than
        # by two dumps happening to agree.
        print(line if after == before else after)


if __name__ == "__main__":
    main()
