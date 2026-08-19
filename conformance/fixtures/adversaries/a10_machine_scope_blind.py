#!/usr/bin/env python3
"""Adversary fixture — machine-scope-blind: the one scope whose workload has a name.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. Container and VM runtimes both register their
workloads as transient scopes, and the two are not equally nameable: a docker
scope carries a random id and its Description is dockerd's own "libcontainer
container <the same id>", so the most a collector can honestly publish is a
join key. libvirt names its scope machine-qemu-<domid>-<domain> and systemd
escapes it, so the domain comes back in full — which is why that one, alone
among the transient scopes, mints a real cross-subsystem edge instead of a
hint.

A port whose author had only ever seen container scopes implements the id
derivation, sees no second case, and ships. Every row it emits is complete by
every test that author could run.

Expected verdict: GREEN on every committed pair, forever — and that green is
the point, not a gap. libvirt is installed on the guest the committed capture
came from and no domain was running, so no machine scope existed to name: the
reference emits no MachineName either and the two streams are identical. This
is DESIGN 20's third trap — replay equivalence proves a collector right about
the machines the corpus holds and nothing else, and a shape that needs a guest
to be UP is a shape a capture of a quiet host cannot hold. The subject's RED
lives in conformance/test_differential.py, where the `systemd-machine-scope`
operator brings a domain up and the reference reads the name this port drops.

**Why this delegates.** The units derivation is large and none of it is the
artefact; the artefact is one regex that was never written. A hand-rolled
second port would disagree about the tail ordering, about which mounts are
synthesised and about the empty-string Slice, and prove nothing about the
defect. So this IS the reference, with the machine name removed from every row
it emits — byte-for-byte what a port that never implemented it produces, and
therefore a difference that is precisely the fact it drops.

The removal is on the OUTPUT rather than on the payload, unlike its
hard-reference sibling: MachineName is derived from the scope's own NAME, which
is also the object's name, so censoring the input would delete the row rather
than the fact and the disagreement would be about the wrong thing.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# fixtures/adversaries/ -> fixtures/ -> conformance/ -> the repository root.
REF = Path(__file__).resolve().parents[3] / "harness" / "bin" / "se-reference-collector"

# The one fact this port never learned to build. Its container sibling stays:
# the defect is not "transient scopes are opaque" — this port names those
# perfectly — it is that the second runtime's naming was never met.
BLIND_FACT = "MachineName"


def _blind(line: str) -> str:
    """One stream record, with the machine name dropped from its facts."""
    record = json.loads(line)
    if record.get("record") != "object":
        return line
    facts = record.get("facts")
    if not isinstance(facts, dict) or BLIND_FACT not in facts:
        return line
    record["facts"] = {k: v for k, v in facts.items() if k != BLIND_FACT}
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


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
    # The commit counts are untouched on purpose: this port emits the same
    # objects and the same zero assertions, so its own accounting is consistent
    # and the truncation check cannot catch it. What is missing is inside a row,
    # which is exactly where a self-consistent stream hides a wrong answer.
    for line in proc.stdout.splitlines():
        if line.strip():
            print(_blind(line))


if __name__ == "__main__":
    main()
