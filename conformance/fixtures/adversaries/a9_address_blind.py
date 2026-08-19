#!/usr/bin/env python3
"""Adversary fixture — address-blind: a domain row that never answers "where".

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. This one is a vms port whose author never
implemented the address fact. Everything else about the row is right — state,
memory, vCPUs, the two flags, the host taps — and the one question an operator
opens the collection to ask ("which guest is 192.168.122.50?") is answered by
nothing at all.

It is a real shape rather than an invented one. `_domains_raw()` carries the
addresses in a member of its own, `ips_by_mac`, populated by a second libvirt
call that is skipped entirely for a guest that is not running — so a port
written against a host whose guests happened to be stopped never meets the
member, and the row it emits is complete by every test its author could run.

Expected verdict: GREEN on every committed pair, forever — and that green is
the point, not a gap. The captured domain is shut off, so the reference emits
no address fact either: a stopped guest has no address because it is off, and
both implementations omit the fact. This is DESIGN 20's third trap — replay
equivalence proves a collector right about the machines the corpus holds and
nothing else. The subject's RED lives in conformance/test_differential.py,
where the `libvirt-running-guest` operator brings the guest up with a lease
and the reference reads the address this port drops.

**Why this delegates.** The vms derivation is small but it is not the artefact;
the artefact is one missing fact. A hand-rolled second port would disagree on
the tap walk, on the summary subset and on the number spellings for a dozen
porting reasons and prove nothing about the defect. So this IS the reference,
with the address members removed from every row it emits — byte-for-byte what
a port that never implemented them produces, and therefore a difference that
is precisely the fact it drops. On a stopped guest the removal is a no-op,
which is what makes the green on the committed corpus honest rather than an
accident of agreement.

The removal is on the OUTPUT rather than on the payload, unlike its l2cache
sibling: `IPAddresses` is derived from a member the reference reads directly,
so censoring the input would make the reference emit the OTHER arm of rule 7 —
a null value with a reason beside it — which is a different wrong answer and
not this port's.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# fixtures/adversaries/ -> fixtures/ -> conformance/ -> the repository root.
REF = Path(__file__).resolve().parents[3] / "harness" / "bin" / "se-reference-collector"

# The row members this port never learned to build. Both, because they are one
# answer: emitting the reason without the value would be a port that says it
# cannot see an address it never looked for.
BLIND_FACTS = ("IPAddresses", "IPAddressesUnobservable")


def _blind(line: str) -> str:
    """One stream record, with the address members dropped from its facts."""
    record = json.loads(line)
    if record.get("record") != "object":
        return line
    facts = record.get("facts")
    if not isinstance(facts, dict) or not any(f in facts for f in BLIND_FACTS):
        return line
    record["facts"] = {k: v for k, v in facts.items() if k not in BLIND_FACTS}
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
    # objects, the same assertions and the same unobservables, so its own
    # accounting is consistent and the truncation check cannot catch it. What
    # is missing is inside a row, which is exactly where a self-consistent
    # stream hides a wrong answer.
    for line in proc.stdout.splitlines():
        if line.strip():
            print(_blind(line))


if __name__ == "__main__":
    main()
