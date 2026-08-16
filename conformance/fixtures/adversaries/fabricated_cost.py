#!/usr/bin/env python3
"""Adversary fixture — regression round: self-cost accounting that is fiction.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. This is the regression round's fabricost
probe, adopted with its lab paths removed. Expected verdict: GREEN — and the
green is a documented adjudication, not an oversight.

Delegates acquisition to the reference (so every FACT about the machine is
correct), then reports a fixed self-cost for every batch: cpu_ms and wall_ms
are constants it never measured — the shape of a first port that has not
wired getrusage() to the emitter yet and returns a placeholder. DESIGN 19
names self-reported cost as advisory BY CONSTRUCTION: a replayed collector
cannot measure real cost and a live one could misreport it, so the rules
bound cpu_ms and wall_ms without authenticating them, and the authoritative
cost of observation is the collator's own accounting of the slice, which no
collector writes. test_adversaries_stay_red.py asserts this fixture PASSES
the judge; if that assertion ever fails, cost has become authenticated and
DESIGN 19 must be updated in the same change.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

# fixtures/adversaries/ -> fixtures/ -> conformance/ -> the repository root.
REF = Path(__file__).resolve().parents[3] / "harness" / "bin" / "se-reference-collector"
CPU, WALL = 0.7, 1.3  # never measured; a struct-default placeholder


def main():
    line = sys.stdin.read()
    proc = subprocess.run([sys.executable, str(REF)], input=line,
                          capture_output=True, text=True, env=dict(os.environ))
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(proc.returncode)
    for raw in proc.stdout.splitlines():
        if not raw.strip():
            continue
        r = json.loads(raw)
        if r["record"] == "commit":
            r["cpu_ms"] = CPU
        elif r["record"] == "end":
            r["cpu_ms"] = CPU
            r["wall_ms"] = WALL
        print(json.dumps(r, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
