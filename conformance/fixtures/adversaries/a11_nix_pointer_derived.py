#!/usr/bin/env python3
"""Adversary fixture — gate 3: a nix port that derives one pointer from another.

Standing rule 6 (docs/PLAN.md §01): a passing-wrong subject joins the suite as
a permanent fixture. This one reports `Booted` as whatever `Current` says,
which is the simplification a port reaches for after noticing that the two
agree on every machine it has ever seen — including on every committed nix
variant, which is exactly why replay equivalence cannot see it.

What it costs when it is wrong is the question this collection answers.
`Booted` without `Current` means something was switched into since the machine
started; `Current` without `Booted` means something was switched away from. A
collector that derives one from the other says neither ever happens, on a host
where both are pending. Expected verdict: RED under nix-pointers-disagree.

Delegates acquisition to the reference so every other fact is correct, and
rewrites the one member: a fixture wrong about more than its class would
redden for the wrong reason.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

# fixtures/adversaries/ -> fixtures/ -> conformance/ -> the repository root.
REF = Path(__file__).resolve().parents[3] / "harness" / "bin" / "se-reference-collector"


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
        record = json.loads(raw)
        facts = record.get("facts")
        if record.get("record") == "object" and isinstance(facts, dict) \
                and "Current" in facts and "Booted" in facts:
            facts["Booted"] = facts["Current"]
        print(json.dumps(record, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
