#!/usr/bin/env python3
"""Adversary fixture — gate 3: a nix port that publishes an unrecorded release
as the empty string.

Standing rule 6 (docs/PLAN.md §01). A closure built without a `nixos-version`
file reads as "" through every reader here, and the honest answer is that this
generation does not record its release — so the fact is omitted. This fixture
publishes "" instead, which invents a release nothing has and leaves a
consumer unable to tell an unrecorded one from a blank one. It is the sixth
sighting of the same family: `x or None`, `raw.get(...)`, and now `value or ""`.

Invisible under plain replay, because every committed closure records one.
Expected verdict: RED under nix-release-unrecorded.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

REF = Path(__file__).resolve().parents[3] / "harness" / "bin" / "se-reference-collector"
RELEASE = "NixosVersion"


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
                and RELEASE not in facts:
            # The reference omitted it, so this closure records none; publish
            # the empty string the reader actually returned.
            facts[RELEASE] = ""
        print(json.dumps(record, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
