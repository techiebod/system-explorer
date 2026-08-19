#!/usr/bin/env python3
"""Adversary fixture — gate 3: a nix port that tells the profile directory's
residents apart by SHAPE rather than by parsing the number.

Standing rule 6 (docs/PLAN.md §01). /nix/var/nix/profiles holds `system` and
`per-user` beside the numbered links, and the obvious filter is "starts with
system-, ends with -link". That is correct on every machine nix has touched
and wrong on any directory carrying a link nix did not make — and it is the
same defect as reading the directory positionally, since both answer with
whatever is there rather than with what parses as a generation.

This fixture rows every such entry, taking its number as 0 where the middle
does not parse. Expected verdict: RED under nix-profile-intruder.

It reads the listing payload directly rather than delegating that part,
because the extra row is one the reference never emits and there is nothing in
the reference's output to derive it from — which is precisely the shape of the
defect.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

REF = Path(__file__).resolve().parents[3] / "harness" / "bin" / "se-reference-collector"
PROFILES_PARENT = "/nix/var/nix"


def intruders():
    """Every profile entry this wrong filter accepts and no number parses."""
    directory = os.environ.get("SE_REPLAY_DIR")
    if not directory:
        return []
    try:
        listing = json.loads((Path(directory) / "listdir.json").read_text())
    except (OSError, ValueError):
        return []
    entries = (listing.get(PROFILES_PARENT) or {}).get("profiles") or []
    found = []
    for name in entries:
        if not (name.startswith("system-") and name.endswith("-link")):
            continue
        middle = name[len("system-"):-len("-link")]
        if not middle.isdigit():
            found.append(name)
    return found


def main():
    line = sys.stdin.read()
    proc = subprocess.run([sys.executable, str(REF)], input=line,
                          capture_output=True, text=True, env=dict(os.environ))
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(proc.returncode)
    records = [json.loads(raw) for raw in proc.stdout.splitlines() if raw.strip()]
    extra = intruders()
    out = []
    added = 0
    for record in records:
        if record.get("record") == "commit" and extra:
            record["objects"] = record.get("objects", 0) + len(extra)
        out.append(record)
    if extra:
        first = next((r for r in out if r.get("record") == "object"), None)
        if first is not None:
            index = out.index(first)
            for name in extra:
                row = json.loads(json.dumps(first))
                row["name"] = "0"
                row["facts"] = {"Current": False, "Booted": False, "Profile": False,
                                "Specialisations": [], "StorePath": name}
                row.pop("names", None)
                out.insert(index, row)
                added += 1
    for record in out:
        print(json.dumps(record, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
