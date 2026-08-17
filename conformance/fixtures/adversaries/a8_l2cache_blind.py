#!/usr/bin/env python3
"""Adversary fixture — group-enum blind: the l2cache group dropped on the floor.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. This is the storage twin of the family-enum
port. `zpool status -j` groups a pool's members under named buckets — logs,
l2cache, spares (storage.py's ZFS_GROUP_VDEVS) — and a port that enumerates the
buckets it has met drops the ones it has not. This one is blind to l2cache: a
cache device holds no pool data, so a pool that has one still reads healthy
with the whole group missing, which is exactly why the blindness survives a
review that only looks at pool state.

Expected verdict: GREEN on every committed pair, forever — and that green is
the point, not a gap. Every captured pool is cache-less (no committed
`zpool status -j` carries an l2cache group), so dropping that group changes
nothing the replay judge can see. This is DESIGN 20's third trap: replay
equivalence proves a collector right about the machines the corpus holds and
nothing else, and a blind spot that falls outside the captured shapes is green
by construction. The subject's RED lives in conformance/test_differential.py,
where the `zpool-cache-vdev` operator mints an l2cache group into the seed and
the reference reads the cache disk this port drops — a class the closure guard
now proves is minted by an operator rather than left an orphan of the declared
ZFS_GROUP_VDEVS set.

**Why this delegates.** The storage derivation is large — capacity properties,
scan stats, device alias resolution, the absent and unobservable channels — and
none of it is the artefact; the artefact is one missing group. A hand-rolled
second port would go red on the mutated pool for a dozen porting reasons and
prove nothing about the defect. So this IS the reference, run against a payload
with the l2cache subtree cut out before the reference ever reads it: the output
is byte-for-byte what a genuinely l2cache-blind port emits — a fully consistent
stream that simply never mentions the cache device — and the difference from a
correct port is therefore precisely the group it drops. On a cache-less payload
the cut is a no-op, which is what makes the green on the committed corpus honest
rather than an accident of agreement.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# fixtures/adversaries/ -> fixtures/ -> conformance/ -> the repository root.
REF = Path(__file__).resolve().parents[3] / "harness" / "bin" / "se-reference-collector"

# The declared group this port is blind to. Named once; the cut is keyed on it,
# and on a payload that has no such subtree the cut removes nothing.
BLIND_GROUP = "l2cache"


def _strip_group(node: object) -> None:
    """Remove the blind group's subtree wherever it sits as a vdev key, to any
    depth — a group vdev is a named child in the `vdevs` map, so deleting the
    key is what a port that never enumerated the group would have read."""
    if isinstance(node, dict):
        node.pop(BLIND_GROUP, None)
        for value in node.values():
            _strip_group(value)
    elif isinstance(node, list):
        for value in node:
            _strip_group(value)


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)

    # Copy the payloads into a private directory and cut the l2cache subtree out
    # of the status document before the reference reads it. The reference is
    # then pointed at the censored copy, so it derives from a pool this port
    # never saw the cache group of — the faithful shape of the blindness.
    with tempfile.TemporaryDirectory(prefix="se-l2cache-blind-") as sealed:
        directory = Path(sealed)
        for payload in sorted(Path(replay_dir).glob("*.json")):
            document = json.loads(payload.read_text())
            _strip_group(document)
            (directory / payload.name).write_text(json.dumps(document, indent=1))
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
