#!/usr/bin/env python3
"""Adversary fixture — thread-share-blind: one thread's counters, reported as the resolver's.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. `unbound-control stats_noreset` reports every
counter TWICE — once per thread as `threadN.…`, once summed as `total.…` — and
adapters/unbound.py keys its table on the whole record name, `total.` prefix
included. A port that reads `thread0.` outright, or that keys a record on its
tail and keeps the first match it meets, publishes one thread's share of the
traffic wearing the whole resolver's name. It is wrong in the direction that
matters: it under-reports the load of the busiest hosts, because more than one
thread is what a busy resolver is configured with.

Expected verdict: GREEN on every committed pair, forever — and that green is the
point, not a gap. The resolver in corpus/unbound/healthy runs ONE thread, so
`thread0.num.queries` and `total.num.queries` are the same number on every line
of the payload and reading either gives the same row. This is DESIGN 20's third
trap: replay equivalence proves a collector right about the machines the corpus
holds and nothing else, and a distinction no capture draws is a distinction a
port can simply not make. The subject's RED lives in
conformance/test_differential.py, where the `unbound-second-thread` operator
gives the resolver a second thread and the two stop being the same number.

**Why this delegates.** The unbound derivation is small but it is not the
artefact; the artefact is one prefix never checked. A hand-rolled second port
would disagree about the uptime split, the int-versus-float of an average, the
row's name — and prove nothing about the defect. So this IS the reference, run
against a payload whose `total.` records have been rewritten to their `thread0.`
twins before the reference ever reads it: the output is byte-for-byte what a
genuinely thread-blind port emits, and the difference from a correct port is
therefore precisely the threads it failed to add up. On a single-threaded
capture the rewrite is a no-op, which is what makes the green on the committed
corpus honest rather than an accident of agreement.
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

# The document that carries the counters twice. `status` has no per-thread
# records at all — it states the thread COUNT and nothing keyed by thread — so
# there is nothing to be blind to there, and naming the payload keeps the
# rewrite from touching anything else.
BLIND_PAYLOAD = "stats_noreset.txt"
THREAD = "thread0."
TOTAL = "total."


def _thread_share(text: str) -> str:
    """Every `total.` record rewritten to the value of its `thread0.` twin.

    Which is what a port that read the first thread had in hand. A total with
    no per-thread twin — the `time.` records at the foot of the document — is
    left exactly as it is: those are readings of the clock, not of a thread,
    and rewriting them would make this fixture wrong about a second thing.
    """
    thread: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.startswith(THREAD):
            thread[key[len(THREAD):]] = value
    out = []
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.startswith(TOTAL) and key[len(TOTAL):] in thread:
            line = f"{key}={thread[key[len(TOTAL):]]}"
        out.append(line)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)

    # Copy the payloads into a private directory and rewrite the counters
    # before the reference reads them. Every file is copied, not just the one
    # rewritten: the status document is what the version and uptime facts come
    # from, and a directory missing it is a broken capture rather than a blind
    # port.
    with tempfile.TemporaryDirectory(prefix="se-thread-blind-") as sealed:
        directory = Path(sealed)
        for payload in sorted(Path(replay_dir).iterdir()):
            if not payload.is_file() or payload.name.startswith("."):
                continue
            if payload.name == BLIND_PAYLOAD:
                (directory / payload.name).write_text(_thread_share(payload.read_text()))
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
