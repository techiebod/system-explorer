#!/usr/bin/env python3
"""Adversary fixture — dynamic-provider-blind: a proxy read as if it fronted nothing.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. A Traefik with no dynamic providers publishes
only its own internal routers and services, and that is the whole committed
capture — the universal shape, present on every install. It is also the shape in
which nine of this collector's declared facts cannot appear at all: an internal
service carries no `type`, no `loadBalancer` and no `serverStatus`; an internal
router carries no `tls` and no `error`; an overview with no providers carries no
`providers`. So a port written against that capture — which is every port
written against this corpus — can simply not read any of them and reproduce the
committed pair exactly.

Expected verdict: GREEN on every committed pair, forever — and that green is the
point, not a gap. This is DESIGN 20's third trap: replay equivalence proves a
collector right about the machines the corpus holds and nothing else, and a
member no capture carries is a member a port can be blind to for free. The
subject's RED lives in conformance/test_differential.py, where the
`traefik-dynamic-provider` operator deploys one TLS'd application on two
backends — one down — plus one route Traefik refused, and every one of those
members arrives at once.

It is blind in the direction that matters twice over. A service whose backends
are all down is a front door onto nothing: the route exists, the service loaded,
the proxy is up, and every request 502s — and the fold over `serverStatus` is
the only place in the product where that shows. And a rejected router is
configuration somebody wrote that carries no traffic, whose reason Traefik
states in its own words; a blind port keeps reporting the overview's
`RoutersErrors: 1` beside a route map where every row looks fine.

**Why this delegates.** The traefik derivation is small but it is not the
artefact; the artefact is the set of members a bare proxy never carries. A
hand-rolled second port would disagree about the priority token, the entrypoint
list's empty-versus-absent, the order of the rows — and prove nothing about the
defect. So this IS the reference, run against payloads whose dynamic-provider
members have been stripped before the reference ever reads them: the output is
byte-for-byte what a genuinely blind port emits — a fully consistent stream that
simply omits what it never learned to look for — and the difference from a
correct port is therefore precisely those members. On a capture that carries
none of them the strip is a no-op, which is what makes the green on the
committed corpus honest rather than an accident of agreement.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# fixtures/adversaries/ -> fixtures/ -> conformance/ -> the repository root.
REF = Path(__file__).resolve().parents[3] / "harness" / "bin" / "se-reference-collector"

# The payload each blindness lives in, and the members that only appear once a
# dynamic provider does. Named per payload rather than swept for by key, so the
# rewrite cannot reach a member this fixture is not about: `status`, `provider`
# and `usedBy` are on every service including the internal ones, and stripping
# one of those would make this fixture wrong about a second thing.
BLIND_MEMBERS = {
    "api-overview.json": ("providers",),
    "api-http-routers.json": ("tls", "error"),
    "api-http-services.json": ("type", "loadBalancer", "serverStatus", "error"),
}


def _strip(document: object, members: tuple[str, ...]) -> object:
    """Every named member removed, wherever the document carries one.

    The overview is one object and the two listings are arrays of them, so both
    shapes are walked — one level, because these members sit at the top of an
    entry and a deeper sweep would reach into the load balancer this fixture is
    supposed to be unable to see at all.
    """
    entries = document if isinstance(document, list) else [document]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for member in members:
            entry.pop(member, None)
    return document


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)

    # Copy the payloads into a private directory and strip the members before
    # the reference reads them. Every file is copied, not just the ones
    # rewritten: the version document is where the Version fact comes from, and
    # a directory missing it is a broken capture rather than a blind port.
    with tempfile.TemporaryDirectory(prefix="se-traefik-blind-") as sealed:
        directory = Path(sealed)
        for payload in sorted(Path(replay_dir).iterdir()):
            if not payload.is_file() or payload.name.startswith("."):
                continue
            members = BLIND_MEMBERS.get(payload.name)
            if members:
                document = _strip(json.loads(payload.read_text()), members)
                (directory / payload.name).write_text(json.dumps(document, indent=1))
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
