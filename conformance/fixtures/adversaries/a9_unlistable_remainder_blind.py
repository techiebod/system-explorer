#!/usr/bin/env python3
"""Adversary fixture — unlistable-remainder blind: an inventory that lists what it counts.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. A Kea host reservation does not have to pin an
address — one that states a hostname alone hands a client its NAME, one that
states only client-classes pins a class — and neither can mint a stable id,
because `reservation:<subnet>/<ip>` has no ip to be keyed on. So
adapters/kea.py counts them on the subnet row and lists them nowhere, and states
that remainder on the wire: ReservationCount is every entry the configuration
holds, UnlistedReservations is the ones no row can carry, and a reader who
subtracts gets the number of rows.

A port that filters the reservation list ONCE, at the top, and then counts what
survived never has a remainder to state. Its ReservationCount equals its row
count by construction, so the two can never disagree — which reads as
consistency and is under-reporting the machine's configuration. An operator
reading a subnet row learns there are six pinned machines where there are seven.

Expected verdict: GREEN on every committed pair, forever — and that green is the
point, not a gap. Every reservation in corpus/kea/no-lease-hook states an
address, so filtering removes nothing, the remainder is nil, and
UnlistedReservations is absent from the correct answer too. This is DESIGN 20's
third trap: replay equivalence proves a collector right about the machines the
corpus holds and nothing else, and a remainder no capture produces is a
remainder a port can simply not have. The subject's RED lives in
conformance/test_differential.py, where the `kea-addressless-reservation`
operator puts a hostname-only reservation into the seed's subnet and the two
counts stop being the same number.

**Why this delegates.** The kea derivation is not the artefact; the artefact is
one filter applied before the count instead of after it. A hand-rolled second
port would disagree about the option-inheritance merge, the statistics join, the
row's native name — and prove nothing about the defect. So this IS the
reference, run against a config document whose unlistable reservations have been
removed before the reference ever reads it: the output is byte-for-byte what a
port that filtered first emits — a fully consistent stream whose counts simply
never see the entries it dropped — and the difference from a correct port is
therefore precisely the remainder it should have stated. On a capture where
every reservation carries an address the removal is a no-op, which is what makes
the green on the committed corpus honest rather than an accident of agreement.
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

# The one document that carries reservations. The statistics document holds the
# counters and names no reservation at all, so there is nothing to be blind to
# there, and naming the payload keeps the removal from touching anything else.
BLIND_PAYLOAD = "config-get.json"


def _listable_only(entries: object) -> object:
    """The reservations a port that filtered first would have had in hand.

    An entry with no truthy ip-address is dropped — which is the same test the
    reference applies before it builds a row, moved one step earlier so it also
    governs the count. A non-object entry goes too, for the same reason the
    reference cannot build a row from one.
    """
    if not isinstance(entries, list):
        return entries
    return [e for e in entries if isinstance(e, dict) and e.get("ip-address")]


def _blind_config(document: object) -> object:
    """Every reservation list in the document, filtered before anything counts.

    Both places Kea declares subnets — top level and inside a shared network —
    and the global list beside them, because a port with this defect has it
    everywhere and a fixture that fixed one arm would disagree with a correct
    port for the wrong reason.
    """
    dhcp4 = ((document or {}).get("arguments") or {}).get("Dhcp4")
    if not isinstance(dhcp4, dict):
        return document
    subnets = list(dhcp4.get("subnet4") or [])
    for network in dhcp4.get("shared-networks") or []:
        if isinstance(network, dict):
            subnets.extend(network.get("subnet4") or [])
    for subnet in subnets:
        if isinstance(subnet, dict) and "reservations" in subnet:
            subnet["reservations"] = _listable_only(subnet["reservations"])
    if "reservations" in dhcp4:
        dhcp4["reservations"] = _listable_only(dhcp4["reservations"])
    return document


def main() -> None:
    replay_dir = os.environ.get("SE_REPLAY_DIR")
    if not replay_dir:
        print("SE_REPLAY_DIR is unset", file=sys.stderr)
        raise SystemExit(2)

    # Copy the payloads into a private directory and filter the reservations
    # before the reference reads them. Every file is copied, not just the one
    # rewritten: the statistics document is where the pool counters come from and
    # the version and status documents are the daemon row, and a directory
    # missing any of them is a broken capture rather than a blind port.
    with tempfile.TemporaryDirectory(prefix="se-remainder-blind-") as sealed:
        directory = Path(sealed)
        for payload in sorted(Path(replay_dir).iterdir()):
            if not payload.is_file() or payload.name.startswith("."):
                continue
            if payload.name == BLIND_PAYLOAD:
                document = _blind_config(json.loads(payload.read_text()))
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
