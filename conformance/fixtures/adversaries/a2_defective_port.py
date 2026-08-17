#!/usr/bin/env python3
"""Adversary fixture — fleet round a2: a port's envelope, wrong one member at a time.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. This is round a2's wrong-collector, adopted
with its lab paths removed and its axes trimmed to the audited set. It wears
exactly the collector's face — request line on stdin, NDJSON on stdout, exit
zero — delegates acquisition to the reference implementation so every FACT it
states is right, and then applies one named envelope defect selected by
$SE_DEFECT: the switch is the lab's, but each position is a mistake a real
port would have baked in.

The axes, and the verdicts test_adversaries_stay_red.py holds them to:

  RED, forever
    generation_invented     mints its own generations instead of echoing issue
    generation_zero_always  every batch, forever, claims generation 0
    generation_constant_100 zero_always's 0 changed to 100 — one character.
                            100 was the base the old fixed issuance handed
                            every single-collection variant, so this passed
                            every channel; red now proves the issuance is
                            seed-varied and excludes 100
    generation_borrowed_base echoes another variant's real base (storage/
                            healthy's 458) against network/healthy: a
                            constant that matches ONE variant must still
                            fail everywhere else, or guessing beats parsing
    batch_drift             end closes a batch begin never opened
    at_wallclock            `at` from time.Now(), not the boottime clock
    at_far_future           `at` in milliseconds against a seconds-scale rule
    boot_id_blank           the boot id read failed and the error was swallowed
    boot_id_constant        the nil UUID — the stub every runtime hands out free
    go_port                 four of the above at once: a first port's true shape

  GREEN, adjudicated — not an oversight (DESIGN 19, the two-regimes law)
    boot_id_constant_valid  a constant but VALID, non-nil id. A boot id is
                            SUPPOSED to vary only across boots, so one capture
                            cannot tell this from a real id by physics; it is a
                            cross-boot variant's to catch. Added at adoption
                            time so the deferral is held in both directions:
                            nil red, valid-constant green.

`--defects` prints the axis names, one per line, so the suite can prove this
table and its own expectation table agree deny-by-default — an axis either
side knows alone is an unaudited one.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

# fixtures/adversaries/ -> fixtures/ -> conformance/ -> the repository root.
REF = Path(__file__).resolve().parents[3] / "harness" / "bin" / "se-reference-collector"


def main() -> None:
    line = sys.stdin.read()
    proc = subprocess.run(
        [sys.executable, str(REF)],
        input=line,
        capture_output=True,
        text=True,
        env=dict(os.environ),
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        raise SystemExit(proc.returncode)
    records = [json.loads(raw) for raw in proc.stdout.splitlines() if raw.strip()]
    records = MUTATIONS[os.environ["SE_DEFECT"]](records)
    for record in records:
        print(json.dumps(record, sort_keys=True, separators=(",", ":")))


# ── the defects ─────────────────────────────────────────────────────────


def batch_drift(records):
    """`end` closes a batch id the collector minted fresh instead of echoing
    the one `begin` opened. A port that calls newULID() in both places."""
    out = []
    for r in records:
        if r["record"] == "end":
            r = dict(r, request="rq-fresh-2", batch="01JC8KOTHERBATCH")
        out.append(r)
    return out


def at_wallclock(records):
    """`at` taken from time.Now().Unix() rather than CLOCK_BOOTTIME."""
    return [
        dict(r, at=1786000000.0 + i) if r["record"] == "object" else r
        for i, r in enumerate(records)
    ]


def at_far_future(records):
    """`at` in milliseconds rather than seconds, against a boottime clock."""
    return [
        dict(r, at=1786000000123.0) if r["record"] == "object" else r for r in records
    ]


def boot_id_blank(records):
    """The boot id read failed and the error was swallowed."""
    return [dict(r, boot_id="") if r["record"] == "begin" else r for r in records]


def boot_id_constant(records):
    """A build-time constant instead of /proc/sys/kernel/random/boot_id —
    and the constant every runtime hands out for free is the nil UUID."""
    return [
        dict(r, boot_id="00000000-0000-0000-0000-000000000000")
        if r["record"] == "begin"
        else r
        for r in records
    ]


def boot_id_constant_valid(records):
    """The same build-time-constant defect wearing a VALID, non-nil UUID.
    This axis is expected GREEN: shape-plus-not-nil is the honest bound of
    what one capture can authenticate (DESIGN 19), and the constant is a
    cross-boot variant's to catch."""
    return [
        dict(r, boot_id="c0ffee00-1234-4abc-8def-abcdef012345")
        if r["record"] == "begin"
        else r
        for r in records
    ]


def generation_invented(records):
    """The collector picks its own generation instead of echoing the
    collator's. Self-consistent between begin and commit, so the echo holds."""
    out = []
    for r in records:
        if r["record"] == "begin":
            r = dict(r, generations={k: 424242 for k in r["generations"]})
        elif r["record"] == "commit":
            r = dict(r, generation=424242)
        out.append(r)
    return out


def generation_zero_always(records):
    """Every batch, forever, claims generation 0 — so the collator's
    below-applied rule refuses every batch after the first."""
    out = []
    for r in records:
        if r["record"] == "begin":
            r = dict(r, generations={k: 0 for k in r["generations"]})
        elif r["record"] == "commit":
            r = dict(r, generation=0)
        out.append(r)
    return out


def generation_constant_100(records):
    """generation_zero_always with its constant changed from 0 to 100 — the
    one-character exploit that reopened the echo guard. The old issuance was
    100 + 17*i over sorted collections, and every variant opened exactly one
    collection, so i was always 0 and 100 was what every request issued:
    the guard caught every invented constant except the one it issued. This
    axis stays as the permanent proof that no request issues 100 anywhere."""
    out = []
    for r in records:
        if r["record"] == "begin":
            r = dict(r, generations={k: 100 for k in r["generations"]})
        elif r["record"] == "commit":
            r = dict(r, generation=100)
        out.append(r)
    return out


def generation_borrowed_base(records):
    """The same defect wearing a REAL base: 458 is storage/healthy's seeded
    base, hardcoded here the way a collector that read one lab run's request
    line and baked the number in would carry it. Judged against
    network/healthy (base 658), so the red proves distinctness does the
    work: a constant matching one variant fails every other, and only
    parsing the request line passes everywhere. If the issuance formula
    moves and 458 collides with network/healthy's, this axis goes green and
    its row's evidence check names the regression."""
    out = []
    for r in records:
        if r["record"] == "begin":
            r = dict(r, generations={k: 458 for k in r["generations"]})
        elif r["record"] == "commit":
            r = dict(r, generation=458)
        out.append(r)
    return out


def go_port(records):
    """One collector, four ordinary porting mistakes at once — the shape a
    real first port has: the wall clock for `at`, a build constant for the
    boot id, a locally-issued generation counter, and a fresh id minted in
    `end` instead of the one `begin` opened."""
    out = []
    for i, r in enumerate(records):
        if r["record"] == "begin":
            r = dict(
                r,
                boot_id="00000000-0000-0000-0000-000000000000",
                generations={k: 1 for k in r["generations"]},
            )
        elif r["record"] == "object":
            r = dict(r, at=1786000000.0 + i)
        elif r["record"] == "commit":
            r = dict(r, generation=1)
        elif r["record"] == "end":
            r = dict(r, request="rq-9999", batch="01JC8KFRESHBATCHID")
        out.append(r)
    return out


MUTATIONS = {
    "generation_invented": generation_invented,
    "generation_zero_always": generation_zero_always,
    "generation_constant_100": generation_constant_100,
    "generation_borrowed_base": generation_borrowed_base,
    "batch_drift": batch_drift,
    "at_wallclock": at_wallclock,
    "at_far_future": at_far_future,
    "boot_id_blank": boot_id_blank,
    "boot_id_constant": boot_id_constant,
    "boot_id_constant_valid": boot_id_constant_valid,
    "go_port": go_port,
}

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--defects":
        print("\n".join(MUTATIONS))
        raise SystemExit(0)
    main()
