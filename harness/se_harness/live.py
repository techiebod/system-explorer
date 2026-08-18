"""What only a live run can authenticate.

DESIGN 19's ownership law splits the work three ways: **the harness
authenticates what varies within one stream; the collator authenticates what
varies across streams; the live comparator authenticates what varies with time
itself.** A rule placed at the wrong tier is not extra safety — it is a guard
that cannot fail, wearing a stricter one's clothes.

Three members are bounded by replay and authenticated here, and the corpus says
so rather than pretending otherwise:

  ``boot_id``   Replay pins it, so a constant-but-plausible value is
                indistinguishable in any single capture — a boot id is
                *supposed* to vary only across boots. Beside a real machine it
                is distinguishable in one run: read /proc and compare. This is
                the venue that closes the deferral, and it closes it outright
                rather than deferring again to a cross-boot capture nobody has
                taken.

  ``at``        Judged for shape under replay — finite, boot-scale,
                non-decreasing — because a deeper claim about a clock is
                untestable under a pinned one. Here the claim is testable: the
                comparator reads CLOCK_BOOTTIME on either side of the run, and
                an honest stamp must land inside that window. The replay
                constant 1.0 does not, on any machine up longer than a second.

  cost          Advisory by construction and it stays advisory: a live
                collector could still misreport it, and the authoritative
                figure is the collator's own accounting of the slice, which no
                collector writes. What IS checkable is that the reported wall
                time does not exceed the wall time the comparator measured
                around the process — a collector claiming to have taken longer
                than it was alive is reporting something it did not measure.

Every function here is pure and takes its observations as parameters, so the
conformance suite can prove each rule discriminates without a lab guest.
"""

from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class Window:
    """What the comparator observed around one collector process.

    ``boot_id`` is read from the machine, not from either stream. ``before``
    and ``after`` are CLOCK_BOOTTIME readings taken immediately either side of
    the spawn, so any honest ``at`` inside the run falls between them.
    """

    boot_id: str
    before: float
    after: float
    wall_ms: float

    def __post_init__(self) -> None:
        if self.after < self.before:
            raise ValueError("the clock went backwards around the run")


# Slack on the `at` window, in seconds, and it is deliberately small.
#
# The bracket is tight by construction: the collector process is spawned AFTER
# `before` is read and has exited BEFORE `after` is read, so no honest stamp
# taken inside it can fall outside — both reads are of the same clock on the
# same machine, so there is no skew to absorb, only the jitter of reading it.
# A generous slack would be a real loss: it is exactly what would let a stamp
# from *before this run began* pass, and "a boot-scale reading from earlier"
# is the one wrong value close enough to be plausible.
#
# It is NOT a tolerance for wrongness. Every value this rule exists to catch —
# a pinned 1.0, a zero, epoch seconds, epoch millis — misses by many orders of
# magnitude and would fail at any slack.
_AT_SLACK_S = 0.25


def authenticate(records: list[dict], window: Window) -> list[str]:
    """Hold one live stream to what the machine says was true.

    Returns the problems, named so a reader can act on them, or an empty list.
    """
    problems: list[str] = []
    begin = next((r for r in records if r.get("record") == "begin"), None)
    if begin is None:
        return ["no begin record: nothing here can be authenticated"]

    claimed = begin.get("boot_id")
    if claimed != window.boot_id:
        problems.append(
            f"begin claims boot_id {claimed!r}; this machine is running "
            f"{window.boot_id!r}. A live collector reads the boot it is on — "
            "a constant that merely looks like a UUID passes replay, where a "
            "boot id is supposed to vary only across boots, and fails here"
        )

    low, high = window.before - _AT_SLACK_S, window.after + _AT_SLACK_S
    for record in records:
        if record.get("record") != "object":
            continue
        at = record.get("at")
        where = f"{record.get('collection')}/{record.get('name')}"
        if not isinstance(at, (int, float)) or isinstance(at, bool) or not math.isfinite(at):
            problems.append(f"{where}: `at` is {at!r}, which is not a clock reading")
            continue
        if not low <= at <= high:
            problems.append(
                f"{where}: `at` is {at!r}, outside the CLOCK_BOOTTIME window "
                f"[{window.before:.3f}, {window.after:.3f}] the comparator "
                "measured around this run. A stamp taken during the run lands "
                "inside it; a pinned constant, a zero, or a wall clock on the "
                "wrong axis does not"
            )

    end = next((r for r in records if r.get("record") == "end"), None)
    if end is not None:
        reported = end.get("wall_ms")
        if isinstance(reported, (int, float)) and not isinstance(reported, bool):
            if reported > window.wall_ms:
                problems.append(
                    f"end reports wall_ms={reported}, and the comparator "
                    f"measured {window.wall_ms:.3f} ms around the whole "
                    "process. Cost stays advisory — the authoritative figure "
                    "is the collator's accounting of the slice — but a batch "
                    "cannot have taken longer than it was alive"
                )

    return problems


def advanced(first: list[dict], second: list[dict]) -> list[str]:
    """Two runs of one collector, separated in time, must move.

    This is the check with no replay analogue at all. Under a pinned clock
    every run is identical BY DESIGN, so "the stamps are the same" is the
    correct answer there and a defect here: a collector that computes `at`
    once and caches it, or derives it from something that is not a clock, is
    invisible to every other tier in this product.
    """
    problems: list[str] = []
    firsts = {
        (r.get("collection"), r.get("name")): r.get("at")
        for r in first
        if r.get("record") == "object"
    }
    seconds = {
        (r.get("collection"), r.get("name")): r.get("at")
        for r in second
        if r.get("record") == "object"
    }
    shared = sorted(set(firsts) & set(seconds), key=lambda k: (str(k[0]), str(k[1])))
    if not shared:
        return [
            "the two runs published no object in common, so nothing here can "
            "say whether the clock moved between them"
        ]
    for key in shared:
        before, after = firsts[key], seconds[key]
        if not isinstance(before, (int, float)) or not isinstance(after, (int, float)):
            continue
        if after <= before:
            problems.append(
                f"{key[0]}/{key[1]}: `at` was {before!r} and is {after!r} — a "
                "later run of the same collector read the clock again, so the "
                "stamp advances. A value that does not is not being read from "
                "a clock, and no replay can tell, because replay pins it"
            )
    return problems


def boot_changed(first_boot: str, second_boot: str) -> list[str]:
    """The cross-boot half, for a comparator run either side of a reboot.

    Separate from ``authenticate`` because it needs two boots and therefore an
    operator, and naming it as its own function is what keeps it from being
    quietly assumed by a single-boot run that cannot see it.
    """
    if first_boot == second_boot:
        return [
            f"both runs report boot_id {first_boot!r}: this machine did not "
            "reboot between them, so the cross-boot claim is untested rather "
            "than confirmed"
        ]
    return []
