"""The live comparator's own rules, held to standing rule 6.

The comparator runs on a lab guest and CI has no ZFS pool, no nftables ruleset
and no reason to acquire one — so what CI can and must judge is the JUDGEMENT:
every rule here is a pure function over observations, and every test feeds it
the exact wrong value the rule exists to catch.

That split matters. A comparator whose rules were only ever exercised on a
machine where they passed would be a guard nobody had seen fail, which is the
defect this repository has found in itself four times: a check that enumerates
what its author thought of, reports success about the rest, and is never shown
to discriminate. The lab proves the tool RUNS; this proves it JUDGES.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
from pathlib import Path

import pytest


def _load_script(name: str):
    """Import one of harness/bin's scripts by path, under a module name of
    its own so two of them cannot collide in sys.modules."""
    path = Path(__file__).resolve().parent.parent / "harness" / "bin" / name
    spec = importlib.util.spec_from_loader(
        name.replace("-", "_"), importlib.machinery.SourceFileLoader(
            name.replace("-", "_"), str(path)))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module

from se_harness import live

# se-compare is a script rather than a module, so it is loaded by path. The
# rules this file exercises are pure functions and tables in it — CI has no
# lab guest, and a guard only ever seen to pass is not a guard.
compare = _load_script("se-compare")


def window(before: float = 100.0, after: float = 100.5,
           boot: str = "4f2a1c8e-7b3d-4a91-9e2f-6c5d8a0b1e37",
           wall_ms: float = 500.0) -> live.Window:
    return live.Window(boot_id=boot, before=before, after=after, wall_ms=wall_ms)


def stream(at: float = 100.2, boot: str = "4f2a1c8e-7b3d-4a91-9e2f-6c5d8a0b1e37",
           wall_ms: float = 12.0) -> list[dict]:
    return [
        {"record": "begin", "request": "r", "batch": "b", "boot_id": boot,
         "declaration": "sha256:x", "timens": 0, "instance": None,
         "generations": {"pools": 1}},
        {"record": "object", "collection": "pools", "name": "tank",
         "facts": {"State": "ONLINE"}, "at": at},
        {"record": "commit", "collection": "pools", "generation": 1,
         "objects": 1, "assertions": 0, "unobservable": 0},
        {"record": "end", "request": "r", "batch": "b", "cpu_ms": 1.0,
         "wall_ms": wall_ms},
    ]


def test_an_honest_live_stream_is_clean() -> None:
    """The control. Without it every test below could pass by the rule being
    unconditionally red, which is a guard that cannot discriminate in the
    other direction."""
    assert live.authenticate(stream(), window()) == []


# ── boot_id: the deferral this venue closes outright ──────────────────────


def test_the_replay_boot_id_constant_fails_against_a_real_machine() -> None:
    """DESIGN 19 defers this to a cross-boot check and says a constant valid
    id is indistinguishable in any single capture. That is true under REPLAY
    and false here: the comparator reads /proc and compares, so the corpus's
    own stand-in — a perfectly UUID-shaped constant that passes every replay
    rule — is caught in one run, on one boot."""
    problems = live.authenticate(
        stream(boot="5e000000-0000-4000-8000-000000000001"), window())
    assert any("this machine is running" in p for p in problems), problems


def test_a_boot_id_that_matches_is_accepted() -> None:
    boot = "9d1f7c34-6a2b-4e55-b0d1-77c4a2e91f08"
    assert live.authenticate(stream(boot=boot), window(boot=boot)) == []


# ── at: shape under replay, truth here ────────────────────────────────────


@pytest.mark.parametrize(
    ("at", "why"),
    [
        (1.0, "the replay constant: finite, positive, boot-scale, and nowhere "
              "near the window this run actually occupied"),
        (0.0, "the placeholder a port reaches for when it has no clock"),
        (1_755_000_000.0, "epoch seconds — a wall clock on the wrong axis"),
        (1_755_000_000_000.0, "epoch milliseconds, same error scaled"),
        (99.0, "a real boot-scale reading, but from before this run began"),
        (200.0, "a reading from after it ended"),
    ],
)
def test_a_stamp_outside_the_measured_window_is_refused(at: float, why: str) -> None:
    """Every value here passes the replay judge's shape rule — finite,
    positive, boot-scale where it needs to be — and every one is wrong. The
    window is what makes them separable, and it is available only live."""
    problems = live.authenticate(stream(at=at), window())
    assert any("outside the CLOCK_BOOTTIME window" in p for p in problems), (
        f"{why}: {problems}"
    )


@pytest.mark.parametrize("at", [None, "100.2", True, float("nan"), float("inf")])
def test_a_stamp_that_is_not_a_reading_is_named_as_such(at) -> None:
    problems = live.authenticate(stream(at=at), window())
    assert any("not a clock reading" in p or "outside" in p for p in problems), problems


def test_the_window_slack_does_not_admit_the_values_it_exists_beside() -> None:
    """The slack is for scheduling, not for wrongness. A stamp a hair outside
    the measured window is a real process scheduled a moment later; the values
    the rule exists to catch miss by orders of magnitude, so no plausible
    slack lets one through — and this pins that, so nobody widens it later to
    quieten a flake and silently retires the rule."""
    assert live.authenticate(stream(at=100.6), window()) == []
    assert live.authenticate(stream(at=1.0), window()) != []


# ── cost: advisory, but not unfalsifiable ─────────────────────────────────


def test_a_batch_cannot_have_taken_longer_than_it_was_alive() -> None:
    problems = live.authenticate(stream(wall_ms=5000.0), window(wall_ms=500.0))
    assert any("longer than it was alive" in p for p in problems), problems


def test_cost_below_the_measured_wall_is_accepted_because_cost_stays_advisory() -> None:
    """Deliberately weak, and the docstring is the reason. The authoritative
    cost figure is the collator's accounting of the slice, which no collector
    writes — so this rule bounds the claim and does not authenticate it. A
    tighter rule here would be a guard pretending to a certainty its tier
    cannot have."""
    assert live.authenticate(stream(wall_ms=0.1), window(wall_ms=500.0)) == []


# ── advancement: the check with no replay analogue at all ─────────────────


def test_a_stamp_that_does_not_move_between_runs_is_refused() -> None:
    """Under a pinned clock every run is identical BY DESIGN, so "the stamps
    match" is the correct answer in replay and a defect here. A collector that
    computes `at` once and caches it — or derives it from something that is
    not a clock — is invisible to every other tier in this product."""
    first = stream(at=100.2)
    problems = live.advanced(first, stream(at=100.2))
    assert any("does not advance" in p or "advances" in p for p in problems), problems


def test_a_stamp_that_moves_forward_is_accepted() -> None:
    assert live.advanced(stream(at=100.2), stream(at=140.9)) == []


def test_a_stamp_that_moves_backward_is_refused() -> None:
    assert live.advanced(stream(at=140.9), stream(at=100.2)) != []


def test_two_runs_sharing_no_object_say_so_rather_than_passing() -> None:
    """The subset-guard defect, pre-empted: with no shared object there is
    nothing to compare, and reporting clean would be a check that silently
    graded an empty set. It says it could not tell instead."""
    other = stream()
    other[1] = dict(other[1], name="other-pool")
    problems = live.advanced(stream(), other)
    assert any("nothing here can say" in p for p in problems), problems


# ── cross-boot: named as untested rather than assumed ─────────────────────


def test_one_boot_reports_the_cross_boot_claim_as_untested() -> None:
    boot = "4f2a1c8e-7b3d-4a91-9e2f-6c5d8a0b1e37"
    problems = live.boot_changed(boot, boot)
    assert any("untested rather than confirmed" in p for p in problems), problems


def test_two_boots_confirm_it() -> None:
    assert live.boot_changed("4f2a1c8e-7b3d-4a91-9e2f-6c5d8a0b1e37",
                             "9d1f7c34-6a2b-4e55-b0d1-77c4a2e91f08") == []


# ── the window's own integrity ────────────────────────────────────────────


def test_a_window_whose_clock_ran_backwards_is_refused_at_construction() -> None:
    """CLOCK_BOOTTIME does not go backwards, so a window claiming it did means
    the comparator itself misread — and a judge built on a bad measurement
    would blame the subject for its own error."""
    with pytest.raises(ValueError):
        live.Window(boot_id="x", before=100.0, after=99.0, wall_ms=1.0)


def test_a_stream_with_no_begin_authenticates_nothing() -> None:
    problems = live.authenticate([{"record": "object", "collection": "p",
                                   "name": "n", "facts": {}, "at": 100.2}],
                                 window())
    assert problems == ["no begin record: nothing here can be authenticated"]


# ── the tool's own wiring ─────────────────────────────────────────────────
#
# CI cannot run the comparator — there is no pool and no ruleset here — but it
# can hold the tool to comparing everything it claims to. A comparator that
# quietly covered a subset would report a clean parity over the half it looked
# at, which is this repository's most repeated defect and the exact shape that
# let nft-rules sit served-but-uncaptured behind a residual.


def test_an_accepted_divergence_is_stripped_from_the_reference_only() -> None:
    """Gate 3's clause is "clean OR its diffs are named and accepted", and a
    comparator that could not express the second half would report a ruled
    scope decision as a defect on every future run.

    The reversion, which is the whole reason this is one-sided: strip BOTH
    streams and a port that emitted a delta fact — wrongly, since the ruling
    puts them out of its scope — becomes invisible. So the reference loses
    them and the port does not, and the port carrying one is itself reported.
    """
    accepted = compare.ACCEPTED_DIVERGENCES["nix"]["facts"]
    record = {"record": "object", "collection": "generations", "name": "3",
              "facts": {"Current": True, "DeltaCounts": {"etc": 5}}}

    stripped = compare._without(record, accepted)
    assert stripped["facts"] == {"Current": True}
    assert record["facts"] == {"Current": True, "DeltaCounts": {"etc": 5}}, (
        "the record is rewritten, never mutated in place — the same records "
        "are handed to the clock check afterwards"
    )

    # A record carrying none of them is returned unchanged, identity included,
    # so the common case allocates nothing and cannot reorder anything.
    untouched = {"record": "object", "facts": {"Current": True}}
    assert compare._without(untouched, accepted) is untouched


def test_the_accepted_divergence_names_only_facts_the_ruling_covers() -> None:
    """An acceptance that widened would quietly stop the comparator seeing a
    real disagreement, which is the one direction this must not fail in."""
    assert set(compare.ACCEPTED_DIVERGENCES) == {"nix"}
    assert compare.ACCEPTED_DIVERGENCES["nix"]["facts"] == frozenset({
        "ComparedWithGeneration", "DeltaCounts", "DeltaFromPrevious",
        "DeltaFromPreviousPartial", "DeltaFromPreviousUnobservable",
    })
    assert "2026-08-19" in compare.ACCEPTED_DIVERGENCES["nix"]["ruling"], (
        "an acceptance carries the ruling that authorised it, dated, or it is "
        "indistinguishable from a defect somebody got tired of"
    )


def test_the_comparator_derives_its_work_from_the_register() -> None:
    """SERVES — a second list of what a collector answers for, filled in
    with what the port implemented — is dead. The work list derives from
    the shared register (whose own drills live in test_port_completeness),
    and the comparator refuses to start on an inconsistent one rather than
    comparing a subset while looking exhaustive. Here: the derived work is
    what compare() actually receives, and the excluded rows reach the
    REPORT — an exclusion only visible in a source file is one a reader of
    the report cannot see."""
    from se_harness import register

    work = register.comparator_work()
    assert set(work) == set(register.reference_collections())
    assert "identity" in work["system"]["compare"], (
        "register row 27: the derived work list is what finally drives "
        "system/identity"
    )
    # Re-anchored twice as R3b landed collections: the pin is "an owed
    # exclusion appears, named", not any one collection staying owed.
    assert "owed: " in work["network"]["excluded"]["nft-tables"]
    assert work["plex"]["excluded"] == {
        "requests": "owed: " + register.NOT_YET_PORTED["plex/requests"]}

    rendered = compare.render({
        "collector": "network",
        "collections": work["network"]["compare"],
        "not_compared": work["network"]["excluded"],
        "nothing_to_compare": "stub — stop before the subprocess half",
    })
    for name in work["network"]["excluded"]:
        assert f"not compared: {name}" in rendered, rendered


def test_a_collector_with_everything_excluded_says_so_and_stays_clean() -> None:
    """The empty-compare shape must be its own visible state: comparing
    nothing is not agreement, and reporting it as bare clean would be
    absence rendered as health."""
    result = compare.compare(
        "storage", {"compare": [], "excluded": {"pools": "owed: stub"}},
        twice=False)
    assert result["clean"] is True
    assert "nothing_to_compare" in result
    assert result["not_compared"] == {"pools": "owed: stub"}


# ── the order layer (register row 5's parity half, new at R2) ─────────────


def _objects(names: list[str], collection: str = "pools") -> list[dict]:
    return [{"record": "object", "collection": collection, "name": name,
             "facts": {}, "at": 1.0} for name in names]


def test_matching_order_is_clean() -> None:
    """The control, so the drills below cannot pass by the check being
    unconditionally red."""
    from se_harness import replay

    assert replay.order_differences(_objects(["a", "b", "c"]),
                                    _objects(["a", "b", "c"])) == []


def test_a_reordered_collection_is_named_with_its_first_divergence() -> None:
    """The drill: same rows, different sequence. diff() is order-blind by
    design, so without this check two different pages would compare clean —
    and applied order IS the page since the 2026-08-21 ruling."""
    from se_harness import replay

    want, got = _objects(["a", "b", "c"]), _objects(["a", "c", "b"])
    assert replay.diff(want, got) == [], "precondition: diff stays order-blind"
    problems = replay.order_differences(want, got)
    assert len(problems) == 1 and "position 1" in problems[0], problems
    assert "'b'" in problems[0] and "'c'" in problems[0], problems


def test_a_membership_difference_is_not_repeated_as_an_order_problem() -> None:
    """A missing or extra row is diff()'s to report; spelling it again as
    an order problem would bury the parity report under a second account of
    one defect."""
    from se_harness import replay

    assert replay.order_differences(_objects(["a", "b", "c"]),
                                    _objects(["a", "c"])) == []
    assert replay.diff(_objects(["a", "b", "c"]), _objects(["a", "c"])), (
        "precondition: the membership difference is diff()'s finding"
    )


def test_order_is_judged_per_collection() -> None:
    from se_harness import replay

    want = _objects(["a", "b"], "pools") + _objects(["x", "y"], "datasets")
    got = _objects(["a", "b"], "pools") + _objects(["y", "x"], "datasets")
    problems = replay.order_differences(want, got)
    assert len(problems) == 1 and problems[0].startswith("datasets:"), problems


# ── the names and type layers: diff() must discriminate on both ───────────


def test_a_dropped_names_member_is_a_named_difference() -> None:
    """The names layer (register row 6) rides the object record, and a port
    that stopped emitting it would sever every stable-identity join. Proven
    here to be diff()'s finding, both dropped and altered, so the layer
    cannot silently leave the comparison."""
    from se_harness import replay

    def one(names):
        record = {"record": "object", "collection": "pools", "name": "tank",
                  "facts": {}, "at": 1.0}
        if names:
            record["names"] = names
        return [record]

    stable = {"stable": {"guid": ["123"]}}
    assert replay.diff(one(stable), one(stable)) == []
    dropped = replay.diff(one(stable), one(None))
    assert dropped and any("names" in d for d in dropped), dropped
    altered = replay.diff(one(stable), one({"stable": {"guid": ["999"]}}))
    assert altered and any("names" in d for d in altered), altered


def test_a_changed_type_is_a_named_difference() -> None:
    """The type layer (register row 4): type is part of a record's identity,
    so a port emitting the wrong kind — or none — must surface, not pair."""
    from se_harness import replay

    def one(kind):
        record = {"record": "object", "collection": "scsi", "name": "0:0:0:0",
                  "facts": {}, "at": 1.0}
        if kind:
            record["type"] = kind
        return [record]

    assert replay.diff(one("disk"), one("disk")) == []
    for wrong in ("expander", None):
        problems = replay.diff(one("disk"), one(wrong))
        assert problems, f"type {wrong!r} compared equal to 'disk'"


def test_the_live_reference_refuses_to_be_used_as_a_replay() -> None:
    """SE_REPLAY_DIR set against the live tool is a misconfiguration that
    would read the wrong machine's interfaces while looking like a replay.
    It refuses rather than ignoring the variable, because ignoring it is how
    the two get confused exactly once, on the machine it matters on."""
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    proc = subprocess.run(
        [sys.executable, str(root / "harness" / "bin" / "se-live-reference")],
        input="collect pools:1\n", capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin", "SE_REPLAY_DIR": "/tmp",
             "SE_REFERENCE_COLLECTOR": "storage"},
    )
    assert proc.returncode == 2, proc
    assert "refusing" in proc.stderr, proc.stderr


# ── the live tier's one exemption, and its four bounds ───────────────────


def test_a_moving_fact_is_exempt_by_value_and_by_nothing_else():
    """The live comparator runs the reference and then the port, so anything
    the machine advances in between differs — and every one of those read as a
    defect until 2026-08-19.

    `resources` reported four differing rows on EVERY run and not one was real:
    monotonic CPU counters and instantaneous memory, moving because time
    passed. That is worse than reporting nothing, because a real disagreement
    arrives buried in noise a reader has been trained to scroll past.

    The exemption is narrow on purpose and this test is what keeps it narrow. A
    fact the collector declares `counter` or `gauge` has its VALUE excused. It
    is still compared for presence and for type, and every fact that is not so
    declared is still compared by value — which is why the exemption cannot be
    used to make a broken port agree with itself.
    """
    from se_harness import replay

    def stream(facts):
        return [{"record": "object", "collection": "workloads",
                 "name": "-.slice", "facts": facts, "at": 1.0}]

    moving = frozenset({"CpuUsageUsec"})

    # 1. the value moved — the whole point, and the only thing excused
    assert not replay.diff(stream({"CpuUsageUsec": 10, "Name": "a"}),
                           stream({"CpuUsageUsec": 99, "Name": "a"}),
                           moving), "a declared counter's value must not be compared"

    # 2. the same difference with NO declaration is still a defect, which is
    #    what proves the exemption is doing the work rather than the diff
    #    having gone blind
    assert replay.diff(stream({"CpuUsageUsec": 10}),
                       stream({"CpuUsageUsec": 99}),
                       frozenset()), (
        "with nothing declared moving, a changed value must still be reported "
        "— otherwise this exemption is not what made case 1 pass"
    )

    # 3. the TYPE changed under it: a port emitting a string where the
    #    reference emits an integer is wrong whatever the number was
    typed = replay.diff(stream({"CpuUsageUsec": 10}),
                        stream({"CpuUsageUsec": "10"}),
                        moving)
    assert typed and "TYPE" in " ".join(typed), (
        f"a moving fact that changed type must still be reported: {typed}"
    )

    # 4. the fact went missing: an exemption from comparison is not an
    #    exemption from being emitted
    assert replay.diff(stream({"CpuUsageUsec": 10}), stream({}), moving), (
        "a moving fact the port stopped emitting must still be reported"
    )

    # 5. a fact BESIDE a moving one is untouched — the row is compared fact by
    #    fact, so one member moving must not excuse its neighbours
    assert replay.diff(stream({"CpuUsageUsec": 10, "Name": "a"}),
                       stream({"CpuUsageUsec": 99, "Name": "b"}),
                       moving), (
        "a non-moving fact must still be compared even when a moving one "
        "shares the row"
    )
