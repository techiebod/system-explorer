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

import pytest

from se_harness import live


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


def test_the_comparator_drives_every_collection_the_seam_serves() -> None:
    """SERVES is a second list of what a collector answers for, and a second
    list is a second thing to disagree with the first. Held to the replay
    seam's table, which is the authority the corpus coverage check already
    reads."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent

    def table(path: Path, name: str) -> dict:
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == name:
                        return ast.literal_eval(node.value)
        raise AssertionError(f"{path} no longer defines {name}")

    # The seam's entry is a dict of specs; only the collections matter here.
    seam_src = (root / "harness" / "bin" / "se-reference-collector").read_text()
    seam_tree = ast.parse(seam_src)
    seam: dict[str, list[str]] = {}
    for node in ast.walk(seam_tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "SEAM" for t in node.targets
        ):
            for key, value in zip(node.value.keys, node.value.values):
                for k, v in zip(value.keys, value.values):
                    if getattr(k, "value", None) == "collections":
                        seam[key.value] = ast.literal_eval(v)

    serves = table(root / "harness" / "bin" / "se-compare", "SERVES")
    assert serves == seam, (
        "the comparator's SERVES and the replay seam's collections must name "
        f"the same set: comparator {serves}, seam {seam}. A collection served "
        "and never compared is a hole with a clean report over it"
    )


def test_the_live_reference_serves_what_the_replay_reference_serves() -> None:
    """The two references are one implementation reached two ways. If the live
    one served a different set, the comparator would be diffing a port against
    a reference the corpus was never built from."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    tree = ast.parse((root / "harness" / "bin" / "se-live-reference").read_text())
    live_table: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "LIVE" for t in node.targets
        ):
            for key, value in zip(node.value.keys, node.value.values):
                for k, v in zip(value.keys, value.values):
                    if getattr(k, "value", None) == "collections":
                        live_table[key.value] = ast.literal_eval(v)

    seam_tree = ast.parse(
        (root / "harness" / "bin" / "se-reference-collector").read_text())
    seam: dict[str, list[str]] = {}
    for node in ast.walk(seam_tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "SEAM" for t in node.targets
        ):
            for key, value in zip(node.value.keys, node.value.values):
                for k, v in zip(value.keys, value.values):
                    if getattr(k, "value", None) == "collections":
                        seam[key.value] = ast.literal_eval(v)

    assert live_table == seam, (
        f"live reference serves {live_table}, replay reference serves {seam}"
    )


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
