"""Every known gap between the reference and the rewrite, held to reality.

**This is the guard that was missing, and its absence carried a gate.**
Gate 3 declared twenty of twenty collectors ported and nineteen of
nineteen clean. Both were true and neither was the question: a collector
is "ported" at the granularity of a BINARY, and the parity comparator
drove a hand-maintained list of collections which had been filled in
with exactly what the port implements. So both sides were asked only for
what the port already had, agreed, and reported clean — while eighteen
collections the reference serves were never asked for at all.

That is this estate's most repeated defect, in the guard built to catch
it: a check that enumerates what its author thought of and reports
success about the rest. Found on 2026-08-20 by a person opening the UI
and saying it looked empty, which no assertion in this suite had managed
to say.

Since R2 the authority is ``se_harness.register``, shared with the live
comparator and the reference driver, and this file holds it to the tree
in BOTH directions:

* the served/ported/registered accounting (``comparator_work`` raises on
  any unregistered gap, stale entry, or frozen-capability breach — and
  the drills below feed it worlds wrong in exactly one way each);
* the 27-row gap register from PLAN's re-baseline — every row built,
  owed or ruled, with a probe wherever the tree can attest it, checked
  in the "claims built and is not" direction AND the "claims owed and
  was built" direction, because the second is how a hole gets forgotten
  twice;
* the answer rulings (register row 26) — every divergence between a
  port's ``answer`` list and the old UI's argued COLUMNS preset carries
  an explicit ruling, and a ruling with no divergence left to rule fails
  as stale.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from se_harness import register
from se_harness.register import (
    ANSWER_RULINGS,
    DELIBERATELY_DROPPED,
    NO_REPLAY_SEAM,
    NOT_YET_PORTED,
    REGISTER,
    RegisterViolation,
)

REPO = Path(__file__).resolve().parent.parent

OLD = register.reference_collections()
NEW = register.ported_collections()


# ── the accounting, and the drills that prove it discriminates ────────────


def test_the_scan_finds_the_adapters_we_know_about() -> None:
    """Anti-vacuity. A parse that stopped matching would make the whole
    file pass by measuring nothing — which is the failure this file is
    about, one level up. register.reference_collections raises below 20
    itself; this pins the shape further."""
    assert len(OLD) == 20, sorted(OLD)
    for expected in ("network", "storage", "system", "units"):
        assert OLD.get(expected), f"{expected} adapter's collections() went unread"
    assert len(OLD["network"]) >= 10 and len(OLD["storage"]) >= 6


def test_the_register_and_the_tree_agree() -> None:
    """The whole accounting in one call: every reference collection ported
    or registered, no stale entries, no unserved registrations, no frozen-
    capability breach. comparator_work raises with every problem named."""
    work = register.comparator_work()
    assert set(work) == set(OLD)
    compared = {f"{collector}/{name}"
                for collector, entry in work.items()
                for name in entry["compare"]}
    declared = {f"{collector}/{name}"
                for collector, collections in NEW.items()
                for name in collections}
    assert compared == declared, (
        "the compared set and the declared set must be the same set; "
        f"only-compared {sorted(compared - declared)}, "
        f"only-declared {sorted(declared - compared)}"
    )


def test_an_unregistered_gap_refuses_the_run() -> None:
    """The drill for the hole the eighteen sat in: an adapter collection
    that is neither ported nor registered must refuse, not vanish."""
    reference = {k: list(v) for k, v in OLD.items()}
    reference["network"] = reference["network"] + ["brand-new-collection"]
    with pytest.raises(RegisterViolation, match="brand-new-collection"):
        register.comparator_work(reference=reference)


def test_a_stale_owed_entry_refuses_the_run() -> None:
    """The drill for the direction that lets a hole be forgotten twice: a
    collection listed as owed that the port now declares must refuse until
    the register is updated."""
    ported = {k: dict(v) for k, v in NEW.items()}
    ported["network"] = dict(ported["network"])
    ported["network"]["links"] = {"name": "links", "answer": []}
    with pytest.raises(RegisterViolation, match="network/links"):
        register.comparator_work(ported=ported)


def test_a_port_only_collection_refuses_the_run() -> None:
    """New capability is frozen until parity (PLAN, the re-baseline): a
    port declaring a collection the reference never served is a breach,
    not an extension."""
    ported = {k: dict(v) for k, v in NEW.items()}
    ported["storage"] = dict(ported["storage"])
    ported["storage"]["shiny"] = {"name": "shiny", "answer": []}
    with pytest.raises(RegisterViolation, match="storage/shiny"):
        register.comparator_work(ported=ported)


def test_a_registration_with_no_subject_refuses_the_run() -> None:
    """An exclusion naming a collection no adapter serves excludes nothing
    and rots silently — refused rather than ignored."""
    reference = {k: list(v) for k, v in OLD.items()}
    reference["system"] = [c for c in reference["system"] if c != "self"]
    with pytest.raises(RegisterViolation, match="system/self"):
        register.comparator_work(reference=reference)


@pytest.mark.parametrize("adapter", sorted(OLD))
def test_no_adapter_lost_more_than_it_kept_without_saying_so(adapter: str) -> None:
    """A per-adapter view, so a single number cannot hide where the holes
    are. network kept 2 of 10 and storage 1 of 6, and both are recorded."""
    old, new = set(OLD[adapter]), set(NEW.get(adapter, {}))
    if len(new) >= len(old):
        return
    for collection in old - new:
        key = f"{adapter}/{collection}"
        assert key in DELIBERATELY_DROPPED or key in NOT_YET_PORTED, key


# ── the three tables one derivation now feeds ─────────────────────────────


def _table_collections(path: Path, name: str) -> dict[str, list[str]]:
    """The `collections` members of a driver table, by AST. Returns {} for
    a table whose entries carry none — which is the desired end state for
    LIVE, whose served sets derive from the register."""
    tree = ast.parse(path.read_text())
    out: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            for key, value in zip(node.value.keys, node.value.values):
                for k, v in zip(value.keys, value.values):
                    if getattr(k, "value", None) == "collections":
                        out[key.value] = ast.literal_eval(v)
    return out


def _table_keys(path: Path, name: str) -> set[str]:
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == name for t in node.targets
        ):
            return {key.value for key in node.value.keys}
    raise AssertionError(f"{path} no longer defines {name}")


def test_the_comparator_no_longer_carries_its_own_list() -> None:
    """SERVES was a second list of what a collector answers for, filled in
    with what the port implemented. It is dead; the comparator derives its
    work from the register, and a resurrected table would be the defect
    returning under its old name."""
    source = (REPO / "harness" / "bin" / "se-compare").read_text()
    assert "comparator_work" in source
    assert re.search(r"^SERVES\s*=", source, re.M) is None, (
        "se-compare has grown a SERVES table again; the work list derives "
        "from the register and a hand list beside it WILL drift"
    )


def test_the_live_driver_serves_the_register_not_a_list() -> None:
    """LIVE's entries say HOW to drive an adapter, never WHICH collections
    it answers for — that is the register's, and a `collections` member
    reappearing would be the three-agreeing-lists defect returning."""
    path = REPO / "harness" / "bin" / "se-live-reference"
    assert _table_collections(path, "LIVE") == {}, (
        "a LIVE entry carries its own collections list again"
    )
    assert "comparator_work" in path.read_text()
    assert _table_keys(path, "LIVE") == set(OLD), (
        "every reference adapter must have a LIVE driving entry — a missing "
        "one silently excludes that collector from every live comparison"
    )


def test_the_replay_seam_stages_what_the_register_compares() -> None:
    """The replay seam physically stages payloads per adapter, so its list
    survives — but held to the register, not to its siblings: SEAM must
    stage exactly the compared set for every collector that has a seam,
    and only NO_REPLAY_SEAM may excuse one that does not."""
    seam = _table_collections(
        REPO / "harness" / "bin" / "se-reference-collector", "SEAM")
    work = register.comparator_work()
    missing = set(work) - set(seam)
    assert missing == set(NO_REPLAY_SEAM), (
        f"collectors with no replay seam: {sorted(missing)}; excused: "
        f"{sorted(NO_REPLAY_SEAM)} — an unexcused gap is a collector the "
        "corpus venues silently skip, and a stale excuse is owed work "
        "hidden as a decision"
    )
    for collector, staged in sorted(seam.items()):
        assert sorted(staged) == sorted(work[collector]["compare"]), (
            f"{collector}: the seam stages {sorted(staged)}, the register "
            f"compares {sorted(work[collector]['compare'])}"
        )


# ── the gap register: 27 rows, probed in both directions ──────────────────


def test_the_register_is_fully_encoded() -> None:
    """Anti-vacuity for the register itself: 27 rows, numbered without gap
    or duplicate, every row owned, every probe-less row saying why."""
    numbers = [row.number for row in REGISTER]
    assert numbers == list(range(1, 28)), numbers
    for row in REGISTER:
        assert row.state in ("built", "owed"), (row.number, row.state)
        assert row.owner.strip(), row.number
        assert len(row.coverage.strip()) >= 30, (
            f"row {row.number}: a probe's coverage — or the reason there is "
            "none — must actually be stated"
        )


@pytest.mark.parametrize("row", [r for r in REGISTER if r.probe],
                         ids=lambda r: f"row-{r.number}")
def test_a_probed_row_matches_the_tree(row) -> None:
    """Both directions at once. A row claiming built whose probe fails is
    an over-claim — gate 3's shape. A row claiming owed whose probe passes
    is a stale register — the shape that let a hole be forgotten twice.
    Either way the fix is the same: look, then update the register row."""
    built = row.probe()
    assert built == (row.state == "built"), (
        f"register row {row.number} ({row.item}) says {row.state!r} and the "
        f"tree says {'built' if built else 'not built'}. Coverage of this "
        f"probe: {row.coverage}"
    )


def test_the_registers_known_rows_read_as_expected() -> None:
    """Spot pins so a mass edit cannot silently renumber the register: the
    two R1 rows are built, the resource measurement is owed in R5's gate,
    and the two R2 rows are built by this phase."""
    by_number = {row.number: row for row in REGISTER}
    assert by_number[4].state == "built" and "R1" in by_number[4].owner
    assert by_number[5].state == "built" and "R1" in by_number[5].owner
    assert by_number[24].state == "owed" and "gate" in by_number[24].owner
    assert by_number[26].state == "built" and "R2" in by_number[26].owner
    assert by_number[27].state == "built" and "R2" in by_number[27].owner


# ── the answer rulings (register row 26) ──────────────────────────────────


PRESETS = register.old_answer_presets()
DIVERGENCES = register.answer_divergences()


def test_every_preset_names_a_collection_something_serves() -> None:
    """A COLUMNS route naming a collection no adapter serves would fall out
    of every other guard here — caught as an orphan instead."""
    for route in PRESETS:
        adapter, collection = route.split("/", 1)
        assert collection in OLD.get(adapter, []), (
            f"{route}: the old UI carries a preset for a collection no "
            "adapter serves"
        )


def test_every_answer_divergence_is_ruled() -> None:
    """Deny-by-default over the argued presets: a ported collection whose
    answer differs from the old UI's COLUMNS entry — as ordered lists,
    because several presets argue their order — carries a ruling, or fails.
    Coverage: presets only; a port collection the old UI had no preset for
    has nothing argued to diverge from, and an unported preset is owned by
    its NOT_YET_PORTED entry until the collection exists to judge."""
    unruled = sorted(set(DIVERGENCES) - set(ANSWER_RULINGS))
    assert not unruled, (
        "these answer lists diverge from the old UI's argued preset and "
        "nothing rules on it:\n  " + "\n  ".join(
            f"{route}: reference {DIVERGENCES[route]['reference']} vs port "
            f"{DIVERGENCES[route]['port']}" for route in unruled) +
        "\n\nAdd each to ANSWER_RULINGS as ruled (with the ground) or owed "
        "(with the phase). Silence is how fourteen of these sat behind a "
        "green gate."
    )


def test_every_answer_ruling_still_has_its_divergence() -> None:
    """The staleness direction: a ruling whose divergence has healed — the
    port now matches the preset, or the preset moved — is a record of a
    decision about nothing, and it would hide a NEW divergence arriving
    under the same route."""
    stale = sorted(set(ANSWER_RULINGS) - set(DIVERGENCES))
    assert not stale, f"these rulings have no divergence left to rule: {stale}"


def test_every_answer_ruling_is_ruled_or_owed() -> None:
    """A ruling is a decision with a ground, or owed work with an owner —
    never a bare acknowledgement, which is the follow-up-promise shape this
    estate has measured the worth of."""
    for route, text in sorted(ANSWER_RULINGS.items()):
        assert text.startswith(("ruled: ", "owed: ")), (
            f"{route}: a ruling starts with its disposition, "
            f"got {text[:40]!r}"
        )
        if text.startswith("owed: "):
            assert re.search(r"R[0-9]\w*", text), (
                f"{route}: owed work names the phase that owns it"
            )


def test_an_agreeing_preset_exists() -> None:
    """Anti-vacuity for the divergence computation: if NO route matches its
    preset exactly, the comparison is producing garbage (a parse artefact
    would differ everywhere) rather than measuring agreement."""
    agreeing = [
        route for route in PRESETS
        if route not in DIVERGENCES
        and route.split("/", 1)[1] in NEW.get(route.split("/", 1)[0], {})
    ]
    assert agreeing, (
        "no ported collection matches its old preset at all — the parse or "
        "the mapping has gone blind, and every ruling above is judging noise"
    )
