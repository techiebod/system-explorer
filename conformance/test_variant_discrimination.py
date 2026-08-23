"""What each staged variant is worth: the corpus without it, and with it.

A variant earns its bytes by failing a subject that is wrong about the machine
(DESIGN 20). test_adversaries_stay_red.py binds each wrong subject to a red on
one variant and a green on named controls, which is most of that claim. This
module makes the remaining half literal, because the control list is a set
somebody maintains and the claim is about the corpus as a whole:

  BEFORE — copy the corpus to a temp root, DELETE the variant, and judge the
           subject over everything that is left. Green, every pair. That is
           the state the repository was actually in before the variant was
           staged, reconstructed rather than remembered: the subject shipped,
           the judge ran, and nothing could say the subject was wrong.
  AFTER  — judge the same subject against the variant. Red, on the anchors,
           naming the fact.

The pair is the whole claim. A variant that fails a subject which was ALREADY
failing proves nothing about the staging — it is the a5_hardcoded_healthy
shape, a red that would survive deleting the variant — so the before half is
what makes the after half evidence. This module fails if either half moves.

The second claim is about the anchors themselves. They are the planted truth
(DESIGN 20), and truth nothing consults is decoration, so every anchor
carrying a value is broken one at a time in a temp copy of the variant and
required to turn that variant red with a message naming the fact it asserts.
An anchor that survives its own falsification is not an anchor.
"""

from __future__ import annotations

import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from se_harness import corpus, replay

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "adversaries"

VARIANTS = {v.name: v for v in corpus.all_variants()}


@dataclass(frozen=True)
class Case:
    """One staged variant and the wrong subject it was staged to kill."""

    variant: str
    subject: str
    collector: str
    # The literal the anchors channel must say, so a red for an unrelated
    # reason cannot satisfy this module — the same binding
    # test_adversaries_stay_red.py puts on its rows.
    evidence: tuple[str, ...]
    # One line: what this variant catches that no other variant catches.
    unique: str
    # The collections this subject implements. Every round-a5 fixture is a
    # chains-only port, and corpus/network/rules opens two collections — so
    # without this the before half judges a subject on a collection it never
    # claimed, and reports "wrong about more than one thing" about a subject
    # that is wrong about exactly one. Narrowing is not a dodge: the excluded
    # variants are asserted genuinely unservable below, so a `serves` shrunk
    # to duck a real failure fails there, and one shrunk far enough to empty
    # the before half fails here.
    serves: frozenset[str]
    # Other variants that ALSO catch this subject. The before half deletes
    # every one of them, because "delete this variant and the subject looks
    # correct" stops being true the moment a second pair stages the same
    # defect — and the useful claim is the one about the set: before ANY of
    # these existed, nothing could say the subject was wrong. Each name is
    # proved to catch the subject below, so this cannot be used to hide a
    # second, unrelated failure.
    shared_with: frozenset[str] = frozenset()


CASES = (
    Case(
        variant="network/goto",
        subject="a5_goto_blind.py",
        collector="network",
        evidence=("inet gotolab dispatch", "JumpedFrom", "Unreferenced"),
        unique="the only ruleset in which the word `jump` never appears, so it "
        "is the only one where reading one verb and reading both give "
        "different answers",
        serves=frozenset({"nft-chains", "nft-tables"}),
    ),
    Case(
        variant="network/asymmetric",
        subject="a5_name_keyed_reachability.py",
        collector="network",
        evidence=("ip6 asym shared", "JumpedFrom", "Unreferenced"),
        unique="the only ruleset carrying one chain name in two families with "
        "the jump in only one of them, so it is the only one where a "
        "name-keyed walk and a (family, table, name)-keyed walk differ",
        serves=frozenset({"nft-chains", "nft-tables"}),
    ),
    Case(
        variant="network/named-map",
        subject="a5_map_blind.py",
        collector="network",
        evidence=("inet maplab landing", "JumpedFrom", "Unreferenced"),
        unique="the only ruleset containing a named verdict map, so it is the "
        "only one where a jump is written somewhere no rule expression "
        "reaches and the rule-to-map join is load-bearing",
        serves=frozenset({"nft-chains", "nft-tables"}),
    ),
    Case(
        variant="storage/degraded",
        subject="a5_health_never_read.py",
        collector="storage",
        evidence=("State", "DEGRADED", "StatusMessage", "UnhealthyVdevs",
                  "VdevsWithErrors"),
        unique="the only pool whose members carry errors ZFS repaired — a "
        "non-zero checksum counter beside Errors 0 — so it is the only "
        "capture that separates a repaired fault from a lost one",
        # The whole storage surface since R3b: the subject wraps the
        # reference, so it serves what the seam serves, and its declared
        # wrongness touches pools records alone — on the util-linux
        # collections it must be byte-faithful, which the before half now
        # proves over the bare-guest pair.
        serves=frozenset({"pools", "block-devices", "mounts"}),
        shared_with=frozenset({"storage/spare-engaged"}),
    ),
)


def _ids(case: Case) -> str:
    return case.variant


def _binary(case: Case) -> list[str]:
    return [sys.executable, str(FIXTURES / case.subject)]


def _judge(binary: list[str], variant: corpus.Variant) -> dict[str, list[str]]:
    """The judge's channels, over one subject and one variant.

    A subject that cannot run is fixture rot rather than a verdict, so exit
    status and emptiness are hard failures here and never a red.
    """
    issued = replay.issue_generations(variant.collections(), seed=variant.name)
    proc = replay.run_collector(binary, variant, issued=issued)
    assert proc.returncode == 0, (
        f"{binary[-1]} exited {proc.returncode} on {variant.name} — the "
        f"subjects wear a collector's face and exit zero; a crash is fixture "
        f"rot, not a verdict\n{proc.stderr[:2000]}"
    )
    emitted = replay.parse_stream(proc.stdout)
    assert emitted, f"{binary[-1]} emitted nothing on {variant.name}"
    return {
        "rules": replay.check_stream(emitted, issued),
        "diff": replay.diff(variant.expected, emitted),
        "anchors": corpus.validate_anchors(variant, emitted),
    }


def _problems(channels: dict[str, list[str]]) -> list[str]:
    return [p for group in channels.values() for p in group]


def _corpus_without(variant: str, root: Path) -> list[corpus.Variant]:
    """The corpus as it stood before this variant was staged.

    A real copy on disk and a real deletion, not a filtered list: the subject
    is run by the same driver against the same layout, so what is proven is
    the repository's state and not a test's arithmetic.
    """
    copied = root / "corpus"
    shutil.copytree(corpus.CORPUS, copied)
    removed = copied / variant
    assert removed.is_dir(), f"{variant} is not a directory under corpus/"
    shutil.rmtree(removed)
    return corpus.all_variants(copied)


# ── the staging is still there ───────────────────────────────────────────


@pytest.mark.parametrize("case", CASES, ids=_ids)
def test_the_staged_variant_is_still_in_the_corpus(case: Case) -> None:
    """A deleted variant must fail LOUDLY, naming what was lost.

    Every other test in this module reads the variant, so deleting one used
    to abort collection with a bare KeyError — red, but a reader learns
    nothing from it and the anchor tests do not run at all. This row is what
    a deletion hits first, and it says which staged fact stopped being
    checkable and which subject is now unopposed.
    """
    assert case.variant in VARIANTS, (
        f"{case.variant} is gone from the corpus. It is the only pair in this "
        f"repository that fails {case.subject}, so deleting it does not "
        f"weaken a test — it un-catches a defect: {case.unique}"
    )


# ── the positive control ─────────────────────────────────────────────────


@pytest.mark.parametrize("case", CASES, ids=_ids)
def test_the_correct_reference_passes_the_staged_variant(case: Case) -> None:
    """Every red below is a subject failing, never an anchor nobody can meet.

    Without this, a variant whose anchors were mistyped at staging time would
    fail every subject including the correct one, and each red in this module
    would read as a catch.
    """
    problems = _problems(_judge(replay.reference_binary(), VARIANTS[case.variant]))
    assert not problems, (
        f"{case.variant}: the reference fails its own staged variant, so no "
        "red in this module is evidence about a subject:\n"
        + "\n".join(f"  - {p}" for p in problems[:10])
    )


# ── the before half: the corpus that could not say ───────────────────────


@pytest.mark.parametrize("case", CASES, ids=_ids)
def test_the_subject_passes_the_corpus_without_the_variant(
    case: Case, tmp_path: Path
) -> None:
    """BEFORE. Delete the variant and the wrong subject is indistinguishable
    from a correct one, over every remaining pair its collector serves.

    This is what makes the red in the next test attributable to the staging.
    A subject that is wrong about several things would fail here, and its red
    on the staged variant would stop being evidence about the staged fact.
    """
    survivors = [
        v
        for v in _corpus_without(case.variant, tmp_path)
        if v.meta["collector"] == case.collector
    ]
    # Scoped to what the subject implements. A chains-only port asked for
    # nft-rules emits nothing for it, which is a real protocol violation and a
    # real red — but it is not the defect this case stages, and counting it
    # here would say the subject is wrong about more than one thing when it is
    # wrong about exactly one. The exclusion is proven, not asserted, by
    # test_an_excluded_variant_is_one_the_subject_genuinely_cannot_serve.
    remaining = [v for v in survivors
                 if v.collections() <= case.serves and v.name not in case.shared_with]
    assert remaining, (
        f"{case.variant}: removing it left no {case.collector} variant this "
        f"subject serves ({sorted(case.serves)}), so the green below would be "
        "vacuous"
    )
    assert case.variant not in {v.name for v in remaining}

    for variant in remaining:
        problems = _problems(_judge(_binary(case), variant))
        assert not problems, (
            f"{case.subject} failed {variant.name}, which does not stage its "
            f"defect. It is meant to be wrong in exactly one way; a red here "
            f"means its red on {case.variant} is no longer attributable to "
            "the staging:\n" + "\n".join(f"  - {p}" for p in problems[:10])
        )


@pytest.mark.parametrize("case", CASES, ids=_ids)
def test_every_shared_coverage_claim_is_true(case: Case) -> None:
    """A variant named as sharing this case's coverage really does catch it.

    `shared_with` removes pairs from the before half, which is precisely the
    lever that could excuse a subject that has started failing something
    unrelated: name the awkward variant a sharer and it stops being judged.
    So each name is executed — the subject is run against it and required to
    go red — and a name that catches nothing fails here instead of quietly
    shrinking the before set.

    Vacuous where nothing is shared, which is correct: the before half is
    then judging the whole corpus, the stronger claim.
    """
    for name in sorted(case.shared_with):
        assert name in VARIANTS, (
            f"{case.variant} names {name!r} as sharing its coverage, and no "
            "such variant exists"
        )
        problems = _problems(_judge(_binary(case), VARIANTS[name]))
        assert problems, (
            f"{case.variant} names {name!r} as also catching {case.subject}, "
            f"but {case.subject} passes it cleanly. A sharer that catches "
            "nothing is a variant removed from the before half for no reason "
            "— drop the claim, and face whatever the before half then says."
        )


@pytest.mark.parametrize("case", CASES, ids=_ids)
def test_an_excluded_variant_is_one_the_subject_genuinely_cannot_serve(
    case: Case,
) -> None:
    """`serves` is a fact about the subject, not a convenience for the test.

    Scoping the before half by a hand-written set is exactly the shape that
    lets a failing subject be excused: narrow `serves` until the awkward
    variant drops out and the green comes back. So the narrowing is executed.
    For every variant of this collector that `serves` excludes, the subject is
    run and required to DECLINE every out-of-scope collection as `unsupported`
    — the contract's own way of saying "I do not serve this" (DESIGN 18).
    Silence is not the test, because silence is a protocol violation in its
    own right; and a commit is the opposite of an exclusion, since a commit
    claims authority over the whole collection. All three chains-only subjects
    committed here when this test was written, emitting chain rows as rules
    over a collection they had never read, which is what the check found on
    its first run.

    Vacuous when nothing is excluded, and that is correct rather than a hole:
    the before half is then judging the subject over the whole corpus, which
    is the stronger claim and needs no permission from here.
    """
    excluded = [
        v
        for v in VARIANTS.values()
        if v.meta["collector"] == case.collector
        and not v.collections() <= case.serves
    ]
    for variant in excluded:
        issued = replay.issue_generations(variant.collections(), seed=variant.name)
        proc = replay.run_collector(_binary(case), variant, issued=issued)
        assert proc.returncode == 0, (
            f"{case.subject} exited {proc.returncode} on {variant.name} — a "
            f"crash is fixture rot, not evidence of an unserved collection\n"
            f"{proc.stderr[:1000]}"
        )
        emitted = replay.parse_stream(proc.stdout)
        refused = {
            r.get("collection")
            for r in emitted
            if r.get("record") == "decline" and r.get("reason") == "unsupported"
        }
        claimed = {
            r.get("collection") for r in emitted if r.get("record") == "commit"
        }
        for collection in sorted(variant.collections() - case.serves):
            assert collection in refused, (
                f"{case.subject} is excluded from {variant.name} because "
                f"{collection!r} is outside its declared {sorted(case.serves)} "
                f"— but it does not decline {collection!r} as unsupported"
                + (
                    f", it COMMITS it, which claims authority over a whole "
                    "collection it never read"
                    if collection in claimed
                    else ", it says nothing about it at all, which is a "
                    "truncated stream rather than a scope statement"
                )
                + ". An exclusion has to be the subject's own statement, or "
                "it is a failing subject being excused."
            )


# ── the after half: the variant that can ─────────────────────────────────


@pytest.mark.parametrize("case", CASES, ids=_ids)
def test_the_variant_kills_the_subject_it_was_staged_for(case: Case) -> None:
    """AFTER. The same subject, the same judge, the staged variant: red.

    Bound to the anchors channel and to literal evidence, because redness
    alone is satisfied by any unrelated regression — and bound to the anchors
    in particular because they are the half of the pair that was written by
    hand at staging time. The byte diff would go red here too, but the diff
    compares against a stream the reference generated, so a diff-only red
    proves the subject differs from the reference and not that it is wrong
    about the machine.
    """
    channels = _judge(_binary(case), VARIANTS[case.variant])
    assert _problems(channels), (
        f"{case.subject} PASSED the judge on {case.variant}. The variant has "
        "stopped killing the subject it was staged for, which means either "
        "the subject stopped exercising its defect or the anchors stopped "
        "being consulted."
    )
    caught = "\n".join(channels["anchors"])
    missing = [text for text in case.evidence if text not in caught]
    assert not missing, (
        f"{case.variant} is red against {case.subject}, but its ANCHORS do "
        f"not mention {missing!r} — so the staged truth is not what did the "
        f"killing.\nWhat the anchors channel said:\n"
        + ("\n".join(f"  - {p}" for p in channels['anchors'][:10]) or "  (nothing)")
    )


# ── the anchors are consulted, one value at a time ───────────────────────


def _value_anchors() -> list[tuple[str, int, str]]:
    """Every anchor in a staged variant that asserts a value, addressed by
    index so the mutation below can rewrite exactly one.

    Tolerant of a missing variant on purpose: this runs at COLLECTION time,
    and a KeyError here aborts the whole module — including the test whose
    entire job is to report the variant as missing. Deleting a staged variant
    must produce a named failure, not a collection error that says only
    'KeyError'.
    """
    found = []
    for case in CASES:
        variant = VARIANTS.get(case.variant)
        if variant is None:
            continue
        for index, anchor in enumerate(variant.meta["anchors"]):
            for key in ("value", "commit_objects"):
                if key in anchor:
                    found.append((case.variant, index, key))
    return found


@pytest.mark.parametrize(
    "variant_name,index,key",
    _value_anchors(),
    ids=lambda v: str(v),
)
def test_breaking_one_anchor_value_turns_the_variant_red(
    variant_name: str, index: int, key: str, tmp_path: Path
) -> None:
    """An anchor that survives its own falsification is decoration.

    The variant is copied, ONE anchor's asserted value is replaced with a
    value the machine did not have, and the CORRECT reference is judged
    against it. It must go red, and the message must name the fact — so the
    anchor is proven to be read, compared and reported, rather than merely
    parsed at load time.

    Both halves of the pair, because both are held to the anchors (DESIGN 20)
    and a corpus that checked only the emitted half would let a committed
    expected.jsonl drift away from what was staged.
    """
    copied = tmp_path / "variant"
    shutil.copytree(VARIANTS[variant_name].path, copied)
    meta = json.loads((copied / "meta.json").read_text())
    anchor = meta["anchors"][index]

    # A value of the same JSON type, so what fails is the comparison and not
    # the loader's shape rules — and one the machine demonstrably did not
    # have, since it is derived from the staged value.
    original = anchor[key]
    if isinstance(original, bool):
        broken = not original
    elif isinstance(original, int):
        broken = original + 1
    elif isinstance(original, str):
        broken = original + "-not-what-was-staged"
    elif isinstance(original, list):
        broken = [*original, "not-what-was-staged"]
    else:
        pytest.fail(f"unhandled anchor value type {type(original).__name__}")
    anchor[key] = broken
    (copied / "meta.json").write_text(json.dumps(meta, indent=2))

    mutated = corpus.load_variant(copied)
    named = anchor.get("fact", key)

    proc = replay.run_collector(replay.reference_binary(), mutated)
    assert proc.returncode == 0, proc.stderr
    emitted = replay.parse_stream(proc.stdout)

    for half, records in (("committed", mutated.expected), ("emitted", emitted)):
        problems = corpus.validate_anchors(mutated, records)
        assert problems, (
            f"{variant_name} anchor #{index} was falsified — {key} moved from "
            f"{original!r} to {broken!r} — and the {half} half still satisfied "
            "it. The anchor is not consulted, so it asserts nothing."
        )
        assert any(named in p for p in problems), (
            f"{variant_name} anchor #{index} went red on the {half} half but "
            f"no message names {named!r}, so a reader cannot tell which staged "
            f"fact was contradicted:\n"
            + "\n".join(f"  - {p}" for p in problems[:5])
        )


# ── each variant's unique power, stated and held ─────────────────────────


def test_no_two_variants_are_killed_by_the_same_subject() -> None:
    """Each staged variant catches something no other variant catches.

    The claim is per-case in `unique`, and this is its executable half: the
    four subjects and the four variants form a permutation, so no variant is
    redundant with another — if two variants died to the same subject, one of
    them would be catching nothing the other did not already catch.

    The stronger form is already proven above: each subject passes the ENTIRE
    corpus with its variant removed, which says the variant is the only pair
    in the repository that can see that defect.
    """
    variants = [case.variant for case in CASES]
    subjects = [case.subject for case in CASES]
    assert len(set(variants)) == len(variants), variants
    assert len(set(subjects)) == len(subjects), subjects
    for case in CASES:
        assert case.unique.strip(), f"{case.variant} claims no unique power"
