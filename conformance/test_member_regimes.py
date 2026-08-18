"""Every declared stream member is judged in one of two regimes (DESIGN 19).

Byte-compared, or rule-governed — never neither. An earlier harness dropped
seven members from comparison on the promise that "something else checks
them", and for five of the seven nothing did; the invariant was prose, so it
failed a code review instead of a test. These tests make it fail a test: the
enumeration walks the contract itself, so a member added to the wire lands in
a regime before it lands in a corpus, and every rule RULED names is proven
reachable by feeding check_stream the violation it exists to catch.

Deliberately corpus-free: the property under test belongs to the judge, and
must hold — and be checkable — while the corpus is mid-regeneration.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from se_harness import replay

REPO = Path(__file__).resolve().parent.parent
STREAM = json.loads((REPO / "contract" / "se.stream.1.json").read_text())


def record_types() -> list[str]:
    """The wire's record types are the oneOf alternatives, not all of $defs —
    the defs also hold shared shapes (name families, fact maps) that are
    members of records, never records themselves."""
    return sorted(
        alternative["$ref"].rsplit("/", 1)[-1] for alternative in STREAM["oneOf"]
    )


def declared_members() -> list[tuple[str, str]]:
    """Every (record_type, member) pair the wire contract declares."""
    return [
        (record_type, member)
        for record_type in record_types()
        for member in sorted(STREAM["$defs"][record_type]["properties"])
    ]


def _varying() -> set[tuple[str, str]]:
    return {
        (record_type, member)
        for record_type, members in replay.RUN_VARYING.items()
        for member in members
    }


# ── the enumeration is exhaustive and honest ─────────────────────────────


@pytest.mark.parametrize(
    "record_type,member", declared_members(), ids=lambda p: p if isinstance(p, str) else ""
)
def test_every_declared_member_is_in_exactly_one_regime(record_type, member) -> None:
    """Deny-by-default over the record itself.

    Not over the members someone remembered to worry about: the walk is the
    contract's, so escaping both regimes requires editing the wire schema,
    at which point this test names the member and demands a decision.
    """
    if (record_type, member) in _varying():
        assert (record_type, member) in replay.RULED, (
            f"{record_type}.{member} is dropped from the byte diff and RULED "
            "names no rule for it — a member in neither regime is a free-fire "
            "zone for every wrong value a port can put there (DESIGN 19)"
        )
    else:
        assert (record_type, member) not in replay.RULED, (
            f"{record_type}.{member} is byte-compared, yet RULED claims a "
            "rule for it — a stale entry teaches a reader the wrong regime"
        )


def test_ruled_and_run_varying_agree_exactly() -> None:
    """The two tables are one enumeration written twice, so they must match
    key-for-key — a rule with no member and a member with no rule are the
    same defect seen from either end."""
    assert _varying() == set(replay.RULED)


def test_run_varying_names_only_declared_members() -> None:
    """A typo in RUN_VARYING silently byte-compares the real member and
    'rules' a phantom one; walking the contract catches both at once."""
    assert _varying() <= set(declared_members()), (
        "RUN_VARYING names members the wire contract does not declare"
    )


# ── every named rule actually fires ──────────────────────────────────────


def _stream(issued: dict[str, int]) -> list[dict]:
    """A minimal stream check_stream accepts in full — the positive control
    every violation below is one mutation away from."""
    return [
        {
            "record": "begin",
            "request": "replay",
            "batch": "replay",
            "declaration": "sha256:replay",
            # the reference's own replay constant: valid v4 shape, obviously
            # synthetic — the shape rule must accept it or every corpus pair
            # fails its own judge
            "boot_id": "5e000000-0000-4000-8000-000000000001",
            "timens": 0,
            "instance": None,
            "generations": dict(issued),
        },
        {
            "record": "object",
            "collection": "pools",
            "name": "a",
            "facts": {"Health": "ONLINE"},
            "at": 1.0,
        },
        {
            "record": "commit",
            "collection": "pools",
            "generation": issued["pools"],
            "objects": 1,
            "assertions": 0,
            "unobservable": 0,
            "cpu_ms": 0.5,
        },
        {
            "record": "end",
            "request": "replay",
            "batch": "replay",
            "cpu_ms": 0.5,
            "wall_ms": 1.0,
        },
    ]


# One violation per ruled member: the mutation a wrong collector would make.
# Keyed identically to RULED so a member gaining a rule without gaining a
# proof fails below rather than passing on the table's say-so.
VIOLATIONS = {
    ("begin", "request"): lambda s: s[0].__setitem__("request", ""),
    ("begin", "batch"): lambda s: s[0].__setitem__("batch", ""),
    ("begin", "boot_id"): lambda s: s[0].__setitem__("boot_id", ""),
    # the declaration a collector never published: a batch whose contract
    # cannot be named leaves the collator refetching on every collect or
    # trusting one it never saw
    ("begin", "declaration"): lambda s: s[0].__setitem__("declaration", None),
    # minted, not echoed — the numbers a collector invents instead of parsing
    ("begin", "generations"): lambda s: (
        s[0].__setitem__("generations", {"pools": 1}),
        s[2].__setitem__("generation", 1),
    ),
    # epoch seconds: the stamp a port reaches for first
    ("object", "at"): lambda s: s[1].__setitem__("at", 1.7e9),
    ("commit", "generation"): lambda s: s[2].__setitem__("generation", 424242),
    ("commit", "cpu_ms"): lambda s: s[2].__setitem__("cpu_ms", float("nan")),
    ("end", "request"): lambda s: s[3].__setitem__("request", "rq-other"),
    ("end", "batch"): lambda s: s[3].__setitem__("batch", "b-other"),
    ("end", "cpu_ms"): lambda s: s[3].__setitem__("cpu_ms", -1.0),
    ("end", "wall_ms"): lambda s: s[3].pop("wall_ms"),
}


def test_the_control_stream_is_clean() -> None:
    """Without this, every reachability proof below could be finding some
    unrelated defect in the fixture rather than the rule it names."""
    issued = replay.issue_generations(["pools"], seed="regime-control")
    assert not replay.check_stream(_stream(issued), issued)


@pytest.mark.parametrize(
    "record_type,member",
    sorted(replay.RULED),
    ids=lambda p: p if isinstance(p, str) else "",
)
def test_the_named_rule_is_reachable(record_type, member) -> None:
    """RULED's word is checked, not taken: feed the violation, find the rule's
    name in a problem string. A table entry naming a rule that cannot fire is
    the original defect — 'something else checks it' — wearing a label."""
    assert (record_type, member) in VIOLATIONS, (
        f"{record_type}.{member} joined RULED without a violation proving its "
        "rule fires — a guard ships with the demonstration it discriminates"
    )
    issued = replay.issue_generations(["pools"], seed="regime-control")
    records = _stream(issued)
    VIOLATIONS[(record_type, member)](records)
    problems = replay.check_stream(records, issued)
    name = replay.RULED[(record_type, member)]
    assert any(name in problem for problem in problems), (
        f"{record_type}.{member}: violating it raised no problem containing "
        f"{name!r} — got {problems}"
    )


@pytest.mark.parametrize(
    "boot_id",
    [
        # the exploit that reopened the repair: constant AND plausible-shaped
        # — nil passed a rule that only refused blank. The shape rule's whole
        # adjudication (DESIGN 19) is that nil and the stub are what one
        # capture CAN catch; a constant VALID id is a cross-boot variant's.
        "00000000-0000-0000-0000-000000000000",
        "replay",  # the reference's own historic stub — the original hole
        "5e000000-0000-4000-8000",  # truncated: a UUID that lost a group
        # 32 hex, no dashes: /etc/machine-id's spelling — the id a port
        # reaches for when it wanted /proc/sys/kernel/random/boot_id
        "5e000000000040008000000000000001",
    ],
)
def test_a_nil_or_misshapen_boot_id_is_refused(boot_id: str) -> None:
    """The blank-only rule was a subset guard: it enumerated the wrong values
    its author foresaw (missing, "", non-string) and reported success about
    every other stub. UUID shape plus not-nil is the deny-by-default form —
    and the honest bound, since single-capture physics cannot tell a constant
    valid id from a real one (DESIGN 19)."""
    issued = replay.issue_generations(["pools"], seed="regime-control")
    records = _stream(issued)
    records[0]["boot_id"] = boot_id
    problems = replay.check_stream(records, issued)
    name = replay.RULED[("begin", "boot_id")]
    assert any(name in problem for problem in problems), (
        f"boot_id {boot_id!r} passed check_stream — got {problems}"
    )


def test_issue_generations_is_deterministic_seeded_and_strided() -> None:
    """Both sides of the wire implement `collect <name>:<gen>` from the same
    deterministic issuance — sorted collections, per-seed base + 17*i. The
    exact-value assertion this replaces pinned the OLD rule, 100 + 17*i,
    whose base was the constant the echo guard could never catch: every
    variant opened one collection, so every request issued 100 and a
    collector echoing 100 passed every channel. What is pinned now is the
    property set, corpus-free — determinism (a committed pair must be
    reproducible), seed-variance (no constant passes everywhere; the
    corpus-backed disjointness half lives in test_corpus_replay), the
    stride (a second collection takes base + 17 — no committed pair opens
    two collections yet, so this table and test_reference_honesty's direct
    two-collection request are what exercise it), and the exclusion of 0
    and 100, the two constants shipped adversaries actually echo."""
    seeds = ("storage/healthy", "network/healthy", "network/goto")
    bases = {}
    for seed in seeds:
        issued = replay.issue_generations(["b", "a", "c"], seed=seed)
        assert issued == replay.issue_generations(["c", "b", "a"], seed=seed), (
            "issuance is not deterministic over collection order"
        )
        base = issued["a"]
        assert issued == {"a": base, "b": base + 17, "c": base + 34}, (
            f"the stride moved: {issued}"
        )
        assert not any(v in (0, 100) for v in issued.values()), (
            f"seed {seed} issued a shipped adversary's constant: {issued}"
        )
        bases[seed] = base
    assert len(set(bases.values())) == len(seeds), (
        f"distinct seeds share a base {bases} — a constant echoing it would "
        "pass more than one variant, which is the exact hole the seed closed"
    )
