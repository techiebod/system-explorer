"""The replay harness, and the two acceptance items it exists to satisfy.

Acceptance item 8 — corpus replay is non-vacuous: an empty environment cannot
produce a green run. This is the item the harness is most likely to fail
silently, because the failure looks exactly like success: a suite that runs
nothing, asserts nothing about what it did not reach, and reports a pass. The
tests below try to make that happen and require it not to.

Acceptance item 11 — planted canary credentials appear in no output channel.
The channels that exist at this phase are the emitted stream and the
collector's stderr; evidence, decline detail and the journal join as the
components carrying them are built.

Everything here drives a collector as a *binary* over stdin and stdout. No
test imports a collector, calls into one, or knows what language it was
written in — which is what keeps these checks usable when the collectors are
Go and the harness is still Python.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from se_harness import corpus, replay

REPO = Path(__file__).resolve().parent.parent
REFERENCE = REPO / "harness" / "bin" / "se-reference-collector"

VARIANTS = corpus.all_variants()


def _binary_for(variant: corpus.Variant) -> list[str]:
    """The collector under test.

    Today every variant replays against the reference implementation, because
    no Go collector exists yet. As each is ported this resolves to the ported
    binary and the assertions below do not change — which is the point of
    checking the outside of the process.
    """
    return [sys.executable, str(REFERENCE)]


def _run(variant: corpus.Variant, payload_dir=None) -> subprocess.CompletedProcess:
    """Drive the module's own entry point.

    One code path, deliberately: an earlier split had the tests setting the
    clock pin and replay.run_collector not, so the published API silently
    dropped the determinism the suite depends on and nothing noticed because
    nothing called it.
    """
    return replay.run_collector(_binary_for(variant), variant, payload_dir)


def _validator():
    registry = Registry()
    for path in sorted((REPO / "contract").glob("*.json")):
        schema = json.loads(path.read_text())
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return Draft202012Validator(
        json.loads((REPO / "contract" / "se.stream.1.json").read_text()),
        registry=registry,
    )


def _assert_legal_stream(label: str, records: list[dict]) -> None:
    validator = _validator()
    for record in records:
        errors = sorted(validator.iter_errors(record), key=str)
        assert not errors, (
            f"{label}: {record.get('record')} record is not a legal stream "
            "record:\n" + "\n".join(f"- {e.json_path}: {e.message}" for e in errors)
        )


# ── the corpus is real ───────────────────────────────────────────────────


def test_the_corpus_is_not_empty() -> None:
    """Item 8's first arm: no variants means every replay test below is
    vacuous, and a suite that passes over an empty set is the exact shape
    this product refuses to ship."""
    assert VARIANTS, (
        "corpus/ holds no variants — every replay assertion would pass over "
        "nothing, which is a green run establishing precisely zero"
    )


def test_the_corpus_states_its_own_coverage() -> None:
    """A specimen shows one machine on one day (DESIGN 20). What the corpus
    covers has to be readable, not inferred from what happens to be there."""
    report = corpus.coverage(VARIANTS)
    assert report["collectors"], "coverage names no collectors"
    for collector, versions in report["source_versions"].items():
        assert all(versions), f"{collector}: a capture with no source version"


def test_coverage_says_what_a_re_stage_needs_where_it_needs_anything() -> None:
    """`regenerable` is a boolean and the truth is not (DESIGN 20).

    storage/degraded IS re-stageable, but only on a guest carrying OpenZFS
    >= 2.3: `zpool status -j` does not exist before it, and the lab's Ubuntu
    24.04 image ships 2.2.2, which produces no storage payload at all. A
    drift run on that guest regenerates the network variants, skips the
    storage one and presents a clean diff over a partial set — the failure
    DESIGN 20 names, wearing a green tick. So a variant may declare what a
    re-stage needs, and the coverage report must carry every such declaration
    rather than leaving it in a note nothing reads.
    """
    report = corpus.coverage(VARIANTS)
    declared = {
        v.name: v.meta["regenerable_on"]
        for v in VARIANTS
        if v.regenerable and v.meta.get("regenerable_on")
    }
    assert declared, (
        "no variant declares what a re-stage of it needs, so this check "
        "passes over nothing. The OpenZFS >= 2.3 constraint on the degraded "
        "pool is the case the field was added for — if it has genuinely gone "
        "away, the field goes with it rather than staying here unexercised"
    )
    assert report["regeneration_requires"] == declared, (
        "the coverage report dropped a stated regeneration constraint: "
        f"{sorted(set(declared) - set(report['regeneration_requires']))}"
    )


def test_the_named_residuals_are_stated_with_a_venue() -> None:
    """The net is named, so absence of a hole is never implied (DESIGN 20).

    A shape the corpus and the differential guard together cannot see must be
    stated with the venue that owns it — otherwise silence reads as coverage,
    which is the subset guard one level up. Deny-by-default over the ledger
    itself: an empty residual set, or one whose reason names no venue, fails
    rather than passing quietly.
    """
    residuals = corpus.coverage(VARIANTS)["named_residuals"]
    assert residuals, "no residual named — a corpus that claims to see everything"
    for name, reason in residuals.items():
        assert "Venue:" in reason or "venue" in reason, (
            f"{name}: a residual names the venue that owns its truth, or it is a "
            "hole dressed as a disclosure"
        )


def test_no_two_variants_issue_the_same_generation() -> None:
    """The property the seeded issuance exists for, asserted over the corpus
    that actually ships.

    The fixed rule it replaced issued the constant 100 to every
    single-collection variant, so the echo guard caught every invented
    constant except the one it issued — a declared-RED adversary passed
    every channel by changing its constant from 0 to 100, one character. The
    guard's teeth are distinctness: a constant can match at most one variant,
    so no baked-in number passes every pair. Distinctness alone does not make
    the request line the ONLY source of the issuance, though — the seed is
    variant.name, the payload directory spells it, and expected.jsonl sits
    beside it, so a collector that reconstructed either could echo the right
    value without ever reading stdin. What forecloses that is replay.run_collector
    replaying every variant from a sealed tempdir that names no variant and
    carries no expected.jsonl (see its docstring): the request line becomes
    the collector's only channel to the issued generation, and this test
    guards the distinctness that channel rests on. 0 and 100 — the two
    constants adversaries have actually shipped — are excluded from the
    issuable range by construction, and that exclusion is asserted here rather
    than trusted to the formula.
    """
    issued_by: dict[str, set[int]] = {
        v.name: set(replay.issue_generations(v.collections(), seed=v.name).values())
        for v in VARIANTS
    }
    for name, values in issued_by.items():
        assert 0 not in values and 100 not in values, (
            f"{name}: issued {sorted(values)} — 0 and 100 are the constants "
            "shipped adversaries echo, and the range must exclude them"
        )
    names = sorted(issued_by)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            shared = issued_by[a] & issued_by[b]
            assert not shared, (
                f"{a} and {b} both issue {sorted(shared)} — a constant "
                "echoing that value would pass both variants, and the "
                "issuance exists so no constant passes more than one"
            )


@pytest.mark.parametrize("variant", VARIANTS, ids=lambda v: v.name)
def test_expected_stream_validates_against_the_contract(variant) -> None:
    """The committed half of every pair is a legal stream.

    A corpus whose expected records could not travel the wire would train a
    collector to emit something the collator must reject.
    """
    _assert_legal_stream(f"{variant.name} (committed)", variant.expected)


@pytest.mark.parametrize("variant", VARIANTS, ids=lambda v: v.name)
def test_the_committed_half_obeys_the_stream_rules(variant) -> None:
    """The committed half is judged by the same rules as the emitted one.

    Two lines that close a whole class: without them, a corpus that violates
    a stream rule trains every collector to violate it too — the reference
    emits it, the pair agrees with itself, and the rule holds against
    everything except the standard the collectors are graded by.
    """
    issued = replay.issue_generations(variant.collections(), seed=variant.name)
    problems = replay.check_stream(variant.expected, issued)
    assert not problems, f"{variant.name} (committed) stream rules:\n" + "\n".join(
        f"  - {p}" for p in problems
    )


@pytest.mark.parametrize("variant", VARIANTS, ids=lambda v: v.name)
def test_anchors_hold_on_both_halves(variant) -> None:
    """The variant's planted truths bind both halves of the pair (DESIGN 20).

    The expected half is generated by the reference, so the halves agreeing
    proves determinism only — anchors are written at staging time, when
    ground truth is known independently of any implementation, and a
    reference that drifts from what was staged must fail its own corpus.
    """
    problems = corpus.validate_anchors(variant, variant.expected)
    assert not problems, f"{variant.name} (committed) anchors:\n" + "\n".join(
        f"  - {p}" for p in problems
    )
    proc = _run(variant)
    assert proc.returncode == 0, f"{variant.name}: collector exited {proc.returncode}"
    problems = corpus.validate_anchors(variant, replay.parse_stream(proc.stdout))
    assert not problems, f"{variant.name} (emitted) anchors:\n" + "\n".join(
        f"  - {p}" for p in problems
    )


# ── replay reproduces the pair ───────────────────────────────────────────


@pytest.mark.parametrize("variant", VARIANTS, ids=lambda v: v.name)
def test_replay_reproduces_the_committed_stream(variant) -> None:
    """Same payloads in, same records out — the whole of the seam."""
    proc = _run(variant)
    assert proc.returncode == 0, (
        f"{variant.name}: collector exited {proc.returncode}; non-zero means "
        f'"I could not run", never a decline.\n{proc.stderr[:2000]}'
    )
    emitted = replay.parse_stream(proc.stdout)
    assert emitted, f"{variant.name}: collector emitted nothing"

    # The EMITTED half, not only the committed one. normalise() drops
    # request/batch/boot_id so a collector could omit them forever and the
    # diff would never see it; schema validation is what restores presence.
    _assert_legal_stream(f"{variant.name} (emitted)", emitted)

    # The same issuance run_collector put on the request line: begin must
    # echo it exactly, so a collector minting its own generations fails
    # here even though the byte diff deliberately cannot see the values.
    issued = replay.issue_generations(variant.collections(), seed=variant.name)
    problems = replay.check_stream(emitted, issued)
    assert not problems, f"{variant.name} stream rules:\n" + "\n".join(
        f"  - {p}" for p in problems
    )

    differences = replay.diff(variant.expected, emitted)
    assert not differences, f"{variant.name}:\n" + "\n".join(
        f"  - {d}" for d in differences[:20]
    )


@pytest.mark.parametrize("variant", VARIANTS, ids=lambda v: v.name)
def test_replay_is_deterministic(variant) -> None:
    """Two runs of one variant agree.

    A harness whose verdict changes between runs teaches a reader to rerun
    until it passes, which is worse than having no harness.
    """
    first, second = _run(variant), _run(variant)
    assert first.stdout == second.stdout, (
        f"{variant.name}: replay is not deterministic — a fact derived against "
        "a live clock is the usual cause, and the corpus pins one for exactly "
        "this reason"
    )


# ── item 8: an empty environment cannot go green ─────────────────────────


def test_an_empty_environment_cannot_satisfy_a_variant_expecting_objects(
    tmp_path,
) -> None:
    """The load-bearing non-vacuity check.

    A collector with nothing to read *correctly* declines and exits zero — the
    design is explicit that non-zero means "I could not run", and a host
    without the interface ran perfectly well. So the exit code cannot be item
    8's guard, and treating it as one would forbid the honest behaviour.

    The guard is the **expectation**, which comes from the committed corpus
    rather than from the machine: a variant that expects objects is not
    satisfied by a decline. That is what stops a CI runner with none of the
    interfaces present from passing every collector at once, and it holds
    without punishing a collector for being truthful.
    """
    expecting_objects = [
        v for v in VARIANTS if any(r["record"] == "object" for r in v.expected)
    ]
    assert expecting_objects, "no variant expects objects; this check is vacuous"

    for variant in expecting_objects:
        # positive control: the same request against the real payloads passes,
        # so a collector that simply always fails cannot satisfy this test
        assert _run(variant).returncode == 0, (
            f"{variant.name}: the positive control failed, so the negative "
            "case below would prove nothing"
        )
        proc = _run(variant, payload_dir=tmp_path)
        emitted = replay.parse_stream(proc.stdout)
        differences = replay.diff(variant.expected, emitted)
        assert differences, (
            f"{variant.name} expects objects, but replaying it against an empty "
            "environment produced no differences — an empty machine just went "
            "green, which is item 8's exact failure"
        )


def test_an_absent_variant_is_satisfied_only_by_a_decline() -> None:
    """The other side of the same rule, so the guard cannot be over-tightened.

    A variant that captured a genuinely absent interface must go green when a
    collector declines, and must NOT go green when one invents objects. Both
    directions matter: a harness that failed the honest decline would teach
    collectors to crash instead.
    """
    absent = [
        v
        for v in VARIANTS
        if any(r["record"] == "decline" and r["reason"] == "absent" for r in v.expected)
    ]
    assert absent, (
        "no variant captures an absent interface — the decline path, which is "
        "the one that retires stale objects, is exercised by nothing"
    )
    variant = absent[0]
    proc = _run(variant)
    emitted = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
    assert not replay.diff(variant.expected, emitted), (
        f"{variant.name}: an honest decline did not satisfy a variant that "
        "captured an absent interface"
    )
    invented = [r for r in variant.expected if r["record"] != "decline"] + [
        {
            "record": "object",
            "collection": "nft-chains",
            "name": "invented",
            "facts": {},
        }
    ]
    assert replay.diff(variant.expected, invented), (
        "a collector inventing an object satisfied an absent variant"
    )


def test_a_silent_collector_is_a_failure_not_a_pass() -> None:
    """A collector that emits nothing against a non-empty variant fails.

    Proven against the harness rather than against a real collector, because
    the property under test belongs to the judge: if diff() forgave an empty
    stream, every broken collector would pass.
    """
    variant = VARIANTS[0]
    differences = replay.diff(variant.expected, [])
    assert differences, (
        "diff() found no differences between a real stream and an empty one — "
        "the harness would pass a collector that produced nothing at all"
    )


def test_the_harness_detects_a_changed_fact() -> None:
    """The judge discriminates.

    A harness that cannot fail is a harness that proves nothing, so this
    corrupts a committed record and requires the difference to be reported —
    naming the fact, so a reader can act on it.
    """
    variant = VARIANTS[0]
    tampered = [dict(r) for r in variant.expected]
    for record in tampered:
        if record.get("record") == "object":
            record["facts"] = {**record["facts"], "State": "TAMPERED"}
            break
    else:
        pytest.fail(f"{variant.name}: no object record to tamper with")
    differences = replay.diff(variant.expected, tampered)
    assert any("State" in d for d in differences), (
        f"a changed fact was not reported: {differences}"
    )


def test_reordering_records_is_not_a_difference() -> None:
    """Order inside a stream is not significant (DESIGN 19).

    The collator buffers a collection until it ends, so a collector that emits
    the same records in another order is correct — and a harness that failed
    it would be enforcing a rule the contract does not state.
    """
    variant = VARIANTS[0]
    assert not replay.diff(variant.expected, list(reversed(variant.expected)))


# ── item 11: canaries appear in no output channel ────────────────────────


def test_at_least_one_variant_plants_a_canary() -> None:
    """Item 11's non-vacuity arm.

    Every canary check below passes trivially if nothing is ever planted, so
    the suite asserts the planting itself: a corpus with no canaries cannot
    establish that credentials do not leak.
    """
    planted = [v.name for v in VARIANTS if v.canaries]
    assert planted, (
        "no corpus variant plants a canary — the canary checks would all pass "
        "over nothing, establishing that no secret leaks from no secret"
    )


@pytest.mark.parametrize(
    "variant", [v for v in VARIANTS if v.canaries], ids=lambda v: v.name
)
def test_canaries_are_actually_in_the_payloads(variant) -> None:
    """A canary that is not in the input cannot be leaked from it."""
    payloads = json.dumps(variant.payloads)
    for canary in variant.canaries:
        assert canary in payloads, (
            f"{variant.name}: declares canary {canary!r} but no payload "
            "contains it — the check would pass without discriminating"
        )


@pytest.mark.parametrize(
    "variant", [v for v in VARIANTS if v.canaries], ids=lambda v: v.name
)
def test_canaries_reach_no_output_channel(variant) -> None:
    """Item 11, over the channels this phase has: stdout and stderr."""
    proc = _run(variant)
    for canary in variant.canaries:
        assert canary not in proc.stdout, (
            f"{variant.name}: canary {canary!r} leaked into the emitted stream"
        )
        assert canary not in proc.stderr, (
            f"{variant.name}: canary {canary!r} leaked into stderr, which goes "
            "straight to the journal and bypasses every redaction path"
        )


@pytest.mark.parametrize(
    "variant", [v for v in VARIANTS if v.canaries], ids=lambda v: v.name
)
def test_canaries_are_absent_from_the_committed_expectation(variant) -> None:
    """The corpus itself must not ratify a leak.

    If a capture ever recorded a canary as expected output, every later replay
    would agree with it and the check would defend the leak instead of finding
    it.
    """
    committed = (variant.path / "expected.jsonl").read_text()
    for canary in variant.canaries:
        assert canary not in committed, (
            f"{variant.name}: canary {canary!r} is committed as expected output"
        )
