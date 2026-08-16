"""Every guard ships with its reversion, executed — permanently.

Standing rule 6 (docs/PLAN.md §01): a guard proven only by tests the FIXED
code passes proves nothing — round two found the round-one repair pinned by
tests that stayed green with their fixes reverted. The demonstration that the
unfixed code fails must therefore be executed, and a demonstration run once in
a lab and described in prose rots the moment the guard is next edited. This
module keeps each one executable: a literal table of reversions — guard name,
file, the exact fixed text and the exact pre-fix text it replaces — and for
each entry a disposable copy of the tree gets the reversion applied by exact
string replacement and must then FAIL the named tests, loudly, in a real
pytest process. Nothing is restored; the copy dies with the tmpdir.

Two guards have their red targets in this module's own probe section, because
no other conformance test discriminates them — typed equality and the
three-required-counts rule are exercised everywhere and pinned nowhere else.
A probe is an ordinary test here (green in every full run) and doubles as the
test the reversion runner selects inside the copied tree.

The anchor tests double as tripwires: when the guarded code is refactored,
the entry's old-string stops matching and the table demands updating in the
same change — which is the rule working, not the rule in the way.

The whole module is budgeted at well under 90 seconds and marked `guard_meta`
so CI can schedule it apart from the fast suite (`-m "not guard_meta"` /
`-m guard_meta`).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from se_harness import replay

pytestmark = pytest.mark.guard_meta

REPO = Path(__file__).resolve().parent.parent

# What every staged copy carries. corpus/ and contract/ ride along even for
# corpus-free selections: the staging is the same for every entry, so a
# selection that later grows a corpus dependency cannot silently skip.
BASE_TREES = ("harness", "contract", "corpus")


# ── probes: red targets no other conformance test provides ───────────────


def _control_stream(issued: dict[str, int]) -> list[dict]:
    """A minimal stream check_stream accepts in full; each probe below is one
    mutation away from it, so a probe failure indicts the mutated member and
    nothing else."""
    return [
        {"record": "begin", "request": "rq", "batch": "b1",
         "declaration": "sha256:replay",
         "boot_id": "5e000000-0000-4000-8000-000000000001",
         "timens": 0, "instance": None, "generations": dict(issued)},
        {"record": "object", "collection": "pools", "name": "a",
         "facts": {"Health": "ONLINE"}, "at": 1.0},
        {"record": "commit", "collection": "pools",
         "generation": issued["pools"], "objects": 1, "assertions": 0,
         "unobservable": 0, "cpu_ms": 0.5},
        {"record": "end", "request": "rq", "batch": "b1",
         "cpu_ms": 0.5, "wall_ms": 1.0},
    ]


def test_probe_typed_drift_is_a_difference() -> None:
    """The judge's equality is typed: Python thinks True == 1 and 20 == 20.0,
    a consumer in a typed language does not, so a port that made either swap
    puts a wrong value on the wire that == would bless. This probe is the red
    target of the typed-equality reversion below — it is the one conformance
    test that discriminates typed_equal from ==."""
    claim = {"record": "object", "collection": "pools", "name": "a",
             "facts": {"BaseChain": True, "RuleCount": 20}, "at": 1.0}
    for facts in ({"BaseChain": 1, "RuleCount": 20},
                  {"BaseChain": True, "RuleCount": 20.0}):
        assert replay.diff([claim], [{**claim, "facts": facts}]), (
            f"typed drift to {facts} vanished under the diff"
        )
    assert not replay.diff([claim], [dict(claim)]), (
        "typed equality rejected an identical record"
    )


def test_probe_an_omitted_count_is_a_problem() -> None:
    """All three commit counts are required members (DESIGN 19): a subject
    that can disable the truncation check by omitting a count has defeated
    it, so absence is a named problem and never a skip. Red target of the
    three-required-counts reversion below — the corpus and every fixture
    stream carry all three, so nothing else feeds check_stream the omission."""
    issued = replay.issue_generations(["pools"])
    assert not replay.check_stream(_control_stream(issued), issued), (
        "the control stream is not clean; the omissions below would indict "
        "the wrong thing"
    )
    for member in ("objects", "assertions", "unobservable"):
        records = _control_stream(issued)
        next(r for r in records if r["record"] == "commit").pop(member)
        problems = replay.check_stream(records, issued)
        assert any(f"lacks {member}" in p for p in problems), (
            f"a commit without {member} raised no problem — the truncation "
            f"check can be switched off by omission again: {problems}"
        )


# ── the reversion table ──────────────────────────────────────────────────


@dataclass(frozen=True)
class Reversion:
    guard: str
    file: str  # repo-relative path holding the guard
    old: str  # the fixed text, exactly as the file carries it today
    new: str  # the pre-fix text the adversarial round exploited
    red_tests: tuple[str, ...]  # pytest node ids that must fail, repo-relative
    extra_trees: tuple[str, ...] = ()  # staged beyond BASE_TREES


ENTRIES = (
    # The vmap defect: a discovery that iterated only a rule's top-level
    # statements published the distribution firewall's input-allow chain as
    # Unreferenced, and the wrong answer went into the corpus as expected
    # (DESIGN 20). The guard is the generic descent; the reversion is the
    # surface-only walk that shipped.
    Reversion(
        guard="verdict-walk-recursion",
        file="src/system_explorer/agent/adapters/network.py",
        old="""    found: list[str] = []

    def descend(node: object) -> None:
        if isinstance(node, dict):
            for verb in ("jump", "goto"):
                body = node.get(verb)
                if (isinstance(body, dict) and body.get("target")
                        and body["target"] not in found):
                    found.append(body["target"])
            for value in node.values():
                descend(value)
        elif isinstance(node, list):
            for value in node:
                descend(value)

    descend(node)
    return found
""",
        new="""    found: list[str] = []
    for statement in node if isinstance(node, list) else []:
        if not isinstance(statement, dict):
            continue
        for verb in ("jump", "goto"):
            body = statement.get(verb)
            if (isinstance(body, dict) and body.get("target")
                    and body["target"] not in found):
                found.append(body["target"])
    return found
""",
        red_tests=(
            "conformance/test_nft_reachability.py::test_a_chain_reached_only_through_a_vmap_jump_is_referenced",
            "conformance/test_nft_reachability.py::test_a_goto_nested_in_a_vmap_reaches_the_chain_too",
        ),
        extra_trees=("src",),
    ),
    # The relation-facts key: the VdevPath-only fix was itself a subset guard
    # — identity keyed on the one discriminator its author had met, so
    # same-type same-target assertions told apart by any OTHER fact collapsed,
    # and a correct collector emitting them reordered failed falsely.
    Reversion(
        guard="relation-facts-identity",
        file="harness/se_harness/replay.py",
        old="""        # Assertions only: an object's identity is (collection, name) and its
        # facts are compared member-wise, so keying them here would turn
        # every wrong fact value into a missing/unexpected pair and lose the
        # named which-member report.
        json.dumps(record.get("facts", {}), sort_keys=True)
""",
        new="""        json.dumps(record.get("facts", {}).get("VdevPath", ""), sort_keys=True)
""",
        red_tests=(
            "conformance/test_harness_discriminates.py::test_a_relation_s_own_facts_are_part_of_its_identity",
        ),
    ),
    # Typed equality: == thinks True == 1 and 20 == 20.0, so a port swapping
    # a bool for an int emitted a wrong wire value no diff would show. The
    # red target is this module's own probe — nothing else discriminates.
    Reversion(
        guard="typed-equality",
        file="harness/se_harness/corpus.py",
        old="""    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(typed_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(
            typed_equal(x, y) for x, y in zip(a, b, strict=True)
        )
    if type(a) is not type(b):
        return False
    return a == b
""",
        new="""    return a == b
""",
        red_tests=(
            "conformance/test_guards_discriminate.py::test_probe_typed_drift_is_a_difference",
        ),
    ),
    # The issued-generations echo: the reference invented generation 1 and
    # nothing exercised newest-wins; the guard compares begin's map against
    # what the request line issued. Reverted, the map is taken on trust and
    # RULED's "must equal the issued generations" rule becomes unreachable.
    Reversion(
        guard="generation-echo-against-issued",
        file="harness/se_harness/replay.py",
        old="""    if issued is not None and not typed_equal(generations, dict(issued)):
        problems.append(
            f"begin: generations {generations!r} must equal the issued "
            f"generations {issued!r} — the collator issues and the collector "
            "echoes; one that mints its own has defeated the ordering the "
            "generation exists for (DESIGN 19)"
        )
""",
        new="""    # REVERTED: the collector's generation map is taken on trust.
""",
        red_tests=(
            "conformance/test_member_regimes.py::test_the_named_rule_is_reachable[begin-generations]",
        ),
    ),
    # end-echoes-begin: request and batch are run-varying, so the byte diff
    # never sees them; without the echo rule a collector can mint fresh ids
    # in end and no batch is attributable (round a2's batch_drift, a6's
    # fresh-end-ids). Reverted, all four echo rules go unreachable.
    Reversion(
        guard="end-echoes-begin",
        file="harness/se_harness/replay.py",
        old="""    # end closes exactly the batch and request begin opened. Both values are
    # run-varying so the diff never sees them, and both must be non-empty on
    # both sides: an empty string echoing an empty string proves nothing.
    if ends:
        for member in ("request", "batch"):
            opened, closed = begin.get(member), ends[0].get(member)
            if not isinstance(opened, str) or not opened:
                problems.append(
                    f"begin: {member} is {opened!r}; end must echo begin's "
                    f"{member}, and a missing or empty one leaves nothing to echo"
                )
            if not isinstance(closed, str) or not closed:
                problems.append(
                    f"end: {member} is {closed!r}; end must echo begin — a "
                    "stream that cannot say which batch it closes is not a batch"
                )
            elif isinstance(opened, str) and opened and closed != opened:
                problems.append(
                    f"end: {member} {closed!r} does not match begin's "
                    f"{opened!r}; end must echo begin, or two interleaved "
                    "streams could close each other's batches"
                )
""",
        new="""    # REVERTED: end's ids are taken on trust.
""",
        red_tests=(
            "conformance/test_member_regimes.py::test_the_named_rule_is_reachable[begin-request]",
            "conformance/test_member_regimes.py::test_the_named_rule_is_reachable[begin-batch]",
            "conformance/test_member_regimes.py::test_the_named_rule_is_reachable[end-request]",
            "conformance/test_member_regimes.py::test_the_named_rule_is_reachable[end-batch]",
        ),
    ),
    # The three required counts: an omitted count is a truncation check
    # switched off (DESIGN 19), and the pre-fix judge skipped what was not
    # there. Red target is this module's own probe — everything else feeds
    # check_stream complete commits.
    Reversion(
        guard="three-required-counts",
        file="harness/se_harness/replay.py",
        old="""                if member not in commit:
                    problems.append(
                        f"{collection}: commit lacks {member} — all three "
                        "counts are required members, zero when zero, because "
                        "an omitted count is a truncation check switched off"
                    )
                    continue
""",
        new="""                if member not in commit:
                    continue
""",
        red_tests=(
            "conformance/test_guards_discriminate.py::test_probe_an_omitted_count_is_a_problem",
        ),
    ),
    # The boot_id shape rule: the blank-only rule it replaced was a subset
    # guard — it enumerated missing, "" and non-string, and the nil UUID
    # sailed past as a plausible constant stub. Reverted to blank-only, the
    # nil UUID and every misshapen spelling pass again.
    Reversion(
        guard="boot-id-shape",
        file="harness/se_harness/replay.py",
        old="""    if (
        not isinstance(boot_id, str)
        or not _BOOT_ID_SHAPE.fullmatch(boot_id)
        or boot_id == _NIL_UUID
    ):
""",
        new="""    if not isinstance(boot_id, str) or not boot_id:
""",
        red_tests=(
            "conformance/test_member_regimes.py::test_a_nil_or_misshapen_boot_id_is_refused",
        ),
    ),
    # The detector-armed --check: the old --check grepped a scrubbed file
    # with the scrubber's own patterns, so it could only confirm the removal
    # it had just performed — 0 detections in 300 fuzzed runs, by
    # construction. That tautology is gone from the tree, so the reversion is
    # its modern equivalent: the independent detectors emptied, a checker
    # that cannot fail.
    Reversion(
        guard="detector-armed-check",
        file="harness/bin/se-anonymise",
        old="""        findings = detectors.scan(
            json.loads(path.read_text()),
            declares_address_fields=declares,
            hostnames=hostnames,
        )
""",
        new="""        findings = []
""",
        red_tests=(
            "conformance/test_scrub_detectors.py::test_regression_check_is_no_longer_the_scrubbers_echo",
        ),
    ),
)


# ── the runner ───────────────────────────────────────────────────────────


def _stage(entry: Reversion, tmp: Path) -> None:
    """The minimum tree the entry's tests need, copied — never the checkout
    itself: the reversion must die with the tmpdir."""
    ignore = shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache")
    for tree in BASE_TREES + entry.extra_trees:
        shutil.copytree(REPO / tree, tmp / tree, ignore=ignore)
    (tmp / "conformance").mkdir(exist_ok=True)
    for node in entry.red_tests:
        rel = node.split("::", 1)[0]
        destination = tmp / rel
        if not destination.exists():
            shutil.copy(REPO / rel, destination)


def _run_named(tmp: Path, nodes: tuple[str, ...]) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    # The repo's pyproject supplies pythonpath to rooted runs; the staged
    # copy has no pyproject, so the same three roots ride the environment.
    env["PYTHONPATH"] = os.pathsep.join(
        str(tmp / p) for p in ("src", "conformance", "harness")
    )
    env.pop("PYTEST_ADDOPTS", None)
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *nodes],
        cwd=tmp,
        env=env,
        capture_output=True,
        text=True,
        timeout=240,
    )


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e.guard)
def test_the_reversion_anchor_still_matches_the_live_code(entry) -> None:
    """The tripwire: the exact fixed text must sit in the live tree, once.
    A refactor that moves the guard fails HERE with the entry's name, and the
    table is updated in the same change — the alternative is a reversion that
    silently stops reverting, which is rule 6's exact failure mode."""
    text = (REPO / entry.file).read_text()
    count = text.count(entry.old)
    assert count == 1, (
        f"{entry.guard}: the reversion anchor matches {count} times in "
        f"{entry.file} — the guarded code moved; update this entry's old/new "
        "pair in the same change"
    )


@pytest.mark.parametrize("entry", ENTRIES, ids=lambda e: e.guard)
def test_the_reversion_goes_red(entry, tmp_path: Path) -> None:
    """Rule 6, executed: apply the pre-fix text in a disposable copy and the
    named tests must fail there. Exit code 1 precisely — tests collected, ran
    and failed; 2+ would mean the run itself broke, which proves nothing
    about the guard. Nothing is restored: the tmpdir is the blast radius."""
    _stage(entry, tmp_path)
    target = tmp_path / entry.file
    text = target.read_text()
    assert text.count(entry.old) == 1, (
        f"{entry.guard}: reversion anchor not found exactly once in the "
        f"staged copy of {entry.file}"
    )
    target.write_text(text.replace(entry.old, entry.new))

    proc = _run_named(tmp_path, entry.red_tests)
    assert proc.returncode == 1, (
        f"{entry.guard}: with the guard reverted, the named tests did not "
        f"fail cleanly (pytest exited {proc.returncode}; 0 means the guard "
        "does not discriminate — its tests pass the UNFIXED code, rule 6's "
        "exact defect; >1 means the run broke).\n"
        f"--- stdout tail ---\n{proc.stdout[-2000:]}\n"
        f"--- stderr tail ---\n{proc.stderr[-1000:]}"
    )
    assert "failed" in proc.stdout, (
        f"{entry.guard}: exit 1 without a failure line — not a test verdict:\n"
        f"{proc.stdout[-2000:]}"
    )
