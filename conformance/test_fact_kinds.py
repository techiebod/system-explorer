"""Measured, derived, declared — and the ratchet that closes the gap.

A detail page renders one flat table of facts and, until this landed,
everything in it looked equally like something the machine had said. It
wasn't. `UsedBytes` is read from ZFS and an operator can check it with one
command. `AdmittedFromCertain` is a two-closure computation over a firewall
ruleset that was WRONG FIVE TIMES in a single review pass — a dport range
inside a set dropped, `match.op` never read, guards unioned instead of
intersected, the address family never consulted, an unreadable verdict
dropped from both closures. `Immutability` is a sentence a person wrote in a
manifest, true because they said so.

The two consumers matter differently. A human reading a number in a table
may sense which is which from the name; a model answering over MCP will
restate a derived figure with exactly the confidence it restates a measured
one, and has nothing to go on at all.

`measured` is the default and is never written down — three hundred
restatements would bury the forty that matter. Which makes the distinction
between "reviewed and all measured" ({}) and "nobody has looked" (None) the
load-bearing one, and the budget below counts only the second.
"""

from __future__ import annotations

import pytest

from common import UNCLASSIFIED_COLLECTION_BUDGET

from system_explorer.agent.adapters import build_adapters

ADAPTERS = build_adapters()
VALID = {"derived", "declared"}

PAIRS = [(sub, coll) for sub in sorted(ADAPTERS)
         for coll in sorted(ADAPTERS[sub].collections())]


def kinds_of(subsystem, collection):
    classify = getattr(ADAPTERS[subsystem], "fact_kinds", None)
    return classify(collection) if classify else None


def reviewed():
    return [(sub, coll) for sub, coll in PAIRS
            if kinds_of(sub, coll) is not None]


def test_the_walk_still_finds_the_classifications():
    """Anti-vacuity: every check below is driven by this, and all of them
    pass trivially on an empty set."""
    assert len(PAIRS) >= 40, f"only {len(PAIRS)} collections found"
    done = reviewed()
    assert len(done) >= 15, f"only {len(done)} collections reviewed"
    classified = sum(len(kinds_of(s, c)) for s, c in done)
    assert classified >= 50, f"only {classified} facts carry a kind"


@pytest.mark.parametrize("subsystem,collection", PAIRS)
def test_every_declared_kind_is_one_of_the_two_that_are_written_down(
        subsystem, collection):
    """`measured` is not a valid value. It is what a fact means by being
    absent, and allowing it to be stated as well would make two spellings of
    one claim — then a reader could not tell a fact somebody classified as
    measured from one somebody forgot, which is the whole distinction this
    file exists to keep."""
    for fact, kind in sorted((kinds_of(subsystem, collection) or {}).items()):
        assert kind in VALID, (
            f"{subsystem}/{collection}.{fact} is {kind!r}; only "
            f"{sorted(VALID)} are written down — measured is the default and "
            "is stated by omission")


@pytest.mark.parametrize("subsystem,collection", PAIRS)
def test_a_classified_fact_is_a_fact_that_exists(subsystem, collection):
    """Both directions of the fact dictionary's own orphan rule. A kind on a
    name nothing emits is a classification of nothing, and it rots silently
    — the fact gets renamed and the entry stays, still looking enforced."""
    glossary = set(ADAPTERS[subsystem].fact_glossary(collection)
                   if hasattr(ADAPTERS[subsystem], "fact_glossary") else ())
    orphans = sorted(set(kinds_of(subsystem, collection) or {}) - glossary)
    assert not orphans, (
        f"{subsystem}/{collection} classifies {orphans}, which its fact "
        "dictionary does not document. Either the fact is gone and the entry "
        "should go with it, or it is real and owes a sentence too.")


def test_the_unclassified_backlog_only_shrinks():
    """The ratchet. Without it the map is a nice gesture that stops growing
    the moment the person who cared moves on, and every unreviewed
    collection silently reports its derived facts as measured — which is the
    exact failure this exists to end, wearing a green build."""
    outstanding = [f"{sub}/{coll}" for sub, coll in PAIRS
                   if kinds_of(sub, coll) is None]
    assert len(outstanding) <= UNCLASSIFIED_COLLECTION_BUDGET, (
        f"{len(outstanding)} collections have no fact_kinds() and the budget "
        f"is {UNCLASSIFIED_COLLECTION_BUDGET}: {sorted(outstanding)}. Add "
        "fact_kinds() returning the derived and declared facts — {} if every "
        "one really is measured — and lower the budget.")


def test_the_budget_is_not_left_slack_after_a_backfill():
    """A ratchet nobody tightens is a ceiling. Whoever classifies a
    collection lowers the number in the same commit, so the next person
    inherits the real figure rather than a stale one with room in it."""
    outstanding = sum(1 for sub, coll in PAIRS if kinds_of(sub, coll) is None)
    assert outstanding == UNCLASSIFIED_COLLECTION_BUDGET, (
        f"{outstanding} collections are unclassified but the budget says "
        f"{UNCLASSIFIED_COLLECTION_BUDGET} — lower it to {outstanding}.")


# ── the ones that motivated it ───────────────────────────────────────────

def test_the_firewall_closure_is_not_presented_as_a_measurement():
    """Five soundness holes in one review pass, every one of them silently
    widening or narrowing this number, and it rendered in the same plain
    table cell as a port read out of /proc/net."""
    exposure = kinds_of("network", "port-exposure")
    assert exposure["AdmittedFromCertain"] == "derived"
    assert exposure["AdmittedFromPossible"] == "derived"
    # And the port itself is measured — stated by being absent from the map.
    assert "LocalPort" not in exposure


def test_the_immutability_sentence_is_declared_not_observed():
    """Security prose a person wrote, carried verbatim precisely because
    paraphrasing it would be this product inventing a security claim.
    Rendering it beside a measured capacity invited the reading that
    somebody had checked."""
    assert kinds_of("protection", "destinations")["Immutability"] == "declared"


def test_what_a_pool_survives_losing_is_read_out_of_a_name():
    """zpool reports vdev_type "raidz" for every parity level and states the
    number nowhere in its document — the parity comes from the NAME zpool
    assigned the vdev. A reader treating this as measured is trusting a
    regex."""
    pools = kinds_of("storage", "pools")
    assert pools["DeviceFailuresTolerated"] == "derived"
    assert pools["Redundancy"] == "derived"


def test_the_unattributed_remainder_is_a_subtraction():
    """Host busy time minus the sum of the top-level slices, across two
    files read moments apart — the figure most likely to be quoted as though
    the kernel had stated it."""
    assert kinds_of("resources", "workloads")["UnattributedCpuUsec"] == "derived"
    assert "CpuUsageUsec" not in kinds_of("resources", "workloads")
