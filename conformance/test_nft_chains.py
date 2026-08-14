"""The ruleset's shape: where the kernel enters it, and what runs what.

This collection exists because the rule list was unreadable at estate scale
and the reason was structural rather than cosmetic — 222 rules on one host,
43 of them in a single chain, presented flat with nothing saying which of
them a packet ever reaches ("the firewall table isn't very human parsable",
reported 2026-08-14).

A ruleset is a graph and nft's own JSON has always carried it; the chain
objects sit in the same document as the rules and were being skipped. Two
facts here are NOT in that document, and they are the two that make it
navigable: JumpedFrom, which needs every rule in every table read to answer
"what runs this chain", and Unreferenced, which falls out of it.

The tests below pin the distinctions that quietly collapse: a base chain and
a regular one, a goto and a jump, a chain with zero rules and a chain that
does not exist, and a policy absent because a chain is regular versus a
policy absent because none is set.
"""

from __future__ import annotations

import asyncio

from system_explorer.agent.adapters import network


def chain(name, table="filter", family="ip", **extra):
    return {"chain": {"family": family, "table": table, "name": name, **extra}}


def rule(chain_name, expr, table="filter", family="ip", handle=1):
    return {"rule": {"family": family, "table": table, "chain": chain_name,
                     "handle": handle, "expr": expr}}


def chains(monkeypatch, *entries):
    monkeypatch.setattr(network, "_nft_json", lambda: {"nftables": list(entries)})
    return {item["id"]: item["facts"]
            for item in asyncio.run(network.Adapter()._nft_chains())}


BASE = dict(type="filter", hook="input", prio=0, policy="accept", handle=3)


# ── the distinction everything else rests on ─────────────────────────────

def test_a_base_chain_states_where_in_the_path_it_runs(monkeypatch):
    facts = chains(monkeypatch, chain("input-fw", **BASE))["nft-chain:ip/filter/input-fw"]
    assert facts["BaseChain"] is True
    assert (facts["Hook"], facts["Type"], facts["Priority"]) == ("input", "filter", 0)
    assert facts["Policy"] == "accept"


def test_a_regular_chain_has_no_policy_rather_than_a_null_one(monkeypatch):
    """A null policy reads as "no policy set", which is a different and much
    more alarming claim than "this chain returns to its caller"."""
    facts = chains(monkeypatch, chain("helper"))["nft-chain:ip/filter/helper"]
    assert facts["BaseChain"] is False
    for absent in ("Policy", "Hook", "Type", "Priority"):
        assert absent not in facts, f"{absent} invented for a regular chain"


def test_a_negative_priority_is_normal_and_is_carried(monkeypatch):
    """-100 is where nat prerouting sits by convention; a falsy check on the
    priority would drop it and leave two chains on one hook with nothing
    saying which sees the packet first."""
    facts = chains(monkeypatch, chain("pre", **{**BASE, "prio": -100}))
    assert facts["nft-chain:ip/filter/pre"]["Priority"] == -100


# ── what runs what ───────────────────────────────────────────────────────

def test_a_chain_names_every_chain_that_jumps_to_it(monkeypatch):
    facts = chains(
        monkeypatch,
        chain("fw", **BASE), chain("accept-it"),
        rule("fw", [{"jump": {"target": "accept-it"}}], handle=1),
        rule("other", [{"jump": {"target": "accept-it"}}], handle=2),
    )
    assert facts["nft-chain:ip/filter/accept-it"]["JumpedFrom"] == ["fw", "other"]


def test_a_goto_reaches_a_chain_just_as_a_jump_does(monkeypatch):
    """goto differs from jump in where it RETURNS to, not in whether it
    arrives. Counting only jumps would report a goto-only chain as
    unreferenced — the one fact here somebody would act on."""
    facts = chains(monkeypatch, chain("fw", **BASE), chain("tail"),
                   rule("fw", [{"goto": {"target": "tail"}}]))
    assert facts["nft-chain:ip/filter/tail"]["JumpedFrom"] == ["fw"]
    assert "Unreferenced" not in facts["nft-chain:ip/filter/tail"]


def test_a_regular_chain_nothing_reaches_says_so(monkeypatch):
    facts = chains(monkeypatch, chain("fw", **BASE), chain("orphan"))
    assert facts["nft-chain:ip/filter/orphan"]["Unreferenced"] is True


def test_a_base_chain_is_never_called_unreferenced(monkeypatch):
    """Nothing jumps to an input hook and nothing needs to — the kernel calls
    it. Marking it unreferenced would report the busiest chain on the host as
    dead code."""
    facts = chains(monkeypatch, chain("fw", **BASE))
    assert "Unreferenced" not in facts["nft-chain:ip/filter/fw"]
    assert "JumpedFrom" not in facts["nft-chain:ip/filter/fw"]


def test_a_jump_does_not_cross_tables(monkeypatch):
    """A chain name is unique within its table, not within the ruleset, and
    docker and nixos-fw both name chains generically. Attributing a jump
    across the boundary would claim a path that does not exist."""
    facts = chains(
        monkeypatch,
        chain("shared", table="a"), chain("shared", table="b"),
        rule("fw", [{"jump": {"target": "shared"}}], table="a"),
    )
    assert facts["nft-chain:ip/a/shared"]["JumpedFrom"] == ["fw"]
    assert facts["nft-chain:ip/b/shared"]["Unreferenced"] is True


def test_the_same_chain_name_in_two_families_is_two_chains(monkeypatch):
    facts = chains(monkeypatch, chain("fw", family="ip", **BASE),
                   chain("fw", family="ip6", **BASE))
    assert set(facts) == {"nft-chain:ip/filter/fw", "nft-chain:ip6/filter/fw"}


# ── counting, and its limits ─────────────────────────────────────────────

def test_a_chain_with_no_rules_counts_zero_rather_than_being_absent(monkeypatch):
    """Zero is measured here, not missing: the chain object exists and holds
    nothing, which is a real and readable state (an empty base chain runs its
    policy on everything). This is the one place a zero is honest — contrast
    a rule's counter, which is absent when uncounted."""
    facts = chains(monkeypatch, chain("empty", **BASE))
    assert facts["nft-chain:ip/filter/empty"]["RuleCount"] == 0


def test_rules_are_counted_against_their_own_chain(monkeypatch):
    facts = chains(monkeypatch, chain("a", **BASE), chain("b"),
                   rule("a", [], handle=1), rule("a", [], handle=2),
                   rule("b", [], handle=3))
    assert facts["nft-chain:ip/filter/a"]["RuleCount"] == 2
    assert facts["nft-chain:ip/filter/b"]["RuleCount"] == 1


def test_chains_carry_no_severity(monkeypatch):
    """Same restraint as nft-rules. Whether an accept policy or a stray chain
    is a problem depends on what the rules inside admit, which is
    port-exposure's question and is answered with two closures, not a dot."""
    monkeypatch.setattr(network, "_nft_json",
                        lambda: {"nftables": [chain("fw", **BASE)]})
    [item] = asyncio.run(network.Adapter()._nft_chains())
    assert "worst_opinion_level" not in item
    assert item["id"] == "nft-chain:ip/filter/fw"
    assert item["native_id"] == "ip filter fw"


# ── the graph, walkable from either end ──────────────────────────────────

def test_a_rule_reaches_its_own_chain_and_the_one_it_jumps_to():
    edges = network.Adapter()._nft_edges("nft-rules", {
        "Family": "ip", "Table": "filter", "Chain": "fw",
        "JumpTarget": "nixos-fw-accept"})
    assert {(e["type"], e["direction"], e["target"]["id"]) for e in edges} == {
        ("member-of", "out", "nft-chain:ip/filter/fw"),
        ("dispatches-to", "out", "nft-chain:ip/filter/nixos-fw-accept")}


def test_a_rule_that_decides_rather_than_jumps_reaches_only_its_chain():
    edges = network.Adapter()._nft_edges("nft-rules", {
        "Family": "ip", "Table": "filter", "Chain": "fw"})
    assert [e["target"]["id"] for e in edges] == ["nft-chain:ip/filter/fw"]


def test_a_chain_reaches_its_table_and_its_callers():
    edges = network.Adapter()._nft_edges("nft-chains", {
        "Family": "ip", "Table": "filter", "Name": "accept-it",
        "JumpedFrom": ["fw", "other"]})
    assert {(e["type"], e["direction"], e["target"]["id"]) for e in edges} == {
        ("member-of", "out", "nft-table:ip/filter"),
        ("dispatches-to", "in", "nft-chain:ip/filter/fw"),
        ("dispatches-to", "in", "nft-chain:ip/filter/other")}


def test_a_collection_with_no_family_draws_no_nft_edges():
    """links and routes go through the same call site; nothing there has a
    family or a table, and inventing `nft-chain:None/None/...` would put dead
    chips on every link page in the product."""
    assert network.Adapter()._nft_edges("links", {"Device": "eth0"}) == []
    assert network.Adapter()._nft_edges("nft-rules", {"Chain": "fw"}) == []
