"""Reachability through nested verdicts: the vmap defect, pinned.

nftables does not keep every verdict at a rule's top level. A ct-state
verdict map carries its jumps two levels down, inside the map's data —
`ct state vmap { established : accept, new : jump input-allow }` — and that
is the FRONT DOOR of the distribution firewall this product most often
reads: one vmap rule dispatches every inbound packet, and the chain holding
every accept is reached through it and through nothing else.

A discovery that iterated only a rule's top-level statements therefore
published that chain as Unreferenced — whose glossary sentence claims no
packet can reach it — and the wrong answer was committed to the corpus as
expected, where it rejected two independently written correct collectors
(DESIGN 20). These tests pin the fix from both sides: a nested jump or goto
is a reference, in its own (family, table) scope only, and a chain nothing
reaches still says so — a descent that manufactured references would be the
same defect inverted.

The port-exposure walk shared the defect, so one test drives it through
the same shape: an accept dispatched through a vmap must appear on the
socket's row rather than being silently unreachable.

The defect has a second spelling, one level further out. A NAMED verdict
map — `ct state vmap @dispatch` — keeps its jumps in the top-level map
OBJECT's elem list; the rule carries only the string "@dispatch", so no
descent into rule expressions can ever find them. The last three tests pin
that repair from both sides too: a map's targets are references where some
rule in the map's own (family, table) uses the map, and are NOT references
where no rule does — the kernel never traverses an unconsulted map, so
reachability through an unreferenced map is not reachability.
"""

from __future__ import annotations

import asyncio

from system_explorer.agent.adapters import network

ACCEPT = {"accept": None}
TCP_HEADER = "  sl  local_address rem_address   st ...\n"


def line(local, state="0A"):
    return (f"   0: {local} 00000000:0000 {state} 00000000:00000000"
            " 00:00000000 00000000     0        0 1"
            " 1 0000000000000000 100 0 0 10 0\n")


def chain(name, table="filter", family="ip", **extra):
    return {"chain": {"family": family, "table": table, "name": name, **extra}}


def rule(chain_name, expr, table="filter", family="ip", handle=1):
    return {"rule": {"family": family, "table": table, "chain": chain_name,
                     "handle": handle, "expr": expr}}


def ct_vmap(*dispatch):
    """The corpus's healthy capture, entry 61: verdicts nested in the map's
    data, two levels below the statement the old discovery iterated."""
    return {"vmap": {"key": {"ct": {"key": "state"}},
                     "data": {"set": [list(pair) for pair in dispatch]}}}


def verdict_map(name, *dispatch, table="filter", family="ip"):
    """The named-map OBJECT as `nft -j list ruleset` prints it: the verdicts
    sit in this top-level entry's elem list and in no rule anywhere."""
    return {"map": {"family": family, "table": table, "name": name,
                    "type": "ct_state", "map": "verdict", "handle": 7,
                    "elem": [list(pair) for pair in dispatch]}}


def vmap_ref(name):
    """`ct state vmap @dispatch` — ALL the rule carries is the @-string."""
    return {"vmap": {"key": {"ct": {"key": "state"}}, "data": f"@{name}"}}


def chains(monkeypatch, *entries):
    monkeypatch.setattr(network, "_nft_json", lambda: {"nftables": list(entries)})
    return {item["id"]: item["facts"]
            for item in asyncio.run(network.Adapter()._nft_chains())}


BASE = dict(type="filter", hook="input", prio=0, policy="drop", handle=3)


# ── the defect itself ────────────────────────────────────────────────────

def test_a_chain_reached_only_through_a_vmap_jump_is_referenced(monkeypatch):
    """The shipped shape, verbatim: new and untracked both jump to the chain
    holding every inbound accept, and nothing else reaches it. Unreferenced
    here is the glossary claiming no packet can reach the busiest chain on
    the host."""
    facts = chains(
        monkeypatch,
        chain("input", **BASE), chain("input-allow"),
        rule("input", [ct_vmap(("invalid", {"drop": None}),
                               ("established", ACCEPT),
                               ("related", ACCEPT),
                               ("new", {"jump": {"target": "input-allow"}}),
                               ("untracked", {"jump": {"target": "input-allow"}}))]),
    )
    row = facts["nft-chain:ip/filter/input-allow"]
    assert row["JumpedFrom"] == ["input"], (
        "a jump nested in a vmap's data did not count as a reference")
    assert "Unreferenced" not in row


def test_a_goto_nested_in_a_vmap_reaches_the_chain_too(monkeypatch):
    """Both verbs at any depth, for the reason both count at the top level:
    goto differs from jump in where it returns to, not in whether it
    arrives."""
    facts = chains(
        monkeypatch,
        chain("input", **BASE), chain("tail"),
        rule("input", [ct_vmap(("new", {"goto": {"target": "tail"}}))]),
    )
    assert facts["nft-chain:ip/filter/tail"]["JumpedFrom"] == ["input"]
    assert "Unreferenced" not in facts["nft-chain:ip/filter/tail"]


# ── the fix must discriminate, not blanket ───────────────────────────────

def test_a_genuinely_unreferenced_chain_still_says_so(monkeypatch):
    """The other half of the guard. The vmap's KEYS are free strings, so one
    is deliberately spelt like the orphan's name: a descent that collected
    strings rather than jump/goto verdicts would manufacture a reference and
    retire the one fact here somebody would act on."""
    facts = chains(
        monkeypatch,
        chain("input", **BASE), chain("input-allow"), chain("orphan"),
        rule("input", [ct_vmap(("orphan", ACCEPT),
                               ("new", {"jump": {"target": "input-allow"}}))]),
    )
    assert facts["nft-chain:ip/filter/orphan"]["Unreferenced"] is True
    assert "JumpedFrom" not in facts["nft-chain:ip/filter/orphan"]


def test_a_nested_jump_does_not_cross_families(monkeypatch):
    """Same scoping law as a top-level jump: a chain name is unique within
    its family and table, not within the ruleset, so an ip-side vmap jump
    must not resurrect the ip6 chain of the same name."""
    facts = chains(
        monkeypatch,
        chain("shared", family="ip"), chain("shared", family="ip6"),
        rule("input", [ct_vmap(("new", {"jump": {"target": "shared"}}))],
             family="ip"),
    )
    assert facts["nft-chain:ip/filter/shared"]["JumpedFrom"] == ["input"]
    assert facts["nft-chain:ip6/filter/shared"]["Unreferenced"] is True


# ── the same walk, on the path that answers a question ───────────────────

def test_port_exposure_follows_a_vmap_dispatched_chain(monkeypatch, tmp_path):
    """Before the walk descended into expression bodies, the accept admitting
    this socket was invisible: not in the certain answer, not in the possible
    one, no gap — silence, which the exposure collection exists to refuse.

    The vmap statement travels into the target chain as a guard, and it is
    residue there, so the answer lands exactly where honesty puts it: the
    rule is REPORTED, the admission is possible, and certainty is refused
    because the ct-state dispatch is a condition this reader does not model.
    """
    monkeypatch.setattr(network, "PROC_NET", str(tmp_path))
    for name in ("tcp", "tcp6", "udp", "udp6"):
        (tmp_path / name).write_text(
            TCP_HEADER + (line("00000000:0016") if name == "tcp" else ""))
    dport22 = {"match": {"op": "==", "right": 22,
                         "left": {"payload": {"protocol": "tcp",
                                              "field": "dport"}}}}
    document = {"nftables": [
        chain("input", **BASE),
        rule("input", [ct_vmap(("established", ACCEPT),
                               ("new", {"jump": {"target": "input-allow"}}),
                               ("untracked", {"jump": {"target": "input-allow"}}))],
             handle=1),
        rule("input-allow", [dport22, ACCEPT], handle=2),
    ]}
    monkeypatch.setattr(network, "_nft_json", lambda: document)
    [item] = asyncio.run(network.Adapter()._exposure_items())
    facts = item["facts"]
    reached = [entry for entry in facts.get("AdmittingRules", ())
               if entry.startswith("ip/filter/input-allow/2:")]
    assert len(reached) == 1, (
        "the vmap-dispatched accept is missing from the row — or walked "
        "once per vmap key that names its chain")
    assert facts["AdmittedFromPossible"] == ["anywhere"]
    # The safe direction, pinned so the fix can never overshoot: the vmap
    # guard is unmodelled, so nothing dispatched through it may reach the
    # answer this product tells an operator they can defend.
    assert "AdmittedFromCertain" not in facts
    assert facts["ClosureGap"] is True


# ── the same defect, one spelling further out: the NAMED map ─────────────

def test_f_a_chain_reached_only_through_a_named_map_is_referenced(monkeypatch):
    """The reviewer's landing shape: the only path to `landing` is a jump in
    the named map's own elem list, which no rule expression contains. The
    unrepaired derivation answered {"RuleCount": 0, "Unreferenced": true} —
    the exact wrong answer the vmap repair exists to end. The caller named
    must be the chain whose rule consults the map: that is where control
    leaves from."""
    facts = chains(
        monkeypatch,
        chain("input", **BASE), chain("landing"),
        verdict_map("dispatch",
                    ("established", ACCEPT),
                    ("new", {"jump": {"target": "landing"}}),
                    ("untracked", {"goto": {"target": "landing"}})),
        rule("input", [vmap_ref("dispatch")]),
    )
    row = facts["nft-chain:ip/filter/landing"]
    assert row["JumpedFrom"] == ["input"], (
        "a jump held in a named map's top-level elem list did not count "
        "as a reference from the chain that uses the map")
    assert "Unreferenced" not in row


def test_g_a_named_map_no_rule_uses_confers_no_reference(monkeypatch):
    """The decision, asserted: a map's jumps are latent until some rule
    consults the map. The kernel never traverses an unconsulted map, so
    reachability through an UNREFERENCED map is not reachability, and
    `landing` here honestly stays Unreferenced. This is also the half that
    keeps the fix discriminating: a repair that counted every map object's
    targets unconditionally would retire Unreferenced from exactly the
    chains it is telling the truth about."""
    facts = chains(
        monkeypatch,
        chain("input", **BASE), chain("landing"),
        verdict_map("dispatch", ("new", {"jump": {"target": "landing"}})),
        # The base chain does real work, none of it consulting the map.
        rule("input", [ACCEPT]),
    )
    row = facts["nft-chain:ip/filter/landing"]
    assert row["Unreferenced"] is True
    assert "JumpedFrom" not in row


def test_h_map_sourced_references_stay_inside_family_and_table(monkeypatch):
    """Same scoping law as every other reference, on both joins at once:
    "@dispatch" in a rule names that rule's own (family, table) map and no
    other's, and a map's targets resolve inside the map's own (family,
    table). An ip6 rule and an ip/mangle rule both spell "@dispatch"; if
    either join dropped its scope, the ip6 chain of the same name would be
    resurrected, or the wrong-side users would appear as callers of the ip
    landing chain."""
    facts = chains(
        monkeypatch,
        chain("input", **BASE), chain("landing"),
        chain("wrongside", family="ip6"), chain("landing", family="ip6"),
        chain("wrongtable", table="mangle"),
        verdict_map("dispatch", ("new", {"jump": {"target": "landing"}})),
        rule("input", [vmap_ref("dispatch")]),
        rule("wrongside", [vmap_ref("dispatch")], family="ip6"),
        rule("wrongtable", [vmap_ref("dispatch")], table="mangle"),
    )
    assert facts["nft-chain:ip/filter/landing"]["JumpedFrom"] == ["input"]
    assert facts["nft-chain:ip6/filter/landing"]["Unreferenced"] is True
    assert "JumpedFrom" not in facts["nft-chain:ip6/filter/landing"]
