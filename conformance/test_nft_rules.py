"""One row per rule, and the measured extent of what the row does not say.

The failure this file exists to prevent is an INVERSION, not an omission. A
renderer that drops a term it does not understand turns

    iifname tailscale0 tcp dport 22 accept

into

    tcp dport 22 accept

— a rule confining sshd to one interface, rendered as one admitting it from
anywhere. Every shipped nftables exporter surveyed makes some version of this
mistake; the two most popular never read `match.op`, so `ip saddr != 10/8`
exports identically to its inverse.

Two mechanisms stop it here and both are tested below. Unrenderable terms are
emitted AT THEIR POSITION as a placeholder, which is nft's own convention, so
the rule keeps its shape. And comprehension is COMPUTED — the statements the
renderer consumed are subtracted from the rule's own expression list, and
whatever is left is carried — so ignorance is a fact rather than an assumption.
"""

from __future__ import annotations

from system_explorer.agent.adapters import network

ACCEPT = {"accept": None}


def render(*expr):
    return network._render_rule(list(expr))


def match(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


PAYLOAD = {"payload": {"protocol": "tcp", "field": "dport"}}
IIFNAME = {"meta": {"key": "iifname"}}


# ── the inversion, from both directions ──────────────────────────────────

def test_an_unrenderable_condition_appears_at_its_position():
    """The whole design in one assertion. `fib oif lo accept` must not render
    as `accept`: a reader seeing a bare verdict concludes the rule is
    unconditional, which is the opposite of what it says."""
    rendered = render(match({"fib": {"result": "oif"}}, "lo"), ACCEPT)
    assert rendered["text"] == "<unrendered fib> accept"
    assert rendered["text"] != "accept"
    assert len(rendered["residue"]) == 1


def test_an_unrenderable_statement_appears_at_its_position_too():
    """Not only matches. A statement verb outside the covered set — synproxy,
    tproxy, secmark, and whatever the next kernel adds — must leave a mark in
    the line rather than vanish from between the terms around it."""
    rendered = render(match(PAYLOAD, 22), {"synproxy": {}}, ACCEPT)
    assert rendered["text"] == "tcp dport 22 <unrendered synproxy> accept"


def test_the_narrow_rule_that_started_this_renders_every_term():
    """The rule keeping sshd safe on the estate's internet-facing host. Both
    conditions present, in order, with the verdict."""
    rendered = render(match(IIFNAME, "tailscale0"), match(PAYLOAD, 22),
                      {"counter": {"packets": 5, "bytes": 300}}, ACCEPT)
    assert rendered["text"] == (
        "meta iifname tailscale0 tcp dport 22 counter accept")
    assert rendered["residue"] == []
    assert rendered["verdict"] == "accept"


def test_negation_is_carried_inside_the_value_not_beside_it():
    """A separate `negated` flag is ignorable, and it WILL be ignored — by a
    consumer selecting one column, by grep, by a model summarising a table —
    and the value it modifies then reads as its own opposite."""
    rendered = render(
        match({"payload": {"protocol": "ip", "field": "saddr"}},
              {"prefix": {"addr": "10.0.0.0", "len": 8}}, op="!="),
        {"drop": None})
    assert rendered["text"] == "ip saddr != 10.0.0.0/8 drop"
    assert "!=" in rendered["text"]


def test_an_equality_match_carries_no_negation_marker():
    rendered = render(match({"payload": {"protocol": "ip", "field": "saddr"}},
                            {"prefix": {"addr": "10.0.0.0", "len": 8}}), ACCEPT)
    assert rendered["text"] == "ip saddr 10.0.0.0/8 accept"


# ── xt: conditions absent from the document, not merely unparsed ─────────

def test_an_xt_term_keeps_its_position_and_marks_the_rule_opaque():
    """nft's JSON carries an xtables extension's NAME and none of its
    parameters, so this rule's conditions are absent from the source document
    rather than unparsed by this renderer. `xt match "conntrack"` is nft's own
    rendering and is kept verbatim."""
    rendered = render({"xt": {"type": "match", "name": "conntrack"}},
                      {"counter": {"packets": 715, "bytes": 55704}},
                      {"jump": {"target": "nixos-fw-accept"}})
    assert rendered["text"] == (
        'xt match "conntrack" counter jump nixos-fw-accept')
    assert rendered["opaque_reason"] == "xt"
    assert rendered["verdict"] is None, "a jump decides nothing by itself"
    assert rendered["jump_target"] == "nixos-fw-accept"


def test_a_bare_string_statement_is_kept_and_flagged():
    """nft emits a bare string where it has no JSON encoder for an expression,
    running its own text printer into a buffer instead. The type change is the
    signal: it is the one construct that arrives already rendered."""
    rendered = render("tcp flags syn / syn,ack", ACCEPT)
    assert rendered["text"] == "tcp flags syn / syn,ack accept"
    assert rendered["opaque_reason"] == "text-fallback"


# ── sets: membership decides what matches ────────────────────────────────

def test_an_anonymous_set_renders_its_elements():
    """The elements are right there in the JSON, so rendering the set as
    `{ ... }` would claim full comprehension while hiding the membership that
    decides what the rule matches."""
    rendered = render(match(PAYLOAD, {"set": [22, 80]}), ACCEPT)
    assert rendered["text"] == "tcp dport { 22, 80 } accept"
    assert rendered["residue"] == []


def test_a_set_range_renders_as_a_range():
    rendered = render(match(PAYLOAD, {"set": [{"range": [8000, 8100]}]}), ACCEPT)
    assert rendered["text"] == "tcp dport { 8000-8100 } accept"


def test_a_named_set_renders_as_the_name_the_rule_actually_says():
    """A reference whose membership is a separate object. The name is what the
    rule says, so rendering it is faithful — expanding it would be this
    collection inventing content from another object's state."""
    rendered = render(match(PAYLOAD, "@allowed"), ACCEPT)
    assert rendered["text"] == "tcp dport @allowed accept"
    assert rendered["residue"] == []


def test_a_set_element_shape_nobody_covers_is_not_rendered_as_narrower():
    """Falling through to a partial set would be the inversion again, one
    level down: a rule matching four ports rendered as matching two."""
    rendered = render(match(PAYLOAD, {"set": [22, {"concat": ["a", "b"]}]}), ACCEPT)
    assert "<unrendered payload>" in rendered["text"]
    assert len(rendered["residue"]) == 1


# ── counters: absent is not zero ─────────────────────────────────────────

def test_a_rule_without_a_counter_carries_no_counter_facts():
    """nftables has no implicit per-rule counters, so a rule written without
    one has no traffic history at all. A zero would report an idle rule that
    is merely uncounted — and 'no traffic' on a firewall rule is exactly the
    kind of reading someone acts on."""
    rendered = render(match(PAYLOAD, 22), ACCEPT)
    assert rendered["packets"] is None and rendered["bytes"] is None


def test_a_counter_that_reads_zero_is_carried_as_zero():
    rendered = render({"counter": {"packets": 0, "bytes": 0}}, ACCEPT)
    assert rendered["packets"] == 0 and rendered["bytes"] == 0


# ── comprehension is computed, never asserted ────────────────────────────

def build(monkeypatch, *rules):
    import asyncio
    payload = {"nftables": [{"rule": r} for r in rules]}
    monkeypatch.setattr(network, "_nft_json", lambda: payload)
    return {i["facts"]["Handle"]: i["facts"]
            for i in asyncio.run(network.Adapter()._nft_rules())}


def rule(handle, expr, chain="input"):
    return {"family": "inet", "table": "filter", "chain": chain,
            "handle": handle, "expr": expr}


def test_comprehension_follows_the_residue(monkeypatch):
    facts = build(monkeypatch,
                  rule(1, [match(PAYLOAD, 22), ACCEPT]),
                  rule(2, [match({"fib": {"result": "oif"}}, "lo"), ACCEPT]),
                  rule(3, [{"xt": {"type": "match", "name": "conntrack"}}, ACCEPT]))
    assert facts[1]["Comprehension"] == "full"
    assert "Residue" not in facts[1]
    assert facts[2]["Comprehension"] == "partial"
    assert len(facts[2]["Residue"]) == 1
    assert facts[3]["Comprehension"] == "opaque"
    assert facts[3]["OpaqueReason"] == "xt"


def test_position_is_preserved_per_chain_because_order_is_meaning(monkeypatch):
    """nftables evaluates top to bottom and the first match wins, so a rule
    list re-sorted for display would be a different ruleset. Each chain
    numbers from zero independently."""
    facts = build(monkeypatch,
                  rule(1, [ACCEPT], chain="input"),
                  rule(2, [ACCEPT], chain="input"),
                  rule(3, [ACCEPT], chain="forward"))
    assert facts[1]["Position"] == 0
    assert facts[2]["Position"] == 1
    assert facts[3]["Position"] == 0, "a second chain numbers from its own start"


def test_every_row_is_keyed_by_the_kernels_handle(monkeypatch):
    import asyncio
    payload = {"nftables": [{"rule": rule(42, [ACCEPT])}]}
    monkeypatch.setattr(network, "_nft_json", lambda: payload)
    [item] = asyncio.run(network.Adapter()._nft_rules())
    assert item["id"] == "nft-rule:inet/filter/input/42"
    assert item["facts"]["Handle"] == 42


def test_the_source_states_what_xt_means_and_where_to_look(monkeypatch):
    """A collection-level statement, because on any Docker or libvirt host
    this fires and the operator needs the tool that can read those rules."""
    notes = network.Adapter()._source_for("nft-rules")["notes"]
    joined = " ".join(notes)
    assert "iptables-nft" in joined
    assert "handle" in joined.lower()
    commands = network.Adapter()._source_for("nft-rules")["reference_commands"]
    assert any("iptables-nft" in c for c in commands)


def test_rules_carry_no_severity(monkeypatch):
    """A rule is not healthy or unhealthy. Grading one would need to know what
    it admits and from where, which is the derived collection's question and
    is answered with two closures rather than a dot."""
    import asyncio
    payload = {"nftables": [{"rule": rule(1, [ACCEPT])}]}
    monkeypatch.setattr(network, "_nft_json", lambda: payload)
    [item] = asyncio.run(network.Adapter()._nft_rules())
    assert "worst_opinion_level" not in item
