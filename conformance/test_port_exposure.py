"""The socket, the rules that admit it, and two answers instead of one.

This is the collection that answers "which ports are reachable, and from
where" — as far as a static read honestly can, which is not all the way, and
the tests below pin the boundary as hard as they pin the answer.

The two-closure construction is borrowed from Diekmann's machine-checked
iptables semantics: an unreadable clause is treated as NON-matching for the
certain answer and as always-matching for the possible one. The property that
matters is directional and structural rather than a discipline anyone has to
remember — ignorance can never strengthen the certain answer, so the worst
case is under-claiming loudly.

The estate's own shape is the fixture throughout: a NixOS input chain that
does nothing but jump to nixos-fw, an sshd bound to 0.0.0.0 that is safe only
because one rule admits it on tailscale0, and an xt rule alongside whose
conditions nft's JSON does not carry.
"""

from __future__ import annotations

import asyncio

import pytest

from system_explorer.agent.adapters import network

ACCEPT = {"accept": None}
TCP_HEADER = "  sl  local_address rem_address   st ...\n"


def line(local, state="0A"):
    return (f"   0: {local} 00000000:0000 {state} 00000000:00000000"
            " 00:00000000 00000000     0        0 1"
            " 1 0000000000000000 100 0 0 10 0\n")


def match(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


DPORT22 = match({"payload": {"protocol": "tcp", "field": "dport"}}, 22)
IIF_TS = match({"meta": {"key": "iifname"}}, "tailscale0")


def estate(monkeypatch, tmp_path, *nixos_fw_rules, sockets=None):
    """A host shaped like the estate's: input jumps to nixos-fw and decides
    nothing itself, which is why a walk that stopped at base chains would
    report that no rule admits anything."""
    monkeypatch.setattr(network, "PROC_NET", str(tmp_path))
    for name in ("tcp", "tcp6", "udp", "udp6"):
        (tmp_path / name).write_text(
            TCP_HEADER + (sockets if sockets is not None and name == "tcp"
                          else ("" if name != "tcp" else line("00000000:0016"))))
    document = {"nftables": [
        {"chain": {"family": "ip", "table": "filter", "name": "INPUT",
                   "hook": "input", "policy": "accept"}},
        {"rule": {"family": "ip", "table": "filter", "chain": "INPUT",
                  "handle": 1, "expr": [{"jump": {"target": "nixos-fw"}}]}},
    ] + [{"rule": {"family": "ip", "table": "filter", "chain": "nixos-fw",
                   "handle": 10 + i, "expr": list(expr)}}
         for i, expr in enumerate(nixos_fw_rules)]}
    monkeypatch.setattr(network, "_nft_json", lambda: document)
    return document


def exposure(monkeypatch, tmp_path, *rules, sockets=None):
    estate(monkeypatch, tmp_path, *rules, sockets=sockets)
    return {i["native_id"]: i["facts"]
            for i in asyncio.run(network.Adapter()._exposure_items())}


# ── the case that started this ───────────────────────────────────────────

def test_the_narrow_rule_is_the_certain_answer(monkeypatch, tmp_path):
    """sshd on 0.0.0.0:22, safe only because one rule admits it on
    tailscale0. The certain answer must name the interface, because that is
    the claim an operator acts on."""
    facts = exposure(monkeypatch, tmp_path, [IIF_TS, DPORT22, ACCEPT])
    row = facts["tcp 0.0.0.0:22"]
    assert row["AdmittedFromCertain"] == ["meta iifname tailscale0"]
    assert row["AdmittedFromPossible"] == ["meta iifname tailscale0"]
    assert row["ClosureGap"] is False
    assert len(row["AdmittingRules"]) == 1


def test_deleting_the_narrow_rule_empties_the_certain_answer(monkeypatch, tmp_path):
    """The whole point, stated as a diff. Today deleting this rule moves a
    count from 25 to 24; here it empties a named field on a row whose subject
    is the socket, which a human scanning the page and a what-changed sweep
    both see."""
    before = exposure(monkeypatch, tmp_path, [IIF_TS, DPORT22, ACCEPT])
    after = exposure(monkeypatch, tmp_path)
    assert before["tcp 0.0.0.0:22"]["AdmittedFromCertain"] == [
        "meta iifname tailscale0"]
    assert "AdmittedFromCertain" not in after["tcp 0.0.0.0:22"]
    assert "AdmittingRules" not in after["tcp 0.0.0.0:22"]


def test_a_rule_with_no_source_constraint_admits_from_anywhere(monkeypatch, tmp_path):
    """An empty source list would read as "no sources", which is the opposite
    of what an unconstrained rule means."""
    facts = exposure(monkeypatch, tmp_path, [DPORT22, ACCEPT])
    assert facts["tcp 0.0.0.0:22"]["AdmittedFromCertain"] == ["anywhere"]


# ── the two closures, and the direction of failure ───────────────────────

def test_an_unreadable_clause_cannot_strengthen_the_certain_answer(
        monkeypatch, tmp_path):
    """The structural guarantee. A rule this adapter cannot fully read is
    excluded from the certain answer entirely — so an unparsed `iifname`
    can never widen what SE claims it can defend."""
    facts = exposure(monkeypatch, tmp_path,
                     [match({"fib": {"result": "oif"}}, "lo"), DPORT22, ACCEPT])
    row = facts["tcp 0.0.0.0:22"]
    assert "AdmittedFromCertain" not in row, (
        "a rule with an unreadable clause reached the lower closure")
    assert row["AdmittedFromPossible"] == ["anywhere"]
    assert row["ClosureGap"] is True
    assert row["ClosureGapRules"] == ["ip/filter/nixos-fw/10"]


def test_an_xt_rule_opens_the_gap_and_names_itself(monkeypatch, tmp_path):
    """The live case on every Docker, libvirt and NixOS-firewall host: nft's
    JSON carries the extension's name and none of its parameters, so the
    rule's conditions are absent from the document rather than unparsed."""
    facts = exposure(monkeypatch, tmp_path,
                     [{"xt": {"type": "match", "name": "conntrack"}}, ACCEPT])
    row = facts["tcp 0.0.0.0:22"]
    assert "AdmittedFromCertain" not in row
    assert row["AdmittedFromPossible"] == ["anywhere"]
    assert row["ClosureGap"] is True


def test_the_certain_answer_survives_an_unreadable_rule_beside_it(
        monkeypatch, tmp_path):
    """Both answers at once, which is the shape an operator actually meets:
    one rule understood, one not. The certain answer keeps what it can
    defend and the gap is flagged rather than the whole row being abandoned.
    """
    facts = exposure(monkeypatch, tmp_path,
                     [IIF_TS, DPORT22, ACCEPT],
                     [{"xt": {"type": "match", "name": "conntrack"}}, ACCEPT])
    row = facts["tcp 0.0.0.0:22"]
    assert row["AdmittedFromCertain"] == ["meta iifname tailscale0"]
    assert row["AdmittedFromPossible"] == ["meta iifname tailscale0", "anywhere"]
    assert row["ClosureGap"] is True
    assert len(row["AdmittingRules"]) == 2


# ── what bears on the socket, and what does not ──────────────────────────

def test_a_rule_for_another_port_does_not_appear(monkeypatch, tmp_path):
    other = match({"payload": {"protocol": "tcp", "field": "dport"}}, 443)
    facts = exposure(monkeypatch, tmp_path, [other, ACCEPT])
    assert "AdmittingRules" not in facts["tcp 0.0.0.0:22"]


def test_a_rule_with_no_port_constraint_bears_on_every_port(monkeypatch, tmp_path):
    """A blanket `iifname lo accept` admits everything, and that is exactly
    the rule an operator most needs to see on this page."""
    facts = exposure(monkeypatch, tmp_path,
                     [match({"meta": {"key": "iifname"}}, "lo"), ACCEPT])
    assert facts["tcp 0.0.0.0:22"]["AdmittedFromCertain"] == ["meta iifname lo"]


def test_a_set_of_ports_is_matched_by_membership(monkeypatch, tmp_path):
    dports = match({"payload": {"protocol": "tcp", "field": "dport"}},
                   {"set": [22, 80]})
    facts = exposure(monkeypatch, tmp_path, [dports, ACCEPT])
    assert facts["tcp 0.0.0.0:22"]["AdmittedFromCertain"] == ["anywhere"]


def test_a_drop_rule_is_not_an_admission(monkeypatch, tmp_path):
    facts = exposure(monkeypatch, tmp_path, [DPORT22, {"drop": None}])
    assert "AdmittingRules" not in facts["tcp 0.0.0.0:22"]


def test_the_walk_follows_the_jump_because_the_estate_is_built_of_them(
        monkeypatch, tmp_path):
    """A NixOS input chain is a jump to nixos-fw and nothing else, so a walk
    that stopped at base chains would report that no rule admits anything on
    every host in the estate."""
    document = estate(monkeypatch, tmp_path, [IIF_TS, DPORT22, ACCEPT])
    walked = network._walk_input_path(document)
    assert [rule["handle"] for rule, _guards in walked] == [1, 10]


def test_a_chain_cycle_terminates(monkeypatch, tmp_path):
    document = {"nftables": [
        {"chain": {"family": "ip", "table": "filter", "name": "INPUT",
                   "hook": "input", "policy": "drop"}},
        {"rule": {"family": "ip", "table": "filter", "chain": "INPUT",
                  "handle": 1, "expr": [{"jump": {"target": "a"}}]}},
        {"rule": {"family": "ip", "table": "filter", "chain": "a",
                  "handle": 2, "expr": [{"jump": {"target": "INPUT"}}]}},
    ]}
    assert len(network._walk_input_path(document)) == 2


# ── the limits, stated where a consumer will meet them ───────────────────

def test_every_row_states_the_path_it_covers(monkeypatch, tmp_path):
    """Not only in the source block. A consumer holding one object must be
    able to see that an empty admitting list is a statement about the input
    path, never about the port — otherwise this rebuilds the firewalld/Docker
    trap it exists to avoid."""
    facts = exposure(monkeypatch, tmp_path)
    assert "input path only" in facts["tcp 0.0.0.0:22"]["PathCoverage"]
    assert "prerouting/forward" in facts["tcp 0.0.0.0:22"]["PathCoverage"]


def test_nothing_in_the_collection_claims_reachability(monkeypatch, tmp_path):
    """The honest ceiling for a static read is "this rule admits it". The
    word reachable belongs to a live trace, which this product cannot arm
    because arming a trace is a write."""
    facts = exposure(monkeypatch, tmp_path, [IIF_TS, DPORT22, ACCEPT])
    row = facts["tcp 0.0.0.0:22"]
    assert not [k for k in row if "reach" in k.lower()]
    glossary = network.Adapter().fact_glossary("port-exposure")
    assert not [k for k in glossary if "reach" in k.lower()]
    notes = " ".join(network.Adapter()._source_for("port-exposure")["notes"])
    assert "Nothing here claims reachability" in notes
    assert "nft monitor trace" in " ".join(
        network.Adapter()._source_for("port-exposure")["reference_commands"])


def test_rows_carry_no_severity(monkeypatch, tmp_path):
    """Whether an admitted port is a problem is the operator's judgement
    about their own estate; a dot here would be this product deciding that a
    port it does not understand the purpose of should alarm."""
    estate(monkeypatch, tmp_path, [DPORT22, ACCEPT])
    [item] = asyncio.run(network.Adapter()._exposure_items())
    assert "worst_opinion_level" not in item


def test_an_unreadable_ruleset_declines_the_collection_by_name():
    """The difference between "no rule admits this" and "the ruleset could
    not be read" — serving sockets with empty admitting lists would report a
    closed port on a host whose firewall was simply unreadable."""
    import asyncio as aio
    adapter = network.Adapter()
    adapter._nft_state = (False, "nft not on PATH")
    adapter._nft_probed_at = float("inf")
    caps = aio.run(adapter.capability())
    reason = caps["unavailable_collections"]["port-exposure"]
    assert "unread ruleset rather than a closed one" in reason


# ── the guard the estate's own firewall depends on ───────────────────────

def test_conditions_on_a_jumping_rule_guard_the_chain_it_jumps_to(
        monkeypatch, tmp_path):
    """The bug this found on a live host. NixOS admits a port by jumping to
    nixos-fw-accept under `iifname tailscale0 tcp dport 22`, and
    nixos-fw-accept holds a bare `counter accept` with no conditions of its
    own. A walk that flattened the two finds an unconditional accept and
    reports EVERY port on the host as admitted from anywhere."""
    monkeypatch.setattr(network, "PROC_NET", str(tmp_path))
    for name in ("tcp", "tcp6", "udp", "udp6"):
        (tmp_path / name).write_text(
            TCP_HEADER + (line("00000000:0016") if name == "tcp" else ""))
    document = {"nftables": [
        {"chain": {"family": "ip", "table": "filter", "name": "INPUT",
                   "hook": "input", "policy": "drop"}},
        {"rule": {"family": "ip", "table": "filter", "chain": "INPUT",
                  "handle": 1, "expr": [{"jump": {"target": "nixos-fw"}}]}},
        {"rule": {"family": "ip", "table": "filter", "chain": "nixos-fw",
                  "handle": 2, "expr": [IIF_TS, DPORT22,
                                        {"jump": {"target": "nixos-fw-accept"}}]}},
        {"rule": {"family": "ip", "table": "filter", "chain": "nixos-fw-accept",
                  "handle": 3, "expr": [{"counter": {"packets": 1, "bytes": 1}},
                                        ACCEPT]}},
    ]}
    monkeypatch.setattr(network, "_nft_json", lambda: document)
    [item] = asyncio.run(network.Adapter()._exposure_items())
    facts = item["facts"]
    assert facts["AdmittedFromCertain"] == ["meta iifname tailscale0"], (
        "the jumping rule's conditions did not reach the accept it guards")
    assert facts["AdmittedFromCertain"] != ["anywhere"]


def test_a_guarded_accept_does_not_leak_to_an_unrelated_port(
        monkeypatch, tmp_path):
    """The same guard, from the other side: an accept reached only under
    `tcp dport 22` must not admit port 443."""
    monkeypatch.setattr(network, "PROC_NET", str(tmp_path))
    for name in ("tcp", "tcp6", "udp", "udp6"):
        (tmp_path / name).write_text(
            TCP_HEADER + (line("00000000:01BB") if name == "tcp" else ""))
    document = {"nftables": [
        {"chain": {"family": "ip", "table": "filter", "name": "INPUT",
                   "hook": "input", "policy": "drop"}},
        {"rule": {"family": "ip", "table": "filter", "chain": "INPUT",
                  "handle": 1, "expr": [DPORT22,
                                        {"jump": {"target": "ok"}}]}},
        {"rule": {"family": "ip", "table": "filter", "chain": "ok",
                  "handle": 2, "expr": [ACCEPT]}},
    ]}
    monkeypatch.setattr(network, "_nft_json", lambda: document)
    [item] = asyncio.run(network.Adapter()._exposure_items())
    assert "AdmittingRules" not in item["facts"]


# ── the bug the estate found after this shipped ──────────────────────────

def test_an_icmp_only_accept_does_not_admit_a_tcp_port(monkeypatch, tmp_path):
    """Found on a live host, and it was CERTAIN — the worst place to be
    because the certain answer is the one an operator is told they can
    defend. nixos-fw-accept holds `meta l4proto ipv6-icmp counter accept`,
    fully rendered and reached under no source constraint, and the closure
    credited it with admitting tcp/22 from anywhere. A protocol can be
    constrained through meta as well as through the packet's own header, and
    reading only the second is the difference between an ICMP hole and an
    open SSH port."""
    monkeypatch.setattr(network, "PROC_NET", str(tmp_path))
    for name in ("tcp", "tcp6", "udp", "udp6"):
        (tmp_path / name).write_text(
            TCP_HEADER + (line("00000000:0016") if name == "tcp" else ""))
    icmp = match({"meta": {"key": "l4proto"}}, "ipv6-icmp")
    document = {"nftables": [
        {"chain": {"family": "ip6", "table": "filter", "name": "INPUT",
                   "hook": "input", "policy": "drop"}},
        {"rule": {"family": "ip6", "table": "filter", "chain": "INPUT",
                  "handle": 1, "expr": [icmp, {"jump": {"target": "ok"}}]}},
        {"rule": {"family": "ip6", "table": "filter", "chain": "ok",
                  "handle": 2, "expr": [{"counter": {}}, ACCEPT]}},
    ]}
    monkeypatch.setattr(network, "_nft_json", lambda: document)
    [item] = asyncio.run(network.Adapter()._exposure_items())
    assert "AdmittedFromCertain" not in item["facts"], (
        "an ICMP-only accept was credited with admitting a TCP port")
    assert "AdmittingRules" not in item["facts"]


def test_a_matching_l4proto_still_admits(monkeypatch, tmp_path):
    """The other direction: `meta l4proto tcp` does bear on a tcp socket, so
    the fix must not turn every meta match into a refusal."""
    monkeypatch.setattr(network, "PROC_NET", str(tmp_path))
    for name in ("tcp", "tcp6", "udp", "udp6"):
        (tmp_path / name).write_text(
            TCP_HEADER + (line("00000000:0016") if name == "tcp" else ""))
    document = {"nftables": [
        {"chain": {"family": "ip", "table": "filter", "name": "INPUT",
                   "hook": "input", "policy": "drop"}},
        {"rule": {"family": "ip", "table": "filter", "chain": "INPUT",
                  "handle": 1, "expr": [match({"meta": {"key": "l4proto"}}, "tcp"),
                                        DPORT22, ACCEPT]}},
    ]}
    monkeypatch.setattr(network, "_nft_json", lambda: document)
    [item] = asyncio.run(network.Adapter()._exposure_items())
    assert item["facts"]["AdmittedFromCertain"] == ["anywhere"]


# ── the coverage mismatch that produced the ICMP defect ──────────────────
#
# That bug was not a parsing failure. The renderer understood
# `meta l4proto ipv6-icmp` perfectly and printed it; the CLOSURE ignored it,
# so a rule constraining protocol read as a rule constraining nothing and
# went into the certain answer. The tests below make that class of mistake
# fail here rather than on a live host.

RENDERABLE_MATCHES = [
    ("tcp dport", {"payload": {"protocol": "tcp", "field": "dport"}}, 22),
    ("ip protocol", {"payload": {"protocol": "ip", "field": "protocol"}}, "icmp"),
    ("ip saddr", {"payload": {"protocol": "ip", "field": "saddr"}},
     {"prefix": {"addr": "10.0.0.0", "len": 8}}),
    ("ip6 saddr", {"payload": {"protocol": "ip6", "field": "saddr"}}, "::1"),
    ("meta iifname", {"meta": {"key": "iifname"}}, "tailscale0"),
    ("meta l4proto", {"meta": {"key": "l4proto"}}, "ipv6-icmp"),
    ("meta mark", {"meta": {"key": "mark"}}, 1),
    ("tcp sport", {"payload": {"protocol": "tcp", "field": "sport"}}, 1234),
    ("ct state", {"ct": {"key": "state"}}, "established"),
]


def test_every_renderable_match_is_classified():
    """The invariant. A term this renderer can print must be sorted into
    exactly one of destination, source or other — and adding a renderable
    shape without deciding which now fails here instead of quietly widening
    the certain answer on a live firewall."""
    for label, left, right in RENDERABLE_MATCHES:
        body = {"op": "==", "left": left, "right": right}
        text, understood = network._render_match(body)
        assert understood, f"{label} no longer renders; update this table"
        assert network._classify_match(body) in ("destination", "source", "other"), (
            f"{label} renders as {text!r} but is classified as nothing")


def test_an_unmodelled_but_renderable_constraint_costs_certainty():
    """`other` is the safety property, not bookkeeping. A rule narrowed by
    something this closure does not model — a mark, a source port, a ct state
    — must not reach the certain answer, because treating that constraint as
    absent is the same inversion in a different coat."""
    marked = [match({"meta": {"key": "mark"}}, 1), DPORT22, ACCEPT]
    rendered = network._render_rule(marked)
    assert rendered["residue"] == [], "the mark renders; this is not a parse gap"
    sure, maybe = network._rule_bears_on(rendered, marked, "tcp", 22)
    assert (sure, maybe) == (False, True)


def test_a_destination_constraint_for_another_protocol_excludes_the_rule():
    """The defect itself, as a unit: an ICMP-only rule bears on no TCP
    socket, whether the protocol was stated through the header or through
    meta."""
    for left, value in (({"meta": {"key": "l4proto"}}, "ipv6-icmp"),
                        ({"payload": {"protocol": "ip", "field": "protocol"}},
                         "icmp")):
        expr = [match(left, value), ACCEPT]
        rendered = network._render_rule(expr)
        assert network._rule_bears_on(rendered, expr, "tcp", 22) == (False, False)


def test_only_source_terms_reach_the_reported_answer():
    """A destination constraint is a filter, not an answer: reporting
    `tcp dport 22` as somewhere traffic comes FROM would be nonsense an
    operator has to unpick."""
    expr = [match({"meta": {"key": "iifname"}}, "tailscale0"), DPORT22, ACCEPT]
    assert network._sources_of(expr) == ["meta iifname tailscale0"]


# ── soundness holes an adversarial review found, each pinned ─────────────
#
# Five of these existed at once in a computation whose whole promise is that
# it can only ever under-claim, and every one made the CERTAIN answer wrong.
# Inspection had already caught two others. The lesson recorded here is that
# this closure needs adversarial cases, not more reading.

def bears(expr, protocol="tcp", port=22):
    return network._rule_bears_on(network._render_rule(expr), expr, protocol, port)


def dport(value, op="=="):
    return match({"payload": {"protocol": "tcp", "field": "dport"}}, value, op)


def test_a_port_range_inside_a_set_is_a_port_constraint():
    """The renderer understands `{ 8000-8100 }` and prints it with no residue.
    A closure that extracted only the integers dropped the whole constraint,
    and an empty port set reads as "no port constraint" — so ONE range rule
    made every port on the host certainly admitted from anywhere."""
    rule = [dport({"set": [{"range": [8000, 8100]}]}), ACCEPT]
    assert bears(rule, port=22) == (False, False)
    assert bears(rule, port=8050) == (True, True)


def test_a_set_mixing_ports_and_ranges_admits_both():
    rule = [dport({"set": [22, {"range": [8000, 8100]}]}), ACCEPT]
    assert bears(rule, port=22) == (True, True)
    assert bears(rule, port=8080) == (True, True)
    assert bears(rule, port=443) == (False, False)


def test_a_malformed_range_is_unreadable_rather_than_unbounded():
    rule = [dport({"set": [{"range": [70000, 1]}]}), ACCEPT]
    sure, maybe = bears(rule)
    assert sure is False, "an unreadable port shape must not stay certain"


def test_a_negated_port_is_not_read_as_the_positive_match():
    """`tcp dport != 22` admits everything BUT ssh. Reading it as `== 22`
    inverts the rule — and the module header names this as the mistake every
    shipped exporter makes, which did not stop it being made here."""
    rule = [dport(22, "!="), ACCEPT]
    sure, maybe = bears(rule, port=22)
    assert sure is False, "an exclusion was read as an inclusion"
    assert maybe is True, "and it is still possible, because it was not modelled"


def test_a_negated_protocol_costs_certainty_too():
    rule = [match({"meta": {"key": "l4proto"}}, "tcp", "!="), ACCEPT]
    assert bears(rule)[0] is False


def test_guard_and_rule_constraints_intersect_rather_than_union():
    """`tcp dport 22 jump svc` guarding `tcp dport 443 accept` admits NEITHER
    port. Pooling both into one list said it admits both — a dispatch jump
    turning two narrow rules into one wide one."""
    assert bears([dport(22), dport(443), ACCEPT], port=22) == (False, False)
    assert bears([dport(22), dport(443), ACCEPT], port=443) == (False, False)
    assert bears([dport(22), dport(22), ACCEPT], port=22) == (True, True)


@pytest.mark.parametrize("family,protocol,applies", [
    ("ip", "tcp", True), ("ip", "tcp6", False),
    ("ip6", "tcp6", True), ("ip6", "tcp", False),
    ("inet", "tcp", True), ("inet", "tcp6", True),
    ("bridge", "tcp", False), ("arp", "tcp", False),
])
def test_a_rules_address_family_must_match_the_socket(family, protocol, applies):
    """A whole table's worth of rules landing on the wrong sockets: an
    ip6-only accept was certainly admitting IPv4 sockets."""
    assert network._family_bears_on(family, protocol) is applies


def test_an_ip6_only_accept_does_not_admit_an_ipv4_socket(monkeypatch, tmp_path):
    monkeypatch.setattr(network, "PROC_NET", str(tmp_path))
    for name in ("tcp", "tcp6", "udp", "udp6"):
        (tmp_path / name).write_text(
            TCP_HEADER + (line("00000000:0016") if name == "tcp" else ""))
    document = {"nftables": [
        {"chain": {"family": "ip6", "table": "filter", "name": "INPUT",
                   "hook": "input", "policy": "drop"}},
        {"rule": {"family": "ip6", "table": "filter", "chain": "INPUT",
                  "handle": 1, "expr": [DPORT22, ACCEPT]}},
    ]}
    monkeypatch.setattr(network, "_nft_json", lambda: document)
    [item] = asyncio.run(network.Adapter()._exposure_items())
    assert "AdmittedFromCertain" not in item["facts"]
    assert "AdmittingRules" not in item["facts"]


def test_a_rule_whose_verdict_cannot_be_read_raises_the_gap(monkeypatch, tmp_path):
    """A verdict map, or a statement nft could only emit as text, might be an
    accept. Skipping it dropped the rule from BOTH closures, so the row
    reported no admitting rule and no gap either — silence where the honest
    answer is "something here might admit this and I cannot tell"."""
    monkeypatch.setattr(network, "PROC_NET", str(tmp_path))
    for name in ("tcp", "tcp6", "udp", "udp6"):
        (tmp_path / name).write_text(
            TCP_HEADER + (line("00000000:0016") if name == "tcp" else ""))
    document = {"nftables": [
        {"chain": {"family": "ip", "table": "filter", "name": "INPUT",
                   "hook": "input", "policy": "drop"}},
        {"rule": {"family": "ip", "table": "filter", "chain": "INPUT",
                  "handle": 1, "expr": [DPORT22, {"vmap": {"key": "x"}}]}},
    ]}
    monkeypatch.setattr(network, "_nft_json", lambda: document)
    [item] = asyncio.run(network.Adapter()._exposure_items())
    facts = item["facts"]
    assert facts["ClosureGap"] is True
    assert "AdmittedFromCertain" not in facts
    assert facts["AdmittedFromPossible"] == ["anywhere"]


def test_the_notes_state_both_deliberate_under_claims():
    notes = " ".join(network.Adapter()._source_for("port-exposure")["notes"])
    assert "IPv4-mapped" in notes
    assert "costs the rule its place in the certain answer" in notes
