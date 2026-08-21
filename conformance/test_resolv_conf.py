"""resolv.conf parses by its own grammar — the resolver's file shape.

A host that resolves names through a dhcpcd-written resolv.conf spent its
life declined because one implementation (resolve1) was absent — the
packages lesson repeated, and now fixed the same way: the question is
universal, only the answer is not, and ResolverService says which answer
this is (SPEC rule 16).
"""

from system_explorer.agent.adapters.network import parse_resolv_conf


def test_the_common_shape():
    facts = parse_resolv_conf(
        "# written by dhcpcd\n"
        "nameserver 192.168.123.1\n"
        "nameserver 100.100.100.100\n"
        "search red.example home.example\n")
    assert facts["Nameservers"] == ["192.168.123.1", "100.100.100.100"]
    assert facts["SearchDomains"] == ["red.example", "home.example"]
    assert facts["Options"] == []


def test_glibc_semantics_replace_search_accumulate_options():
    facts = parse_resolv_conf(
        "search first.example\n"
        "options timeout:1\n"
        "domain second.example\n"      # deprecated spelling; last wins
        "options attempts:2 rotate\n")
    assert facts["SearchDomains"] == ["second.example"]
    assert facts["Options"] == ["timeout:1", "attempts:2", "rotate"]


def test_comments_and_blank_lines_vanish():
    facts = parse_resolv_conf(
        "; resolvconf comment\n"
        "\n"
        "nameserver 1.1.1.1 # trailing\n")
    assert facts["Nameservers"] == ["1.1.1.1"]


def test_an_empty_file_is_empty_facts_not_an_error():
    facts = parse_resolv_conf("")
    assert facts == {"Nameservers": [], "SearchDomains": [], "Options": []}


def test_systemd_261_rehomes_loopback_globals_onto_lo():
    # Raw probe from a live estate host on systemd 261.1 (2026-08-13):
    # resolved.conf says DNS=127.0.0.1 ::1, yet Manager.DNS presents those
    # servers with ifindex 1 (loopback), not the classic global ifindex 0
    # — while resolvectl still files them under "Global". The ifindex-0
    # filter read empty globals and fired a false fallback warn on a host
    # running a deliberate local recursive resolver.
    from system_explorer.agent.adapters.network import global_dns_servers
    jar_probe = [
        [1, 2, bytes([127, 0, 0, 1])],
        [1, 10, bytes([0] * 15 + [1])],
        [7, 2, bytes([100, 100, 100, 100])],
        [7, 10, bytes.fromhex("fd7a115ca1e00000000000000000" + "0053")],
    ]
    servers = global_dns_servers(jar_probe)
    assert "127.0.0.1" in servers and "::1" in servers
    # The per-link (tailscale, ifindex 7) servers stay per-link.
    assert "100.100.100.100" not in servers
    # The classic ifindex-0 shape keeps working on older resolved.
    assert global_dns_servers([[0, 2, bytes([9, 9, 9, 9])]]) == ["9.9.9.9"]


# ── a route's family is read from the route, not from the call ───────────

def test_family_is_derived_from_the_destination():
    """The label was an artefact of which subprocess the row arrived in, and
    a widened dump therefore mislabelled a whole family. Reading it from the
    destination means the fact cannot contradict the address beside it."""
    from system_explorer.agent.adapters.network import _family_of
    assert _family_of("10.0.0.0/8") == "ipv4"
    assert _family_of("192.168.1.1") == "ipv4"
    assert _family_of("fd7a:115c:a1e0::53") == "ipv6"
    assert _family_of("2a01:4b00:875f:b700::/64") == "ipv6"
    assert _family_of("ff00::/8") == "ipv6"


def test_a_destination_naming_no_address_falls_back_to_the_call():
    """`default` is the one row where the call is the only evidence of
    family, so it keeps it rather than being dropped or guessed."""
    from system_explorer.agent.adapters.network import _family_of
    assert _family_of("default") is None
    assert _family_of("") is None


def test_the_ipv4_dump_states_its_family_to_the_tool():
    """iproute2 only defaults a route dump to AF_INET when a table filter is
    set, and `table all` unsets it — so a call without `-4` returns BOTH
    families and every row gets stamped with the loop's family. This asserts
    the flag is present in the call AND in the reference command, because an
    administrator running the cited command must see what was measured."""
    import inspect
    from system_explorer.agent.adapters import network
    # The argv moved into the zero-arg seam wrappers at R3b; the claim this
    # guard holds — the family is stated, because `table all` unsets the
    # AF_INET default — now lives there.
    source = inspect.getsource(network._ip_route4)
    assert '"-4", "route", "show", "table", "all"' in source, (
        "the ipv4 route dump no longer states its family; `table all` widens "
        "it to AF_UNSPEC and every IPv6 route comes back labelled ipv4"
    )
    assert network.ROUTE_REFERENCE[0] == "ip -4 route show table all"
