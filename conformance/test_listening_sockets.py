"""What is listening, and what the collection refuses to claim about it.

This is the prerequisite half of the reachability question. The market answer
to "which ports are reachable, and from where" is not a better rule list — ufw's
`show listening` and the three cloud consoles' effective-rules views all invert
the grain and put the SOCKET first, with the rules as evidence beneath it. This
collection is that first half, and its discipline is that it makes no claim
about the second: a socket on the wildcard address is not an exposed one until
a rule admits it.

The address decoding gets its own tests because getting it wrong is silent.
/proc/net prints 32-bit words in host byte order, so 0100007F is 127.0.0.1 —
and a reversed-string decoder yields 1.0.0.127, which is a plausible-looking
address for a socket that is not there.
"""

from __future__ import annotations

import asyncio

import pytest

from system_explorer.agent.adapters import network

TCP_HEADER = ("  sl  local_address rem_address   st tx_queue rx_queue tr"
              " tm->when retrnsmt   uid  timeout inode\n")


def line(local, state, uid=0, inode=1, remote="00000000:0000"):
    """One /proc/net row in the kernel's real column layout.

    Written through a helper because the layout is the thing under test and
    it is easy to get wrong by hand: tx_queue:rx_queue is ONE whitespace
    field and so is tr:tm->when, despite the header naming four columns. A
    fixture with an extra field shifts uid and inode and the parser looks
    broken when it is not — which is exactly what happened while writing
    these tests.
    """
    return (f"   0: {local} {remote} {state} 00000000:00000000"
            f" 00:00000000 00000000 {uid:5} {0:8} {inode}"
            " 1 0000000000000000 100 0 0 10 0\n")


def proc_net(monkeypatch, tmp_path, **tables):
    monkeypatch.setattr(network, "PROC_NET", str(tmp_path))
    for name, body in tables.items():
        (tmp_path / name).write_text(TCP_HEADER + body)
    return tmp_path


def rows(monkeypatch, tmp_path):
    return {item["native_id"]: item for item in network.Adapter()._listening_items()}


# ── the decoding, which is silent when wrong ─────────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("0100007F", "127.0.0.1"),
    ("00000000", "0.0.0.0"),
    ("0101A8C0", "192.168.1.1"),
    ("0" * 32, "::"),
    ("00000000000000000000000001000000", "::1"),
])
def test_proc_net_addresses_decode_word_wise(raw, expected):
    """Host byte order per 32-bit word, not a reversed string. The wrong
    decoder produces addresses that look real — 1.0.0.127 for loopback — so
    nothing downstream would ever notice."""
    assert network._hex_addr(raw) == expected


def test_an_address_that_will_not_decode_yields_nothing_rather_than_a_guess():
    assert network._hex_addr("nonsense") is None
    assert network._hex_addr("0102") is None


@pytest.mark.parametrize("address,scope", [
    ("0.0.0.0", "all-interfaces"),
    ("::", "all-interfaces"),
    ("127.0.0.1", "loopback"),
    ("127.0.0.53", "loopback"),
    ("::1", "loopback"),
    ("192.168.1.5", "specific-address"),
])
def test_scope_is_what_the_binding_says_before_any_rule(address, scope):
    """The fact the firewall question hangs off: a loopback socket is
    unreachable from off the host whatever the ruleset permits."""
    assert network._listening_scope(address) == scope


# ── only sockets that are actually accepting ─────────────────────────────

def test_only_listening_tcp_and_unconnected_udp_are_rows(monkeypatch, tmp_path):
    """An established connection is not a listening socket, and publishing it
    as one would report every outbound connection as an exposed port."""
    proc_net(monkeypatch, tmp_path,
             tcp=line("00000000:0016", "0A") + line("0100007F:8AE1", "01", remote="0100007F:C1B2"),
             tcp6="", udp=line("00000000:0035", "07"),
             udp6="")
    found = rows(monkeypatch, tmp_path)
    assert "tcp 0.0.0.0:22" in found
    assert "udp 0.0.0.0:53" in found
    assert not [k for k in found if "35553" in k or ":49633" in k], (
        "an established connection reached the listening collection")


def test_both_stacks_appear_as_separate_sockets(monkeypatch, tmp_path):
    """Two sockets, and a ruleset can admit one family and not the other, so
    collapsing them would hide a real asymmetry."""
    proc_net(monkeypatch, tmp_path,
             tcp=line("00000000:0016", "0A"),
             tcp6=line("0" * 32 + ":0016", "0A", remote="0" * 32 + ":0000"),
             udp="", udp6="")
    found = rows(monkeypatch, tmp_path)
    assert "tcp 0.0.0.0:22" in found
    assert "tcp6 :::22" in found


def test_rows_are_ordered_by_port(monkeypatch, tmp_path):
    """The number an operator is looking for, not the kernel's hash order."""
    proc_net(monkeypatch, tmp_path,
             tcp=(line("00000000:1F90", "0A") + line("00000000:0016", "0A")
                  + line("0100007F:0035", "0A")),
             tcp6="", udp="", udp6="")
    ports = [i["facts"]["LocalPort"] for i in network.Adapter()._listening_items()]
    assert ports == [22, 53, 8080]


# ── what it refuses to claim ─────────────────────────────────────────────

def test_every_row_says_why_no_process_is_named(monkeypatch, tmp_path):
    """Stated per row rather than once on the collection: a consumer reading a
    single object must not have to have read the source block to know the
    process is missing for a reason rather than missing."""
    proc_net(monkeypatch, tmp_path,
             tcp=line("00000000:0016", "0A", uid=101, inode=27577),
             tcp6="", udp="", udp6="")
    facts = rows(monkeypatch, tmp_path)["tcp 0.0.0.0:22"]["facts"]
    assert "DynamicUser" in facts["ProcessUnobservable"]
    assert facts["Uid"] == 101, "what CAN be said about ownership is said"
    assert "Process" not in facts and "Command" not in facts


def test_a_table_that_will_not_open_is_named_on_the_rows(monkeypatch, tmp_path):
    """Otherwise a host whose /proc/net/udp6 was unreadable publishes a
    complete-looking list of TCP sockets — the absence-as-health shape, on the
    collection that exists to enumerate exposure."""
    proc_net(monkeypatch, tmp_path,
             tcp=line("00000000:0016", "0A"),
             tcp6="", udp="")
    # udp6 deliberately not written
    facts = rows(monkeypatch, tmp_path)["tcp 0.0.0.0:22"]["facts"]
    assert "udp6" in facts["TablesUnreadable"]


def test_a_complete_read_carries_no_unreadable_fact(monkeypatch, tmp_path):
    proc_net(monkeypatch, tmp_path,
             tcp=line("00000000:0016", "0A"),
             tcp6="", udp="", udp6="")
    facts = rows(monkeypatch, tmp_path)["tcp 0.0.0.0:22"]["facts"]
    assert "TablesUnreadable" not in facts


def test_the_collection_makes_no_reachability_claim(monkeypatch, tmp_path):
    """The discipline that keeps this honest: a wildcard socket is not an
    exposed one until a rule admits it, and no fact or opinion here says
    otherwise. Rows carry no severity at all — there is nothing to grade."""
    proc_net(monkeypatch, tmp_path,
             tcp=line("00000000:0016", "0A"),
             tcp6="", udp="", udp6="")
    [item] = network.Adapter()._listening_items()
    assert item["facts"]["Scope"] == "all-interfaces"
    assert "worst_opinion_level" not in item, (
        "a socket has no health of its own; grading one would be this "
        "collection answering a question it deliberately does not ask")
    notes = network.Adapter()._source_for("listening")["notes"]
    assert any("makes no claim" in n for n in notes)


def test_a_malformed_line_is_skipped_and_the_rest_survive(monkeypatch, tmp_path):
    proc_net(monkeypatch, tmp_path,
             tcp="   0: garbage\n" + line("00000000:0016", "0A"),
             tcp6="", udp="", udp6="")
    assert list(rows(monkeypatch, tmp_path)) == ["tcp 0.0.0.0:22"]


def test_the_collection_is_served_and_paged(monkeypatch, tmp_path):
    proc_net(monkeypatch, tmp_path,
             tcp=line("00000000:0016", "0A"),
             tcp6="", udp="", udp6="")
    page = asyncio.run(network.Adapter().collect("listening", {}, None, None))
    assert page["subsystem"] == "network"
    assert page["items"][0]["native_id"] == "tcp 0.0.0.0:22"
    assert page["source"]["adapter"] == "proc-net"
