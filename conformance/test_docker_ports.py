"""Container port mappings render actionably in every shape docker lists.

The admin question this fact answers — "how do I connect to this container
from the network" — went unanswerable: the rows folded state and image from
/containers/json and dropped the Ports member on the floor, so nothing on
screen said where a service was published. The document also has two shapes
that would render dishonestly if folded naively: a dual-stack publish is
listed twice (IP 0.0.0.0 and ::) for one binding, and an exposed-but-
unpublished port has no PublicPort at all — the second is exactly the "why
can't I reach this" case, so it renders marked rather than being omitted.

_port_mappings() is module-level and pure (the scan_facts precedent); the
rendering rules it commits to are stated in its own docstring.
"""

from system_explorer.agent.adapters.docker import _port_mappings


def test_a_published_mapping_renders_host_arrow_container():
    assert _port_mappings(
        [{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080,
          "Type": "tcp"}]) == ["0.0.0.0:8080->80/tcp"]


def test_multiple_mappings_sort_by_container_port_then_protocol():
    # The daemon lists in arbitrary order; the fold's order is by container
    # port, protocol, host port — stable, so rows diff cleanly across runs.
    got = _port_mappings([
        {"IP": "0.0.0.0", "PrivatePort": 443, "PublicPort": 8443, "Type": "tcp"},
        {"IP": "0.0.0.0", "PrivatePort": 53, "PublicPort": 53, "Type": "udp"},
        {"IP": "0.0.0.0", "PrivatePort": 53, "PublicPort": 53, "Type": "tcp"},
        {"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"},
    ])
    assert got == ["0.0.0.0:53->53/tcp", "0.0.0.0:53->53/udp",
                   "0.0.0.0:8080->80/tcp", "0.0.0.0:8443->443/tcp"]


def test_the_dual_stack_pair_collapses_to_one_entry():
    # Docker lists one `-p 8080:80` twice, once per address family; two rows
    # for one binding would read as two bindings.
    got = _port_mappings([
        {"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"},
        {"IP": "::", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"},
    ])
    assert got == ["0.0.0.0:8080->80/tcp"]


def test_differing_host_ports_are_different_claims_and_both_stay():
    # `-p 8080:80` on v4 and `-p 8081:80` on v6 is two bindings, not a
    # duplicate; collapsing here would hide a reachable port.
    got = _port_mappings([
        {"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"},
        {"IP": "::", "PrivatePort": 80, "PublicPort": 8081, "Type": "tcp"},
    ])
    assert got == ["0.0.0.0:8080->80/tcp", "[::]:8081->80/tcp"]


def test_a_specific_host_address_renders_verbatim():
    got = _port_mappings([
        {"IP": "192.0.2.10", "PrivatePort": 5432, "PublicPort": 5432,
         "Type": "tcp"}])
    assert got == ["192.0.2.10:5432->5432/tcp"]


def test_an_ipv6_only_publish_is_bracketed_so_it_pastes_into_curl():
    got = _port_mappings([
        {"IP": "::", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}])
    assert got == ["[::]:8080->80/tcp"]


def test_an_exposed_only_port_is_marked_not_omitted():
    # No PublicPort means EXPOSE without publish: reachable only from other
    # containers. Saying so is the answer to "why can't I reach this";
    # omitting it would mask the absence being chased.
    got = _port_mappings([
        {"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"},
        {"PrivatePort": 9000, "Type": "tcp"},
    ])
    assert got == ["0.0.0.0:8080->80/tcp", "9000/tcp (exposed)"]


def test_no_ports_at_all_is_none_never_an_empty_list():
    # None is what lets the caller leave the fact off entirely: a portless
    # container (host networking, batch jobs) says nothing rather than [].
    assert _port_mappings([]) is None
    assert _port_mappings(None) is None


def test_host_networking_states_its_mode_beside_the_absent_ports():
    # The two portless shapes must never render identically: "host" means
    # every port the process binds is open on the host's own addresses,
    # not nothing-reachable (adversarial review, 2026-08-13). NetworkMode
    # rides from the same document, so the row says which shape it is.
    import asyncio
    import json as jsonlib

    import httpx

    from system_explorer.agent.adapters import docker as mod

    def serve(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/containers/json"
        return httpx.Response(200, content=jsonlib.dumps([{
            "Names": ["/example-dns"], "State": "running",
            "Status": "Up 2 hours", "Image": "example:latest",
            "Created": 1755000000, "Id": "abcdef123456789",
            "HostConfig": {"NetworkMode": "host"}, "Ports": [],
        }]), headers={"content-type": "application/json"})

    adapter = mod.Adapter.__new__(mod.Adapter)
    adapter._client = httpx.AsyncClient(
        transport=httpx.MockTransport(serve), base_url="http://docker")
    [item] = asyncio.run(adapter._container_items())
    assert item["facts"]["NetworkMode"] == "host"
    assert "Ports" not in item["facts"]
