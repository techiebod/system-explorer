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


def test_a_stopped_container_claims_no_scope_systemd_deleted():
    # The scope is transient: systemd drops it with the container's last
    # process, so naming it on an exited row would state a unit
    # `systemctl status` cannot find, and hang the runs edge on a target
    # units/units can never serve (adversarial review, 2026-08-13).
    from system_explorer.agent.adapters.docker import _scope_unit

    ident = "a" * 64
    assert _scope_unit(ident, "running") == f"docker-{ident}.scope"
    assert _scope_unit(ident, "restarting") == f"docker-{ident}.scope"
    assert _scope_unit(ident, "paused") == f"docker-{ident}.scope"
    for gone in ("exited", "created", "dead", "removing"):
        assert _scope_unit(ident, gone) is None, gone
    # No id, no claim; and an unstated state keeps the derivation rather
    # than inventing a stop nobody observed.
    assert _scope_unit("", "running") is None
    assert _scope_unit(ident) == f"docker-{ident}.scope"


# ── facts that do not apply are omitted, not defaulted ───────────────────

RUNNING = {
    "Id": "c06407a40a9409ad9c956bd718c2bfa3ca4f441df8d9a7612c1e4eec7b30e9e5",
    "RestartCount": 0, "Image": "sha256:a45b5ab0",
    "Config": {"Image": "linuxserver/radarr:latest@sha256:a45b5ab0",
               "Labels": {"com.docker.compose.project": "arr"}},
    "HostConfig": {"NetworkMode": "proxy"},
    "State": {"Status": "running", "ExitCode": 0, "Error": "", "OOMKilled": False,
              "Health": None, "StartedAt": "2026-08-13T20:36:02.844883089Z",
              "FinishedAt": "0001-01-01T00:00:00Z"},
}


def container(**state):
    from copy import deepcopy
    raw = deepcopy(RUNNING)
    raw["State"].update(state)
    return raw


def test_a_running_container_makes_no_claim_about_a_run_that_has_not_ended():
    """Reported from the deployed UI: five of fourteen rows said nothing.
    `ExitCode: 0` beside `State: running` is worse than noise — it positively
    asserts a clean exit for a process that never exited, and a model over
    MCP has to reconcile the two."""
    from system_explorer.agent.adapters.docker import _container_facts
    facts = _container_facts(RUNNING)
    for absent in ("ExitCode", "FinishedAt", "OOMKilled", "Error", "Health"):
        assert absent not in facts, f"{absent} was manufactured for a running container"
    assert facts["State"] == "running"
    assert facts["StartedAt"], "what DID happen is still stated"


def test_an_ended_run_carries_its_outcome():
    from system_explorer.agent.adapters.docker import _container_facts
    facts = _container_facts(container(Status="exited", ExitCode=137,
                                       FinishedAt="2026-08-14T01:00:00Z"))
    assert facts["ExitCode"] == 137
    assert facts["FinishedAt"]


def test_oomkilled_appears_only_when_true():
    """False is dockerd's default for every container that was not OOM-killed,
    and carrying it puts the word on the screen of every healthy container in
    the estate."""
    from system_explorer.agent.adapters.docker import _container_facts
    ended = container(Status="exited", ExitCode=0, FinishedAt="2026-08-14T01:00:00Z")
    assert "OOMKilled" not in _container_facts(ended)
    ended["State"]["OOMKilled"] = True
    assert _container_facts(ended)["OOMKilled"] is True


def test_health_is_absent_where_the_image_declares_no_healthcheck():
    """Absent is not unhealthy and not unknown — three different answers that
    a null would collapse into one."""
    from system_explorer.agent.adapters.docker import _container_facts
    assert "Health" not in _container_facts(RUNNING)
    assert _container_facts(
        container(Health={"Status": "healthy"}))["Health"] == "healthy"


def test_a_container_created_but_never_started_states_neither_end():
    from system_explorer.agent.adapters.docker import _container_facts
    facts = _container_facts(container(Status="created",
                                       StartedAt="0001-01-01T00:00:00Z"))
    assert "StartedAt" not in facts and "FinishedAt" not in facts
    assert facts["State"] == "created"


def test_a_digest_pinned_image_is_not_printed_twice():
    """Reported from the deployed UI: "nearly half the information is
    duplicated". Config.Image already ENDS with the image id when the
    reference is digest-pinned — which every compose stack in the estate is —
    so the row carried the same 71-character sha256 under two names, one line
    apart."""
    from system_explorer.agent.adapters.docker import _container_facts
    facts = _container_facts(RUNNING)
    assert facts["Image"] == "linuxserver/radarr:latest@sha256:a45b5ab0"
    assert "ImageID" not in facts, "the digest is already in Image, in full"


def test_a_tag_only_reference_keeps_the_id_that_says_which_build():
    """The collapse is a duplicate check, not a decision that ImageID is
    uninteresting. Against a bare tag the id is the ONLY thing on the row
    that says which build is actually running, and dropping it would hide
    exactly the fact an operator chasing a stale container needs."""
    from copy import deepcopy

    from system_explorer.agent.adapters.docker import _container_facts
    raw = deepcopy(RUNNING)
    raw["Config"]["Image"] = "linuxserver/radarr:latest"
    facts = _container_facts(raw)
    assert facts["ImageID"] == "sha256:a45b5ab0"


def test_a_partial_digest_match_is_not_treated_as_a_duplicate():
    """Anchored on the full `@<id>` suffix, not a substring: an image whose
    NAME happens to contain the id's characters must not lose the id."""
    from copy import deepcopy

    from system_explorer.agent.adapters.docker import _container_facts
    raw = deepcopy(RUNNING)
    raw["Config"]["Image"] = "registry/sha256:a45b5ab0/app:latest"
    assert _container_facts(raw)["ImageID"] == "sha256:a45b5ab0"
