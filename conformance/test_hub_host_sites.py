"""Which hub fronts a host, and where the host actually is.

Two different facts shared one member until 2026-08-14. A hub built its
listing by probing each agent's /health, had nothing in the answer naming a
site, and stamped its OWN — so a cloud host at a different provider,
registered with a home hub because that is where its operator looks, was
listed as living at home. The host's own capabilities said otherwise the
whole time, one route away.

`site` could not simply be corrected, because it is load-bearing in the
other direction: the browser reaches an agent at /sites/<site>/agents/<name>,
so it answers "through which hub" and has to keep doing so. The location
answer is a second member, stated only by the host.
"""

from __future__ import annotations

import asyncio

import pytest

from system_explorer.hub import server


class FakeResponse:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


def local_hosts(monkeypatch, agents, health):
    monkeypatch.setattr(server, "AGENTS", agents)

    async def get(url, **_kwargs):
        for name, base in agents.items():
            if url.startswith(base):
                body = health.get(name)
                if body is None:
                    raise ConnectionError("refused")
                return FakeResponse(body)
        raise AssertionError(f"probed an agent nobody registered: {url}")

    monkeypatch.setattr(server._client, "get", get)
    return asyncio.run(server._local_hosts())


AGENTS = {"near": "http://near:8090", "far": "http://far:8090"}


def test_a_host_that_names_its_site_is_not_relabelled_by_the_hub(monkeypatch):
    monkeypatch.setattr(server, "SITE", "home")
    hosts = local_hosts(monkeypatch, AGENTS, {
        "near": {"status": "ok", "host": {"hostname": "near"}},
        "far": {"status": "ok", "host": {"hostname": "far"}, "site": "elsewhere"},
    })
    # Routing is unchanged: both are reached through THIS hub.
    assert hosts["near"]["site"] == hosts["far"]["site"] == "home"
    # Location is not.
    assert hosts["far"]["agent_site"] == "elsewhere"
    assert "agent_site" not in hosts["near"], (
        "an agent naming no site must not be given one — silence is not a "
        "claim that it shares the hub's")


def test_an_unreachable_agent_states_no_location_at_all(monkeypatch):
    """It could not be asked. Carrying the hub's site there would be the same
    misattribution, made about a host nobody could reach."""
    monkeypatch.setattr(server, "SITE", "home")
    hosts = local_hosts(monkeypatch, AGENTS, {
        "near": {"status": "ok", "host": {"hostname": "near"}}})
    assert hosts["far"]["reachable"] is False
    assert "agent_site" not in hosts["far"]


def test_a_hub_with_no_site_still_carries_the_hosts_own(monkeypatch):
    """The two are independent. A single-site deployment configures no site
    name at all, and a host that names one is still entitled to say so."""
    monkeypatch.setattr(server, "SITE", None)
    hosts = local_hosts(monkeypatch, {"far": AGENTS["far"]}, {
        "far": {"status": "ok", "host": {"hostname": "far"}, "site": "elsewhere"}})
    assert hosts["far"]["site"] is None
    assert hosts["far"]["agent_site"] == "elsewhere"


@pytest.mark.parametrize("stated", ["", None])
def test_an_empty_site_is_not_a_site(monkeypatch, stated):
    monkeypatch.setattr(server, "SITE", "home")
    hosts = local_hosts(monkeypatch, {"near": AGENTS["near"]}, {
        "near": {"status": "ok", "site": stated}})
    assert "agent_site" not in hosts["near"]
