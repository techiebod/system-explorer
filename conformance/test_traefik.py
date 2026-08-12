"""The traefik explorer's pure halves: API parsing and the ingress rules.

Parsers and rules are pure over documents (the paperless arrangement). The
cases that matter most: a green router over all-down backends is critical
(the wrapper-is-not-the-app shape at the ingress tier), Traefik's own
error lists become critical opinions in its own words, and the absence of
a serverStatus map claims nothing (rule 7 — a service Traefik has not
health-checked is not a service with zero down backends).
"""

from system_explorer.agent.adapters.traefik import (overview_facts,
                                                    router_facts,
                                                    service_facts)
from system_explorer.agent.rules.traefik import (router_opinions,
                                                 service_opinions)

ROUTER = {
    "entryPoints": ["websecure"],
    "middlewares": ["secure-headers@file"],
    "service": "paperless",
    "rule": "Host(`paperless.example.internal`)",
    "priority": 42,
    "tls": {"certResolver": "letsencrypt"},
    "status": "enabled",
    "using": ["websecure"],
    "name": "paperless@docker",
    "provider": "docker",
}

SERVICE = {
    "loadBalancer": {"servers": [{"url": "http://172.18.0.5:8000"}],
                     "passHostHeader": True},
    "status": "enabled",
    "usedBy": ["paperless@docker"],
    "serverStatus": {"http://172.18.0.5:8000": "UP"},
    "name": "paperless@docker",
    "provider": "docker",
    "type": "loadbalancer",
}


def test_a_router_parses_to_native_named_facts_and_stays_quiet():
    facts = router_facts(ROUTER)
    assert facts["Rule"] == "Host(`paperless.example.internal`)"
    assert facts["Service"] == "paperless"
    assert facts["Tls"] is True and facts["CertResolver"] == "letsencrypt"
    assert facts["Status"] == "enabled"
    assert router_opinions(facts) == []


def test_a_rejected_router_speaks_in_traefiks_own_words():
    facts = router_facts({**ROUTER, "status": "disabled",
                          "error": ['middleware "gone@docker" does not exist']})
    keys = {(o["key"], o["level"]) for o in router_opinions(facts)}
    assert keys == {("router-error", "critical"), ("router-disabled", "warn")}
    [error_opinion] = [o for o in router_opinions(facts)
                       if o["key"] == "router-error"]
    assert 'gone@docker' in error_opinion["message"]


def test_server_health_folds_to_counts_and_names_the_down_ones():
    raw = {**SERVICE, "serverStatus": {"http://172.18.0.5:8000": "UP",
                                       "http://172.18.0.9:8000": "DOWN"}}
    facts = service_facts(raw)
    assert facts["ServersUp"] == 1 and facts["ServersDown"] == 1
    assert facts["DownServers"] == ["http://172.18.0.9:8000"]
    [opinion] = service_opinions(facts)
    assert (opinion["key"], opinion["level"]) == ("service-servers-down", "warn")


def test_all_backends_down_is_a_front_door_onto_nothing():
    raw = {**SERVICE, "serverStatus": {"http://172.18.0.5:8000": "DOWN"}}
    [opinion] = service_opinions(service_facts(raw))
    assert (opinion["key"], opinion["level"]) == ("service-servers-down", "critical")


def test_no_health_map_claims_nothing():
    # An unchecked service is not a service with zero down backends: no
    # serverStatus, no counts, no verdict (rule 7).
    raw = {key: value for key, value in SERVICE.items() if key != "serverStatus"}
    facts = service_facts(raw)
    assert "ServersUp" not in facts and "ServersDown" not in facts
    assert service_opinions(facts) == []


def test_the_overview_folds_families_and_keeps_the_estate_vocabulary():
    facts = overview_facts(
        {"http": {"routers": {"total": 26, "warnings": 0, "errors": 1},
                  "services": {"total": 22, "warnings": 0, "errors": 0},
                  "middlewares": {"total": 4, "warnings": 0, "errors": 0}},
         "providers": ["docker", "file"]},
        {"Version": "3.1.4", "Codename": "comte"},
        [{"name": "web", "address": ":80"},
         {"name": "websecure", "address": ":443"},
         {"name": "traefik", "address": ":8080"}])
    assert facts["Version"] == "3.1.4"
    assert facts["RoutersTotal"] == 26 and facts["RoutersErrors"] == 1
    assert facts["Providers"] == ["docker", "file"]
    assert facts["EntryPoints"] == ["web", "websecure", "traefik"]


def test_a_warning_router_still_routes_and_is_never_a_false_outage():
    # Traefik's status vocabulary is three-valued: warning ROUTES —
    # AddError appends non-critical errors while the router keeps serving.
    # Reading it as two values claimed a serving router was rejected with
    # nothing routing through it (adversarial review, 2026-08-12).
    facts = router_facts({**ROUTER, "status": "warning",
                          "error": ['entryPoint "typo" does not exist']})
    opinions = router_opinions(facts)
    assert {(o["key"], o["level"]) for o in opinions} == {("router-warning", "warn")}
    assert not any("nothing routes" in o["message"] for o in opinions)
    assert "still routing" in opinions[0]["message"]


def test_backend_urls_shed_userinfo_in_facts_and_evidence():
    from system_explorer.agent.adapters.traefik import (
        _redact_service_evidence, _redact_url_userinfo)
    assert _redact_url_userinfo("http://user:pw@10.0.0.5:8000") == \
        "http://«redacted»@10.0.0.5:8000"
    assert _redact_url_userinfo("http://10.0.0.5:8000") == "http://10.0.0.5:8000"
    raw = {"loadBalancer": {"servers": [{"url": "http://u:pw@10.0.0.5:8000"}]},
           "serverStatus": {"http://u:pw@10.0.0.5:8000": "DOWN"},
           "status": "enabled"}
    facts = service_facts(raw)
    assert "pw" not in str(facts)
    redacted, paths = _redact_service_evidence(raw)
    assert "pw" not in str(redacted)
    assert "loadBalancer.servers.0.url" in paths and "serverStatus" in paths
    assert "pw" in str(raw)  # the original is untouched


def test_every_page_of_a_paginated_listing_is_fetched():
    # Traefik slices list endpoints at 100 per page and signals more ONLY
    # via X-Next-Page; a single-page fetch renders absence as a complete
    # healthy listing (adversarial review, 2026-08-12 — reproduced against
    # a faithful mock of the API's own pagination arithmetic).
    import asyncio
    import json as jsonlib

    import httpx

    from system_explorer.agent.adapters import traefik as traefik_adapter

    routers = [{"name": f"app{i}@docker", "rule": f"Host(`app{i}`)",
                "status": "enabled", "service": f"app{i}"} for i in range(150)]

    def serve(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params.get("page", "1"))
        per_page = int(request.url.params.get("per_page", "100"))
        start, end = (page - 1) * per_page, page * per_page
        next_page = page + 1 if end < len(routers) else 1
        return httpx.Response(200, content=jsonlib.dumps(routers[start:end]),
                              headers={"X-Next-Page": str(next_page),
                                       "content-type": "application/json"})

    adapter = traefik_adapter.Adapter.__new__(traefik_adapter.Adapter)
    adapter.url = "http://traefik.test"
    adapter._client = httpx.AsyncClient(
        transport=httpx.MockTransport(serve))
    fetched = asyncio.run(adapter._get_list("/api/http/routers"))
    assert len(fetched) == 150
    assert fetched[-1]["name"] == "app149@docker"
