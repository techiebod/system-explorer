"""traefik subsystem: the ingress tier, observed as an application.

Every stack's HTTP path crosses Traefik, so this one adapter's rows name
every route in the estate — which host serves which application, from the
proxy's own mouth. The app-explorer pattern (paperless set it): envelopes
carry the composite locator's `app` member, configuration is one
deployment receipt (SE_TRAEFIK_URL, no default, declined by name when
absent), and the adapter is read-only by construction — every call is a
GET against the API the deployment chose to expose (the estate publishes
it loopback-only; where it binds is the deployment's decision and the
bind-tightening design's concern, not this code's).

No credential: Traefik's API in this posture carries none. What it DOES
carry, deliberately not served here, is middleware definitions — the one
document family where secret material lives (basicAuth users hashes), so
there is no middlewares collection and no evidence path to one; their
error COUNT surfaces on the overview instead. Routers and services carry
rules, entrypoint names, provider names and backend URLs: topology, not
secrets.

Three collections, the tidy tiers: `overview` (one row — version, per-
family totals and error counts, entrypoints), `routers` (one row per
router: rule, entrypoints, service, TLS, the router's own error list),
`services` (one row per service with the load balancer's per-server
health map folded to counts — a green router over all-down backends is
the wrapper-is-not-the-app shape at the ingress tier, and the map is
where it shows). Router→service flow stays a FACT (`Service`,
filterable) until the relationship vocabulary for flow edges is decided
in the SPEC — an edge type invented here would pre-empt that decision.
"""

from __future__ import annotations

import copy
import os
from urllib.parse import urlsplit, urlunsplit

import httpx

from .. import envelope as env
from ..rules.traefik import overview_opinions, router_opinions, service_opinions

OVERVIEW_PATH = "/api/overview"
VERSION_PATH = "/api/version"
ENTRYPOINTS_PATH = "/api/entrypoints"
ROUTERS_PATH = "/api/http/routers"
SERVICES_PATH = "/api/http/services"

REFERENCE = ["curl <url>/api/overview",
             "curl <url>/api/http/routers",
             "curl <url>/api/http/services"]

HOST_BLOCK = env.host_block(app="traefik")

# Server health values the API emits in serverStatus maps; anything not UP
# counts as down for the fold (the map is carried verbatim in DownServers
# for the ones that are not).
_UP = "UP"


def router_facts(raw: dict) -> dict:
    facts: dict = {
        "Rule": raw.get("rule"),
        "Service": raw.get("service"),
        "EntryPoints": raw.get("entryPoints") or [],
        "Provider": raw.get("provider"),
        "Status": raw.get("status"),
    }
    if raw.get("priority") is not None:
        facts["Priority"] = raw["priority"]
    if raw.get("middlewares"):
        facts["Middlewares"] = raw["middlewares"]
    tls = raw.get("tls")
    if isinstance(tls, dict):
        facts["Tls"] = True
        if tls.get("certResolver"):
            facts["CertResolver"] = tls["certResolver"]
    error = raw.get("error")
    if error:
        facts["Error"] = error if isinstance(error, list) else [str(error)]
    return facts


def _redact_url_userinfo(url: object) -> object:
    """A backend URL with DSN userinfo stripped (env.REDACTED marker kept
    so withholding is visible). The docker provider never writes one, but
    a file-provider server URL can carry basic-auth — and Servers,
    DownServers and the evidence payload all reach unauthenticated
    pollers (adversarial review, 2026-08-12)."""
    if not isinstance(url, str) or "@" not in url:
        return url
    parts = urlsplit(url)
    if "@" not in parts.netloc:
        return url
    host = parts.netloc.rpartition("@")[2]
    return urlunsplit(parts._replace(netloc=f"{env.REDACTED}@{host}"))


def _redact_service_evidence(payload: dict) -> tuple[dict, list[str]]:
    """A service document with backend-URL userinfo stripped wherever the
    document carries one (loadBalancer.servers[].url/address, serverStatus
    keys). Returns the copy and the paths actually altered — redaction
    that hides its own existence would invert the provenance contract."""
    out = copy.deepcopy(payload)
    paths: list[str] = []
    balancer = out.get("loadBalancer")
    if isinstance(balancer, dict):
        for index, server in enumerate(balancer.get("servers") or []):
            if not isinstance(server, dict):
                continue
            for member in ("url", "address"):
                value = server.get(member)
                redacted = _redact_url_userinfo(value)
                if redacted != value:
                    server[member] = redacted
                    paths.append(f"loadBalancer.servers.{index}.{member}")
    status_map = out.get("serverStatus")
    if isinstance(status_map, dict):
        rewritten = {}
        changed = False
        for url, state in status_map.items():
            redacted = _redact_url_userinfo(url)
            rewritten[str(redacted)] = state
            changed = changed or redacted != url
        if changed:
            out["serverStatus"] = rewritten
            paths.append("serverStatus")
    return out, paths


def service_facts(raw: dict) -> dict:
    facts: dict = {
        "Type": raw.get("type"),
        "Provider": raw.get("provider"),
        "Status": raw.get("status"),
    }
    if raw.get("usedBy"):
        facts["UsedBy"] = raw["usedBy"]
    balancer = raw.get("loadBalancer")
    if isinstance(balancer, dict) and balancer.get("servers"):
        facts["Servers"] = [_redact_url_userinfo(server.get("url")
                                                 or server.get("address"))
                            for server in balancer["servers"]]
    status_map = raw.get("serverStatus")
    if isinstance(status_map, dict) and status_map:
        down = sorted(str(_redact_url_userinfo(url))
                      for url, state in status_map.items() if state != _UP)
        facts["ServersUp"] = len(status_map) - len(down)
        facts["ServersDown"] = len(down)
        if down:
            facts["DownServers"] = down
    error = raw.get("error")
    if error:
        facts["Error"] = error if isinstance(error, list) else [str(error)]
    return facts


# Literal fact names per family member — a table, not string surgery, so
# the glossary orphan check can see every name in the source.
_FAMILY_COUNTS = (
    ("routers", (("total", "RoutersTotal"), ("errors", "RoutersErrors"),
                 ("warnings", "RoutersWarnings"))),
    ("services", (("total", "ServicesTotal"), ("errors", "ServicesErrors"),
                  ("warnings", "ServicesWarnings"))),
    ("middlewares", (("total", "MiddlewaresTotal"),
                     ("errors", "MiddlewaresErrors"),
                     ("warnings", "MiddlewaresWarnings"))),
)


def overview_facts(overview: dict, version: dict,
                   entrypoints: list) -> dict:
    facts: dict = {}
    if version.get("Version"):
        facts["Version"] = version["Version"]
    http = overview.get("http") or {}
    for family, members in _FAMILY_COUNTS:
        counts = http.get(family) or {}
        for member, fact in members:
            if member in counts:
                facts[fact] = counts[member]
    providers = overview.get("providers")
    if providers:
        facts["Providers"] = providers
    names = [entry.get("name") for entry in entrypoints
             if isinstance(entry, dict) and entry.get("name")]
    if names:
        facts["EntryPoints"] = names
    return facts


_ROUTER_GLOSSARY = {
    "Rule": "The matching expression that selects requests for this router — the hostname half of \"which URL reaches which app\".",
    "Service": "The service this router hands matched requests to; the flow's next hop, carried as a filterable name.",
    "EntryPoints": "The listening ports this router is mounted on, by the entrypoint names the install config declares.",
    "Provider": "Where this router's configuration came from (docker labels, the file provider, …) — who to edit to change it.",
    "Status": "Traefik's own three-valued verdict: enabled routes clean, warning ROUTES despite non-critical errors, disabled does not route.",
    "Priority": "Evaluation order among overlapping rules; higher wins.",
    "Middlewares": "The middleware chain applied to matched requests, by name only — the definitions themselves are deliberately not served here.",
    "Tls": "Whether this router terminates TLS.",
    "CertResolver": "The ACME resolver that keeps this router's certificate current.",
    "Error": "Why Traefik rejects this router, in its own words; absent means it loaded clean.",
}

_SERVICE_GLOSSARY = {
    "Type": "The service's balancing shape (loadbalancer, weighted, mirroring).",
    "Provider": "Where this service's configuration came from.",
    "Status": "Traefik's own three-valued verdict on the service: enabled, warning (still serving), or disabled.",
    "UsedBy": "The routers that hand traffic to this service — the flow's previous hop.",
    "Servers": "The backend URLs this service balances across.",
    "ServersUp": "How many backends currently pass Traefik's health view.",
    "ServersDown": "How many do not; a green router over ServersUp 0 is a front door onto nothing.",
    "DownServers": "Exactly which backend URLs report down.",
    "Error": "Why Traefik rejects this service, in its own words; absent means it loaded clean.",
}

_OVERVIEW_GLOSSARY = {
    "Version": "The Traefik release answering the API.",
    "RoutersTotal": "How many HTTP routers are loaded.",
    "RoutersErrors": "How many of them Traefik rejects; each one is also a critical opinion on its own row.",
    "RoutersWarnings": "How many routers Traefik loaded with warnings.",
    "ServicesTotal": "How many HTTP services are loaded.",
    "ServicesErrors": "How many of those services Traefik rejects outright.",
    "ServicesWarnings": "How many services loaded with warnings.",
    "MiddlewaresTotal": "How many middlewares are loaded across every provider.",
    "MiddlewaresErrors": "How many middlewares Traefik rejects — surfaced here because middleware documents (where auth material lives) are deliberately not served as rows.",
    "MiddlewaresWarnings": "How many middlewares loaded with warnings.",
    "Providers": "The configuration providers this instance runs.",
    "EntryPoints": "The listening ports this instance declares, by name.",
}


class Adapter:
    subsystem = "traefik"
    host_block = HOST_BLOCK

    def __init__(self) -> None:
        self.url = (os.environ.get("SE_TRAEFIK_URL") or "").rstrip("/") or None
        self._client = httpx.AsyncClient(timeout=10.0)

    def collections(self) -> list[str]:
        return ["overview", "routers", "services"]

    async def capability(self) -> dict:
        if not self.url:
            return {"available": False, "reason": (
                "SE_TRAEFIK_URL is not configured — this process observes"
                " no traefik (point it at the API the deployment exposes;"
                " the estate publishes it loopback-only)")}
        try:
            await self._get(VERSION_PATH)
        except Exception as exc:  # noqa: BLE001 - a dark API is a capability fact
            # One cheap probe here (the docker /_ping arrangement) instead
            # of three collections each paying the full client timeout per
            # status sweep against a dead endpoint.
            return {"available": False, "reason": env.reason(
                f"SE_TRAEFIK_URL is set but the API did not answer"
                f" {VERSION_PATH}: {type(exc).__name__}: {exc}")}
        return {"available": True, "collections": self.collections(),
                "url": self.url}

    def fact_glossary(self, collection: str) -> dict:
        return {"overview": _OVERVIEW_GLOSSARY,
                "routers": _ROUTER_GLOSSARY,
                "services": _SERVICE_GLOSSARY}.get(collection, {})

    def _source(self, collection: str) -> dict:
        method = {"overview": f"GET {OVERVIEW_PATH} + {VERSION_PATH} + {ENTRYPOINTS_PATH}",
                  "routers": f"GET {ROUTERS_PATH}",
                  "services": f"GET {SERVICES_PATH}"}[collection]
        return env.source("traefik-api", "traefik REST API", REFERENCE,
                          method=method)

    async def _get(self, path: str):
        response = await self._client.get(f"{self.url}{path}")
        response.raise_for_status()
        return response.json()

    async def _get_list(self, path: str) -> list:
        """Every page of a Traefik list endpoint. The API slices at 100
        per page and signals continuation ONLY via the X-Next-Page header
        (value 1 when exhausted) — a single-page fetch past 100 routers
        would render absence as a complete healthy listing, with evidence
        404ing on objects Traefik actually serves (adversarial review,
        2026-08-12, reproduced against a faithful mock of the API's own
        pagination code)."""
        items: list = []
        page = 1
        while True:
            response = await self._client.get(
                f"{self.url}{path}", params={"page": page, "per_page": 100})
            response.raise_for_status()
            items.extend(response.json())
            try:
                next_page = int(response.headers.get("X-Next-Page", "1"))
            except ValueError:
                break
            if next_page <= page:
                break
            page = next_page
        return items

    async def _overview_items(self) -> list[dict]:
        facts = overview_facts(await self._get(OVERVIEW_PATH),
                               await self._get(VERSION_PATH),
                               await self._get_list(ENTRYPOINTS_PATH))
        return [env.item_summary(
            "overview:traefik", "traefik-overview", "traefik", facts,
            opinions=overview_opinions(facts),
            healthy="ok" if "MiddlewaresErrors" in facts else "info")]

    async def _router_items(self) -> list[dict]:
        items = []
        for raw in await self._get_list(ROUTERS_PATH):
            name = raw.get("name") or "unnamed"
            facts = router_facts(raw)
            items.append(env.item_summary(
                f"router:{name}", "traefik-router", name, facts,
                opinions=router_opinions(facts),
                healthy="ok" if facts.get("Status") == "enabled" else "info"))
        return items

    async def _service_items(self) -> list[dict]:
        items = []
        for raw in await self._get_list(SERVICES_PATH):
            name = raw.get("name") or "unnamed"
            facts = service_facts(raw)
            items.append(env.item_summary(
                f"service:{name}", "traefik-service", name, facts,
                opinions=service_opinions(facts),
                healthy="ok" if facts.get("Status") == "enabled" else "info"))
        return items

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        if collection == "overview":
            return await self._overview_items()
        if collection == "routers":
            return await self._router_items()
        if collection == "services":
            return await self._service_items()
        raise env.UnknownCollection(collection)

    async def collect(self, collection: str, query: dict, limit: int | None,
                      cursor: str | None) -> dict:
        fetched = await self.acquire(collection)
        items = env.apply_fact_filters(fetched, query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection,
                                   self._source(collection),
                                   page, applied, next_cursor,
                                   requested_limit=limit, total=total,
                                   filters=query or None, host=HOST_BLOCK)

    async def get_object(self, collection: str, object_id: str) -> dict:
        matches = [item for item in await self.acquire(collection)
                   if item["id"] == object_id]
        if not matches:
            raise env.UnknownObject(object_id)
        item = matches[0]
        opinions = {"overview": overview_opinions,
                    "routers": router_opinions,
                    "services": service_opinions}[collection](item["facts"])
        return env.observation(
            self.subsystem,
            env.obj_ref(item["id"], item["type"], item["native_id"]),
            self._source(collection), item["facts"], opinions=opinions,
            evidence_ref=env.evidence_ref(self.subsystem, collection,
                                          item["id"]),
            host=HOST_BLOCK)

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        if collection not in self.collections():
            raise env.UnknownCollection(collection)
        if collection == "overview":
            if object_id != "overview:traefik":
                raise env.UnknownObject(object_id)
            payload = {"overview": await self._get(OVERVIEW_PATH),
                       "version": await self._get(VERSION_PATH),
                       "entrypoints": await self._get(ENTRYPOINTS_PATH)}
        else:
            path = ROUTERS_PATH if collection == "routers" else SERVICES_PATH
            prefix = "router:" if collection == "routers" else "service:"
            if not object_id.startswith(prefix):
                raise env.UnknownObject(object_id)
            name = object_id[len(prefix):]
            documents = [raw for raw in await self._get_list(path)
                         if raw.get("name") == name]
            if not documents:
                raise env.UnknownObject(object_id)
            payload = documents[0]
            if collection == "services":
                payload, redacted = _redact_service_evidence(payload)
                out = {"object_id": object_id, "captured_at": env.utc_now(),
                       "interface": "traefik REST API", "payload": payload}
                if redacted:
                    out["redacted"] = redacted
                return out
        return {"object_id": object_id, "captured_at": env.utc_now(),
                "interface": "traefik REST API", "payload": payload}
