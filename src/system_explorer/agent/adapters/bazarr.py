"""bazarr subsystem: the subtitle manager, the thin end of the app tier.

Deliberately NOT part of the servarr adapter — bazarr wears the same
estate colours but speaks its own API family — and deliberately thin:
one `instance` collection carrying the version, the versions of the
managers it is wired to, and the app's own health list mirrored whole
(bazarr does not grade its issues, so the mirror is one warn carrying
the count with the issues themselves as facts). The paperless pattern
otherwise: SE_BAZARR_URL + SE_BAZARR_API_KEY receipts, X-API-KEY
header, configured-but-dark as a critical row.
"""

from __future__ import annotations

import os

import httpx

from .. import envelope as env
from ..rules.bazarr import instance_opinions

STATUS_PATH = "/api/system/status"
HEALTH_PATH = "/api/system/health"

REFERENCE = [
    "curl -H 'X-API-KEY: <key>' <url>/api/system/status",
    "curl -H 'X-API-KEY: <key>' <url>/api/system/health",
]

HOST_BLOCK = env.host_block(app="bazarr")

_GLOSSARY = {
    "Version": "The bazarr release answering the API.",
    "SonarrVersion": "The sonarr this instance is wired to, as bazarr reports it.",
    "RadarrVersion": "The radarr this instance is wired to, as bazarr reports it.",
    "HealthIssues": "The app's own health list, mirrored whole and ungraded because bazarr does not grade it; empty means the app raises nothing.",
    "ConfigMissing": "The receipts this instance still needs before it can be observed.",
    "StatusUnobservable": "Why the instance's API could not be asked, when it could not — the row stays, because a configured manager that does not answer is a statement rather than a gap.",
}


def status_facts(raw: dict) -> dict:
    data = raw.get("data") or {}
    facts: dict = {}
    for fact, member in (("Version", "bazarr_version"),
                         ("SonarrVersion", "sonarr_version"),
                         ("RadarrVersion", "radarr_version")):
        if data.get(member):
            facts[fact] = data[member]
    return facts


def health_facts(raw: dict) -> list[str]:
    """bazarr's health document: {data: [{object, issue}]} — folded to the
    app's own sentences, bounded, one per issue."""
    issues = []
    for entry in raw.get("data") or []:
        if not isinstance(entry, dict):
            continue
        subject = entry.get("object")
        issue = entry.get("issue")
        line = f"{subject}: {issue}" if subject and issue else (issue or subject)
        if line:
            issues.append(env.reason(line))
    return issues


class Adapter:
    subsystem = "bazarr"
    host_block = HOST_BLOCK

    def __init__(self) -> None:
        self.url = (os.environ.get("SE_BAZARR_URL") or "").rstrip("/") or None
        key = os.environ.get("SE_BAZARR_API_KEY") or None
        self._key_problem: str | None = None
        if key is not None and not (key.isascii() and key.isprintable()):
            self._key_problem = ("SE_BAZARR_API_KEY contains control or"
                                 " non-ASCII characters — refusing to send"
                                 " it in a header")
            key = None
        self._client = httpx.AsyncClient(
            timeout=10.0, headers={"X-API-KEY": key} if key else {})
        self._key_set = key is not None

    def collections(self) -> list[str]:
        return ["instance"]

    async def capability(self) -> dict:
        if not self.url:
            return {"available": False, "reason": (
                "SE_BAZARR_URL is not configured — this process observes"
                " no bazarr")}
        return {"available": True, "collections": self.collections(),
                "url": self.url}

    def fact_glossary(self, collection: str) -> dict:
        return _GLOSSARY if collection == "instance" else {}

    def _source(self) -> dict:
        return env.source("bazarr-api", "bazarr REST API", REFERENCE,
                          method=f"GET {STATUS_PATH} + {HEALTH_PATH}")

    async def _get(self, path: str) -> dict:
        response = await self._client.get(f"{self.url}{path}")
        response.raise_for_status()
        return response.json()

    async def _instance_items(self) -> list[dict]:
        facts: dict = {}
        if self._key_problem:
            facts["ConfigMissing"] = [self._key_problem]
        elif not self._key_set:
            facts["ConfigMissing"] = ["SE_BAZARR_API_KEY"]
        else:
            try:
                facts.update(status_facts(await self._get(STATUS_PATH)))
                facts["HealthIssues"] = health_facts(
                    await self._get(HEALTH_PATH))
            except Exception as exc:  # noqa: BLE001 - a dark manager is an observation
                facts["StatusUnobservable"] = env.reason(
                    f"{type(exc).__name__}: {exc}")
        return [env.item_summary(
            "instance:bazarr", "bazarr-instance", "bazarr", facts,
            opinions=instance_opinions(facts),
            healthy="ok" if "StatusUnobservable" not in facts
            and "ConfigMissing" not in facts else "info")]

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        if collection != "instance":
            raise env.UnknownCollection(collection)
        return await self._instance_items()

    async def collect(self, collection: str, query: dict, limit: int | None,
                      cursor: str | None) -> dict:
        fetched = await self.acquire(collection)
        items = env.apply_fact_filters(fetched, query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection, self._source(),
                                   page, applied, next_cursor,
                                   requested_limit=limit, total=total,
                                   filters=query or None, host=HOST_BLOCK)

    async def get_object(self, collection: str, object_id: str) -> dict:
        matches = [item for item in await self.acquire(collection)
                   if item["id"] == object_id]
        if not matches:
            raise env.UnknownObject(object_id)
        item = matches[0]
        return env.observation(
            self.subsystem,
            env.obj_ref(item["id"], item["type"], item["native_id"]),
            self._source(), item["facts"],
            opinions=instance_opinions(item["facts"]),
            evidence_ref=env.evidence_ref(self.subsystem, collection,
                                          item["id"]),
            host=HOST_BLOCK)

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        if collection != "instance":
            raise env.UnknownCollection(collection)
        if object_id != "instance:bazarr":
            raise env.UnknownObject(object_id)
        return {"object_id": object_id, "captured_at": env.utc_now(),
                "interface": "bazarr REST API",
                "payload": {"status": await self._get(STATUS_PATH),
                            "health": await self._get(HEALTH_PATH)}}
