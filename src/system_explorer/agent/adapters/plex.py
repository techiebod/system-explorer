"""plex subsystem: the media server tier — plex itself, and the request
front door (seerr) that feeds the managers.

One subsystem for the family, four collections in the tidy tiers:
`server` (identity, version, and reachability of the thing every stream
depends on), `libraries` (each section with its own item count and scan
times — the "library went empty" shape lives here), `sessions` (what is
playing right now: activity, not health, so no verdicts), and `requests`
(seerr's pending/approved queue — a pending request is a person waiting,
carried as info on the object and never paged). Tautulli deliberately
has no collection: its value is watch HISTORY and trends, which is
provider territory — the UI links out; SE does not become a worse
Tautulli (the anti-sprawl rule).

Configuration is deployment receipts per member: SE_PLEX_URL +
SE_PLEX_TOKEN (X-Plex-Token header; the Accept header asks for JSON
because Plex answers XML by default), SE_SEERR_URL + SE_SEERR_API_KEY
(X-Api-Key). Either member absent means its collections decline with
the missing name; seerr going dark costs the requests collection alone
(per-collection unavailability), never the server's.

Flow: seerr is the pipeline's entry door — its dispatches-to edges
toward the managers land when its API's service settings are read,
deferred until the edge has demonstrated demand (the trace criterion is
already satisfiable manager-side).
"""

from __future__ import annotations

import os

import httpx

from .. import envelope as env
from ..rules.plex import request_opinions, server_opinions

PLEX_HEADERS = {"Accept": "application/json"}
SESSIONS_PATH = "/status/sessions"
SECTIONS_PATH = "/library/sections"
REQUESTS_PATH = "/api/v1/request"

REFERENCE = [
    "curl -H 'X-Plex-Token: <token>' -H 'Accept: application/json' <url>/",
    "curl -H 'X-Plex-Token: <token>' -H 'Accept: application/json' <url>/status/sessions",
    "curl -H 'X-Api-Key: <key>' '<url>/api/v1/request?take=100'",
]

HOST_BLOCK = env.host_block(app="plex")

# seerr's MediaRequestStatus, its own documented numbering — failed is
# the one fault-shaped state (dispatch to the managers failed).
SEERR_STATUS = {1: "pending", 2: "approved", 3: "declined",
                4: "failed", 5: "completed"}

# The requests walk is bounded, never silently truncated: pages
# accumulate until seerr's own pageInfo says done, capped so a lying
# total cannot spin the sweep (trust the rows gathered over the claim).
REQUEST_PAGE_SIZE = 100
MAX_REQUEST_PAGES = 20


def server_facts(raw: dict) -> dict:
    container = raw.get("MediaContainer") or {}
    facts: dict = {}
    for fact, member in (("FriendlyName", "friendlyName"),
                         ("Version", "version"),
                         ("Platform", "platform")):
        if container.get(member):
            facts[fact] = container[member]
    return facts


def library_facts(raw: dict) -> dict:
    facts: dict = {"Title": raw.get("title"), "Type": raw.get("type")}
    if raw.get("refreshing") is not None:
        facts["Refreshing"] = bool(raw["refreshing"])
    for fact, member in (("ScannedAt", "scannedAt"),
                         ("UpdatedAt", "updatedAt")):
        value = raw.get(member)
        if isinstance(value, int) and value > 0:
            facts[fact] = env.usec_to_iso(value * 1_000_000)
    return facts


def session_facts(raw: dict) -> dict:
    title = raw.get("title")
    grandparent = raw.get("grandparentTitle")
    facts: dict = {
        "Title": f"{grandparent} — {title}" if grandparent else title,
        "Type": raw.get("type"),
    }
    user = (raw.get("User") or {}).get("title")
    if user:
        facts["User"] = user
    player = raw.get("Player") or {}
    if player.get("product"):
        facts["Player"] = player["product"]
    if player.get("state"):
        facts["State"] = player["state"]
    transcode = raw.get("TranscodeSession") or {}
    if transcode.get("videoDecision"):
        facts["VideoDecision"] = transcode["videoDecision"]
    return facts


def request_facts(raw: dict) -> dict:
    facts: dict = {}
    status = raw.get("status")
    if isinstance(status, int):
        facts["Status"] = SEERR_STATUS.get(status, str(status))
    if raw.get("type"):
        facts["Type"] = raw["type"]
    requester = (raw.get("requestedBy") or {}).get("displayName")
    if requester:
        facts["RequestedBy"] = requester
    if raw.get("createdAt"):
        facts["CreatedAt"] = raw["createdAt"]
    return facts


_SERVER_GLOSSARY = {
    "FriendlyName": "The name the server calls itself in every Plex client.",
    "Version": "The Plex Media Server release answering the API.",
    "Platform": "The OS the server reports it runs on.",
    "SessionCount": "How many streams are playing right now, from the sessions document's own size.",
    "ConfigMissing": "The receipts this member still needs before it can be observed.",
    "StatusUnobservable": "Why the server's API could not be asked, when it could not — the row stays, because every stream in the house depends on this answering.",
}

_LIBRARY_GLOSSARY = {
    "Title": "The section's name as every client shows it.",
    "Type": "What the section holds: movie, show, artist or photo.",
    "ItemCount": "How many items the section reports holding — zero on a section that held things is the emptied-library shape, worth ruling out before anything else.",
    "ItemCountUnobservable": "Why this section's count could not be read when it could not — an unreadable count is not an empty library, and the emptied-library shape cannot be ruled out without it.",
    "Refreshing": "Whether the server says a scan of this section is running right now.",
    "ScannedAt": "When the section last completed a scan, per the server.",
    "UpdatedAt": "When the section's contents last changed, per the server.",
}

_SESSION_GLOSSARY = {
    "Title": "What is playing, with its series named when there is one.",
    "Type": "The kind of item playing (episode, movie, track).",
    "User": "Who is watching, by their Plex account name.",
    "Player": "The client product doing the playing.",
    "State": "The player's own state: playing, paused, buffering.",
    "VideoDecision": "The server's transcode verdict for the video stream: copy is direct, transcode is the CPU-costly path.",
}

_REQUEST_GLOSSARY = {
    "Status": "Where the request sits in seerr's own flow: pending awaits a person, approved awaits the managers, failed means the dispatch to the managers failed — the one fault-shaped state.",
    "Type": "Whether a movie or a series was asked for.",
    "RequestedBy": "Who is waiting, by their display name.",
    "CreatedAt": "When the request was filed, so the wait a pending row represents is readable at a glance.",
}


class Adapter:
    subsystem = "plex"
    host_block = HOST_BLOCK

    def __init__(self) -> None:
        self.plex_url = (os.environ.get("SE_PLEX_URL") or "").rstrip("/") or None
        token = os.environ.get("SE_PLEX_TOKEN") or None
        self.seerr_url = (os.environ.get("SE_SEERR_URL") or "").rstrip("/") or None
        seerr_key = os.environ.get("SE_SEERR_API_KEY") or None
        self._plex_problem: str | None = None
        if token is not None and not (token.isascii() and token.isprintable()):
            self._plex_problem = ("SE_PLEX_TOKEN contains control or"
                                  " non-ASCII characters — refusing to send"
                                  " it in a header")
            token = None
        self._plex = httpx.AsyncClient(
            timeout=10.0, headers={**PLEX_HEADERS,
                                   **({"X-Plex-Token": token} if token else {})})
        self._seerr = httpx.AsyncClient(
            timeout=10.0, headers={"X-Api-Key": seerr_key} if seerr_key else {})
        self._plex_token_set = token is not None
        self._seerr_key_set = seerr_key is not None

    def collections(self) -> list[str]:
        return ["server", "libraries", "sessions", "requests"]

    async def capability(self) -> dict:
        if not self.plex_url and not self.seerr_url:
            return {"available": False, "reason": (
                "neither SE_PLEX_URL nor SE_SEERR_URL is configured — this"
                " process observes no media server tier")}
        unavailable: dict = {}
        if not self.plex_url:
            for name in ("server", "libraries", "sessions"):
                unavailable[name] = "SE_PLEX_URL is not configured"
        elif not self._plex_token_set:
            # The server row stays available: ConfigMissing on it is the
            # standing signal. But libraries and sessions cannot be asked
            # for — guessing would only manufacture 401s (the paperless
            # rule), and a config gap must not dress as an outage.
            reason = self._plex_problem or (
                "SE_PLEX_TOKEN is not configured — Plex answers 401"
                " without one")
            for name in ("libraries", "sessions"):
                unavailable[name] = reason
        if not self.seerr_url:
            unavailable["requests"] = "SE_SEERR_URL is not configured"
        elif not self._seerr_key_set:
            unavailable["requests"] = ("SE_SEERR_API_KEY is not configured —"
                                       " seerr answers nothing without one")
        out: dict = {"available": True,
                     "collections": [c for c in self.collections()
                                     if c not in unavailable]}
        if unavailable:
            out["unavailable_collections"] = unavailable
        return out

    def fact_glossary(self, collection: str) -> dict:
        return {"server": _SERVER_GLOSSARY, "libraries": _LIBRARY_GLOSSARY,
                "sessions": _SESSION_GLOSSARY,
                "requests": _REQUEST_GLOSSARY}.get(collection, {})

    def _source(self, collection: str) -> dict:
        method = {"server": "GET / + /status/sessions",
                  "libraries": "GET /library/sections (+ per-section size)",
                  "sessions": f"GET {SESSIONS_PATH}",
                  "requests": f"GET {REQUESTS_PATH}"}[collection]
        return env.source("plex-api", "Plex + seerr REST APIs", REFERENCE,
                          method=method)

    async def _plex_get(self, path: str, params: dict | None = None) -> dict:
        response = await self._plex.get(f"{self.plex_url}{path}", params=params)
        response.raise_for_status()
        return response.json()

    async def _server_items(self) -> list[dict]:
        facts: dict = {}
        if self._plex_problem:
            facts["ConfigMissing"] = [self._plex_problem]
        elif not self._plex_token_set:
            facts["ConfigMissing"] = ["SE_PLEX_TOKEN"]
        else:
            try:
                facts.update(server_facts(await self._plex_get("/")))
                sessions = await self._plex_get(SESSIONS_PATH)
                size = (sessions.get("MediaContainer") or {}).get("size")
                if isinstance(size, int):
                    facts["SessionCount"] = size
            except Exception as exc:  # noqa: BLE001 - a dark server is an observation
                facts["StatusUnobservable"] = env.reason(
                    f"{type(exc).__name__}: {exc}")
        return [env.item_summary(
            "server:plex", "plex-server", "plex", facts,
            name=facts.get("FriendlyName"),
            opinions=server_opinions(facts),
            healthy="ok" if "StatusUnobservable" not in facts
            and "ConfigMissing" not in facts else "info")]

    async def _library_items(self) -> list[dict]:
        body = await self._plex_get(SECTIONS_PATH)
        items = []
        for raw in (body.get("MediaContainer") or {}).get("Directory") or []:
            key = raw.get("key")
            if key is None:
                continue
            facts = library_facts(raw)
            try:
                page = await self._plex_get(
                    f"{SECTIONS_PATH}/{key}/all",
                    params={"X-Plex-Container-Start": 0,
                            "X-Plex-Container-Size": 0})
                total = (page.get("MediaContainer") or {}).get("totalSize")
                if isinstance(total, int):
                    facts["ItemCount"] = total
            except Exception as exc:  # noqa: BLE001 - the count narrows, and says so
                facts["ItemCountUnobservable"] = env.reason(
                    f"{type(exc).__name__}: {exc}")
            items.append(env.item_summary(
                f"library:{key}", "plex-library", str(key), facts,
                name=facts.get("Title"), opinions=[],
                healthy="ok" if "ItemCountUnobservable" not in facts
                else "info"))
        return items

    async def _session_items(self) -> list[dict]:
        body = await self._plex_get(SESSIONS_PATH)
        items = []
        for raw in (body.get("MediaContainer") or {}).get("Metadata") or []:
            session_key = raw.get("sessionKey") or raw.get("ratingKey")
            if session_key is None:
                continue
            facts = session_facts(raw)
            items.append(env.item_summary(
                f"session:{session_key}", "plex-session", str(session_key),
                facts, name=facts.get("Title"), opinions=[], healthy=None))
        return items

    async def _request_pages(self) -> list[dict]:
        """Every page of seerr's request list, walked to seerr's own
        pageInfo and bounded by MAX_REQUEST_PAGES — rows and evidence
        share this walk so they cannot disagree about what exists. A
        one-shot take=100 would silently cap the collection at 100 with
        no cursor, the exact truncation lie paginate() exists to
        prevent."""
        pages: list[dict] = []
        skip = 0
        for _ in range(MAX_REQUEST_PAGES):
            response = await self._seerr.get(
                f"{self.seerr_url}{REQUESTS_PATH}",
                params={"take": REQUEST_PAGE_SIZE, "skip": skip,
                        "sort": "added"})
            response.raise_for_status()
            body = response.json()
            pages.append(body)
            results = body.get("results") or []
            if not results:
                break
            skip += len(results)
            declared = (body.get("pageInfo") or {}).get("results")
            if isinstance(declared, int) and skip >= declared:
                break
        return pages

    async def _request_items(self) -> list[dict]:
        items = []
        for body in await self._request_pages():
            for raw in body.get("results") or []:
                ident = raw.get("id")
                if ident is None:
                    continue
                facts = request_facts(raw)
                items.append(env.item_summary(
                    f"request:{ident}", "media-request", str(ident), facts,
                    opinions=request_opinions(facts), healthy=None))
        return items

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        if collection == "server":
            return await self._server_items()
        if collection == "libraries":
            return await self._library_items()
        if collection == "sessions":
            return await self._session_items()
        if collection == "requests":
            return await self._request_items()
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
        opinions = (server_opinions(item["facts"]) if collection == "server"
                    else request_opinions(item["facts"])
                    if collection == "requests" else [])
        return env.observation(
            self.subsystem,
            env.obj_ref(item["id"], item["type"], item["native_id"],
                        name=item.get("name")),
            self._source(collection), item["facts"],
            opinions=opinions or None,
            evidence_ref=env.evidence_ref(self.subsystem, collection,
                                          item["id"]),
            host=HOST_BLOCK)

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        """Fetch once and check membership in that same document (the
        traefik/downloaders shape): an acquire()-then-refetch pair lets
        a session end between the two calls and ships 200 evidence that
        cannot show its object."""
        if collection not in self.collections():
            raise env.UnknownCollection(collection)
        payload: object
        if collection == "server":
            if object_id != "server:plex":
                raise env.UnknownObject(object_id)
            payload = await self._plex_get("/")
        elif collection == "libraries":
            body = await self._plex_get(SECTIONS_PATH)
            known = {f"library:{raw['key']}"
                     for raw in (body.get("MediaContainer") or {}).get("Directory") or []
                     if raw.get("key") is not None}
            if object_id not in known:
                raise env.UnknownObject(object_id)
            payload = body
        elif collection == "sessions":
            body = await self._plex_get(SESSIONS_PATH)
            known = {f"session:{raw.get('sessionKey') or raw.get('ratingKey')}"
                     for raw in (body.get("MediaContainer") or {}).get("Metadata") or []
                     if raw.get("sessionKey") or raw.get("ratingKey")}
            if object_id not in known:
                raise env.UnknownObject(object_id)
            payload = body
        else:
            pages = await self._request_pages()
            known = {f"request:{raw['id']}" for page in pages
                     for raw in page.get("results") or []
                     if raw.get("id") is not None}
            if object_id not in known:
                raise env.UnknownObject(object_id)
            payload = pages[0] if len(pages) == 1 else {"pages": pages}
        return {"object_id": object_id, "captured_at": env.utc_now(),
                "interface": "Plex + seerr REST APIs", "payload": payload}
