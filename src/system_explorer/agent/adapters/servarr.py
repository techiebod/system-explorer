"""servarr subsystem: the media managers, one API shape, many instances.

Sonarr, radarr, lidarr, readarr and prowlarr all speak the same API
family, so ONE adapter fronts the fleet and the apps are ROWS, not
subsystems — the same move that made containers rows under docker. Three
collections, the tidy tiers: `apps` (one row per configured instance —
version, its own health rolled to counts, queue depth), `health` (the
app's typed self-diagnosis, one row per item, severity MIRRORED never
invented), `queue` (work in flight, with the app's own per-download
verdict — the "completed but will not import" shape that goes unnoticed
is exactly what this surfaces, which is also why every queue fetch asks
for the include-unknown variants of all four apps: the ORPHANED download
the app cannot map to a series/movie/artist/author is the stuck one, and
every app hides it from the queue by default while still counting it in
totalCount — absence reading as health, adversarial review 2026-08-13).

Configuration is deployment receipts, plural: SE_SERVARR_INSTANCES names
the instances (comma-separated, operator-chosen names; a `:v1` suffix
selects the API family — v3 is sonarr and radarr's, while lidarr,
readarr and prowlarr have only ever served /api/v1, so those three take
the suffix), and each name owns SE_<NAME>_URL and SE_<NAME>_API_KEY
with hyphens normalised to underscores — readarr-audio:v1 reads
SE_READARR_AUDIO_URL. The key rides the X-Api-Key header, never a URL;
the env-name suffix keeps it inside text.scrub()'s substitution net. An
instance named but missing its receipts is a warn ROW, not a silent
skip; a duplicated name keeps its first entry and says so; an instance
that stops answering is a critical row — the estate's own statements,
beside the mirrored ones.

Identity: object ids are namespaced by instance name (health:sonarr/…,
queue:readarr-audio/12) so two readarrs never collide under rule 15;
the envelope's app locator is the fleet ("servarr"), and the App fact on
every row is the filterable instance handle. bazarr is deliberately NOT
here — it does not speak this API family and gets its own thin adapter.

Flow: the first emitted edges in the app tier, each derived from a
member THIS app's API states (the vocabulary's rule). A queue object
`tracks` its transfer — target `transfer:<client>/<join>` in the
downloaders subsystem, where the join key is the downloadId both sides
state (info-hashes normalised lowercase, matching the downloaders
adapter's ids; sabnzbd nzo ids verbatim, they are case-sensitive) — and
an app object `dispatches-to` each download client it declares enabled
(/downloadclient), target `client:<name lowercased>`. The client label
is the app's own; a whitespace-free nonstandard label mints an edge
whose target simply does not resolve, and a label that cannot mint a
schema-valid id at all (whitespace) gets NO edge — its name still rides
the facts, because an invalid envelope is worse than a missing arrow.

A dark instance narrows, never masks: health and queue serve the
instances that answered, their envelope goes status partial naming who
did not, and the apps row for the dark one goes critical. Only every
instance failing at once raises (and lands in `unobserved`). Instances
are independent HTTP endpoints, so all per-instance work runs
concurrently — the shared-socket rationale that keeps collections
sequential does not apply within one collection here.
"""

from __future__ import annotations

import asyncio
import os

import httpx

from .. import envelope as env
from ..rules.servarr import app_opinions, health_opinions, queue_opinions

REFERENCE = [
    "curl -H 'X-Api-Key: <key>' <url>/api/v3/system/status",
    "curl -H 'X-Api-Key: <key>' <url>/api/v3/health",
    "curl -H 'X-Api-Key: <key>' '<url>/api/v3/queue?page=1&pageSize=250'",
]

HOST_BLOCK = env.host_block(app="servarr")

QUEUE_PAGE_SIZE = 250
# A runaway guard, not a working limit: 40 pages is ten thousand tracked
# downloads, far past any real queue. Hitting it stops the walk with the
# rows already gathered rather than looping on a lying totalRecords.
QUEUE_MAX_PAGES = 40
# Every app's include-unknown flag, sent together on every queue call:
# ASP.NET Core binds only the parameter the app declares and ignores the
# rest, and the default (false, all four apps) hides exactly the orphaned
# records whose verdicts this collection exists to surface.
INCLUDE_UNKNOWN = {"includeUnknownSeriesItems": "true",
                   "includeUnknownMovieItems": "true",
                   "includeUnknownArtistItems": "true",
                   "includeUnknownAuthorItems": "true"}


def instance_specs() -> list[dict]:
    """The configured fleet: [{name, api, url, key, missing, duplicates}].
    Pure over the environment as read at call time (the adapter captures
    it once at process start), so conformance exercises every shape with
    a patched env. A named instance with absent receipts, a duplicated
    name, or a name that cannot mint unambiguous ids is RETURNED with the
    fault stated — the apps collection wears it; silently dropping any of
    them would be a typo vanishing into green."""
    raw = os.environ.get("SE_SERVARR_INSTANCES", "")
    specs: list[dict] = []
    by_name: dict[str, dict] = {}
    for entry in (piece.strip() for piece in raw.split(",")):
        if not entry:
            continue
        name, _, version = entry.partition(":")
        if name in by_name:
            by_name[name]["duplicates"].append(entry)
            continue
        env_base = name.upper().replace("-", "_")
        url = (os.environ.get(f"SE_{env_base}_URL") or "").rstrip("/") or None
        key = os.environ.get(f"SE_{env_base}_API_KEY") or None
        missing = ([f"SE_{env_base}_URL"] if not url else []) \
            + ([f"SE_{env_base}_API_KEY"] if not key else [])
        if "/" in name:
            # Ids namespace by instance name WITH '/', so a slash-bearing
            # name cannot mint unambiguous ids — a config fault, stated.
            missing.append(f"instance name {name!r} contains '/'")
        spec = {"name": name, "api": version or "v3",
                "url": url, "key": key, "missing": missing,
                "duplicates": []}
        by_name[name] = spec
        specs.append(spec)
    return specs


def status_facts(raw: dict) -> dict:
    facts: dict = {}
    if raw.get("version"):
        facts["Version"] = raw["version"]
    if raw.get("appName"):
        facts["AppName"] = raw["appName"]
    return facts


def health_item_facts(instance: str, raw: dict) -> dict:
    facts: dict = {"App": instance,
                   "Source": raw.get("source"),
                   "Type": raw.get("type"),
                   "Message": (env.reason(raw["message"])
                               if raw.get("message") else None)}
    if raw.get("wikiUrl"):
        facts["WikiUrl"] = raw["wikiUrl"]
    return facts


def queue_record_facts(instance: str, raw: dict) -> dict:
    facts: dict = {"App": instance,
                   "Title": raw.get("title"),
                   "Status": raw.get("status"),
                   "TrackedDownloadStatus": raw.get("trackedDownloadStatus"),
                   "TrackedDownloadState": raw.get("trackedDownloadState")}
    for fact, member in (("DownloadClient", "downloadClient"),
                         ("Indexer", "indexer"),
                         ("Protocol", "protocol"),
                         ("DownloadId", "downloadId")):
        if raw.get(member):
            facts[fact] = raw[member]
    if raw.get("sizeleft") is not None:
        facts["SizeLeftBytes"] = raw["sizeleft"]
    if raw.get("errorMessage"):
        facts["ErrorMessage"] = env.reason(raw["errorMessage"])
    messages = raw.get("statusMessages")
    if isinstance(messages, list) and messages:
        lines = [str(text) for entry in messages if isinstance(entry, dict)
                 for text in (entry.get("messages") or [])]
        if lines:
            facts["StatusMessages"] = env.reason("; ".join(lines))
    return facts


_APP_GLOSSARY = {
    "App": "The instance's operator-chosen name — the filterable handle every row in this subsystem carries.",
    "AppName": "What the app calls itself (Sonarr, Radarr, …), from its own status document.",
    "Version": "The release this instance is running.",
    "HealthErrors": "How many of the app's own health items this product mirrors as critical; each is a row on the health collection.",
    "HealthWarnings": "How many of the app's own health items mirror as warn — notices and passing checks are not counted, so this number and the health rows judge alike.",
    "QueueTotal": "How many downloads the instance is currently tracking, imported or not, orphans included.",
    "QueueUnobservable": "Why the queue count could not be read when it could not — a missing queue endpoint (prowlarr) is not this; that is silence by design.",
    "ApiFamily": "Which API family this instance speaks — v3 for sonarr and radarr, v1 for lidarr, readarr and prowlarr — stated in configuration, never probed.",
    "ConfigMissing": "The receipts this named instance still needs before it can be observed, or the fault in its name.",
    "ConfigDuplicate": "Entries in SE_SERVARR_INSTANCES that duplicated this name and were dropped; the first entry won.",
    "StatusUnobservable": "Why the instance's API could not be asked, when it could not — the row stays, because a configured manager that does not answer is a statement rather than a gap.",
    "DownloadClients": "The download clients this app declares enabled, in its own labels — each whitespace-free label becomes a dispatches-to edge on the opened object (a label that cannot mint a valid id keeps its fact and gets no edge).",
    "DownloadClientsUnobservable": "Why the app\u2019s download-client list could not be read when it could not — no dispatches-to edges can be minted without it.",
}

_HEALTH_GLOSSARY = {
    "App": "Which instance raised this item.",
    "Source": "The app's own name for the check that fired (IndexerStatusCheck, DownloadClientCheck, …).",
    "Type": "The app's own grade for it — ok, notice, warning or error — mirrored, never re-judged, by this product (notice mirrors as info, error as critical).",
    "Message": "The app's own sentence describing the problem, bounded.",
    "WikiUrl": "The app's documentation link for this exact condition.",
}

_QUEUE_GLOSSARY = {
    "App": "Which instance is tracking this download.",
    "Title": "What the download is, as the app titles it.",
    "Status": "The transfer's state as the app sees it (downloading, completed, …).",
    "TrackedDownloadStatus": "The app's verdict on the whole tracked download: ok, warning or error — warning is where completed-but-not-imported lives.",
    "TrackedDownloadState": "Where in the pipeline the app says this item sits (downloading, importPending, importBlocked, …).",
    "DownloadClient": "Which download client holds the transfer, in the app\u2019s own label — lowercased, it is the client half of the tracks target (transfer:<client>/<join>).",
    "Indexer": "Which indexer supplied the release.",
    "Protocol": "Which transfer world the release came from: torrent or usenet.",
    "DownloadId": "The client's own id for the transfer — the tracks join key both sides state.",
    "SizeLeftBytes": "Bytes still to fetch; zero with a warning verdict is the stuck-import shape.",
    "ErrorMessage": "The app's own error line for this item, bounded.",
    "StatusMessages": "The app's per-item status lines folded to one bounded line.",
}


class Adapter:
    subsystem = "servarr"
    host_block = HOST_BLOCK

    def __init__(self) -> None:
        self.specs = instance_specs()
        self._clients: dict[str, httpx.AsyncClient] = {}
        # Per-collection failure lines from the latest fan-out, read by
        # collect() right after awaiting acquire() (the same single
        # flight), so a partially-answered sweep ships status partial
        # instead of discarding who failed.
        self._sweep_failures: dict[str, list[str]] = {}
        for spec in self.specs:
            key = spec["key"]
            if spec["url"] and key and key.isascii() and key.isprintable():
                self._clients[spec["name"]] = httpx.AsyncClient(
                    timeout=10.0, headers={"X-Api-Key": key})
            elif key and not (key.isascii() and key.isprintable()):
                # The paperless posture: a key that cannot survive a header
                # is a config fault named without its value.
                spec["missing"] = spec["missing"] + [
                    f"SE_{spec['name'].upper().replace('-', '_')}_API_KEY"
                    " (contains control or non-ASCII characters)"]

    def collections(self) -> list[str]:
        return ["apps", "health", "queue"]

    async def capability(self) -> dict:
        if not self.specs:
            return {"available": False, "reason": (
                "SE_SERVARR_INSTANCES is not configured — this process"
                " observes no media managers (name them, and give each"
                " its SE_<NAME>_URL and SE_<NAME>_API_KEY)")}
        return {"available": True, "collections": self.collections(),
                "instances": [spec["name"] for spec in self.specs]}

    def fact_glossary(self, collection: str) -> dict:
        return {"apps": _APP_GLOSSARY, "health": _HEALTH_GLOSSARY,
                "queue": _QUEUE_GLOSSARY}.get(collection, {})

    def _source(self, collection: str) -> dict:
        method = {"apps": "GET /api/{family}/system/status + /health + /queue/status",
                  "health": "GET /api/{family}/health",
                  "queue": "GET /api/{family}/queue (paged)"}[collection]
        return env.source("servarr-api", "Servarr REST API", REFERENCE,
                          method=method)

    async def _get(self, spec: dict, path: str, params: dict | None = None):
        client = self._clients[spec["name"]]
        response = await client.get(
            f"{spec['url']}/api/{spec['api']}{path}", params=params)
        response.raise_for_status()
        return response.json()

    def _ready(self) -> list[dict]:
        return [spec for spec in self.specs
                if not spec["missing"] and spec["name"] in self._clients]

    def _spec_named(self, instance: str) -> dict | None:
        return next((s for s in self.specs if s["name"] == instance), None)

    async def _app_item(self, spec: dict) -> dict:
        name = spec["name"]
        facts: dict = {"App": name, "ApiFamily": spec["api"]}
        if spec["duplicates"]:
            facts["ConfigDuplicate"] = list(spec["duplicates"])
        if spec["missing"]:
            facts["ConfigMissing"] = sorted(spec["missing"])
            return env.item_summary(
                f"app:{name}", "servarr-app", name, facts, name=name,
                opinions=app_opinions(facts), healthy="info")
        try:
            facts.update(status_facts(await self._get(spec, "/system/status")))
            health = await self._get(spec, "/health")
            # Counted through the SAME evaluator that grades the health
            # rows, so the fleet number and the rows cannot disagree about
            # what deserves attention (one evaluator, rule 14).
            levels = [op["level"] for item in health
                      for op in health_opinions(health_item_facts(name, item))]
            facts["HealthErrors"] = levels.count("critical")
            facts["HealthWarnings"] = levels.count("warn")
        except Exception as exc:  # noqa: BLE001 - a dark manager is an observation
            facts["StatusUnobservable"] = env.reason(
                f"{type(exc).__name__}: {exc}")
        else:
            try:
                queue_status = await self._get(spec, "/queue/status")
                if isinstance(queue_status, dict) \
                        and queue_status.get("totalCount") is not None:
                    facts["QueueTotal"] = queue_status["totalCount"]
            except httpx.HTTPStatusError as exc:
                # 404 is prowlarr: no queue endpoint at all — silence by
                # design. Anything else is a narrowed observation, stated.
                if exc.response.status_code != 404:
                    facts["QueueUnobservable"] = env.reason(
                        f"HTTPStatusError: {exc}")
            except Exception as exc:  # noqa: BLE001 - narrowed, not broken
                facts["QueueUnobservable"] = env.reason(
                    f"{type(exc).__name__}: {exc}")
        return env.item_summary(
            f"app:{name}", "servarr-app", name, facts, name=name,
            opinions=app_opinions(facts),
            healthy="ok" if "StatusUnobservable" not in facts else "info")

    async def _app_items(self) -> list[dict]:
        self._sweep_failures["apps"] = []
        return list(await asyncio.gather(
            *(self._app_item(spec) for spec in self.specs)))

    async def _fanout(self, collection: str, fetch) -> list[dict]:
        """Rows from every instance that answers, concurrently; the ones
        that fail are named in this collection's envelope (status partial)
        AND go critical on their apps row. Only ALL of them failing
        raises — landing in `unobserved`."""
        ready = self._ready()
        if not ready:
            raise RuntimeError(
                "no configured instance has complete receipts —"
                " see the apps collection for what is missing")
        results = await asyncio.gather(
            *(fetch(spec) for spec in ready), return_exceptions=True)
        items: list[dict] = []
        failures: list[str] = []
        for spec, result in zip(ready, results, strict=True):
            if isinstance(result, BaseException):
                failures.append(
                    f"{spec['name']}: {type(result).__name__}: {result}")
            else:
                items.extend(result)
        if len(failures) == len(ready):
            raise RuntimeError("no instance answered — " + "; ".join(failures))
        self._sweep_failures[collection] = failures
        return items

    async def _health_rows(self, spec: dict) -> list[dict]:
        items = []
        for raw in await self._get(spec, "/health"):
            facts = health_item_facts(spec["name"], raw)
            source = facts.get("Source") or "unknown"
            items.append(env.item_summary(
                f"health:{spec['name']}/{source}", "servarr-health-item",
                f"{spec['name']}/{source}", facts,
                opinions=health_opinions(facts), healthy=None))
        return items

    async def _queue_pages(self, spec: dict):
        """Every queue record, page by page — one walk shared by the rows
        and the evidence, so they cannot disagree about what exists. An
        instance without the endpoint at all (prowlarr) yields nothing."""
        page = 1
        while page <= QUEUE_MAX_PAGES:
            try:
                body = await self._get(spec, "/queue",
                                       {"page": page,
                                        "pageSize": QUEUE_PAGE_SIZE,
                                        **INCLUDE_UNKNOWN})
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404 and page == 1:
                    return
                raise
            records = body.get("records") or []
            for raw in records:
                yield raw
            total = body.get("totalRecords")
            if not records or not isinstance(total, int) \
                    or page * QUEUE_PAGE_SIZE >= total:
                return
            page += 1

    async def _queue_rows(self, spec: dict) -> list[dict]:
        items: list[dict] = []
        seen: set[str] = set()
        index = 0
        async for raw in self._queue_pages(spec):
            native = (str(raw["id"]) if raw.get("id") is not None
                      else f"index-{index}")
            index += 1
            object_id = f"queue:{spec['name']}/{native}"
            if object_id in seen:
                continue
            seen.add(object_id)
            facts = queue_record_facts(spec["name"], raw)
            items.append(env.item_summary(
                object_id, "servarr-queue-item",
                f"{spec['name']}/{native}", facts,
                opinions=queue_opinions(facts), healthy="info"))
        return items

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        if collection == "apps":
            return await self._app_items()
        if collection == "health":
            return await self._fanout("health", self._health_rows)
        if collection == "queue":
            return await self._fanout("queue", self._queue_rows)
        raise env.UnknownCollection(collection)

    async def collect(self, collection: str, query: dict, limit: int | None,
                      cursor: str | None) -> dict:
        fetched = await self.acquire(collection)
        failures = self._sweep_failures.get(collection) or []
        items = env.apply_fact_filters(fetched, query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection,
                                   self._source(collection),
                                   page, applied, next_cursor,
                                   requested_limit=limit, total=total,
                                   filters=query or None,
                                   status="partial" if failures else "ok",
                                   errors=failures or None,
                                   host=HOST_BLOCK)

    @staticmethod
    def _queue_relationships(facts: dict) -> list[dict]:
        """The tracks edge, from the two members the app itself stated."""
        client = facts.get("DownloadClient")
        join = facts.get("DownloadId")
        if not client or not join:
            return []
        if facts.get("Protocol") == "torrent":
            join = str(join).lower()  # the downloaders adapter's id casing
        target = f"transfer:{str(client).lower()}/{join}"
        if any(ch.isspace() for ch in target):
            # A label with whitespace cannot mint a schema-valid id
            # (objectId forbids it): no edge, never an invalid envelope --
            # the label still rides the DownloadClient fact.
            return []
        return [env.rel("tracks", "out", target, subsystem="downloaders")]

    async def _app_relationships(
            self, spec: dict) -> tuple[list[dict], list[str], str | None]:
        """dispatches-to edges from the app's own /downloadclient list —
        an enrichment on the opened object only, so a failure narrows the
        observation and SAYS so (DownloadClientsUnobservable): silence
        here would make a transient endpoint error indistinguishable from
        an app that dispatches to nothing."""
        try:
            declared = await self._get(spec, "/downloadclient")
        except Exception as exc:  # noqa: BLE001 - narrowed, and stated
            return [], [], env.reason(f"{type(exc).__name__}: {exc}")
        names = [str(entry["name"]) for entry in declared
                 if isinstance(entry, dict) and entry.get("enable")
                 and entry.get("name")]
        edges = [env.rel("dispatches-to", "out",
                         f"client:{name.lower()}", subsystem="downloaders")
                 for name in names
                 if not any(ch.isspace() for ch in name)]
        return edges, names, None

    async def get_object(self, collection: str, object_id: str) -> dict:
        matches = [item for item in await self.acquire(collection)
                   if item["id"] == object_id]
        if not matches:
            raise env.UnknownObject(object_id)
        item = matches[0]
        facts = dict(item["facts"])
        relationships: list[dict] = []
        if collection == "queue":
            relationships = self._queue_relationships(facts)
        elif (collection == "apps" and "StatusUnobservable" not in facts
                and "ConfigMissing" not in facts):
            spec = self._spec_named(facts.get("App") or "")
            if spec is not None and spec["name"] in self._clients:
                relationships, names, why_not = (
                    await self._app_relationships(spec))
                if names:
                    facts["DownloadClients"] = names
                elif why_not:
                    facts["DownloadClientsUnobservable"] = why_not
        item = {**item, "facts": facts}
        opinions = {"apps": app_opinions, "health": health_opinions,
                    "queue": queue_opinions}[collection](item["facts"])
        return env.observation(
            self.subsystem,
            env.obj_ref(item["id"], item["type"], item["native_id"],
                        name=item.get("name")),
            self._source(collection), item["facts"], opinions=opinions,
            relationships=relationships or None,
            evidence_ref=env.evidence_ref(self.subsystem, collection,
                                          item["id"]),
            host=HOST_BLOCK)

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        prefixes = {"apps": "app:", "health": "health:", "queue": "queue:"}
        prefix = prefixes.get(collection)
        if prefix is None:
            raise env.UnknownCollection(collection)
        if not object_id.startswith(prefix):
            raise env.UnknownObject(object_id)
        rest = object_id[len(prefix):]
        instance = rest.partition("/")[0] if collection != "apps" else rest
        spec = self._spec_named(instance)
        if spec is None:
            raise env.UnknownObject(object_id)
        if spec["missing"] or spec["name"] not in self._clients:
            # The apps row for this instance EXISTS (get_object serves it),
            # so its evidence must not deny it — the honest payload is the
            # stated fault, as an error envelope from the route's handler.
            raise RuntimeError(
                "instance has no complete receipts, so there is nothing to"
                " ask it: " + ", ".join(sorted(spec["missing"])))
        payload: object
        if collection == "apps":
            payload = {"system_status": await self._get(spec, "/system/status"),
                       "health": await self._get(spec, "/health")}
        elif collection == "health":
            source = rest.partition("/")[2]
            matching = [raw for raw in await self._get(spec, "/health")
                        if (raw.get("source") or "unknown") == source]
            if not matching:
                raise env.UnknownObject(object_id)
            payload = matching[0] if len(matching) == 1 else matching
        else:
            native = rest.partition("/")[2]
            payload = None
            async for raw in self._queue_pages(spec):
                if raw.get("id") is not None and str(raw["id"]) == native:
                    payload = raw
                    break
            if payload is None:
                raise env.UnknownObject(object_id)
        return {"object_id": object_id, "captured_at": env.utc_now(),
                "interface": "Servarr REST API", "payload": payload}
