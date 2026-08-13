"""servarr subsystem: the media managers, one API shape, many instances.

Sonarr, radarr, lidarr, readarr and prowlarr all speak the same API
family, so ONE adapter fronts the fleet and the apps are ROWS, not
subsystems — the same move that made containers rows under docker. Four
collections, the tidy tiers: `apps` (one row per configured instance —
version, its own health rolled to counts, queue depth), `health` (the
app's typed self-diagnosis, one row per item, severity MIRRORED never
invented), `queue` (work in flight, with the app's own per-download
verdict — the "completed but will not import" shape that goes unnoticed
is exactly what this surfaces, which is also why every queue fetch asks
for the include-unknown variants of all four apps: the ORPHANED download
the app cannot map to a series/movie/artist/author is the stuck one, and
every app hides it from the queue by default while still counting it in
totalCount — absence reading as health, adversarial review 2026-08-13),
and `history` (the acquisition trail — each app's own recent event log,
one bounded page, newest first).

Answers: `apps` — which managers are configured here and how each one
stands; `health` — what each app says is wrong with itself; `queue` —
what is in flight and the app's own verdict on it; `history` — what
was grabbed and what arrived recently, via which client — the indexer
is a grab-event member, so an arrival names it only through the grab
that preceded it, and only while that grab is still inside the bounded
tail.

`history` is page 1 of each app's own history, date-descending,
HISTORY_PAGE_SIZE records — deliberately a bounded recent tail, because
the question it answers is "what arrived lately", not "everything that
ever did". Events are not current health: rows carry no severity
(healthy=None, no opinions) and the /v1/status roll-up declines the
collection the way logs/journal is declined ("the acquisition trail is
a bounded recent tail; no current health" — main.py's STATUS_DECLINES),
so the roll-up never reads yesterday's grab as this hour's standing.
Facts are the members the app states, its vocabulary verbatim. WHO
asked for a title is the request pipeline's half (the seerr requests
collection) and is deliberately not restated here; the pipeline view
joins that side. prowlarr is excluded, by its own appName statement in
/system/status rather than by its operator-chosen instance name: its
/api/v1/history is indexer telemetry (releaseGrabbed, indexerQuery,
indexerRss, indexerAuth, indexerInfo — records carrying no source
title, quality or download client), a search audit rather than an
acquisition trail, and the grabs it does file are the same events the
asking apps' own histories state with the full acquisition members.
History EVIDENCE serves the page document with every URL a record
states cut back to scheme and host, withheld and declared — a grab's
downloadUrl is where indexer credentials live (_redact_history_urls).
History is the ONE redacted family: apps, health and queue evidence
still passes through raw, on the reviewed ground the per-collection
exemption entries carry (servarr:apps, servarr:health, servarr:queue
in EVIDENCE_REDACTION_EXEMPTIONS) — the API key travels only in the
request header this adapter sends and appears in none of those three
document families. The same reason sits at the raw branches in
get_evidence; a new member carrying a URL there must re-argue it or
route through the redactor.

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
(/downloadclient). The client half of every target is the client's
IMPLEMENTATION lowercased (Transmission -> transmission) — the member
the API states beside the label — because the label is the operator's
pet name (LocalTransmission) while the downloaders adapter files its
rows under the product, and label-minted targets dangled on the first
real estate (live repro, 2026-08-13). Where the implementation cannot
be read, the lowercased label is the honest fallback: an edge whose
target simply does not resolve. A handle that cannot mint a
schema-valid id at all (whitespace) gets NO edge — the name still
rides the facts, because an invalid envelope is worse than a missing
arrow.

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
import copy
import os
import re
from urllib.parse import urlsplit

import httpx

from .. import envelope as env
from ..rules.servarr import app_opinions, health_opinions, queue_opinions

REFERENCE = [
    "curl -H 'X-Api-Key: <key>' <url>/api/v3/system/status",
    "curl -H 'X-Api-Key: <key>' <url>/api/v3/health",
    "curl -H 'X-Api-Key: <key>' '<url>/api/v3/queue?page=1&pageSize=250'",
    "curl -H 'X-Api-Key: <key>' <url>/api/v3/queue/status",
    "curl -H 'X-Api-Key: <key>' '<url>/api/v3/history?page=1&pageSize=100"
    "&sortKey=date&sortDirection=descending'",
    "curl -H 'X-Api-Key: <key>' <url>/api/v3/downloadclient",
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
# The acquisition trail is ONE page per app, deliberately: the newest
# HISTORY_PAGE_SIZE events, date-descending. Walking the whole table would
# answer "everything that ever arrived" — a different question — and would
# pay that walk on every sweep.
HISTORY_PAGE_SIZE = 100
HISTORY_PARAMS = {"page": 1, "pageSize": HISTORY_PAGE_SIZE,
                  "sortKey": "date", "sortDirection": "descending"}


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


def history_record_facts(instance: str, raw: dict) -> dict:
    """One history event's stated members, the app's vocabulary verbatim:
    eventType rides exactly as the app spells it (grabbed,
    downloadFolderImported, downloadFailed, trackFileImported and kin) —
    never translated, because a vocabulary this product invented would be
    it re-grading events the app already named. An absent member is an
    absent fact, never a guess (rule 7)."""
    facts: dict = {"App": instance}
    data = raw.get("data")
    if not isinstance(data, dict):
        data = {}
    for fact, value in (("EventType", raw.get("eventType")),
                        ("Title", raw.get("sourceTitle")),
                        ("Indexer", data.get("indexer")),
                        ("DownloadClient", data.get("downloadClient")),
                        ("DownloadId", raw.get("downloadId")),
                        ("Date", raw.get("date"))):
        if value:
            facts[fact] = value
    quality = raw.get("quality")
    quality = quality.get("quality") if isinstance(quality, dict) else None
    if isinstance(quality, dict) and quality.get("name"):
        facts["Quality"] = quality["name"]
    return facts


def _history_natives(records: list) -> list[tuple[str, dict]]:
    """Every record's native id, minted ONE way for the whole page: the
    app's own id where it states one, index-N (the record's position in
    the page) where it does not. Shared by _history_rows and
    get_evidence's membership check so the two cannot disagree about what
    exists — the rows minting index-N while the evidence set was rebuilt
    from real ids alone was exactly that disagreement: an object the
    product serves whose own evidence route denied it. Enumerates the
    full list (non-dict positions still count) and drops non-dicts after,
    so both sides number identically."""
    return [((str(raw["id"]) if raw.get("id") is not None
              else f"index-{index}"), raw)
            for index, raw in enumerate(records)
            if isinstance(raw, dict)]


# A URL occurrence anywhere inside a string value — not whole values
# only, because failed events are the real carrier: sabnzbd's URL-fetch
# failure text embeds the full source URL mid-sentence ("URL Fetching
# failed; https://indexer/getnzb?…&apikey=…"), and qBittorrent tracker
# errors embed announce URLs with passkeys. A whole-value gate let every
# one of those ride out with the credential intact.
_EMBEDDED_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _keep_scheme_host(match: re.Match[str]) -> str:
    """One matched URL cut back to its diagnostic half. The regex found
    it, so it announces http(s), and announcing is enough to deny: a
    value urlsplit refuses ("Invalid IPv6 URL" and kin) is withheld
    whole — scheme://REDACTED, never skipped, because a refusal is not a
    clearance and no host can be trusted out of a string the parser
    rejected. A junk port keeps the host and drops the port. A bare
    scheme+host with nothing after it (no path beyond /, no query,
    fragment or userinfo) rides back unchanged: there is nothing to
    withhold, and declaring a withholding that never happened is the lie
    the declared-paths contract exists to prevent."""
    url = match.group(0)
    try:
        parts = urlsplit(url)
    except ValueError:
        scheme = url.partition("://")[0].lower()
        return f"{scheme}://{env.REDACTED}"
    if not parts.hostname:
        return url
    if (parts.path in ("", "/") and not parts.query
            and not parts.fragment and "@" not in parts.netloc):
        return url  # bare scheme+host: nothing after the host to withhold
    try:
        port = parts.port
    except ValueError:
        port = None  # an uncastable port: keep the host, drop the port
    host = parts.hostname + (f":{port}" if port else "")
    return f"{parts.scheme}://{host}/{env.REDACTED}"


def _redact_history_urls(page: dict) -> tuple[dict, list[str]]:
    """The credential half of every URL a history record states, withheld:
    a grab's downloadUrl is where indexer credentials live — a newznab api
    key in the query, a private tracker's passkey in the path, and a
    prowlarr-proxied link carries the very key this process is configured
    with — on an evidence route that requires no authentication. The
    scheme and host stay, because "where did it come from" is the
    diagnostic half; everything after the host is withheld and DECLARED
    (the traefik/docker contract: a declared path must really differ, so
    a member is declared only when substitution actually changed it — a
    bare scheme+host rides untouched and undeclared). Matched on value
    shape wherever it appears in the string, not a member-name list and
    not whole values only — deny-by-default applies to every occurrence,
    and the next app member carrying a URL must not arrive unredacted."""
    out = copy.deepcopy(page)
    paths: list[str] = []
    for index, record in enumerate(out.get("records") or []):
        data = record.get("data") if isinstance(record, dict) else None
        if not isinstance(data, dict):
            continue
        for member, value in data.items():
            if not isinstance(value, str):
                continue
            replacement = _EMBEDDED_URL.sub(_keep_scheme_host, value)
            if replacement != value:
                data[member] = replacement
                paths.append(f"records.{index}.data.{member}")
    return out, paths


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
    "DownloadClients": "The download clients this app declares enabled, in its own labels — each becomes a dispatches-to edge targeted by the client’s implementation, deduplicated (a handle that cannot mint a valid id keeps its fact and gets no edge).",
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
    "DownloadClient": "Which download client holds the transfer, in the app\u2019s own label — the tracks edge resolves it to the client\u2019s implementation (transfer:<implementation>/<join>) so the arrow lands on the row the downloaders adapter actually serves.",
    "Indexer": "Which indexer supplied the release.",
    "Protocol": "Which transfer world the release came from: torrent or usenet.",
    "DownloadId": "The client's own id for the transfer — the tracks join key both sides state.",
    "SizeLeftBytes": "Bytes still to fetch; zero with a warning verdict is the stuck-import shape.",
    "ErrorMessage": "The app's own error line for this item, bounded.",
    "StatusMessages": "The app's per-item status lines folded to one bounded line.",
}

_HISTORY_GLOSSARY = {
    "App": "Which instance recorded this event.",
    "EventType": "What happened, in the app's own vocabulary — grabbed, "
                 "downloadFolderImported, downloadFailed, trackFileImported "
                 "and kin — served verbatim, never translated.",
    "Title": "The release the event concerns, as the app recorded it "
             "(their sourceTitle member).",
    "Indexer": "Which indexer supplied the release, on the events where the "
               "app states one (a grab does; an import does not — an import "
               "names its client and download id, and its indexer lives on "
               "the grab that preceded it, which the bounded tail may no "
               "longer hold).",
    "DownloadClient": "Which download client carried the transfer, in the "
                      "app's own label, on the events that state one.",
    "DownloadId": "The client's own id for the transfer this event belongs "
                  "to — the same join key the queue states while the "
                  "download is still live.",
    "Quality": "The quality the app assigned the release, in its own "
               "profile vocabulary.",
    "Date": "When the app recorded the event — its own timestamp, served "
            "verbatim.",
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
        return ["apps", "health", "queue", "history"]

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
                "queue": _QUEUE_GLOSSARY,
                "history": _HISTORY_GLOSSARY}.get(collection, {})

    def _source(self, collection: str) -> dict:
        method = {"apps": "GET /api/{family}/system/status + /health + /queue/status",
                  "health": "GET /api/{family}/health",
                  "queue": "GET /api/{family}/queue (paged)",
                  "history": "GET /api/{family}/history (page 1, newest first)"}[collection]
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

    async def _history_page(self, spec: dict) -> dict | None:
        """The one page the trail serves — fetched once and shared by rows
        and evidence, so the two cannot disagree about what exists. None
        means the instance said it is Prowlarr (appName in /system/status —
        the app's own statement, never the operator-chosen instance name):
        excluded, for the shape of its records rather than by fiat (see the
        module docstring)."""
        status = await self._get(spec, "/system/status")
        if isinstance(status, dict) and status.get("appName") == "Prowlarr":
            return None
        return await self._get(spec, "/history", HISTORY_PARAMS)

    async def _history_rows(self, spec: dict) -> list[dict]:
        page = await self._history_page(spec)
        records = page.get("records") if isinstance(page, dict) else None
        items: list[dict] = []
        seen: set[str] = set()
        for native, raw in _history_natives(records or []):
            object_id = f"history:{spec['name']}/{native}"
            if object_id in seen:
                continue
            seen.add(object_id)
            # An event is not current health: no severity claim at all.
            items.append(env.item_summary(
                object_id, "servarr-history-event",
                f"{spec['name']}/{native}",
                history_record_facts(spec["name"], raw),
                opinions=[], healthy=None))
        return items

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        if collection == "apps":
            return await self._app_items()
        if collection == "health":
            return await self._fanout("health", self._health_rows)
        if collection == "queue":
            return await self._fanout("queue", self._queue_rows)
        if collection == "history":
            return await self._fanout("history", self._history_rows)
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

    async def _declared_clients(
            self, spec: dict) -> tuple[list[dict] | None, str | None]:
        """The app's own enabled /downloadclient entries, or why they
        could not be read — one fetch shared by both edge surfaces."""
        try:
            declared = await self._get(spec, "/downloadclient")
        except Exception as exc:  # noqa: BLE001 - enrichment, narrowed and stated
            return None, env.reason(f"{type(exc).__name__}: {exc}")
        return [entry for entry in declared
                if isinstance(entry, dict) and entry.get("enable")], None

    @staticmethod
    def _impl_by_label(declared: list[dict]) -> dict[str, str]:
        """label.lower() -> implementation.lower(): the source-stated
        bridge between the app's pet names for its clients and the
        product names the downloaders adapter files its rows under."""
        return {str(entry["name"]).lower(): str(entry["implementation"]).lower()
                for entry in declared
                if entry.get("name") and entry.get("implementation")}

    @staticmethod
    def _queue_relationships(
            facts: dict,
            impl_by_label: dict[str, str] | None = None) -> list[dict]:
        """The tracks edge, from the members the app itself stated. The
        client half of the target resolves through the implementation
        map when the app's client list could be read; without it the
        lowercased label is the honest fallback."""
        client = facts.get("DownloadClient")
        join = facts.get("DownloadId")
        if not client or not join:
            return []
        if facts.get("Protocol") == "torrent":
            join = str(join).lower()  # the downloaders adapter's id casing
        handle = str(client).lower()
        handle = (impl_by_label or {}).get(handle, handle)
        target = f"transfer:{handle}/{join}"
        if any(ch.isspace() for ch in target):
            # A handle with whitespace cannot mint a schema-valid id
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
        an app that dispatches to nothing. Targets resolve through the
        implementation map and deduplicate — two labels for one product
        are one arrow — while the labels themselves ride the
        DownloadClients fact in the app's own words."""
        declared, why_not = await self._declared_clients(spec)
        if declared is None:
            return [], [], why_not
        names = [str(entry["name"]) for entry in declared if entry.get("name")]
        impl_by_label = self._impl_by_label(declared)
        targets: list[str] = []
        for name in names:
            handle = impl_by_label.get(name.lower(), name.lower())
            if any(ch.isspace() for ch in handle):
                continue  # cannot mint a schema-valid id; the fact keeps the name
            if handle not in targets:
                targets.append(handle)
        edges = [env.rel("dispatches-to", "out", f"client:{handle}",
                         subsystem="downloaders")
                 for handle in targets]
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
            impl_by_label = None
            spec = self._spec_named(facts.get("App") or "")
            if spec is not None and spec["name"] in self._clients:
                declared, _ = await self._declared_clients(spec)
                if declared is not None:
                    impl_by_label = self._impl_by_label(declared)
            relationships = self._queue_relationships(facts, impl_by_label)
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
        # history mints NO edges: the queue's live `tracks` edge is the flow
        # surface; history is the trail behind it.
        item = {**item, "facts": facts}
        evaluator = {"apps": app_opinions, "health": health_opinions,
                     "queue": queue_opinions}.get(collection)
        opinions = evaluator(item["facts"]) if evaluator is not None else None
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
        prefixes = {"apps": "app:", "health": "health:", "queue": "queue:",
                    "history": "history:"}
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
        # apps/health/queue evidence is served RAW, deliberately — the
        # reason the per-collection EVIDENCE_REDACTION_EXEMPTIONS entries
        # (servarr:apps, servarr:health, servarr:queue) hold in writing:
        # the API key travels only in the request header this adapter
        # sends and appears in none of these three document families. If
        # an app version adds a URL-bearing member to any of them, route
        # that branch through _redact_history_urls's walk instead.
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
        elif collection == "history":
            # The page document IS the evidence — fetched once, membership
            # checked in that same document (the traefik/downloaders shape),
            # so a trail that moved between two calls cannot ship 200
            # evidence that fails to show its object. Served with its URL
            # tails withheld: see _redact_history_urls.
            native = rest.partition("/")[2]
            page = await self._history_page(spec)
            if not isinstance(page, dict):
                # A page that is not a document cannot vouch for anything.
                raise env.UnknownObject(object_id)
            # Membership through the SAME minting the rows use, so an
            # index-N row's evidence cannot deny the record its page
            # plainly contains.
            known = {native_id for native_id, _ in
                     _history_natives(page.get("records") or [])}
            if native not in known:
                raise env.UnknownObject(object_id)
            payload, redacted = _redact_history_urls(page)
            out = {"object_id": object_id, "captured_at": env.utc_now(),
                   "interface": "Servarr REST API", "payload": payload}
            if redacted:
                out["redacted"] = redacted
            return out
        elif collection == "queue":
            native = rest.partition("/")[2]
            payload = None
            async for raw in self._queue_pages(spec):
                if raw.get("id") is not None and str(raw["id"]) == native:
                    payload = raw
                    break
            if payload is None:
                raise env.UnknownObject(object_id)
        else:
            raise env.UnknownCollection(collection)
        return {"object_id": object_id, "captured_at": env.utc_now(),
                "interface": "Servarr REST API", "payload": payload}
