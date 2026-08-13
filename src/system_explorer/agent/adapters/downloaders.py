"""downloaders subsystem: the transfer tier, observed as applications.

Transmission and sabnzbd are where the managers' dispatched work actually
moves, and the estate incident class this closes is the invisible middle:
a manager says "grabbed", a library says "missing", and nothing showed
the transfer sitting stalled or erroring in between. Two collections:
`clients` (one row per configured client — version, speeds, queue depth,
the disk headroom the client itself measures from inside its own mount)
and `transfers` (per-item state in each client's own vocabulary, with
the client's own error text and stalled verdicts mirrored).

This adapter is the OTHER END of the first flow edges: transfer ids are
`transfer:<client>/<join-key>` where the join key is exactly what the
managers state as downloadId — a torrent's info-hash (normalised
lowercase on both sides; the managers uppercase it, transmission lowers
it) or sabnzbd's nzo id (verbatim; it is case-sensitive). The servarr
adapter emits `tracks` edges against these ids and `dispatches-to`
against `client:<name>`; nothing here guesses at the reverse — one side
owns each edge, and it is the side whose API stated the key.

Configuration is deployment receipts: SE_TRANSMISSION_URL (the estate
runs its RPC unauthenticated on loopback) and SE_SABNZBD_URL +
SE_SABNZBD_API_KEY. A client with no URL is simply absent — the estate
runs one of each at most, and rows exist for what is configured; a
sabnzbd URL without its key is a stated-fault row. The sabnzbd key
travels ONLY as a query parameter because that is the only place the
API accepts it — which is exactly why text.scrub() strips query strings
from all failure text, and why the reference commands show <key>.

Transmission RPC mechanics, for the reader who meets the 409: every
session opens with a CSRF handshake — the first POST is refused with
X-Transmission-Session-Id, which is echoed back on the retry and kept
for the connection's life. One retry, never a loop.
"""

from __future__ import annotations

import asyncio
import os

import httpx

from .. import envelope as env
from ..rules.downloaders import client_opinions, transfer_opinions

TRANSMISSION_RPC = "/transmission/rpc"
SAB_API = "/api"

REFERENCE = [
    "curl -X POST <url>/transmission/rpc -H 'X-Transmission-Session-Id: <id>'"
    " -d '{\"method\": \"torrent-get\", \"arguments\": {\"fields\":"
    " [\"hashString\", \"name\", \"status\"]}}'",
    "curl '<url>/api?mode=queue&output=json&apikey=<key>'",
    "curl '<url>/api?mode=fullstatus&output=json&apikey=<key>'",
]

HOST_BLOCK = env.host_block(app="downloaders")

# transmission's documented status vocabulary, by RPC enum position: its
# own names, not inventions (rule 2) — the int is the wire form and the
# name is how every transmission surface renders it.
TRANSMISSION_STATUS = ("stopped", "check-wait", "check", "download-wait",
                       "download", "seed-wait", "seed")

TORRENT_FIELDS = ["hashString", "name", "status", "percentDone",
                  "rateDownload", "rateUpload", "error", "errorString",
                  "isStalled", "sizeWhenDone", "leftUntilDone"]


def torrent_facts(raw: dict) -> dict:
    facts: dict = {"Client": "transmission",
                   "Name": raw.get("name")}
    status = raw.get("status")
    if isinstance(status, int) and 0 <= status < len(TRANSMISSION_STATUS):
        facts["Status"] = TRANSMISSION_STATUS[status]
    percent = raw.get("percentDone")
    if isinstance(percent, (int, float)):
        facts["PercentDone"] = round(percent * 100, 1)
    for fact, member in (("RateDownloadBytes", "rateDownload"),
                         ("RateUploadBytes", "rateUpload"),
                         ("SizeWhenDoneBytes", "sizeWhenDone"),
                         ("LeftUntilDoneBytes", "leftUntilDone")):
        if isinstance(raw.get(member), (int, float)):
            facts[fact] = raw[member]
    error = raw.get("error")
    if isinstance(error, int):
        facts["Error"] = error
        if error != 0 and raw.get("errorString"):
            facts["ErrorString"] = env.reason(raw["errorString"])
    if raw.get("isStalled") is not None:
        facts["IsStalled"] = bool(raw["isStalled"])
    return facts


def sab_slot_facts(raw: dict) -> dict:
    facts: dict = {"Client": "sabnzbd",
                   "Name": raw.get("filename"),
                   "Status": raw.get("status")}
    if raw.get("percentage") is not None:
        try:
            facts["PercentDone"] = float(raw["percentage"])
        except (TypeError, ValueError):
            pass
    for fact, member in (("SizeMB", "mb"), ("LeftMB", "mbleft")):
        try:
            facts[fact] = float(raw[member])
        except (TypeError, ValueError, KeyError):
            pass
    if raw.get("timeleft"):
        facts["TimeLeft"] = raw["timeleft"]
    return facts


def sab_queue_client_facts(queue: dict) -> dict:
    """Client-level facts from sabnzbd's queue document, which is where it
    states its own vantage: speeds, depth, pause state, and the disk it
    measures from inside its own mount (GB in, bytes out — the API's unit,
    converted once here rather than by every consumer)."""
    facts: dict = {}
    if queue.get("version"):
        facts["Version"] = queue["version"]
    if queue.get("paused") is not None:
        facts["Paused"] = bool(queue["paused"])
    try:
        facts["DownloadRateBytes"] = int(float(queue["kbpersec"]) * 1024)
    except (TypeError, ValueError, KeyError):
        pass
    try:
        facts["QueueCount"] = int(queue["noofslots_total"])
    except (TypeError, ValueError, KeyError):
        if queue.get("noofslots") is not None:
            try:
                facts["QueueCount"] = int(queue["noofslots"])
            except (TypeError, ValueError):
                pass
    for fact, member in (("DiskFreeBytes", "diskspace1"),
                         ("DiskTotalBytes", "diskspacetotal1")):
        try:
            facts[fact] = int(float(queue[member]) * 1024 ** 3)
        except (TypeError, ValueError, KeyError):
            pass
    return facts


_CLIENT_GLOSSARY = {
    "Client": "Which download client this row describes — the filterable handle, and the name the managers' dispatches-to edges target.",
    "Version": "The release the client reports for itself.",
    "Paused": "The whole-queue pause switch (sabnzbd); true means nothing dispatched will move until resumed.",
    "DownloadRateBytes": "Current aggregate download rate, from the client's own meter.",
    "UploadRateBytes": "Current aggregate upload rate (transmission).",
    "QueueCount": "How many items the client is holding, in its own counting.",
    "ActiveTorrentCount": "Torrents currently moving data, by transmission's own count.",
    "PausedTorrentCount": "Torrents individually paused, by transmission's own count.",
    "TorrentCount": "Every torrent the client holds, seeding included.",
    "DiskFreeBytes": "Free space on the download volume AS THE CLIENT SEES IT from inside its own mount — which can differ from any host row when a bind has diverged (the incident class this subsystem watches).",
    "DiskTotalBytes": "Size of that same volume from the same vantage; present only where the client states it (sabnzbd does, transmission states free alone).",
    "ConfigMissing": "The receipts this client still needs before it can be observed.",
    "StatusUnobservable": "Why the client's API could not be asked, when it could not — the row stays, because a configured client that does not answer blocks every manager dispatching to it.",
}

_TRANSFER_GLOSSARY = {
    "Client": "Which client holds this transfer.",
    "Name": "What the transfer is, as the client names it.",
    "Status": "The client's own state word — transmission's documented vocabulary (stopped, check, download, seed…) or sabnzbd's (Downloading, Paused, Queued…).",
    "PercentDone": "How complete the transfer is, per the client.",
    "RateDownloadBytes": "This transfer's current download rate.",
    "RateUploadBytes": "This transfer's current upload rate.",
    "SizeWhenDoneBytes": "Total bytes this transfer will occupy when complete.",
    "LeftUntilDoneBytes": "How many bytes this transfer still has to fetch before completion.",
    "SizeMB": "Total size in megabytes, sabnzbd's own unit kept as stated.",
    "LeftMB": "Megabytes still to fetch, sabnzbd's unit.",
    "TimeLeft": "The client's own remaining-time estimate (sabnzbd), verbatim.",
    "Error": "The error class transmission assigns this transfer: 0 none, 1 tracker warning, 2 tracker error, 3 local error.",
    "ErrorString": "The client's own error line, bounded.",
    "IsStalled": "The client's own verdict that no peers are moving this transfer (transmission).",
}


class Adapter:
    subsystem = "downloaders"
    host_block = HOST_BLOCK

    def __init__(self) -> None:
        self.transmission_url = (os.environ.get("SE_TRANSMISSION_URL") or "").rstrip("/") or None
        self.sab_url = (os.environ.get("SE_SABNZBD_URL") or "").rstrip("/") or None
        self.sab_key = os.environ.get("SE_SABNZBD_API_KEY") or None
        self._client = httpx.AsyncClient(timeout=10.0)
        self._session_id: str | None = None
        # Per-collection failure lines from the latest sweep, read by
        # collect() after awaiting acquire() (the servarr arrangement): a
        # one-client failure ships the other client's rows plus status
        # partial naming who failed, never an all-or-nothing error.
        self._sweep_failures: dict[str, list[str]] = {}

    def collections(self) -> list[str]:
        return ["clients", "transfers"]

    async def capability(self) -> dict:
        if not self.transmission_url and not self.sab_url:
            return {"available": False, "reason": (
                "neither SE_TRANSMISSION_URL nor SE_SABNZBD_URL is"
                " configured — this process observes no download clients")}
        clients = ([{"transmission": self.transmission_url}] if self.transmission_url else []) \
            + ([{"sabnzbd": self.sab_url}] if self.sab_url else [])
        return {"available": True, "collections": self.collections(),
                "clients": [name for entry in clients for name in entry]}

    def fact_glossary(self, collection: str) -> dict:
        return {"clients": _CLIENT_GLOSSARY,
                "transfers": _TRANSFER_GLOSSARY}.get(collection, {})

    def _source(self, collection: str) -> dict:
        return env.source(
            "downloader-api",
            "transmission RPC + sabnzbd JSON API", REFERENCE,
            method={"clients": "session-get/session-stats + mode=queue",
                    "transfers": "torrent-get + mode=queue"}[collection])

    async def _rpc(self, method: str, arguments: dict | None = None) -> dict:
        """One transmission RPC call, with the 409 session handshake: the
        refused first POST hands over X-Transmission-Session-Id, echoed on
        exactly one retry (never a loop — a second 409 is a real error)."""
        body = {"method": method, "arguments": arguments or {}}
        for attempt in (1, 2):
            headers = ({"X-Transmission-Session-Id": self._session_id}
                       if self._session_id else {})
            response = await self._client.post(
                f"{self.transmission_url}{TRANSMISSION_RPC}",
                json=body, headers=headers)
            if response.status_code == 409 and attempt == 1:
                self._session_id = response.headers.get(
                    "X-Transmission-Session-Id")
                continue
            response.raise_for_status()
            payload = response.json()
            if payload.get("result") != "success":
                raise RuntimeError(
                    f"transmission RPC {method} answered"
                    f" {payload.get('result')!r}")
            return payload.get("arguments") or {}
        raise RuntimeError("transmission RPC handshake did not converge")

    async def _sab(self, mode: str) -> dict:
        response = await self._client.get(
            f"{self.sab_url}{SAB_API}",
            params={"mode": mode, "output": "json", "apikey": self.sab_key})
        response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict) and payload.get("status") is False:
            raise RuntimeError(
                f"sabnzbd refused mode={mode}: {payload.get('error')}")
        return payload

    async def _transmission_client_row(self) -> dict:
        facts: dict = {"Client": "transmission"}
        try:
            session = await self._rpc("session-get")
            stats = await self._rpc("session-stats")
        except Exception as exc:  # noqa: BLE001 - a dark client is an observation
            facts["StatusUnobservable"] = env.reason(
                f"{type(exc).__name__}: {exc}")
        else:
            if session.get("version"):
                facts["Version"] = session["version"]
            free = session.get("download-dir-free-space")
            if isinstance(free, int) and free >= 0:
                facts["DiskFreeBytes"] = free
            for fact, member in (("ActiveTorrentCount", "activeTorrentCount"),
                                 ("PausedTorrentCount", "pausedTorrentCount"),
                                 ("TorrentCount", "torrentCount"),
                                 ("DownloadRateBytes", "downloadSpeed"),
                                 ("UploadRateBytes", "uploadSpeed")):
                if isinstance(stats.get(member), int):
                    facts[fact] = stats[member]
        return env.item_summary(
            "client:transmission", "download-client", "transmission", facts,
            name="transmission", opinions=client_opinions(facts),
            healthy="ok" if "StatusUnobservable" not in facts else "info")

    async def _sab_client_row(self) -> dict:
        facts: dict = {"Client": "sabnzbd"}
        if not self.sab_key:
            facts["ConfigMissing"] = ["SE_SABNZBD_API_KEY"]
        else:
            try:
                queue = (await self._sab("queue")).get("queue") or {}
            except Exception as exc:  # noqa: BLE001 - a dark client is an observation
                facts["StatusUnobservable"] = env.reason(
                    f"{type(exc).__name__}: {exc}")
            else:
                facts.update(sab_queue_client_facts(queue))
        return env.item_summary(
            "client:sabnzbd", "download-client", "sabnzbd", facts,
            name="sabnzbd", opinions=client_opinions(facts),
            healthy="ok" if "StatusUnobservable" not in facts
            and "ConfigMissing" not in facts else "info")

    async def _client_items(self) -> list[dict]:
        self._sweep_failures["clients"] = []
        builders = []
        if self.transmission_url:
            builders.append(self._transmission_client_row())
        if self.sab_url:
            builders.append(self._sab_client_row())
        # Concurrent: each row already states its own failure, so a dark
        # transmission must not make the sab row wait out its timeout.
        return list(await asyncio.gather(*builders))

    async def _transmission_transfers(self) -> list[dict]:
        items: list[dict] = []
        payload = await self._rpc("torrent-get", {"fields": TORRENT_FIELDS})
        for raw in payload.get("torrents") or []:
            digest = str(raw.get("hashString") or "").lower()
            if not digest:
                continue
            facts = torrent_facts(raw)
            items.append(env.item_summary(
                f"transfer:transmission/{digest}", "transfer", digest,
                facts, name=raw.get("name"),
                opinions=transfer_opinions(facts), healthy="info"))
        return items

    async def _sab_transfers(self) -> list[dict]:
        items: list[dict] = []
        queue = (await self._sab("queue")).get("queue") or {}
        for raw in queue.get("slots") or []:
            nzo = raw.get("nzo_id")
            if not nzo:
                continue
            facts = sab_slot_facts(raw)
            items.append(env.item_summary(
                f"transfer:sabnzbd/{nzo}", "transfer", str(nzo),
                facts, name=raw.get("filename"),
                opinions=transfer_opinions(facts), healthy="info"))
        return items

    @staticmethod
    async def _sab_key_missing() -> list[dict]:
        # A URL-configured, keyless sabnzbd must flow through the SAME
        # per-client failure machinery as a dark one: silently omitting
        # it would make "sab has no transfers" and "sab could not be
        # asked" byte-identical envelopes.
        raise RuntimeError(
            "configured by URL but SE_SABNZBD_API_KEY is missing — its"
            " transfers cannot be asked for")

    async def _transfer_items(self) -> list[dict]:
        """Per-client degradation, the servarr _fanout contract: one dark
        client costs its own rows plus a named failure line (status
        partial), never the other client's transfers; only every client
        failing raises, into `unobserved`."""
        self._sweep_failures["transfers"] = []
        named = []
        if self.transmission_url:
            named.append(("transmission", self._transmission_transfers()))
        if self.sab_url:
            named.append(("sabnzbd", self._sab_transfers() if self.sab_key
                          else self._sab_key_missing()))
        results = await asyncio.gather(*(coro for _, coro in named),
                                       return_exceptions=True)
        items: list[dict] = []
        failures: list[str] = []
        for (client, _), result in zip(named, results, strict=True):
            if isinstance(result, BaseException):
                failures.append(f"{client}: {type(result).__name__}: {result}")
            else:
                items.extend(result)
        if named and len(failures) == len(named):
            raise RuntimeError("no client answered — " + "; ".join(failures))
        self._sweep_failures["transfers"] = failures
        return items

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        if collection == "clients":
            return await self._client_items()
        if collection == "transfers":
            return await self._transfer_items()
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

    async def get_object(self, collection: str, object_id: str) -> dict:
        matches = [item for item in await self.acquire(collection)
                   if item["id"] == object_id]
        if not matches:
            raise env.UnknownObject(object_id)
        item = matches[0]
        opinions = {"clients": client_opinions,
                    "transfers": transfer_opinions}[collection](item["facts"])
        return env.observation(
            self.subsystem,
            env.obj_ref(item["id"], item["type"], item["native_id"],
                        name=item.get("name")),
            self._source(collection), item["facts"], opinions=opinions,
            evidence_ref=env.evidence_ref(self.subsystem, collection,
                                          item["id"]),
            host=HOST_BLOCK)

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        if collection == "clients":
            if object_id == "client:transmission" and self.transmission_url:
                payload: object = {
                    "session": await self._rpc("session-get"),
                    "stats": await self._rpc("session-stats")}
            elif object_id == "client:sabnzbd" and self.sab_url:
                if not self.sab_key:
                    # The row EXISTS (a stated-fault row), so its evidence
                    # must not deny it: the fault is the honest answer.
                    raise RuntimeError(
                        "sabnzbd is configured by URL but"
                        " SE_SABNZBD_API_KEY is missing — there is nothing"
                        " to ask it")
                payload = await self._sab("fullstatus")
            else:
                raise env.UnknownObject(object_id)
        elif collection == "transfers":
            if not object_id.startswith("transfer:"):
                raise env.UnknownObject(object_id)
            client, _, native = object_id[len("transfer:"):].partition("/")
            if client == "transmission" and self.transmission_url:
                payload = await self._rpc("torrent-get",
                                          {"fields": TORRENT_FIELDS})
                torrents = [raw for raw in payload.get("torrents") or []
                            if str(raw.get("hashString") or "").lower() == native]
                if not torrents:
                    raise env.UnknownObject(object_id)
                payload = torrents[0]
            elif client == "sabnzbd" and self.sab_url and self.sab_key:
                queue = (await self._sab("queue")).get("queue") or {}
                slots = [raw for raw in queue.get("slots") or []
                         if raw.get("nzo_id") == native]
                if not slots:
                    raise env.UnknownObject(object_id)
                payload = slots[0]
            else:
                raise env.UnknownObject(object_id)
        else:
            raise env.UnknownCollection(collection)
        return {"object_id": object_id, "captured_at": env.utc_now(),
                "interface": "transmission RPC + sabnzbd JSON API",
                "payload": payload}
