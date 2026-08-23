"""paperless subsystem: the document archive, observed as an application.

The app-explorer pattern's first shipped instance (roadmap Phase 5): the
subject is an application answering its own REST API, every envelope
carries the composite locator's `app` member (SPEC rule 15), and
configuration is deployment receipts — SE_PAPERLESS_URL and
SE_PAPERLESS_TOKEN, no defaults, declined with the missing name when
absent. The intended deployment is an app INSTANCE
(services.systemExplorer.instances): credentials via EnvironmentFile,
no host grants, which is the credential-isolation design running for
real for the first time.

Why paperless: two incidents in one week, same shape — a healthy
container row over a broken archive (a secret drift emptied the library
38 -> 0; then a diverged data path with no snapshots). The wrapper is not
the app, and DocumentCount is the fact both incidents needed surfaced.

This is also the product's first CREDENTIALED adapter, so the posture is
stated here once for everything that follows it: the token is sent as an
Authorization header, NEVER in a URL (query strings are where the
envelope scrubber assumes credentials hide, and it strips them from all
failure text); the env names end in _TOKEN/_URL deliberately, because
text.scrub() substitutes secret VALUES by env-name suffix, so even a
stringified exception carrying the token would leave the process as
[redacted:$SE_PAPERLESS_TOKEN]. A token that could not survive a header
(non-ASCII or control bytes — the classic newline paste artifact) is
refused at construction and becomes a capability decline naming the
problem without the value: handing it to the HTTP client would either
crash the process at import or leak the escaped value into failure text,
and both are worse than an honest decline. Evidence redacts the status
document's connection URLs as defence-in-depth: current releases emit
database.url as a bare database name and a credential-stripped
redis_url (raw userinfo shipped only in early 2.6-era releases), but
the scrub drops userinfo and query strings regardless of version — the
values go while the shape stays.

The credential the alarm depends on, stated plainly because getting it
wrong manufactures the exact incident this subsystem exists to catch:
/api/statistics/ counts are PERMISSION-SCOPED to the requesting user
(owned + unowned + explicitly shared documents). A dedicated
low-privilege user sees 0 documents in an archive of 38, and nothing in
the response says so. The token must belong to the archive-owning user,
a superuser, or (newer releases) a user granted
paperless.view_global_statistics. /api/status/ is additionally
admin-only; a token without that narrows the observation to the
inventory numbers — component checks land as StatusUnobservable with
the HTTP reason and their rules simply do not evaluate (rule 7).
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit, urlunsplit

import httpx

from .. import envelope as env
from ..rules.paperless import instance_opinions

STATISTICS_PATH = "/api/statistics/"
STATUS_PATH = "/api/status/"

REFERENCE = [
    "curl -H 'Authorization: Token <token>' <url>/api/statistics/",
    "curl -H 'Authorization: Token <token>' <url>/api/status/",
]

HOST_BLOCK = env.host_block(app="paperless")

# The status document's connection-URL positions, scrubbed as
# defence-in-depth (see module docstring: current releases already emit
# them credential-free; early ones did not, and the next version is not
# this code's to predict).
_CREDENTIAL_URLS = (("database", "url"), ("tasks", "redis_url"))


def _redact_url_credentials(payload: dict) -> tuple[dict, list[str]]:
    """Strip userinfo AND query strings from the status document's
    connection URLs, keeping scheme and host (the diagnostically useful
    halves) — the same two credential positions text.scrub() strips from
    failure text, applied to the one evidence payload that carries URLs.
    Returns the copy and the paths actually altered: redaction that hides
    its own existence would invert the provenance contract."""
    out = {key: (dict(value) if isinstance(value, dict) else value)
           for key, value in payload.items()}
    paths: list[str] = []
    for section, member in _CREDENTIAL_URLS:
        holder = out.get(section)
        if not isinstance(holder, dict):
            continue
        value = holder.get(member)
        if not isinstance(value, str):
            continue
        parts = urlsplit(value)
        changed = False
        if "@" in parts.netloc:
            host = parts.netloc.rpartition("@")[2]
            parts = parts._replace(netloc=f"{env.REDACTED}@{host}")
            changed = True
        if parts.query:
            parts = parts._replace(query="query-stripped")
            changed = True
        if changed:
            holder[member] = urlunsplit(parts)
            paths.append(f"{section}.{member}")
    return out, paths


def statistics_facts(raw: dict) -> dict:
    """The archive's inventory numbers, present only when the API stated
    them — a paperless old enough to lack a member says nothing."""
    facts: dict = {}
    for fact, member in (("DocumentCount", "documents_total"),
                         ("InboxCount", "documents_inbox"),
                         ("TagCount", "tag_count"),
                         ("CorrespondentCount", "correspondent_count"),
                         ("DocumentTypeCount", "document_type_count")):
        value = raw.get(member)
        if isinstance(value, int):
            facts[fact] = value
    return facts


def status_facts(raw: dict) -> dict:
    """The app's own health checks, native status words kept."""
    facts: dict = {}
    if raw.get("pngx_version"):
        facts["PngxVersion"] = raw["pngx_version"]
    storage = raw.get("storage") or {}
    for fact, member in (("StorageTotalBytes", "total"),
                         ("StorageAvailableBytes", "available")):
        if isinstance(storage.get(member), int):
            facts[fact] = storage[member]
    # Minted on both implementations because the storage rule names one
    # fact and a threshold, and the closed condition vocabulary cannot do
    # the arithmetic (register row 8's residue). Only where the app states
    # both halves.
    total = facts.get("StorageTotalBytes")
    available = facts.get("StorageAvailableBytes")
    if isinstance(total, int) and isinstance(available, int) and total > 0:
        facts["StorageUsedPercent"] = round((total - available) * 100 / total)
    database = raw.get("database") or {}
    if database.get("status"):
        facts["DatabaseStatus"] = database["status"]
        if database.get("error"):
            facts["DatabaseError"] = env.reason(database["error"])
    tasks = raw.get("tasks") or {}
    for status_fact, error_fact, member in (
            ("RedisStatus", "RedisError", "redis_status"),
            ("CeleryStatus", "CeleryError", "celery_status"),
            ("IndexStatus", "IndexError", "index_status"),
            ("ClassifierStatus", "ClassifierError", "classifier_status")):
        if tasks.get(member):
            facts[status_fact] = tasks[member]
            error = tasks.get(member.replace("_status", "_error"))
            if error:
                facts[error_fact] = env.reason(error)
    return facts


_GLOSSARY = {
    "DocumentCount": "How many documents the TOKEN'S USER can see — the archive total only when the token has global visibility (owner, superuser, or the view_global_statistics grant), because the statistics endpoint scopes every count by permission. Zero is the emptied-library shape this subsystem exists to catch, judged critical.",
    "InboxCount": "Documents carrying the inbox tag — ingested but not yet filed.",
    "TagCount": "How many tags the instance defines.",
    "CorrespondentCount": "How many correspondents the instance defines.",
    "DocumentTypeCount": "How many document types the instance defines.",
    "PngxVersion": "The paperless-ngx release answering the API.",
    "StorageTotalBytes": "Size of the media volume as the app sees it from inside its own mount, which can differ from any host row when a bind has diverged.",
    "StorageAvailableBytes": "Free space on that same media volume, from the same vantage.",
    "StorageUsedPercent": "How full the media volume is, from the two figures the app itself states — present only where it states both, because a percentage without a stated denominator would be invented.",
    "DatabaseStatus": "The app's own database connectivity check; anything but OK means the archive cannot be trusted to answer.",
    "DatabaseError": "What the database check said when it failed, bounded.",
    "RedisStatus": "The app's broker connectivity check; ingestion and every background task stop without it.",
    "RedisError": "What the broker check said when it failed, bounded.",
    "CeleryStatus": "Whether the background worker answers; documents queue but do not process while it is down.",
    "CeleryError": "What the worker check said when it failed, bounded.",
    "IndexStatus": "Whether the search index passes the app's check; search degrades while the archive itself stays intact.",
    "IndexError": "What the index check said when it failed, bounded.",
    "ClassifierStatus": "Whether the auto-tagging classifier loads; WARNING on an instance with too little training data is the app being honest, not broken.",
    "ClassifierError": "What the classifier check said when it failed, bounded.",
    "StatusUnobservable": "Why the component checks could not be read when they could not — /api/status/ is admin-only, so a read-only token narrows this observation to the inventory numbers.",
}


class Adapter:
    subsystem = "paperless"
    # The locator every envelope from this subsystem carries — including
    # the ones MAIN.PY builds on the adapter's behalf (declines, error
    # envelopes, evidence stamps). Without this, a declined app collection
    # would claim the host-native locator and rule 15's identity would
    # differ between a healthy answer and its own error shape.
    host_block = HOST_BLOCK

    def __init__(self) -> None:
        self.url = (os.environ.get("SE_PAPERLESS_URL") or "").rstrip("/") or None
        # What capability() may echo: the configured URL with any userinfo
        # removed. An operator routing through a basic-auth proxy puts a
        # credential INSIDE the URL, and /v1/capabilities serves every
        # unauthenticated poller — the client keeps the verbatim URL
        # (httpx derives Basic auth from userinfo at request time), the
        # surface never does.
        self.display_url = self.url
        if self.url and "@" in urlsplit(self.url).netloc:
            parts = urlsplit(self.url)
            self.display_url = urlunsplit(parts._replace(
                netloc=parts.netloc.rpartition("@")[2]))
        token = os.environ.get("SE_PAPERLESS_TOKEN") or None
        # A token that cannot survive an HTTP header is refused HERE: httpx
        # raises on non-ASCII header values at client construction (which
        # would crash the whole agent at import), and h11's escaped
        # rendering of control bytes would leak the value into failure
        # text in a form the exact-value scrub cannot match. The decline
        # names the shape of the problem, never the value.
        self._token_problem: str | None = None
        if token is not None and not (token.isascii() and token.isprintable()):
            self._token_problem = (
                "SE_PAPERLESS_TOKEN contains control or non-ASCII"
                " characters (a newline paste artifact is the classic) —"
                " refusing to send it in a header")
            token = None
        self._client = httpx.AsyncClient(
            timeout=10.0,
            headers={"Authorization": f"Token {token}"} if token else {})
        self._token_set = token is not None

    def collections(self) -> list[str]:
        return ["instance"]

    async def capability(self) -> dict:
        if not self.url:
            return {"available": False, "reason": (
                "SE_PAPERLESS_URL is not configured — this process observes"
                " no paperless (the intended home is an app instance with an"
                " EnvironmentFile carrying SE_PAPERLESS_URL and"
                " SE_PAPERLESS_TOKEN)")}
        if self._token_problem:
            return {"available": False, "reason": self._token_problem}
        if not self._token_set:
            return {"available": False, "reason": (
                "SE_PAPERLESS_TOKEN is not configured — the paperless API"
                " answers nothing without one, so guessing would only"
                " manufacture 401s")}
        return {"available": True, "collections": self.collections(),
                "url": self.display_url}

    def fact_glossary(self, collection: str) -> dict:
        return _GLOSSARY if collection == "instance" else {}

    def _source(self) -> dict:
        return env.source("paperless-api", "paperless-ngx REST API",
                          REFERENCE,
                          method=f"GET {STATISTICS_PATH} + {STATUS_PATH}")

    async def _get(self, path: str) -> dict:
        response = await self._client.get(f"{self.url}{path}")
        response.raise_for_status()
        return response.json()

    async def _instance_items(self) -> list[dict]:
        # Statistics are required — an instance that cannot state its
        # inventory is an acquisition failure, not a quiet row. The
        # component checks are optional by design (admin-only endpoint).
        facts = statistics_facts(await self._get(STATISTICS_PATH))
        try:
            facts.update(status_facts(await self._get(STATUS_PATH)))
        except Exception as exc:  # noqa: BLE001 - narrowed, not broken (rule 7)
            facts["StatusUnobservable"] = env.reason(
                f"{type(exc).__name__}: {exc}")
        return [env.item_summary(
            "instance:paperless", "paperless-instance", "paperless", facts,
            opinions=instance_opinions(facts),
            healthy="ok" if "StatusUnobservable" not in facts else "info")]

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
        if object_id != "instance:paperless":
            raise env.UnknownObject(object_id)
        payload: dict = {"statistics": await self._get(STATISTICS_PATH)}
        redacted: list[str] = []
        try:
            status, paths = _redact_url_credentials(await self._get(STATUS_PATH))
        except Exception as exc:  # noqa: BLE001 - narrowed, not broken
            payload["status_error"] = env.reason(f"{type(exc).__name__}: {exc}")
        else:
            payload["status"] = status
            redacted = [f"status.{path}" for path in paths]
        out = {"object_id": object_id, "captured_at": env.utc_now(),
               "interface": "paperless-ngx REST API",
               "method": f"GET {STATISTICS_PATH} + {STATUS_PATH}",
               "payload": payload}
        if redacted:
            out["redacted"] = redacted
        return out
