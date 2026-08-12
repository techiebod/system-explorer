"""Observation and collection envelope construction.

The JSON Schemas under ../schema are authoritative; these builders exist so
adapters cannot accidentally emit a shape the conformance suite would reject.
Key invariants enforced here rather than left to discipline:

- errors are present exactly when status != ok;
- opinions always cite evidence (the builder requires it);
- opinion levels come from the closed three-value enum;
- timestamps are UTC with a Z suffix.
"""

from __future__ import annotations

import asyncio
import copy
import functools
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .. import text as _text

SCHEMA_OBSERVATION = "se.observation/1"
SCHEMA_COLLECTION = "se.collection/1"

# The severity vocabulary, lowest to highest — the ordering IS the ranking
# function. It lives here rather than in the rulebook that reads it because
# every rules module imports this one, so the reverse direction is a cycle;
# agent.rules re-exports it as the rulebook's own vocabulary.
OPINION_LEVELS = ("info", "warn", "critical")

DEFAULT_LIMIT = 500
MAX_LIMIT = 1000

# systemd uses this for "unset" on unsigned 64-bit properties.
UNSET_U64 = 2**64 - 1


class UnknownCollection(KeyError):
    """Deliberate 404: the adapter does not expose this collection. The HTTP
    layer maps only this (never bare KeyError) to 404, so an incidental
    KeyError from a data-shape surprise stays an error envelope instead of
    masquerading as an unknown route."""


class UnknownObject(LookupError):
    """Deliberate 404: no object with this id in the collection. Same
    contract as UnknownCollection for LookupError."""


def _machine_id() -> str:
    try:
        return Path("/etc/machine-id").read_text().strip()
    except OSError:
        return "0" * 32


HOST = {"machine_id": _machine_id(), "hostname": socket.gethostname().split(".")[0]}


def reason(value: object, limit: int = _text.MAX_LENGTH) -> str:
    """Bounded, whole-word failure text for a capability reason or an
    error-envelope entry. See system_explorer.text for why this is central."""
    return _text.one_line(value, limit)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def usec_to_iso(usec: Any) -> str | None:
    """systemd realtime timestamps are microseconds since the epoch."""
    if not isinstance(usec, int) or usec in (0, UNSET_U64):
        return None
    return datetime.fromtimestamp(usec / 1e6, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def norm_u64(value: Any) -> Any:
    return None if value == UNSET_U64 else value


def source(adapter: str, interface: str, reference_commands: list[str],
           method: str | None = None, notes: list[str] | None = None) -> dict:
    out: dict[str, Any] = {
        "adapter": adapter,
        "interface": interface,
        "reference_commands": reference_commands,
    }
    if method:
        out["method"] = method
    if notes:
        out["notes"] = notes
    return out


def opinion(key: str, level: str, message: str, evidence: list[str]) -> dict:
    if not evidence:
        raise ValueError(f"opinion {key!r} must cite evidence (SPEC section 2, rule 3)")
    if level not in OPINION_LEVELS:
        # Checked here so a typo fails at the rule that wrote it. Otherwise it
        # reaches the schema enum on the detail path, or explodes far away in
        # worst_level's max(key=OPINION_LEVELS.index) on the row path — and a
        # consumer that cannot rank a level declines to colour it, so an
        # invented level is silently invisible rather than loud.
        raise ValueError(
            f"opinion {key!r} has level {level!r}; the enum is closed at "
            f"{OPINION_LEVELS} (SPEC section 5.1, rule 6)"
        )
    return {"key": key, "level": level, "message": message, "evidence": evidence}


REDACTED = "«redacted»"


def redact_assignments(values: list) -> tuple[list[str], bool]:
    """Replace the value half of every NAME=VALUE entry, keeping the name.

    Names are what make evidence diagnostically useful — "is DATABASE_URL even
    set?" is a real question — and the value is the credential. A token
    carrying no '=' carries no value and stays legible: deny-by-default applies
    to values, not to words.

    Returns the rewritten list and whether anything ACTUALLY changed. That flag
    is the point. Both redactors used to declare a path whenever a watched key
    was present, so every container published `redacted: ["Config.Cmd"]` while
    serving its Cmd verbatim — an envelope claiming to withhold what it served
    in full, which is the provenance contract inverted rather than upheld.

    Coerces through str() before testing, because the test and the operation
    disagreeing on type is how a bytes element turned the evidence route into
    a 500.
    """
    out: list[str] = []
    for value in values:
        text = str(value)
        name, separator, _ = text.partition("=")
        out.append(f"{name}={REDACTED}" if separator else text)
    return out, out != [str(value) for value in values]


def redact_list_properties(payload: dict, keys: tuple[str, ...]) -> tuple[dict, list[str]]:
    """Redact NAME=VALUE list properties in a D-Bus GetAll payload, which is
    keyed by interface. Returns (copy, the paths where something was withheld).

    Shared because the exposure was: units redacted a service's Environment=
    while system served org.freedesktop.systemd1.Manager.Environment — the
    manager-wide block passed to every executed process — from the same
    unauthenticated API. One redactor, so the next interface carrying the same
    property cannot be missed the same way.
    """
    out = copy.deepcopy(payload)
    paths: list[str] = []
    for interface, properties in out.items():
        if not isinstance(properties, dict):
            continue
        for key in keys:
            value = properties.get(key)
            if not isinstance(value, list) or not value:
                continue
            properties[key], changed = redact_assignments(value)
            if changed:
                paths.append(f"{interface}.{key}")
    return out, paths


def rel(rel_type: str, direction: str, target_id: str, subsystem: str | None = None,
        container: str | None = None, app: str | None = None) -> dict:
    """A typed edge. container/app scope the TARGET (rule 15's locator):
    an app-scoped object naming a host-scoped one omits them, a host-scoped
    object naming an app-scoped one carries them — the cross-locator edge a
    cross-app trace walks. Absent means host-native, like everywhere."""
    target: dict[str, Any] = {"id": target_id}
    if subsystem:
        target["subsystem"] = subsystem
    if container:
        target["container"] = container
    if app:
        target["app"] = app
    return {"type": rel_type, "direction": direction, "target": target}


def host_block(container: str | None = None, app: str | None = None) -> dict:
    """The envelope's host member, optionally narrowed by the composite
    locator (SPEC rule 15, decided 0.6): same machine identity, plus which
    container and which application instance the observing process fronts.
    Absent members mean host-native — never a zero value, because an
    invented identity is worse than an admitted absence. Host-scoped
    adapters never call this; they get plain HOST by default."""
    if not container and not app:
        return HOST
    out = dict(HOST)
    if container:
        out["container"] = container
    if app:
        out["app"] = app
    return out


def obj_ref(object_id: str, obj_type: str, native_id: str, name: str | None = None) -> dict:
    out = {"id": object_id, "type": obj_type, "native_id": native_id}
    if name:
        out["name"] = name
    return out


def observation(subsystem: str, obj: dict, src: dict, facts: dict,
                opinions: list[dict] | None = None,
                relationships: list[dict] | None = None,
                status: str = "ok", errors: list[str] | None = None,
                evidence_ref: str | None = None,
                host: dict | None = None) -> dict:
    out: dict[str, Any] = {
        "schema": SCHEMA_OBSERVATION,
        "host": host or HOST,
        "subsystem": subsystem,
        "object": obj,
        "observed_at": utc_now(),
        "status": status,
        "source": src,
        "facts": facts,
    }
    if status != "ok":
        out["errors"] = errors or ["unspecified acquisition failure"]
    if opinions:
        out["opinions"] = opinions
    if relationships:
        out["relationships"] = relationships
    if evidence_ref:
        out["evidence_ref"] = evidence_ref
    return out


def collection_page(subsystem: str, collection: str, src: dict, items: list[dict],
                    applied_limit: int, next_cursor: str | None,
                    requested_limit: int | None = None, total: int | None = None,
                    filters: dict[str, str] | None = None,
                    status: str = "ok", errors: list[str] | None = None,
                    host: dict | None = None) -> dict:
    out: dict[str, Any] = {
        "schema": SCHEMA_COLLECTION,
        "host": host or HOST,
        "subsystem": subsystem,
        "collection": collection,
        "observed_at": utc_now(),
        "status": status,
        "source": src,
        "applied_limit": applied_limit,
        "next_cursor": next_cursor,
        "items": items,
    }
    if status != "ok":
        out["errors"] = errors or ["unspecified acquisition failure"]
    if requested_limit is not None:
        out["requested_limit"] = requested_limit
    if total is not None:
        out["total"] = total
    if filters:
        out["filters"] = filters
    return out


def single_flight(method):
    """Concurrent identical acquisitions share one in-flight result.

    Coalescing, NOT caching — nothing survives the flight, so rule 4 (no
    capability or observation carried between requests) stays intact: the
    next caller after the flight lands starts a fresh acquisition. What this
    removes is the pile-up: the UI re-polls a collection every 15 s while
    `zpool status -j` carries a 15 s subprocess timeout and no route timeout
    exists, so on a degraded pool — where acquisition is slowest and the
    operator is most likely to be watching — every poll started another full
    acquisition beside the ones still running, on an endpoint that needs no
    authentication. Keyed per (instance, args); the shared task is shielded
    from any single waiter's cancellation, so a browser navigating away does
    not kill the acquisition three other callers are awaiting. If the
    creating waiter is cancelled the flight is unregistered while the
    orphaned task completes harmlessly — a new caller then starts its own
    flight, which costs one duplicate acquisition and retains nothing.
    """
    flights: dict = {}

    @functools.wraps(method)
    async def wrapper(self, *args):
        key = (id(self), args)
        existing = flights.get(key)
        if existing is not None:
            return await asyncio.shield(existing)
        task = asyncio.ensure_future(method(self, *args))
        flights[key] = task
        try:
            return await asyncio.shield(task)
        finally:
            flights.pop(key, None)
    return wrapper


def evidence_ref(subsystem: str, collection: str, object_id: str) -> str:
    """The one place an evidence URL is spelled.

    /v1/evidence/<subsystem>/<collection>/<id>, prefix-first deliberately: the
    old form appended /evidence to the object path, and because the object id
    is a {path} route parameter, any object whose native id itself ended in
    /evidence was unreachable — the request answered with its parent's
    evidence instead of the object (measured live, 2026-08-12: a mount named
    <target>/evidence would have; dataset and route ids carry slashes too).
    A prefix the id grammar cannot produce ends the ambiguity for every
    current and future id shape, which is why this is a function and not
    eighteen f-strings.

    The id is percent-encoded HERE, `:` and `/` preserved — the same rule as
    the MCP client's _idpath and the UI's idPath. The ref is followed
    verbatim by both consumers, so the emitter owns the encoding: an
    unencoded `#` in a mount or dataset id would be cut off as a URL
    fragment by the browser, silently fetching a DIFFERENT object's
    evidence with HTTP 200 — the parent's-evidence failure this helper was
    written to end, arriving through the other door (cross-file review,
    2026-08-12).
    """
    return f"/v1/evidence/{subsystem}/{collection}/{quote(object_id, safe=':/')}"


def item_summary(object_id: str, obj_type: str, native_id: str, facts: dict,
                 worst_opinion_level: str | None = None, name: str | None = None) -> dict:
    out: dict[str, Any] = {"id": object_id, "type": obj_type, "native_id": native_id, "facts": facts}
    if name:
        out["name"] = name
    if worst_opinion_level:
        out["worst_opinion_level"] = worst_opinion_level
    return out


class UnknownFilterKey(ValueError):
    """A filter key that is a near-miss of a fact the collection carries."""


def _fold(key: str) -> str:
    # The near-miss equivalence: case and underscores. `activestate`,
    # `ACTIVESTATE` and `active_state` all fold to what `ActiveState` folds
    # to — the guesses a consumer typing from memory actually makes.
    return key.lower().replace("_", "")


def apply_fact_filters(items: list[dict], filters: dict[str, str]) -> list[dict]:
    """Generic equality filters: 'type' matches the object type, anything else
    matches the stringified summary fact of that name.

    A key that is a NEAR-MISS of a carried fact is refused with the real
    name: `?activestate=failed` and `?ActiveState=failed` used to return
    byte-identical `status ok, total 0` envelopes, so a mistyped question was
    indistinguishable from a healthy empty answer — rule 7's exact lie, and
    it lands hardest on the MCP consumer, which cannot glance at a column
    header to notice its own typo.

    Refusal stops at provable near-misses, deliberately. The fact vocabulary
    is OPEN — the glossary is partial by design, and rule 7 makes omission a
    legitimate shape for any fact — so "no item carries this key right now"
    is a statement about the moment, not about the vocabulary:
    `?RuntimeSynthesised=True` on a host with no synthesised mounts, or
    `?IPAddresses=…` while every domain is off, are correct queries whose
    honest answer is the empty page. Refusing them would make the same query
    flip between ok and error as host state drifts (three independent review
    passes converged on this before the first version shipped). A typo with
    no near-miss therefore also gets the empty page: on an open vocabulary
    the two cases cannot be told apart, and inventing an error would claim
    knowledge the agent does not have.
    """
    if items and filters:
        carried: set[str] = {"type"}
        for item in items:
            carried.update(item["facts"].keys())
        for key in filters:
            if key in carried:
                continue
            folded = _fold(key)
            twin = next((k for k in sorted(carried) if _fold(k) == folded), None)
            if twin:
                raise UnknownFilterKey(
                    f"no fact named {key!r} here, but {twin!r} is carried — "
                    "fact names are matched exactly")

    def keep(item: dict) -> bool:
        for key, wanted in filters.items():
            actual = item["type"] if key == "type" else item["facts"].get(key)
            if actual is None or str(actual) != wanted:
                return False
        return True
    return [item for item in items if keep(item)]


def paginate(items: list[dict], requested_limit: int | None, cursor: str | None,
             default: int = DEFAULT_LIMIT) -> tuple[list[dict], int, str | None, int]:
    """Offset pagination over a fully materialised item list.

    Returns (page, applied_limit, next_cursor, total). The cursor is an
    opaque stringified offset — explicit, per SPEC section 6: a client never
    has to infer truncation.
    """
    applied = min(requested_limit or default, MAX_LIMIT)
    offset = 0
    if cursor:
        try:
            offset = max(0, int(cursor))
        except ValueError:
            offset = 0
    page = items[offset:offset + applied]
    next_cursor = str(offset + applied) if offset + applied < len(items) else None
    return page, applied, next_cursor, len(items)
