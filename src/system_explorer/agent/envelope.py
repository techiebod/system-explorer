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
import os
import re
import resource
import socket
import sys
import time
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


def worst_level(opinions: list[dict], healthy: str | None = "ok") -> str | None:
    """Row severity from the object's opinions (collection.schema.json:
    ok = positively healthy, info = neutral, warn/critical mirror the worst
    opinion). `healthy` is the no-opinion value: "ok" when the evaluator
    could vouch for the object, "info" when the deciding fact was absent,
    None to omit the field entirely.

    Moved here from agent.rules in 0.6 (re-exported there, the
    OPINION_LEVELS arrangement in reverse) because item_summary() now
    derives row severity itself, from the same list whose attention subset
    it carries — the one-evaluator rule made structural instead of a
    convention at fifteen call sites."""
    if opinions:
        return max((op["level"] for op in opinions), key=OPINION_LEVELS.index)
    return healthy


def attention(opinions: list[dict]) -> list[dict]:
    """The warn/critical subset a row carries (see item_summary). Info
    opinions stay on the opened object: they are commentary, not attention,
    and ten thousand rows must not pay for them (the /v1/facts economy)."""
    return [op for op in opinions if op["level"] != "info"]

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
    """Bounded, whole-word, credential-scrubbed failure text for a
    capability reason or an error-envelope entry. See system_explorer.text
    for why bounding is central and why scrubbing lives beside it: failure
    text is the one channel that reaches unauthenticated pollers from
    inside an exception handler nobody reviews for secrets."""
    return _text.scrub(_text.one_line(value, limit))


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


# A route hint's closed member set. `subsystem` and `collection` address a
# collection route this agent serves; `fact` names the fact that ORDERS the
# answer there, so a consumer knows what to sort and highlight by; `label` is
# the phrase the link is worded with ("which units are waiting on I/O").
LOOK_MEMBERS = ("subsystem", "collection", "fact", "label")

# The subsystem/collection grammar, the same one observation.schema.json's
# subsystemName declares. Duplicated rather than imported: the schemas are the
# published contract and nothing loads them at runtime.
_ROUTE_NAME = re.compile(r"^[a-z][a-z0-9-]*$")

# ── where an object id can be opened ─────────────────────────────────────
#
# An object id is `<prefix>:<native id>` (SPEC rule 15) and the prefix is the
# only thing a consumer holding a bare id has to go on. The browser used to
# keep its own copy of this map, which was the fourth-copy failure the fact
# dictionary exists to prevent, and it had drifted exactly as predicted: the
# whole application tier was missing, so every app-tier relationship chip
# rendered as dead text.
#
# A LIST, NOT A ROUTE, and that is the substance rather than the shape.
# A prefix is NOT unique — five are claimed twice, and two of those are the
# same object genuinely served by two collections:
#
#   unit    units/units and resources/workloads publish THE SAME IDS. One is
#           the systemd view, the other the cgroup accounting view; neither
#           is a copy of the other and neither is wrong.
#   socket  network/listening and network/port-exposure, likewise — the
#           derived collection reuses the socket's id deliberately, because
#           inventing a second identity for one listening socket would put
#           two rows in the graph where the kernel has one thing.
#   daemon  kea and unbound both run one, on the same host.
#   instance, overview  two subsystems each, for the same reason.
#
# So the FIRST entry is the canonical home — where a bare id opens — and the
# rest are the other places that same object appears. A consumer with more
# context than a bare id (a relationship's own `subsystem`, or the page it is
# already on) should prefer that; the order is the answer for one that has
# nothing. Publishing it as a list is what lets a detail view say "this also
# appears in resources/workloads" without a second table to disagree with.
OBJECT_PREFIXES: dict[str, list[tuple[str, str]]] = {
    "app": [("servarr", "apps")],
    "array": [("storage", "arrays")],
    "block-device": [("storage", "block-devices")],
    "boot": [("system", "boot")],
    "client": [("downloaders", "clients")],
    "container": [("docker", "containers")],
    "daemon": [("kea", "daemon"), ("unbound", "daemon")],
    "dataset": [("storage", "datasets")],
    "destination": [("protection", "destinations")],
    "docker-network": [("docker", "networks")],
    "domain": [("vms", "domains")],
    "entry": [("logs", "journal")],
    "generation": [("nix", "generations")],
    "health": [("servarr", "health")],
    "identity": [("system", "identity")],
    "instance": [("paperless", "instance"), ("bazarr", "instance")],
    "job": [("protection", "jobs")],
    "lease": [("kea", "leases")],
    "library": [("plex", "libraries")],
    "link": [("network", "links")],
    "lookup": [("network", "lookups"), ("storage", "lookups")],
    "mount": [("storage", "mounts")],
    "nft-chain": [("network", "nft-chains")],
    "nft-rule": [("network", "nft-rules")],
    "nft-table": [("network", "nft-tables")],
    "nvme": [("hardware", "nvme")],
    "overview": [("system", "overview"), ("traefik", "overview")],
    "package": [("packages", "packages")],
    "pci": [("hardware", "pci")],
    "platform": [("hardware", "platform")],
    "pool": [("storage", "pools")],
    "request": [("plex", "requests")],
    "reservation": [("kea", "reservations")],
    "resolver": [("network", "resolver")],
    "route": [("network", "routes")],
    "router": [("traefik", "routers")],
    "scsi": [("hardware", "scsi")],
    "self": [("system", "self")],
    "server": [("plex", "server")],
    "service": [("traefik", "services")],
    "session": [("plex", "sessions")],
    "socket": [("network", "listening"), ("network", "port-exposure")],
    "subnet": [("kea", "subnets")],
    "tailscale": [("network", "tailscale")],
    "target": [("protection", "targets")],
    "time": [("system", "time")],
    "transfer": [("downloaders", "transfers")],
    "unit": [("units", "units"), ("resources", "workloads")],
    "usb": [("hardware", "usb")],
    "volume": [("docker", "volumes")],
}


def object_prefixes(served: dict[str, list[str]]) -> dict[str, list[dict]]:
    """The map above, narrowed to what THIS host actually serves.

    A host with no libvirt must not claim it can open `domain:`, because a
    chip that leads to a 404 is worse than one that stayed plain text — the
    reader followed it. `served` is {subsystem: collections}, and a prefix
    whose every home has gone leaves the map entirely rather than lingering
    as an empty list, which reads as "known but currently none".
    """
    out: dict[str, list[dict]] = {}
    for prefix, homes in OBJECT_PREFIXES.items():
        live = [{"subsystem": subsystem, "collection": collection}
                for subsystem, collection in homes
                if collection in served.get(subsystem, ())]
        if live:
            out[prefix] = live
    return out


def _look_entry(key: str, entry: object) -> dict:
    """One validated route hint, normalised and copied.

    Copied because rulebooks declare their hints as module constants and an
    opinion is handed to consumers that may hold it: sharing one dict across
    every opinion a rule ever emits makes a consumer's mutation everyone's.
    """
    if not isinstance(entry, dict):
        raise ValueError(
            f"opinion {key!r} has a look entry of type "
            f"{type(entry).__name__}; entries are route hints "
            f"({', '.join(LOOK_MEMBERS)})")
    unknown = sorted(set(entry) - set(LOOK_MEMBERS))
    if unknown:
        raise ValueError(
            f"opinion {key!r} look entry carries {unknown}; the member set is "
            f"closed at {LOOK_MEMBERS}")
    out: dict[str, Any] = {}
    for member in ("subsystem", "collection"):
        value = entry.get(member)
        if not isinstance(value, str) or not _ROUTE_NAME.match(value):
            raise ValueError(
                f"opinion {key!r} look entry has {member}={value!r}; a route "
                "name matches ^[a-z][a-z0-9-]*$")
        out[member] = value
    fact = entry.get("fact")
    if fact is not None:
        if not isinstance(fact, str) or not fact:
            raise ValueError(
                f"opinion {key!r} look entry has fact={fact!r}; a fact name is "
                "a non-empty string, or absent when no single fact orders the "
                "answer")
        out["fact"] = fact
    label = entry.get("label")
    if not isinstance(label, str) or not label.strip():
        raise ValueError(
            f"opinion {key!r} look entry has label={label!r}; the link needs "
            "the human phrase a reader clicks")
    out["label"] = label
    return out


def opinion(key: str, level: str, message: str, evidence: list[str],
            look: list[dict] | None = None) -> dict:
    """One opinion. `evidence` cites facts on THIS object; `look` points
    somewhere else — the next place to look, when one exists.

    `look` closes the gap between a condition and a next step. A host PSI
    warning states that every non-idle task was waiting on I/O and offers
    nowhere to go, even though units/units already carries the same kernel
    accounting per unit. Each entry is {subsystem, collection, fact?, label}:
    the route, the fact that ORDERS the answer there, and the phrase to word
    the link with. Pure data — the agent resolves none of it, and a consumer
    that does not understand `look` renders exactly what it rendered before.

    Deliberately NOT filters. apply_fact_filters speaks string equality,
    negation and prefix, so the predicate this link actually wants —
    "PsiIoFullAvg60 greater than zero" — is inexpressible: `!0` compares
    against the STRINGIFIED fact, and a row carrying 0.0 stringifies to "0.0",
    which is not equal to "0" and therefore survives the negation. A filter
    that silently keeps every row is worse than no filter, because the link
    would claim a narrowing it did not perform. Ordering is the honest
    primitive here — it puts the answer at the top without asserting a
    threshold — and a `filters` member belongs on this shape only once the
    filter language can express a numeric comparison.

    Shape is validated HERE, the way the level enum is: a malformed hint fails
    at the rule that wrote it. That is safe because hints are literals in the
    rulebook, never interpolated from fact values, so every one of them is
    reached by the conformance cases and the raise lands in CI. Whether the
    route EXISTS is deliberately not checked here — the envelope cannot import
    the adapter registry, and main.py turns an adapter exception into an error
    envelope, so raising on a dead link would blank a whole page over a bad
    link. That check is a conformance test, exactly as rel() leaves proving
    its target id resolves to one.
    """
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
    out: dict[str, Any] = {"key": key, "level": level, "message": message,
                           "evidence": evidence}
    if look:
        out["look"] = [_look_entry(key, entry) for entry in look]
    return out


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
        # Scrubbed at the boundary, wholesale: the fifteen call sites that
        # interpolate exceptions inherit it unchanged, and the sixteenth
        # cannot forget (SPEC section 11, rule 10 extended — failure text
        # is a credential channel).
        out["errors"] = [_text.scrub(_text.one_line(entry))
                         for entry in (errors or ["unspecified acquisition failure"])]
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
        # Scrubbed at the boundary, wholesale: the fifteen call sites that
        # interpolate exceptions inherit it unchanged, and the sixteenth
        # cannot forget (SPEC section 11, rule 10 extended — failure text
        # is a credential channel).
        out["errors"] = [_text.scrub(_text.one_line(entry))
                         for entry in (errors or ["unspecified acquisition failure"])]
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
                 opinions: list[dict] | None = None, healthy: str | None = "ok",
                 name: str | None = None) -> dict:
    """One collection row. The caller hands over the row's evaluated
    opinions and severity is derived HERE — worst_opinion_level and the
    carried warn/critical subset come from the same list in the same call,
    so the red dot and its explanation cannot disagree (rule 14, made
    structural: the summary surface used to compute worst_level() beside
    this call at fifteen sites, each one a place the two could drift).
    The carried subset is what /v1/findings sweeps and what a consumer
    needs to explain a red row without a per-object round trip.
    `opinions=None` (an inventory row with no evaluator — packages) makes
    no severity claim at all."""
    out: dict[str, Any] = {"id": object_id, "type": obj_type, "native_id": native_id, "facts": facts}
    if name:
        out["name"] = name
    if opinions is not None:
        worst = worst_level(opinions, healthy=healthy)
        if worst:
            out["worst_opinion_level"] = worst
        subset = attention(opinions)
        if subset:
            out["opinions"] = subset
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
            # Operators belong on the VALUE (?ActiveState=!failed); a key
            # wearing one is provably not a fact name — no emitted fact
            # starts with "!" or ends with "*" — so strip them before
            # folding and the predictable misplacement finds its twin.
            folded = _fold(key.removeprefix("!").removesuffix("*"))
            twin = next((k for k in sorted(carried) if _fold(k) == folded), None)
            if twin:
                raise UnknownFilterKey(
                    f"no fact named {key!r} here, but {twin!r} is carried — "
                    "fact names are matched exactly")

    def matches(actual: object, wanted: str) -> bool:
        # Two operators beyond equality, both from live curation demand
        # (2026-08-13: a view needed "mounts not under /run" and equality
        # could not say it): a leading "!" negates, a trailing "*" prefix-
        # matches, and they compose ("!/run*"). An absent fact matches
        # only negated filters — absence is not equal to anything, but it
        # is honestly not-equal to everything.
        negate = wanted.startswith("!")
        pattern = wanted[1:] if negate else wanted
        if actual is None:
            return negate
        text_value = str(actual)
        hit = (text_value.startswith(pattern[:-1]) if pattern.endswith("*")
               else text_value == pattern)
        return hit != negate

    def keep(item: dict) -> bool:
        for key, wanted in filters.items():
            actual = item["type"] if key == "type" else item["facts"].get(key)
            if not matches(actual, wanted):
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


# ── what this product costs the host it observes ─────────────────────────
#
# Added 0.6, after the estate measured the agent from OUTSIDE and found that
# answering one /v1/findings sweep cost 2.4 seconds of CPU on a one-core
# host — three quarters of that agent's entire standing bill. The number was
# correct and nothing in the product could have produced it: an observer of
# Linux that could not observe itself, which is exactly the gap it exists to
# close everywhere else.
#
# WHAT CAN HONESTLY BE ATTRIBUTED, and it is not the same in both cases:
#
#   A single-collection request runs one adapter and nothing else, so the
#   process CPU burned across it IS that collection's cost. Exact.
#
#   A sweep runs every subsystem CONCURRENTLY. Process CPU across it is the
#   whole sweep's and cannot be split; per-subsystem wall times overlap and
#   sum to more than the sweep took. So the sweep reports one CPU figure for
#   itself and wall per subsystem, said in those words — a per-adapter CPU
#   column would be a number nobody can produce, which is worse than none.
#
# Child CPU is separate because most of what an adapter costs is not this
# process at all: `zpool status -j`, `nft -j` and `lsblk` burn their own,
# charged to the cgroup and invisible in this process's rusage. Splitting
# them says whether a slow collection is our arithmetic or somebody else's
# program, which is the first question anyone asks.
#
# The overhead is two perf_counter reads and two getrusage syscalls per
# request — microseconds against acquisitions measured in seconds. It is
# never sampled, never aggregated in memory, and holds no state: each
# response reports its own cost and nothing else's.

class Stopwatch:
    """Wall, this process's CPU, and its children's, across one span."""

    __slots__ = ("_wall", "_cpu", "_child", "elapsed")

    def __enter__(self) -> Stopwatch:
        self._wall = time.perf_counter()
        self._cpu, self._child = _cpu_seconds()
        self.elapsed: dict[str, float] = {}
        return self

    def __exit__(self, *_exc) -> None:
        wall = time.perf_counter() - self._wall
        cpu, child = _cpu_seconds()
        self.elapsed = {
            "wall_ms": round(wall * 1000, 1),
            "cpu_ms": round((cpu - self._cpu) * 1000, 1),
            "child_cpu_ms": round((child - self._child) * 1000, 1),
        }


def _cpu_seconds() -> tuple[float, float]:
    """(this process's CPU, its reaped children's), both user+system.

    getrusage counts a child only once it has been REAPED, which is exactly
    when subprocess.run returns — so an adapter's external commands are all
    accounted for by the time its span closes. A command still running would
    be missed, and nothing here starts one it does not wait for.
    """
    me = resource.getrusage(resource.RUSAGE_SELF)
    kids = resource.getrusage(resource.RUSAGE_CHILDREN)
    return (me.ru_utime + me.ru_stime, kids.ru_utime + kids.ru_stime)


# RSS the moment the process finished importing and before it served
# anything — the baseline that makes the question answerable. Beacon's agent
# is the largest process on a one-core cloud host at ~88 MB, and the first
# thing anyone needs to know is how much of that is Python having been
# started at all. Measured on a developer machine: 62 MiB before a single
# request, 26 MiB of it FastAPI's import graph alone and ~16 MiB this
# product's own modules. Without the baseline the answer is a shell session;
# with it the row says "grown 26 MB since start" and the question is over.
START_RSS: dict[str, int] = {}
# Set by main.py once the registry is built — envelope cannot import
# adapters without a cycle, and the count predicts the agent's cost
# better than any property of the host does.
ADAPTER_COUNT = 0
START_MONOTONIC = time.monotonic()


def record_start_memory() -> None:
    """Called once the imports are done and before the first request."""
    START_RSS.update(self_memory())


def self_memory() -> dict:
    """This process's own memory, as the kernel reports it.

    Current resident size is read from /proc/self/statm because getrusage
    offers only the PEAK, and a peak from an hour ago answers a different
    question from "what is it holding now" — the one an operator watching a
    small host actually asks. Where there is no procfs the peak is still
    stated, under its own name, rather than being passed off as current.

    Deliberately NOT broken down by adapter. Python has no per-object
    ownership the runtime can attribute, and a plausible-looking split would
    be invention — the honest per-adapter answer is the cost figures above,
    which are measured.
    """
    out: dict[str, int] = {}
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if peak:
        # Linux reports kibibytes, macOS bytes. The platform this runs on in
        # production is the one that needs scaling; the other is a developer
        # machine and being 1024x wrong there would still be noticed.
        out["peak_rss_bytes"] = peak * 1024 if sys.platform.startswith("linux") else peak
    try:
        with open("/proc/self/statm", encoding="utf-8") as handle:
            resident = int(handle.read().split()[1])
        out["rss_bytes"] = resident * os.sysconf("SC_PAGE_SIZE")
    except (OSError, IndexError, ValueError):
        pass
    return out
