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

import copy
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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


def rel(rel_type: str, direction: str, target_id: str, subsystem: str | None = None) -> dict:
    target: dict[str, Any] = {"id": target_id}
    if subsystem:
        target["subsystem"] = subsystem
    return {"type": rel_type, "direction": direction, "target": target}


def obj_ref(object_id: str, obj_type: str, native_id: str, name: str | None = None) -> dict:
    out = {"id": object_id, "type": obj_type, "native_id": native_id}
    if name:
        out["name"] = name
    return out


def observation(subsystem: str, obj: dict, src: dict, facts: dict,
                opinions: list[dict] | None = None,
                relationships: list[dict] | None = None,
                status: str = "ok", errors: list[str] | None = None,
                evidence_ref: str | None = None) -> dict:
    out: dict[str, Any] = {
        "schema": SCHEMA_OBSERVATION,
        "host": HOST,
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
                    status: str = "ok", errors: list[str] | None = None) -> dict:
    out: dict[str, Any] = {
        "schema": SCHEMA_COLLECTION,
        "host": HOST,
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


def item_summary(object_id: str, obj_type: str, native_id: str, facts: dict,
                 worst_opinion_level: str | None = None, name: str | None = None) -> dict:
    out: dict[str, Any] = {"id": object_id, "type": obj_type, "native_id": native_id, "facts": facts}
    if name:
        out["name"] = name
    if worst_opinion_level:
        out["worst_opinion_level"] = worst_opinion_level
    return out


def apply_fact_filters(items: list[dict], filters: dict[str, str]) -> list[dict]:
    """Generic equality filters: 'type' matches the object type, anything else
    matches the stringified summary fact of that name."""
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
