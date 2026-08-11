"""System Explorer host agent — HTTP surface.

Routes are the SPEC section 6 table, nothing more. Adapter failures become
error envelopes with HTTP 200, because errors are observations; only unknown
routes and unknown objects are HTTP errors.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
from pathlib import Path

import anyio
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __version__
from ..paths import UI_DIR
from . import envelope as env
from . import history
from .adapters import PLANNED, build_adapters

RESERVED_PARAMS = {"limit", "cursor"}

# Surfaced in /health and capabilities so fleet skew across hosts is visible
# from the product (backlog note, 2026-08-09). The literal lives in
# system_explorer/__init__.py, which pyproject.toml and nix/version.nix also
# read — one edit per release, and no way to disagree.
VERSION = __version__

# Snapshot history (SPEC section 10): SQLite under systemd's StateDirectory.
# No STATE_DIRECTORY means history is deliberately off — /v1/changes then
# answers with an error envelope saying so, never a 500. systemd renders
# multiple StateDirectory= entries colon-separated; the first is ours.
_STATE_DIR = os.environ.get("STATE_DIRECTORY", "").split(":")[0]
HISTORY = history.HistoryStore(Path(_STATE_DIR) / "history.db") if _STATE_DIR else None
SNAPSHOT_INTERVAL = float(os.environ.get("SE_SNAPSHOT_INTERVAL_SECONDS", "900"))
SNAPSHOT_RETENTION_DAYS = float(os.environ.get("SE_SNAPSHOT_RETENTION_DAYS", "30"))


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # The snapshot loop is an in-process task, not a systemd timer (SPEC
    # section 10): it needs the adapters anyway, and this way history stops
    # with the service instead of racing its shutdown.
    task = asyncio.create_task(_snapshot_loop()) if HISTORY else None
    yield
    if task:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="System Explorer agent", version=VERSION, docs_url=None, redoc_url=None,
              lifespan=lifespan)
ADAPTERS = build_adapters()

# DNS-rebinding defence. The API is unauthenticated inside its network trust
# boundary (SPEC section 7), but a browser is not bound by that boundary: a
# malicious page can rebind its own hostname to an agent IP and read every
# endpoint. Rejecting unknown Host headers closes that path without breaking
# unauthenticated LAN clients, whose requests carry the address they dialled.
# Comma-separated names/IPs, no ports; unset leaves the check off.
_ALLOWED_HOSTS = [h.strip() for h in os.environ.get("SE_ALLOWED_HOSTS", "").split(",") if h.strip()]
if _ALLOWED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=_ALLOWED_HOSTS)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # The UI builds all DOM via textContent (no HTML sinks — enforced by
    # conformance lint); the CSP is defence in depth for that invariant, and
    # it costs the self-contained static UI nothing.
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'none'")
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

# The operator UI (SPEC section 8): static, self-contained, consuming only
# the same /v1 API agents use. Optional so the API works without it.
if UI_DIR.is_dir():
    app.mount("/ui", StaticFiles(directory=UI_DIR), name="ui")

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(UI_DIR / "index.html")

    @app.middleware("http")
    async def ui_cache_control(request, call_next):
        # no-cache = revalidate every load (ETag/304 keeps it cheap). Without
        # this Safari serves stale bundles across deploys until a manual
        # cache clear.
        response = await call_next(request)
        path = request.url.path
        if path == "/" or path.startswith("/ui"):
            response.headers["Cache-Control"] = "no-cache"
        return response


def _adapter(subsystem: str):
    adapter = ADAPTERS.get(subsystem)
    if adapter is None:
        detail = PLANNED.get(subsystem, f"unknown subsystem: {subsystem}")
        raise HTTPException(status_code=404, detail=detail)
    return adapter


def _query(request: Request) -> tuple[dict, int | None, str | None]:
    params = dict(request.query_params)
    limit = params.pop("limit", None)
    cursor = params.pop("cursor", None)
    try:
        parsed_limit = int(limit) if limit is not None else None
    except ValueError:
        raise HTTPException(status_code=422, detail="limit must be an integer")
    if parsed_limit is not None and parsed_limit < 1:
        raise HTTPException(status_code=422, detail="limit must be >= 1")
    return params, parsed_limit, cursor


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "host": env.HOST, "version": VERSION}


# Where this host's site view lives, if the operator configured one. The agent
# does not discover it and never talks to it: aggregation must never be a
# precondition for observation (SPEC §7, ROADMAP §6), so this is a display
# hint the deployment supplies, not a dependency.
#
# It exists because a whole deployed capability turned out to be invisible. An
# operator running four hosts behind two hubs asked what had happened to the
# host switcher — while browsing an agent directly, where by construction
# there is one host and no switcher. Nothing was broken; nothing said the
# site view existed.
HUB_URL = os.environ.get("SE_HUB_URL") or None
SITE = os.environ.get("SE_SITE") or None


@app.get("/v1/capabilities")
async def capabilities() -> dict:
    subsystems: dict = {}
    for name, adapter in ADAPTERS.items():
        try:
            subsystems[name] = await adapter.capability()
        except Exception as exc:  # noqa: BLE001 - a broken adapter is itself a capability fact
            subsystems[name] = {"available": False, "reason": env.reason(
                f"capability discovery failed: {type(exc).__name__}: {exc}")}
    for name, reason in PLANNED.items():
        subsystems[name] = {"available": False, "reason": reason}
    out = {
        "schema": "se.capabilities/1",
        "host": env.HOST,
        "observed_at": env.utc_now(),
        "version": VERSION,
        "subsystems": subsystems,
    }
    # Additive and optional (SPEC §5.1): a consumer that has never heard of a
    # site is unaffected, and an agent with no hub configured says nothing
    # rather than claiming it stands alone.
    if HUB_URL:
        out["site"] = {"hub_url": HUB_URL, **({"name": SITE} if SITE else {})}
    return out


# Collections whose contents have no honest current health to roll up,
# declined with a reason — the roll-up is nullable by design (ROADMAP
# slice 1). Hard-coded so a new collection rolls up by default and is
# excluded here deliberately, in review. Every lookups collection is a
# parameterised catalog (SPEC section 6): its items are documentation,
# not observed objects with health.
STATUS_DECLINES: dict[tuple[str, str], str] = {
    ("logs", "journal"): "a bounded log query has no current health",
    ("system", "packages"): "inventory; no severity semantics",
}
LOOKUPS_DECLINE = "parameterised catalog"


async def _collect_items(adapter, collection: str) -> tuple[list[dict], str]:
    """Follow one collection's pagination to completion: every item summary
    plus the last page's observed_at. One collector serves the status
    roll-up, the snapshot task, and the /v1/changes live side, so all three
    see the same materialisation. An error envelope becomes a raise —
    collect() built it instead of raising, and treating its zero items as
    data would misreport an empty, healthy collection."""
    items: list[dict] = []
    observed_at = env.utc_now()
    cursor: str | None = None
    while True:
        page = await adapter.collect(collection, {}, None, cursor)
        if page["status"] == "error":
            raise RuntimeError("; ".join(page["errors"]))
        observed_at = page["observed_at"]
        items.extend(page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    return items, observed_at


async def _status_rollup(adapter, collection: str) -> dict:
    """Roll one collection's rows up to level counts and a worst level.
    Row semantics per collection.schema.json: ok = positively healthy,
    info = neutral, absent ("none") = the row carries no severity."""
    items, observed_at = await _collect_items(adapter, collection)
    counts: dict[str, int] = {}
    for item in items:
        level = item.get("worst_opinion_level", "none")
        counts[level] = counts.get(level, 0) + 1
    # critical > warn > any positively-healthy row > occupied-but-neutral
    # > null for an empty collection.
    if counts.get("critical"):
        worst = "critical"
    elif counts.get("warn"):
        worst = "warn"
    elif counts.get("ok"):
        worst = "ok"
    else:
        worst = "info" if items else None
    return {"worst": worst, "counts": counts, "total": len(items), "observed_at": observed_at}


async def _subsystem_status(name: str, adapter) -> tuple[dict, list[str]]:
    """One subsystem's per-collection entries plus its errors[] lines.
    Collections run sequentially — adapters share one socket or bus."""
    entries: dict = {}
    errors: list[str] = []
    try:
        cap = await adapter.capability()
    except Exception as exc:  # noqa: BLE001 - degrade the subsystem, not the endpoint
        errors.append(env.reason(
            f"{name}: capability discovery failed: {type(exc).__name__}: {exc}"))
        return ({c: {"worst": None, "error": f"{type(exc).__name__}: {exc}"}
                 for c in adapter.collections()}, errors)
    unavailable = cap.get("unavailable_collections", {})
    for collection in adapter.collections():
        decline = (LOOKUPS_DECLINE if collection == "lookups"
                   else STATUS_DECLINES.get((name, collection)))
        if decline:
            entries[collection] = {"worst": None, "reason": decline}
        elif not cap["available"]:
            entries[collection] = {"worst": None, "reason": cap["reason"]}
        elif collection in unavailable:
            entries[collection] = {"worst": None, "reason": unavailable[collection]}
        else:
            try:
                entries[collection] = await _status_rollup(adapter, collection)
            except Exception as exc:  # noqa: BLE001 - errors are observations
                entries[collection] = {"worst": None, "error": f"{type(exc).__name__}: {exc}"}
                errors.append(f"{name}/{collection}: {type(exc).__name__}: {exc}")
    return entries, errors


@app.get("/v1/status")
async def status() -> dict:
    """Per-collection severity roll-up: the attention surface (ROADMAP slice 1).

    Polled by the UI (~60s). Every request re-collects every available
    collection to completion — the deliberate cost of statelessness: fresh
    capture on demand, nothing cached between requests (SPEC section 2,
    rule 4; snapshot-on-demand per rule 10). Subsystems collect concurrently,
    collections within one sequentially. A failed collection degrades to an
    error entry and status "partial", never a 500 (rule 7).
    """
    results = await asyncio.gather(
        *(_subsystem_status(name, adapter) for name, adapter in ADAPTERS.items()))
    errors = [line for _, lines in results for line in lines]
    out: dict = {
        "schema": "se.status/1",
        "host": env.HOST,
        "observed_at": env.utc_now(),
        "status": "partial" if errors else "ok",
    }
    if errors:
        out["errors"] = errors
    out["subsystems"] = {name: entries for name, (entries, _) in zip(ADAPTERS, results)}
    return out


# What the snapshot task stores: every collection EXCEPT the bounded journal
# query (a query result, not object state) and every lookups catalog (its
# items are documentation) — SPEC section 10. Collections a capability
# declares unavailable are simply absent from that snapshot; absence is not
# an error (SPEC section 2, rule 7).
SNAPSHOT_EXCLUDES: set[tuple[str, str]] = {("logs", "journal")}


def _history_log(message: str) -> None:
    # The agent has no logger; under systemd, stderr is the journal.
    print(f"history: {message}", file=sys.stderr)


async def _subsystem_snapshot(name: str, adapter) -> dict[str, list[dict]]:
    """One subsystem's snapshot-worthy collections, fully materialised.
    A collection that fails to collect is skipped with a stderr line, never
    stored empty — a fabricated empty snapshot would read later as
    everything-removed."""
    collections: dict[str, list[dict]] = {}
    try:
        cap = await adapter.capability()
    except Exception as exc:  # noqa: BLE001 - degrade the subsystem, not the snapshot
        _history_log(f"snapshot {name}: capability discovery failed: {type(exc).__name__}: {exc}")
        return collections
    unavailable = cap.get("unavailable_collections", {})
    for collection in adapter.collections():
        if collection == "lookups" or (name, collection) in SNAPSHOT_EXCLUDES:
            continue
        if not cap["available"] or collection in unavailable:
            continue
        try:
            items, _ = await _collect_items(adapter, collection)
        except Exception as exc:  # noqa: BLE001 - errors are observations
            _history_log(f"snapshot {name}/{collection}: {type(exc).__name__}: {exc}")
            continue
        collections[collection] = items
    return collections


async def _take_snapshot() -> None:
    results = await asyncio.gather(
        *(_subsystem_snapshot(name, adapter) for name, adapter in ADAPTERS.items()))
    data = {name: colls for name, colls in zip(ADAPTERS, results) if colls}
    await anyio.to_thread.run_sync(
        HISTORY.write_snapshot, env.utc_now(), history.read_boot_id(),
        data, SNAPSHOT_RETENTION_DAYS)


async def _snapshot_loop() -> None:
    """The SE_SNAPSHOT_INTERVAL_SECONDS cadence, resumable across restarts:
    the startup snapshot is taken only when the newest stored one is missing
    or already older than the interval, so a redeploy does not stack extra
    snapshots. Failures are logged and the loop continues — history must
    never break serving (SPEC section 10)."""
    while True:
        delay = SNAPSHOT_INTERVAL
        try:
            newest = await anyio.to_thread.run_sync(HISTORY.newest_snapshot_at)
            age = history.iso_age_seconds(newest) if newest else None
            if age is None or age >= SNAPSHOT_INTERVAL:
                await _take_snapshot()
            else:
                delay = SNAPSHOT_INTERVAL - age
        except Exception as exc:  # noqa: BLE001 - log-and-continue, never crash the loop
            _history_log(f"snapshot failed: {type(exc).__name__}: {exc}")
        await asyncio.sleep(delay)


def _changes_error(errors: list[str], since_requested: str | None = None) -> dict:
    out: dict = {
        "schema": "se.changes/1",
        "host": env.HOST,
        "observed_at": env.utc_now(),
    }
    if since_requested:
        out["since_requested"] = since_requested
    out["status"] = "error"
    out["errors"] = errors
    return out


async def _subsystem_changes(name: str, baseline: dict[str, list[dict]]) -> tuple[dict, list[str]]:
    """Diff one subsystem's baseline collections against live collections of
    the same names. Collections run sequentially — adapters share one socket
    or bus (same rule as _subsystem_status)."""
    diffs: dict = {}
    errors: list[str] = []
    adapter = ADAPTERS.get(name)
    for collection, before in baseline.items():
        if adapter is None or collection not in adapter.collections():
            errors.append(f"{name}/{collection}: snapshotted then, not exposed now")
            continue
        try:
            after, _ = await _collect_items(adapter, collection)
        except Exception as exc:  # noqa: BLE001 - errors are observations
            errors.append(f"{name}/{collection}: {type(exc).__name__}: {exc}")
            continue
        diff = history.diff_items(before, after)
        if diff:
            diffs[collection] = diff
    return diffs, errors


@app.get("/v1/changes")
async def changes(since: str | None = None, subsystem: str | None = None) -> dict:
    """What changed since a moment (SPEC section 10): the newest stored
    snapshot at-or-before `since` (UTC ISO or relative like -24h; omitted
    means since history began) diffed against a live collection of the same
    collections now. Diff-on-read — the baseline is storage, the current
    side is fresh. History being off, empty, or handed a bad `since` is an
    error envelope, never a 500: errors are observations.
    """
    if HISTORY is None:
        return _changes_error([
            "history disabled: STATE_DIRECTORY is not set, so there is no snapshot"
            " store (the NixOS module sets StateDirectory=system-explorer)"])
    since_iso: str | None = None
    if since is not None:
        try:
            since_iso = history.parse_since(since)
        except ValueError as exc:
            return _changes_error([str(exc)])
    try:
        base = await anyio.to_thread.run_sync(HISTORY.baseline, since_iso, subsystem)
    except Exception as exc:  # noqa: BLE001 - errors are observations
        return _changes_error(
            [f"snapshot store unreadable: {type(exc).__name__}: {exc}"], since_iso)
    if base is None:
        return _changes_error(
            ["no snapshots stored yet; the first lands within"
             f" SE_SNAPSHOT_INTERVAL_SECONDS={int(SNAPSHOT_INTERVAL)}s of startup"],
            since_iso)
    if subsystem is not None and not base["data"]:
        return _changes_error(
            [f"baseline snapshot has no data for subsystem {subsystem!r};"
             f" known subsystems: {', '.join(sorted(ADAPTERS))}"], since_iso)
    results = await asyncio.gather(
        *(_subsystem_changes(name, colls) for name, colls in base["data"].items()))
    errors = [line for _, lines in results for line in lines]
    current_boot_id = history.read_boot_id()
    out: dict = {
        "schema": "se.changes/1",
        "host": env.HOST,
        "observed_at": env.utc_now(),
    }
    if since_iso:
        out["since_requested"] = since_iso
    out["baseline"] = {"snapshot_at": base["snapshot_at"], "boot_id": base["boot_id"]}
    if base["fallback"]:
        # Nothing stored is as old as since_requested; the oldest snapshot
        # stands in, and the envelope says so rather than implying coverage.
        out["baseline"]["fallback"] = True
    out["current_boot_id"] = current_boot_id
    out["rebooted"] = base["boot_id"] != current_boot_id
    out["status"] = "partial" if errors else "ok"
    if errors:
        out["errors"] = errors
    out["subsystems"] = {name: diffs for name, (diffs, _) in zip(base["data"], results) if diffs}
    return out


# Returned when the adapter has never heard of the name at all — a client
# error (404), as distinct from a collection it knows and cannot answer.
UNKNOWN_COLLECTION = object()


async def _collection_state(adapter, collection: str):
    """Why this collection cannot be answered here, or None if it can.

    SPEC section 2 rule 7: an absence is reported with a reason, never as a
    clean empty answer. The routes below cannot get that from the acquisition
    itself, because "the directory is not there" and "the directory is there
    and empty" both produce zero items — globbing a missing /nix/var/nix/
    profiles or a missing /sys/class/nvme yields nothing at all, quietly.

    So the gate is here rather than in each adapter: the adapters already
    compute their own unavailability for capabilities and /v1/status, this
    reuses that single answer, and a collection added later cannot forget to
    do it. The cost is one capability() per request — the same probe
    /v1/status makes every poll, and cheap by construction (existence checks
    and, for docker, a socket ping).

    This was a real, measured lie: GET /v1/system/generations on Ubuntu
    24.04 answered `status: ok, items: 0, total: 0, errors: None` while
    capabilities, /v1/status, the UI and the snapshot task all declined it
    correctly (ROADMAP section 5, 2026-08-10). The raw collection route is
    the one an MCP client reaches first.

    Returns UNKNOWN_COLLECTION for a name the subsystem does not have at all.
    The unavailability check comes FIRST, deliberately: a collection the
    capability names with a reason is one the agent knows about, so it must
    answer with that reason even when it is not in collections() — which is
    how a planned-but-unimplemented collection (network/conntrack-summary)
    stops answering "unknown collection" while a perfectly good explanation
    sits one call away.
    """
    try:
        cap = await adapter.capability()
    except Exception as exc:  # noqa: BLE001 - a broken adapter is itself a fact
        return env.reason(f"capability discovery failed: {type(exc).__name__}: {exc}")
    reason = cap.get("unavailable_collections", {}).get(collection)
    if reason is not None:
        return reason
    if collection not in adapter.collections():
        return UNKNOWN_COLLECTION
    if not cap.get("available", False):
        return cap.get("reason") or "subsystem unavailable"
    return None


def _unknown(collection: str) -> HTTPException:
    return HTTPException(status_code=404, detail=f"unknown collection: {collection}")


@app.get("/v1/{subsystem}/{collection}/{object_id:path}/evidence")
async def evidence(subsystem: str, collection: str, object_id: str) -> dict:
    adapter = _adapter(subsystem)
    reason = await _collection_state(adapter, collection)
    if reason is UNKNOWN_COLLECTION:
        raise _unknown(collection)
    if reason is not None:
        return {"object_id": object_id, "captured_at": env.utc_now(), "error": reason}
    try:
        return await adapter.get_evidence(collection, object_id)
    except env.UnknownCollection:
        raise HTTPException(status_code=404, detail=f"unknown collection: {collection}")
    except env.UnknownObject:
        raise HTTPException(status_code=404, detail=f"unknown object: {object_id}")
    except Exception as exc:  # noqa: BLE001 - errors are observations
        return {
            "object_id": object_id,
            "captured_at": env.utc_now(),
            "error": f"{type(exc).__name__}: {exc}",
        }


@app.get("/v1/{subsystem}/{collection}/{object_id:path}")
async def get_object(subsystem: str, collection: str, object_id: str) -> dict:
    adapter = _adapter(subsystem)
    reason = await _collection_state(adapter, collection)
    if reason is UNKNOWN_COLLECTION:
        raise _unknown(collection)
    if reason is not None:
        return env.observation(
            subsystem,
            env.obj_ref(object_id if ":" in object_id else f"error:{object_id}",
                        "unknown", object_id),
            env.source(subsystem, "unavailable", ["(collection unavailable; see errors)"]),
            {}, status="error", errors=[reason],
        )
    try:
        return await adapter.get_object(collection, object_id)
    except env.UnknownCollection:
        raise HTTPException(status_code=404, detail=f"unknown collection: {collection}")
    except env.UnknownObject:
        raise HTTPException(status_code=404, detail=f"unknown object: {object_id}")
    except Exception as exc:  # noqa: BLE001 - errors are observations
        return env.observation(
            subsystem,
            env.obj_ref(object_id if ":" in object_id else f"error:{object_id}",
                        "unknown", object_id),
            env.source(subsystem, "unavailable", ["(acquisition failed; see errors)"]),
            {}, status="error", errors=[f"{type(exc).__name__}: {exc}"],
        )


@app.get("/v1/{subsystem}/{collection}")
async def get_collection(subsystem: str, collection: str, request: Request) -> dict:
    adapter = _adapter(subsystem)
    reason = await _collection_state(adapter, collection)
    if reason is UNKNOWN_COLLECTION:
        raise _unknown(collection)
    filters, limit, cursor = _query(request)
    if reason is not None:
        return env.collection_page(
            subsystem, collection,
            env.source(subsystem, "unavailable", ["(collection unavailable; see errors)"]),
            [], applied_limit=limit or env.DEFAULT_LIMIT, next_cursor=None,
            requested_limit=limit, filters=filters or None,
            status="error", errors=[reason],
        )
    try:
        return await adapter.collect(collection, filters, limit, cursor)
    except env.UnknownCollection:
        raise HTTPException(status_code=404, detail=f"unknown collection: {collection}")
    except Exception as exc:  # noqa: BLE001 - errors are observations
        return env.collection_page(
            subsystem, collection,
            env.source(subsystem, "unavailable", ["(acquisition failed; see errors)"]),
            [], applied_limit=limit or env.DEFAULT_LIMIT, next_cursor=None,
            requested_limit=limit, filters=filters or None,
            status="error", errors=[f"{type(exc).__name__}: {exc}"],
        )
