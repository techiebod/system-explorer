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
import time
from pathlib import Path

import anyio
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __revision__, __version__
from ..paths import UI_DIR
from . import envelope as env
from . import history
from .adapters import PLANNED, build_adapters
from .findings import (deselected_unobserved, finding_records,
                       findings_envelope, locator_scoped)

RESERVED_PARAMS = {"limit", "cursor"}

# Surfaced in /health and capabilities so fleet skew across hosts is visible
# from the product (backlog note, 2026-08-09). The literal lives in
# system_explorer/__init__.py, which pyproject.toml and nix/version.nix also
# read — one edit per release, and no way to disagree.
VERSION = __version__
# The build's source revision, or None off a Nix build (see __init__.py). Sent
# alongside the version so an operator can tell from the screen which build
# they are looking at — between releases the version alone cannot.
REVISION = __revision__

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
    # The store rides as a parameter: the None check happens once,
    # here, and the loop's signature says it cannot run without one.
    task = asyncio.create_task(_snapshot_loop(HISTORY)) if HISTORY else None
    yield
    if task:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task


app = FastAPI(title="System Explorer agent", version=VERSION, docs_url=None, redoc_url=None,
              lifespan=lifespan)
# SE_ADAPTERS selects this process's subsystems (comma-separated); unset
# runs them all — the single-host default. An unknown name refuses to
# start, which is the honest failure for a unit whose grants were audited
# against a list it is not actually running.
_SELECTED = [name.strip()
             for name in os.environ.get("SE_ADAPTERS", "").split(",")
             if name.strip()] or None
ADAPTERS = build_adapters(_SELECTED)

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
        raise HTTPException(status_code=422, detail="limit must be an integer") from None
    if parsed_limit is not None and parsed_limit < 1:
        raise HTTPException(status_code=422, detail="limit must be >= 1")
    return params, parsed_limit, cursor


@app.get("/health")
async def health() -> dict:
    out = {"status": "ok", "host": env.HOST, "version": VERSION}
    if REVISION:
        out["revision"] = REVISION
    # The site this host says it is in. A hub probes /health to build its
    # listing and had nothing to go on, so it stamped its OWN site onto every
    # agent it fronts — and a cloud host at a different provider, fronted by
    # a home hub, read as living at home. Fronting and residing are different
    # facts and only one of them is the hub's to state.
    if SITE:
        out["site"] = SITE
    return out


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
        # How to open an object id, from the agent that mints them. This was
        # a table in the browser until 2026-08-14, which is the fourth-copy
        # failure the fact dictionary exists to prevent, and it had drifted
        # exactly as that rule predicts: the entire application tier was
        # missing, so every app-tier relationship chip rendered as dead text.
        # Narrowed to the collections this host answers, so a chip never
        # leads anywhere this agent would 404 on.
        "object_prefixes": env.object_prefixes({
            name: cap.get("collections") or []
            for name, cap in subsystems.items() if cap.get("available")}),
    }
    if REVISION:
        out["revision"] = REVISION
    # Additive and optional (SPEC §5.1): a consumer that has never heard of a
    # site is unaffected, and an agent with no hub configured says nothing
    # rather than claiming it stands alone.
    if HUB_URL:
        out["site"] = {"hub_url": HUB_URL, **({"name": SITE} if SITE else {})}
    return out


@app.get("/v1/facts")
async def fact_dictionary() -> dict:
    """What each fact MEANS — one sentence, owned by the adapter that emits it.

    Facts carry native property names (SPEC section 5) and native names are not
    self-explanatory. A reader looking at LinkSpeed "8.0 GT/s PCIe" beside
    LinkWidth 2 reasonably asked whether lanes and speed were the same thing;
    nothing on the screen could tell them, and no amount of renaming would have.

    An endpoint rather than a map in the UI, because a second copy of this
    knowledge in the browser is a second rulebook and they drift (SPEC rule 14
    exists because three of them already had). An endpoint rather than
    descriptions on every envelope, because an agent paging ten thousand rows
    should not pay for the same prose ten thousand times. Fetched once, cached,
    and equally available to an LLM as to the UI — one contract, two consumers.
    """
    subsystems: dict = {}
    kinds: dict = {}
    for name, adapter in ADAPTERS.items():
        glossary = getattr(adapter, "fact_glossary", None)
        if glossary is None:
            continue
        documented = {collection: entries
                      for collection in adapter.collections()
                      if (entries := glossary(collection))}
        if documented:
            subsystems[name] = documented
        # Which of those facts are NOT measured. Only the exceptions are
        # carried: `measured` is the default and stating it on every entry
        # would bury the forty that matter under three hundred that do not.
        classify = getattr(adapter, "fact_kinds", None)
        if classify is None:
            continue
        classified = {collection: entries
                      for collection in adapter.collections()
                      if (entries := classify(collection))}
        if classified:
            kinds[name] = classified
    out = {
        "schema": "se.facts/1",
        "host": env.HOST,
        "observed_at": env.utc_now(),
        "version": VERSION,
        "subsystems": subsystems,
    }
    if kinds:
        out["kinds"] = kinds
    if REVISION:
        out["revision"] = REVISION
    return out


# Collections whose contents have no honest current health to roll up,
# declined with a reason — the roll-up is nullable by design (ROADMAP
# slice 1). Hard-coded so a new collection rolls up by default and is
# excluded here deliberately, in review. Every lookups collection is a
# parameterised catalog (SPEC section 6): its items are documentation,
# not observed objects with health.
STATUS_DECLINES: dict[tuple[str, str], str] = {
    ("logs", "journal"): "a bounded log query has no current health",
    ("packages", "packages"): "inventory; no severity semantics",
    ("servarr", "history"): ("the acquisition trail is a bounded recent"
                             " tail; no current health"),
}
LOOKUPS_DECLINE = "parameterised catalog"


async def _collect_items(adapter, collection: str) -> tuple[list[dict], str]:
    """Every item summary, in one acquisition. One collector serves the
    status roll-up, the snapshot task, and the /v1/changes live side, so all
    three see the same materialisation.

    This used to follow collect()'s pagination to completion — and because
    every page re-ran the whole acquisition before slicing, a two-page
    collection paid ListUnits, ListUnitFiles and ~800 procfs reads TWICE to
    produce one severity count, which was most of why /v1/status took 2 s to
    answer 3 KB (measured 2026-08-12; limit=1 cost what limit=1000 cost).
    acquire() is the materialisation alone — no filter, no paginate, no
    envelope — and it is single-flighted, so this sweep and a concurrent UI
    poll of the same collection share one acquisition instead of stacking
    two. Acquisition failures propagate as exceptions; the callers already
    treat any raise as one collection degrading, never the endpoint."""
    items = await adapter.acquire(collection)
    return items, env.utc_now()


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
    worst: str | None
    if counts.get("critical"):
        worst = "critical"
    elif counts.get("warn"):
        worst = "warn"
    elif counts.get("ok"):
        worst = "ok"
    else:
        worst = "info" if items else None
    return {"worst": worst, "counts": counts, "total": len(items), "observed_at": observed_at}


async def _timed(name: str, coro):
    """(name, result, wall ms) for one subsystem's share of a sweep.

    WALL, not CPU, and that is the honest limit rather than an omission.
    A sweep runs every subsystem concurrently in one process, so process CPU
    across it belongs to the sweep and cannot be split; these numbers overlap
    and sum to more than the sweep took. They are still the useful signal,
    because most of what an adapter costs is waiting on somebody else's
    program — and the sweep's own cpu_ms and child_cpu_ms say how much of the
    total was arithmetic here versus work done elsewhere.
    """
    started = time.perf_counter()
    result = await coro
    return name, result, round((time.perf_counter() - started) * 1000, 1)


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
        return ({c: {"worst": None, "error": env.reason(f"{type(exc).__name__}: {exc}")}
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
                entries[collection] = {"worst": None,
                                       "error": env.reason(f"{type(exc).__name__}: {exc}")}
                errors.append(env.reason(f"{name}/{collection}: {type(exc).__name__}: {exc}"))
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
    with env.Stopwatch() as cost:
        timed = await asyncio.gather(
            *(_timed(name, _subsystem_status(name, adapter))
              for name, adapter in ADAPTERS.items()))
    results = [result for _n, result, _ms in timed]
    errors = [line for _, lines in results for line in lines]
    out: dict = {
        "schema": "se.status/1",
        "host": env.HOST,
        "observed_at": env.utc_now(),
        "status": "partial" if errors else "ok",
    }
    if errors:
        out["errors"] = errors
    out["subsystems"] = {name: entries for name, (entries, _) in zip(ADAPTERS, results, strict=True)}
    # What this sweep cost the host answering it. The sweep's own CPU is
    # exact; the per-subsystem figures are wall and overlap, which is said in
    # the schema rather than left for a reader to discover by summing them.
    out["timing"] = {**cost.elapsed,
                     "subsystems": {name: {"wall_ms": ms} for name, _r, ms in timed},
                     **env.self_memory()}
    return out


# What this process is NOT running, owed to the findings surface: a
# narrowed SE_ADAPTERS selection must name the deselected subsystems'
# collections as unobserved, or its envelope claims full coverage and the
# hub resolves findings nobody looked at (agent/findings.py). Computed once
# — the adapter universe and its collections are static per build.
_DESELECTED_UNOBSERVED = [
    entry
    for name, adapter in build_adapters(None).items()
    if name not in ADAPTERS
    for entry in locator_scoped(
        deselected_unobserved({name: adapter.collections()},
                              set(STATUS_DECLINES)),
        getattr(adapter, "host_block", None))
] if _SELECTED else []


async def _subsystem_findings(name: str, adapter) -> tuple[list, list, list[str]]:
    """(findings, unobserved, errors) for one subsystem's sweep.

    The decline table is /v1/status's, deliberately: a bounded journal query
    is events, not standing conditions (its entry ids are cursors — no
    stable rule-15 identity to attach lifecycle to), packages are inventory,
    lookups are catalogs. Everything else that cannot be evaluated lands in
    `unobserved` with its reason, because a collection the sweep skipped
    silently would read at the hub as all of its findings resolving at once
    (see agent/findings.py)."""
    found: list = []
    unobserved: list = []
    errors: list[str] = []
    try:
        cap = await adapter.capability()
    except Exception as exc:  # noqa: BLE001 - degrade the subsystem, not the endpoint
        reason = env.reason(f"capability discovery failed: {type(exc).__name__}: {exc}")
        errors.append(f"{name}: {reason}")
        unobserved.extend({"subsystem": name, "collection": collection, "reason": reason}
                          for collection in adapter.collections()
                          if collection != "lookups"
                          and (name, collection) not in STATUS_DECLINES)
        return found, unobserved, errors
    unavailable = cap.get("unavailable_collections", {})
    for collection in adapter.collections():
        if collection == "lookups" or (name, collection) in STATUS_DECLINES:
            continue
        if not cap["available"] or collection in unavailable:
            unobserved.append({"subsystem": name, "collection": collection,
                               "reason": unavailable.get(collection) or cap["reason"]})
            continue
        try:
            items, _ = await _collect_items(adapter, collection)
        except Exception as exc:  # noqa: BLE001 - errors are observations
            reason = env.reason(f"{type(exc).__name__}: {exc}")
            unobserved.append({"subsystem": name, "collection": collection,
                               "reason": reason})
            errors.append(f"{name}/{collection}: {reason}")
            continue
        found.extend(finding_records(name, collection, items))
    block = getattr(adapter, "host_block", None)
    return locator_scoped(found, block), locator_scoped(unobserved, block), errors


@app.get("/v1/findings")
async def findings() -> dict:
    """Every warn/critical opinion this host derives right now, with the
    rule-15 identity the hub's registry keys on (SPEC section 6.3). The
    same sweep /v1/status makes — single-flighted acquisitions, subsystems
    concurrent — but keeping the opinions the rows carry instead of
    reducing them to counts, so the estate's attention roll-up is one
    request per host rather than one per collection."""
    with env.Stopwatch() as cost:
        timed = await asyncio.gather(
            *(_timed(name, _subsystem_findings(name, adapter))
              for name, adapter in ADAPTERS.items()))
    results = [result for _n, result, _ms in timed]
    locators: list[dict] = [env.HOST]
    for adapter in ADAPTERS.values():
        block = getattr(adapter, "host_block", None)
        if block is not None and block not in locators:
            locators.append(block)
    envelope = findings_envelope(
        env.utc_now(),
        [record for found, _, _ in results for record in found],
        [entry for _, unobserved, _ in results for entry in unobserved]
        + _DESELECTED_UNOBSERVED,
        errors=[line for _, _, lines in results for line in lines] or None,
        locators=locators,
    )
    # THE ROUTE THAT COSTS THE MOST, and until 0.6 nothing in the product
    # could say so. A hub sweeps this every 60s by default and each sweep
    # re-acquires every collection on the host; measured from outside, one
    # sweep burned 2.4 s of CPU on a single-core host — three quarters of
    # that agent's entire standing bill, invisible from the inside. It is
    # the figure a cadence should be set from, so it rides on the answer.
    envelope["timing"] = {**cost.elapsed,
                          "subsystems": {name: {"wall_ms": ms}
                                         for name, _r, ms in timed},
                          **env.self_memory()}
    return envelope


# What the snapshot task stores: every collection EXCEPT the bounded journal
# query (a query result, not object state) and every lookups catalog (its
# items are documentation) — SPEC section 10. Collections a capability
# declares unavailable are simply absent from that snapshot; absence is not
# an error (SPEC section 2, rule 7).
SNAPSHOT_EXCLUDES: set[tuple[str, str]] = {("logs", "journal")}


def _history_log(message: str) -> None:
    # The agent has no logger; under systemd, stderr is the journal — which
    # is exactly why the scrub happens HERE, at the chokepoint: a snapshot
    # failure's exception text can carry a request URL, and the first
    # query-string credential in the estate (sabnzbd) made that a leak
    # path into journalctl (adversarial review, 2026-08-13).
    print(f"history: {env.reason(message)}", file=sys.stderr)


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


async def _take_snapshot(store: history.HistoryStore) -> None:
    results = await asyncio.gather(
        *(_subsystem_snapshot(name, adapter) for name, adapter in ADAPTERS.items()))
    data = {name: colls for name, colls in zip(ADAPTERS, results, strict=True) if colls}
    await anyio.to_thread.run_sync(
        store.write_snapshot, env.utc_now(), history.read_boot_id(),
        data, SNAPSHOT_RETENTION_DAYS)


async def _snapshot_loop(store: history.HistoryStore) -> None:
    """The SE_SNAPSHOT_INTERVAL_SECONDS cadence, resumable across restarts:
    the startup snapshot is taken only when the newest stored one is missing
    or already older than the interval, so a redeploy does not stack extra
    snapshots. Failures are logged and the loop continues — history must
    never break serving (SPEC section 10)."""
    while True:
        delay = SNAPSHOT_INTERVAL
        try:
            newest = await anyio.to_thread.run_sync(store.newest_snapshot_at)
            age = history.iso_age_seconds(newest) if newest else None
            if age is None or age >= SNAPSHOT_INTERVAL:
                await _take_snapshot(store)
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
            errors.append(env.reason(f"{name}/{collection}: {type(exc).__name__}: {exc}"))
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
    out["subsystems"] = {name: diffs for name, (diffs, _) in zip(base["data"], results, strict=True) if diffs}
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


def _evidence_envelope(body: dict, host: dict | None = None) -> dict:
    """Stamp the discriminator and host onto an evidence response.

    Evidence was the last undeclared surface on the wire — capabilities and
    hub-hosts gained their schemas earlier, and every adapter's
    get_evidence() returns a bare dict. Stamped HERE, once, rather than in
    ten adapters: the envelope-level members are the API's concern, the
    payload is the adapter's, and a new adapter cannot forget what it never
    had to remember. Declared as se.evidence/1 (schema/evidence.schema.json)
    so the live check and every consumer can validate the shape instead of
    sniffing it.
    """
    out = {"schema": "se.evidence/1", "host": host or env.HOST, **body}
    if "error" in out:
        out["error"] = env.reason(out["error"])
    return out


# Prefix-first, not suffix: the old shape appended /evidence to the object
# path, and because object_id is a {path} parameter and this route was
# declared before get_object, any object whose id ended in /evidence was
# unreachable — the request answered with its PARENT's evidence instead of
# 404ing (measured live, 2026-08-12; mount:, dataset: and route: ids all
# carry slashes, so `dataset:tank/evidence` was one `zfs create` away). A
# leading segment the id grammar cannot occupy removes the ambiguity for
# every current and future id shape. env.evidence_ref() is the only place
# the URL is spelled; this route must stay declared before get_object so
# "evidence" is never parsed as a subsystem name.
@app.get("/v1/evidence/{subsystem}/{collection}/{object_id:path}")
async def evidence(subsystem: str, collection: str, object_id: str) -> dict:
    adapter = _adapter(subsystem)
    locator = getattr(adapter, "host_block", None)
    reason = await _collection_state(adapter, collection)
    if reason is UNKNOWN_COLLECTION:
        raise _unknown(collection)
    if reason is not None:
        return _evidence_envelope(
            {"object_id": object_id, "captured_at": env.utc_now(), "error": reason},
            host=locator)
    try:
        return _evidence_envelope(await adapter.get_evidence(collection, object_id),
                                  host=locator)
    except env.UnknownCollection:
        raise HTTPException(status_code=404, detail=f"unknown collection: {collection}") from None
    except env.UnknownObject:
        raise HTTPException(status_code=404, detail=f"unknown object: {object_id}") from None
    except Exception as exc:  # noqa: BLE001 - errors are observations
        return _evidence_envelope({
            "object_id": object_id,
            "captured_at": env.utc_now(),
            "error": f"{type(exc).__name__}: {exc}",
        }, host=locator)


def _costed(envelope: dict, cost: env.Stopwatch) -> dict:
    """Stamp an envelope with what producing it cost.

    A single-collection request runs ONE adapter and nothing else, so the
    process CPU across this span is that collection's cost exactly —
    attribution the concurrent sweeps cannot honestly claim, and the reason
    this is worth stamping per route rather than only on the sweep.

    Additive and optional (SPEC section 5.1): a consumer that has never heard
    of `timing` is unaffected, and it is stamped at the ROUTE rather than
    inside each adapter so no adapter can forget to and none has to remember.

    Not stored: history snapshots items, never envelopes, so a figure that
    differs on every request cannot churn /v1/changes into noise.
    """
    if isinstance(envelope, dict):
        envelope["timing"] = cost.elapsed
    return envelope


@app.get("/v1/{subsystem}/{collection}/{object_id:path}")
async def get_object(subsystem: str, collection: str, object_id: str) -> dict:
    # Around the WHOLE route, capability probe included. A collection that
    # declines still costs something to decline — the probe may shell out —
    # and a cost that only appears on the successful path hides exactly the
    # surprise an operator is looking for.
    with env.Stopwatch() as cost:
        answer = await _get_object(subsystem, collection, object_id)
    return _costed(answer, cost)


async def _get_object(subsystem: str, collection: str, object_id: str) -> dict:
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
            host=getattr(adapter, "host_block", None),
        )
    try:
        return await adapter.get_object(collection, object_id)
    except env.UnknownCollection:
        raise HTTPException(status_code=404, detail=f"unknown collection: {collection}") from None
    except env.UnknownObject:
        raise HTTPException(status_code=404, detail=f"unknown object: {object_id}") from None
    except Exception as exc:  # noqa: BLE001 - errors are observations
        return env.observation(
            subsystem,
            env.obj_ref(object_id if ":" in object_id else f"error:{object_id}",
                        "unknown", object_id),
            env.source(subsystem, "unavailable", ["(acquisition failed; see errors)"]),
            {}, status="error", errors=[f"{type(exc).__name__}: {exc}"],
            host=getattr(adapter, "host_block", None),
        )


@app.get("/v1/{subsystem}/{collection}")
async def get_collection(subsystem: str, collection: str, request: Request) -> dict:
    with env.Stopwatch() as cost:
        answer = await _get_collection(subsystem, collection, request)
    return _costed(answer, cost)


async def _get_collection(subsystem: str, collection: str, request: Request) -> dict:
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
            host=getattr(adapter, "host_block", None),
        )
    try:
        return await adapter.collect(collection, filters, limit, cursor)
    except env.UnknownCollection:
        raise HTTPException(status_code=404, detail=f"unknown collection: {collection}") from None
    except env.UnknownFilterKey as exc:
        # A near-miss filter key is a malformed request, not an acquisition
        # failure: the same 422 a bad `limit` gets (_query above). Left to the
        # generic handler below it rendered as "acquisition failed" with the
        # class name leaked — a client typo wearing an outage's envelope, so
        # retry logic hammered a permanently-bad request and the UI reported
        # a healthy collection unavailable (three review passes converged).
        raise HTTPException(status_code=422, detail=str(exc)) from None
    except Exception as exc:  # noqa: BLE001 - errors are observations
        return env.collection_page(
            subsystem, collection,
            env.source(subsystem, "unavailable", ["(acquisition failed; see errors)"]),
            [], applied_limit=limit or env.DEFAULT_LIMIT, next_cursor=None,
            requested_limit=limit, filters=filters or None,
            status="error", errors=[f"{type(exc).__name__}: {exc}"],
            host=getattr(adapter, "host_block", None),
        )
