"""Adapter registry.

Each adapter observes one subsystem via native interfaces (SPEC section 4)
and exposes: subsystem, collections(), capability(), acquire(), collect(),
get_object(), get_evidence(). Unknown collection -> KeyError; unknown object
-> LookupError; both become 404 at the API layer. Anything else becomes an
error envelope, because errors are observations.

acquire(collection) is the materialisation alone — every item summary, no
filter, no paginate, no envelope — decorated @env.single_flight so
concurrent callers share one in-flight acquisition. collect() pages what
acquire() returns; main.py's status, snapshot and changes sweeps call
acquire() directly, which is what stopped a multi-page collection paying
its whole acquisition once per page (measured 2026-08-12: /v1/status spent
2 s producing 3 KB, and limit=1 cost what limit=1000 cost). The `logs`
adapter has no acquire(): a bounded journal query has no "all items" to
materialise, and every sweep that would call it already declines
logs/journal by name.

Optionally an adapter also exposes fact_glossary(collection) -> {fact name:
one sentence}, served from /v1/facts. Optional because a subsystem whose facts
are undocumented should say nothing rather than block on prose; absent is an
empty dict, not an error.
"""

from __future__ import annotations

from . import (docker, hardware, logs, network, nix, packages, paperless,
               servarr, storage, system, traefik, units, vms)

# Subsystems declared in SPEC section 4 with no adapter yet. Absence is a
# capability statement, not an error — reported with a reason, never faked
# with placeholder objects (the v0.1 mistake). All seven now have adapters;
# partial gaps live in each adapter's unavailable_collections instead.
PLANNED: dict[str, str] = {}


def build_adapters(selected: list[str] | None = None) -> dict:
    """The subsystems this PROCESS observes — all of them by default, a
    selection when SE_ADAPTERS names one (Phase 3 of the estate design:
    the unit of code is an adapter, the unit of deployment is a process
    running a selected set, and privilege separation becomes a deployment
    decision — an app-scoped instance holds API keys and no host grants,
    which only works if it can decline to be a host observer at all).

    An unknown name fails at startup, loudly: a typo'd selection that
    silently ran everything would hold grants nobody audited, and one that
    silently ran nothing would be absence-as-health with a service in the
    green. The single-host default — no selection — is unchanged.
    """
    adapters: list = [
        system.Adapter(),
        nix.Adapter(),
        packages.Adapter(),
        hardware.Adapter(),
        units.Adapter(),
        logs.Adapter(),
        storage.Adapter(),
        network.Adapter(),
        docker.Adapter(),
        vms.Adapter(),
        paperless.Adapter(),
        traefik.Adapter(),
        servarr.Adapter(),
    ]
    by_name = {adapter.subsystem: adapter for adapter in adapters}
    if selected is None:
        return by_name
    unknown = sorted(set(selected) - set(by_name))
    if unknown:
        raise ValueError(
            f"SE_ADAPTERS names unknown subsystems {unknown}; "
            f"known: {sorted(by_name)}")
    return {name: by_name[name] for name in by_name if name in set(selected)}
