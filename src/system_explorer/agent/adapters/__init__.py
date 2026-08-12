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

from . import (docker, hardware, logs, network, nix, packages, storage,
               system, units, vms)

# Subsystems declared in SPEC section 4 with no adapter yet. Absence is a
# capability statement, not an error — reported with a reason, never faked
# with placeholder objects (the v0.1 mistake). All seven now have adapters;
# partial gaps live in each adapter's unavailable_collections instead.
PLANNED: dict[str, str] = {}


def build_adapters() -> dict:
    adapters = [
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
    ]
    return {adapter.subsystem: adapter for adapter in adapters}
