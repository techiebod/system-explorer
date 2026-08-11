"""Adapter registry.

Each adapter observes one subsystem via native interfaces (SPEC section 4)
and exposes: subsystem, collections(), capability(), collect(), get_object(),
get_evidence(). Unknown collection -> KeyError; unknown object -> LookupError;
both become 404 at the API layer. Anything else becomes an error envelope,
because errors are observations.
"""

from __future__ import annotations

from . import docker, hardware, logs, network, nix, storage, system, units, vms

# Subsystems declared in SPEC section 4 with no adapter yet. Absence is a
# capability statement, not an error — reported with a reason, never faked
# with placeholder objects (the v0.1 mistake). All seven now have adapters;
# partial gaps live in each adapter's unavailable_collections instead.
PLANNED: dict[str, str] = {}


def build_adapters() -> dict:
    adapters = [
        system.Adapter(),
        nix.Adapter(),
        hardware.Adapter(),
        units.Adapter(),
        logs.Adapter(),
        storage.Adapter(),
        network.Adapter(),
        docker.Adapter(),
        vms.Adapter(),
    ]
    return {adapter.subsystem: adapter for adapter in adapters}
