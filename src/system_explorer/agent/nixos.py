"""NixOS closure primitives, shared by the two adapters that read them.

Both `system` (identity and boot-pointer facts) and `nix` (generations and
packages) read the same handful of paths and readlinks. They live here rather
than in either adapter because an adapter importing another adapter would make
the dependency invisible and the ownership arbitrary.

There is a second reason, and it is the better one: this file is the complete
inventory of what the agent reads that only exists on NixOS. Portability is a
stated goal and NixOS is meant to be first-class rather than the boundary
(ROADMAP section 5), which is much easier to keep honest when the
NixOS-specific acquisition surface is one importable module instead of a
scattering of path constants.

Every reader here is deliberately tolerant: a missing file or a broken symlink
is absence, not an error, because on a non-NixOS host absence is the correct
and expected answer.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

PROFILES = Path("/nix/var/nix/profiles")
CURRENT_SYSTEM = "/run/current-system"
BOOTED_SYSTEM = "/run/booted-system"
SW = f"{CURRENT_SYSTEM}/sw"


def is_nixos() -> bool:
    """Whether this host has a nix system closure to read facts out of.

    /run/current-system is the activated-closure pointer, and it exists only
    where something activated one. Nix-derived facts are omitted entirely off
    such a host rather than emitted as nulls: a null "NixosVersion" on Debian
    reads as *unknown*, when the truth is *not applicable*, and four null rows
    on the boot card is what a non-Nix user saw first (ROADMAP section 5,
    phase 2). Absence with a reason is the rule (SPEC section 2, rule 7);
    for individual facts, the honest form of that is not to claim the fact.
    """
    return os.path.exists(CURRENT_SYSTEM)


def read(path: str) -> str:
    """File contents stripped, or "" — absence is not an error here."""
    try:
        return Path(path).read_text().strip()
    except OSError:
        return ""


def realpath(path: str) -> str | None:
    try:
        return os.path.realpath(path) if os.path.exists(path) else None
    except OSError:
        return None


def epoch_to_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def pointers() -> dict[str, str | None]:
    """The three closures that can disagree: what is activated now, what the
    last boot activated, and what the next boot would pick. Their disagreement
    is the whole point — a test-activated system a reboot would discard, or a
    switch that has not been booted into yet."""
    return {"current": realpath(CURRENT_SYSTEM),
            "booted": realpath(BOOTED_SYSTEM),
            "default": realpath(str(PROFILES / "system"))}


def generation_links() -> list[tuple[int, Path, str]]:
    """(generation number, profile link, store path), newest first."""
    out = []
    for link in PROFILES.glob("system-*-link"):
        try:
            number = int(link.name[len("system-"):-len("-link")])
        except ValueError:
            continue
        try:
            out.append((number, link, os.readlink(link)))
        except OSError:
            continue
    return sorted(out, reverse=True)
