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

import json
import os
from datetime import datetime, timezone
from pathlib import Path

PROFILES = Path("/nix/var/nix/profiles")
CURRENT_SYSTEM = "/run/current-system"
BOOTED_SYSTEM = "/run/booted-system"
SW = f"{CURRENT_SYSTEM}/sw"

# An optional file a generation may carry, in the same place and with the same
# properties as nixos-version: inside the closure, immutable per generation, and
# readable without executing anything (SPEC rule 5). nixpkgs knows nothing about
# it — whatever builds the closure writes it — so it is absent far more often
# than present, and absence is simply "this generation does not record that".
#
# The name is deliberately this agent's rather than any particular estate's. What
# it must contain is documented in docs/SPEC.md; the shape read here is:
#
#   {"schema": 2, "revision": "<vcs revision>", "receiptsExpected": true,
#    "inputs": {"<name>": {"revision": "...", "narHash": "...",
#                          "lastModified": 1786089803}}}
GENERATION_MANIFEST = "se-generation.json"

# The lowest manifest schema that promises a deployment receipt exists for every
# generation. Below it, a generation without a receipt says nothing at all: it
# predates the workflow that writes them. Only the closure knows which era it
# came from, which is why the flag travels inside it.
RECEIPTS_EXPECTED_SCHEMA = 2


def receipts_dir() -> Path | None:
    """Directory of per-generation deployment receipts, or None.

    No default on purpose. An estate that does not write receipts must not have
    this agent inventing a path, finding nothing there, and reporting the nothing
    as a deployment that bypassed a workflow it never had.
    """
    configured = os.environ.get("SE_DEPLOYMENT_RECEIPTS", "").strip()
    return Path(configured) if configured else None


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


def read_json(path: str | Path) -> dict | None:
    """Parsed JSON object, or None for absent, unreadable or malformed.

    Same tolerance as read() and for the same reason, with one addition: a file
    that exists but does not parse is also None. A half-written manifest is not
    evidence of anything, and the caller's honest answer for both cases is that
    it has no manifest — not a partially-populated one.
    """
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def generation_manifest(target: str) -> dict | None:
    """The build manifest a generation carries, if it carries one."""
    return read_json(f"{target}/{GENERATION_MANIFEST}")


def deployment_receipt(number: int) -> dict | None:
    """The deployment receipt for a generation, if receipts are configured and
    this generation has one."""
    directory = receipts_dir()
    if directory is None:
        return None
    return read_json(directory / f"{number}.json")


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
