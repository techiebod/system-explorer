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
import re
from datetime import datetime, timezone
from pathlib import Path

PROFILES = Path("/nix/var/nix/profiles")
CURRENT_SYSTEM = "/run/current-system"
BOOTED_SYSTEM = "/run/booted-system"
SW = f"{CURRENT_SYSTEM}/sw"

STORE_RE = re.compile(r"(/nix/store/[a-z0-9]{32}-([^/]+))")
# buildEnv links a package's own subdirectories, so the environment has to be
# walked one level deeper than its root.
SW_SUBDIRS = ("bin", "sbin", "lib", "libexec", "share", "etc")

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


# ── the five filesystem primitives, and why they are functions ───────────
#
# Everything below this line reads the closure tree through exactly these
# five calls, and nothing in this file or in adapters/nix.py touches the
# filesystem any other way. That is not tidiness: it is the replay seam.
# A collector whose interface answers a WALK is replayed by transcribing the
# filesystem it walked (DESIGN's tree ruling), and the transcription can only
# be substituted where the walk goes through named module-level functions.
# Until 2026-08-19 these reads were spread across this module and the adapter
# as inline Path(...) and os.* calls, so `nix` could not be captured at all —
# a replay would have read the tree of whichever machine was replaying.
#
# Each is deliberately tolerant, because on a non-NixOS host absence is the
# correct and expected answer, not an error.


def exists(path: str) -> bool:
    return os.path.exists(path)


def read(path: str) -> str:
    """File contents stripped, or "" — absence is not an error here."""
    try:
        return Path(path).read_text().strip()
    except OSError:
        return ""


def realpath(path: str) -> str | None:
    try:
        return os.path.realpath(path) if exists(path) else None
    except OSError:
        return None


def listdir(path: str) -> list[str]:
    """Directory entries, sorted, or [] — a directory that is not there is a
    reading, not a failure. Sorted here rather than at each caller so two
    hosts with the same tree emit the same order."""
    try:
        return sorted(os.listdir(path))
    except OSError:
        return []


def readlink(path: str) -> str | None:
    """The link's IMMEDIATE target, unresolved.

    Distinct from realpath and both are needed: a profile link's own target is
    the store path the generation IS, while resolving it would follow into
    whatever that path in turn points at.
    """
    try:
        return os.readlink(path)
    except OSError:
        return None


def mtime(path: str) -> float | None:
    """The link's own mtime, not its target's — lstat, because a generation's
    creation time is when the LINK was made and every closure under it is
    immutable and shares whatever timestamp nix gave it."""
    try:
        return os.lstat(path).st_mtime
    except OSError:
        return None


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
    return exists(CURRENT_SYSTEM)


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


def store_paths(sw_root: str) -> dict[str, str]:
    """name-version → store path for everything linked into a system environment.

    Takes the environment root rather than assuming the running one, because the
    same link farm exists inside every generation at `<generation>/sw`. That is
    what makes a package-level comparison between two generations a pair of
    directory walks rather than a subprocess: `nix store diff-closures` would
    answer the same question with prose this agent is not allowed to parse
    (SPEC rule 5).

    Two scandir levels: buildEnv links packages directly or, on collision, merges
    one directory level and links inside it.
    """
    seen: dict[str, str] = {}

    def record(target: str) -> None:
        match = STORE_RE.match(target)
        if match:
            seen.setdefault(match.group(2), match.group(1))

    for sub in SW_SUBDIRS:
        try:
            entries = list(os.scandir(os.path.join(sw_root, sub)))
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                record(os.readlink(entry.path))
            elif entry.is_dir(follow_symlinks=False):
                try:
                    for nested in os.scandir(entry.path):
                        if nested.is_symlink():
                            record(os.readlink(nested.path))
                except OSError:
                    continue
    return seen


def read_json(path: str | Path) -> dict | None:
    """Parsed JSON object, or None for absent, unreadable or malformed.

    Same tolerance as read() and for the same reason, with one addition: a file
    that exists but does not parse is also None. A half-written manifest is not
    evidence of anything, and the caller's honest answer for both cases is that
    it has no manifest — not a partially-populated one.

    Through read(), so the JSON readers ride the same seam the plain ones do
    rather than being a sixth way to touch the tree. read() answers "" for an
    absent file and "" is not JSON, so both cases still arrive here as None.
    """
    try:
        data = json.loads(read(str(path)))
    except ValueError:
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


def generation_links() -> list[tuple[int, str, str]]:
    """(generation number, profile link PATH, store path), newest first.

    Through listdir and readlink rather than Path.glob and Path.readlink, so
    the whole walk rides the seam; the link is carried as a string for the
    same reason — a Path would invite a caller to stat it directly and put a
    sixth read back outside the five primitives. A link that is not a symlink,
    or whose number does not parse, is skipped: the profile directory holds
    `system` and `per-user` beside the numbered links.
    """
    out = []
    for name in listdir(str(PROFILES)):
        if not (name.startswith("system-") and name.endswith("-link")):
            continue
        try:
            number = int(name[len("system-"):-len("-link")])
        except ValueError:
            continue
        path = f"{PROFILES}/{name}"
        target = readlink(path)
        if target is None:
            continue
        out.append((number, path, target))
    return sorted(out, reverse=True)
