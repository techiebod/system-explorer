"""nix subsystem: the deployment itself — generations and installed packages.

Split out of `system` because these two collections are the only ones in the
product that do not exist on every host it targets, and mixing them in made
both halves worse. On a Debian host they showed up as two odd declining rows
inside an otherwise universal subsystem; on a NixOS host they sat beside
identity and time as if a package inventory were the same kind of thing as a
hostname. Now a non-Nix host declines one whole subsystem with one reason, and
the operator UI — whose navigation is generated from /v1/capabilities — gets
the deployment in its own section for free.

No subprocess: generations come from the profile link farm and the closure
metadata files, packages from the /run/current-system/sw link farm. Both are
pure filesystem reads (agent/nixos.py holds the primitives, shared with the
`system` adapter's identity and boot-pointer facts).
"""

from __future__ import annotations

import os
import re

import anyio

from .. import envelope as env
from .. import nixos as nx
from ..rules import worst_level
from ..rules.nix import generation_opinions

GENERATIONS_REFERENCE = ["nixos-rebuild list-generations",
                         "ls -l /nix/var/nix/profiles",
                         "readlink -f /run/current-system /run/booted-system"]
PACKAGES_REFERENCE = ["ls /run/current-system/sw/bin",
                      "readlink /run/current-system/sw/bin/<command>"]

STORE_RE = re.compile(r"(/nix/store/[a-z0-9]{32}-([^/]+))")
# name-version split: the version starts at the first dash followed by a digit.
NAME_VERSION_RE = re.compile(r"(.+?)-([0-9].*)")

SW_SUBDIRS = ("bin", "sbin", "lib", "libexec", "share", "etc")


class Adapter:
    subsystem = "nix"

    def collections(self) -> list[str]:
        # Static, always both. An availability-dependent collections() is what
        # made storage/pools 404 with a reason available and omitted pools from
        # the roll-up entirely (nix/tests/module.nix caught it); the route gate
        # reads this list and unavailability belongs in capability() alone.
        return ["generations", "packages"]

    async def capability(self) -> dict:
        """Unavailable as a whole off NixOS, with the path that proves it.

        Declining the subsystem rather than each collection is the point of the
        split: one reason instead of two, and the nav shows one greyed group
        instead of odd rows inside `system`.
        """
        if not nx.is_nixos():
            return {"available": False,
                    "reason": f"{nx.CURRENT_SYSTEM} does not exist "
                              "(no activated Nix system closure — not a NixOS host?)"}
        unavailable: dict[str, str] = {}
        if not nx.PROFILES.is_dir():
            unavailable["generations"] = f"{nx.PROFILES} does not exist"
        if not os.path.isdir(nx.SW):
            unavailable["packages"] = f"{nx.SW} does not exist"
        return {"available": True,
                "collections": [c for c in self.collections() if c not in unavailable],
                "unavailable_collections": unavailable}

    # ── generations ──────────────────────────────────────────
    def _generation_items(self) -> list[dict]:
        pointers = nx.pointers()
        items = []
        for number, link, target in nx.generation_links():
            kernel = nx.realpath(f"{target}/kernel")
            kernel_match = STORE_RE.match(kernel or "")
            revision = nx.read(f"{target}/configuration-revision")
            try:
                specialisations = sorted(os.listdir(f"{target}/specialisation"))
            except OSError:
                specialisations = []
            facts = {
                "NixosVersion": nx.read(f"{target}/nixos-version") or None,
                "Kernel": kernel_match.group(2) if kernel_match else None,
                "ConfigurationRevision": revision or None,
                "Created": nx.epoch_to_iso(link.lstat().st_mtime),
                "Current": target == pointers["current"],
                "Booted": target == pointers["booted"],
                "Profile": target == pointers["default"],
                "Specialisations": specialisations,
                "StorePath": target,
            }
            # Only the running generation is positively vouched for; the rest
            # are neutral history unless a rule (generation-pending) fires.
            items.append(env.item_summary(
                f"generation:{number}", "generation", str(number), facts,
                worst_opinion_level=worst_level(
                    generation_opinions(facts),
                    healthy="ok" if facts["Current"] else "info")))
        return items

    # ── packages ─────────────────────────────────────────────
    @staticmethod
    def _package_paths() -> dict[str, str]:
        """name-version → store path for everything linked into the system
        environment. Two scandir levels: buildEnv links packages directly or,
        on collision, merges one directory level and links inside it."""
        seen: dict[str, str] = {}

        def record(link_target: str) -> None:
            match = STORE_RE.match(link_target)
            if match:
                seen.setdefault(match.group(2), match.group(1))

        for sub in SW_SUBDIRS:
            root = os.path.join(nx.SW, sub)
            try:
                level_one = list(os.scandir(root))
            except OSError:
                continue
            for entry in level_one:
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

    def _package_items(self) -> list[dict]:
        items = []
        for name_version, store_path in sorted(self._package_paths().items()):
            match = NAME_VERSION_RE.match(name_version)
            facts = {
                "Name": match.group(1) if match else name_version,
                "Version": match.group(2) if match else None,
                "StorePath": store_path,
            }
            items.append(env.item_summary(
                f"package:{name_version}", "package", name_version, facts))
        items.sort(key=lambda i: (i["facts"]["Name"], i["native_id"]))
        return items

    # ── plumbing ─────────────────────────────────────────────
    def _source(self, collection: str) -> dict:
        if collection == "generations":
            return env.source("nixos-fs", "/nix/var/nix/profiles (filesystem)",
                              GENERATIONS_REFERENCE)
        return env.source("nixos-fs", "/run/current-system/sw (filesystem)",
                          PACKAGES_REFERENCE)

    def _items(self, collection: str) -> list[dict]:
        if collection == "generations":
            return self._generation_items()
        if collection == "packages":
            return self._package_items()
        raise env.UnknownCollection(collection)

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        # The link-farm and profile scandir walks are synchronous filesystem
        # work — off the event loop like every other adapter's acquisition
        # (backlog note, 2026-08-09: async hygiene).
        fetched = await anyio.to_thread.run_sync(self._items, collection)
        items = env.apply_fact_filters(fetched, query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection,
                                   self._source(collection), page,
                                   applied, next_cursor, requested_limit=limit,
                                   total=total, filters=query or None)

    # Evaluators per collection (agent/rules/nix.py), shared verbatim with the
    # summary path — rows and opened objects cannot disagree. packages carry no
    # verdict: an inventory has no health.
    _RULES = {"generations": generation_opinions}

    async def get_object(self, collection: str, object_id: str) -> dict:
        fetched = await anyio.to_thread.run_sync(self._items, collection)
        match = next((i for i in fetched if i["id"] == object_id), None)
        if match is None:
            raise env.UnknownObject(object_id)
        rule = self._RULES.get(collection)
        opinions = rule(match["facts"]) if rule else []
        return env.observation(
            self.subsystem,
            env.obj_ref(object_id, match["type"], match["native_id"]),
            self._source(collection), match["facts"], opinions=opinions,
            evidence_ref=f"/v1/nix/{collection}/{object_id}/evidence")

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        if collection == "generations":
            number = object_id.removeprefix("generation:")
            link = nx.PROFILES / f"system-{number}-link"
            if not link.is_symlink():
                raise env.UnknownObject(object_id)
            target = os.readlink(link)
            return {
                "object_id": object_id,
                "captured_at": env.utc_now(),
                "interface": "/nix/var/nix/profiles (filesystem)",
                "payload": {
                    "link": str(link), "target": target,
                    "pointers": nx.pointers(),
                    "nixos-version": nx.read(f"{target}/nixos-version"),
                    "configuration-revision": nx.read(f"{target}/configuration-revision"),
                    "kernel": nx.realpath(f"{target}/kernel"),
                },
            }
        if collection == "packages":
            name_version = object_id.removeprefix("package:")
            store_path = self._package_paths().get(name_version)
            if store_path is None:
                raise env.UnknownObject(object_id)
            links = {}
            for sub in SW_SUBDIRS:
                root = os.path.join(nx.SW, sub)
                try:
                    for entry in os.scandir(root):
                        if entry.is_symlink():
                            target = os.readlink(entry.path)
                            if target.startswith(store_path + "/"):
                                links[f"{sub}/{entry.name}"] = target
                except OSError:
                    continue
            return {
                "object_id": object_id,
                "captured_at": env.utc_now(),
                "interface": "/run/current-system/sw (filesystem)",
                "payload": {"store_path": store_path, "links": links},
            }
        raise env.UnknownCollection(collection)
