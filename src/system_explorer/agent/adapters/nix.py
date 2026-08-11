"""nix subsystem: the deployment itself — generations of the system closure.

Split out of `system` because a generation is the one thing here that does not
exist on every host this agent targets, and mixing it in made both halves
worse: on Debian it was an odd declining row inside an otherwise universal
subsystem, and on NixOS it sat beside identity and time as if it were the same
kind of fact as a hostname. A non-Nix host now declines one subsystem with one
reason, and the operator UI — whose navigation is generated from
/v1/capabilities — gets the deployment in its own section for free.

Packages started here too and moved on the same day, to their own subsystem:
"what is installed" is a question dpkg and rpm answer as readily as the store,
so keeping it Nix-shaped left non-Nix hosts with no inventory at all. What
remains is genuinely Nix-only.

No subprocess: the profile link farm and the metadata files every closure
carries. agent/nixos.py holds the primitives, shared with the `system`
adapter's identity and boot-pointer facts.
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
STORE_RE = re.compile(r"(/nix/store/[a-z0-9]{32}-([^/]+))")
# name-version split: the version starts at the first dash followed by a digit.
NAME_VERSION_RE = re.compile(r"(.+?)-([0-9].*)")


class Adapter:
    subsystem = "nix"

    def collections(self) -> list[str]:
        # generations only. Packages moved to their own subsystem: the question
        # "what is installed" is universal and dpkg and rpm answer it as readily
        # as the store, whereas a generation has no equivalent anywhere else.
        return ["generations"]

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

    # ── plumbing ─────────────────────────────────────────────
    def _source(self, collection: str) -> dict:
        if collection != "generations":
            raise env.UnknownCollection(collection)
        return env.source("nixos-fs", "/nix/var/nix/profiles (filesystem)",
                          GENERATIONS_REFERENCE)

    def _items(self, collection: str) -> list[dict]:
        if collection != "generations":
            raise env.UnknownCollection(collection)
        return self._generation_items()

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

    # The evaluator (agent/rules/nix.py), shared verbatim with the summary path
    # so rows and opened objects cannot disagree.
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
        raise env.UnknownCollection(collection)
