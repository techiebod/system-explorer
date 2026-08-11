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
                         "readlink -f /run/current-system /run/booted-system",
                         f"cat /nix/var/nix/profiles/system-*-link/{nx.GENERATION_MANIFEST}",
                         "cat $SE_DEPLOYMENT_RECEIPTS/<generation>.json"]
STORE_RE = re.compile(r"(/nix/store/[a-z0-9]{32}-([^/]+))")
# name-version split: the version starts at the first dash followed by a digit.
NAME_VERSION_RE = re.compile(r"(.+?)-([0-9].*)")


def _input_identity(entry: object) -> str | None:
    """How an input is identified for comparison: its revision, or its content
    hash where it has no revision (a path or tarball input has no commit)."""
    if not isinstance(entry, dict):
        return None
    return entry.get("revision") or entry.get("narHash")


def _delta_rows(older: dict, newer: dict) -> list[dict]:
    """What changed between two generations' manifests.

    Deliberately a comparison of two recorded manifests rather than a diff of two
    closures. `nvd` and `nix store diff-closures` have no structured output, so an
    adapter running one would be executing a reference command and parsing its
    prose — which SPEC rule 5 forbids, and no allowlist entry could make correct.
    Whatever built these closures already knew what went into them; reading what
    it recorded is the honest route to the same answer.

    Uniform {Kind, Name, From, To} rows so the UI renders them as one table and
    an opinion can cite DeltaFromPrevious.<n>.Name.
    """
    rows: list[dict] = []
    if older.get("revision") != newer.get("revision"):
        rows.append({"Kind": "revision", "Name": "configuration",
                     "From": older.get("revision"), "To": newer.get("revision")})
    old_inputs = older.get("inputs") if isinstance(older.get("inputs"), dict) else {}
    new_inputs = newer.get("inputs") if isinstance(newer.get("inputs"), dict) else {}
    for name in sorted(set(old_inputs) | set(new_inputs)):
        before = _input_identity(old_inputs.get(name))
        after = _input_identity(new_inputs.get(name))
        if before != after:
            rows.append({"Kind": "input", "Name": name, "From": before, "To": after})
    return rows


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
    def _delta_facts(self, number: int, manifest: dict,
                     previous: int | None, manifests: dict[int, dict | None]) -> dict:
        """What this generation changed, against the previous one still present.

        "Previous" is the next generation number that has not been collected, not
        necessarily number - 1, so it is named in a fact rather than implied — a
        delta against generation 84 when 85 was garbage-collected is a true
        statement about a different span than the reader would assume.
        """
        if previous is None:
            return {"DeltaFromPrevious": None,
                    "DeltaFromPreviousUnobservable":
                        f"Generation {number} is the oldest still present on this "
                        "host, so there is nothing here to compare it against."}
        older = manifests.get(previous)
        if older is None:
            return {"ComparedWithGeneration": previous,
                    "DeltaFromPrevious": None,
                    "DeltaFromPreviousUnobservable":
                        f"Generation {previous} carries no {nx.GENERATION_MANIFEST}, "
                        "so it records nothing to compare against. Comparison begins "
                        "at the first generation built after that file existed."}
        return {"ComparedWithGeneration": previous,
                "DeltaFromPrevious": _delta_rows(older, manifest)}

    def _deployment_facts(self, number: int, manifest: dict,
                          receipts_visible: bool) -> dict:
        """How this generation came to be, where that was recorded.

        Both conditions matter before claiming anything. The closure must say that
        receipts are expected — an older generation predates the workflow, and its
        lack of one means nothing — and this agent must be able to see them at all.
        Without both, the facts are omitted rather than nulled, because "no receipt
        exists" and "I cannot see receipts" are different statements and only the
        first is about the deployment.
        """
        schema = manifest.get("schema")
        expected = (bool(manifest.get("receiptsExpected"))
                    and isinstance(schema, int)
                    and schema >= nx.RECEIPTS_EXPECTED_SCHEMA)
        if not (expected and receipts_visible):
            return {}
        receipt = nx.deployment_receipt(number)
        if receipt is None:
            return {"ReceiptsExpected": True, "Deployment": None}
        activation = receipt.get("activation")
        activation = activation if isinstance(activation, dict) else {}
        return {"ReceiptsExpected": True,
                "Deployment": {
                    "Mode": activation.get("mode"),
                    "Outcome": activation.get("outcome"),
                    "VerifiedAt": activation.get("verified_at"),
                    "Risks": receipt.get("risks") or [],
                    "SourceRevision": (receipt.get("source") or {}).get("git_revision"),
                }}

    def _generation_items(self) -> list[dict]:
        pointers = nx.pointers()
        links = nx.generation_links()
        # Read every manifest once: each generation's delta needs its neighbour's.
        manifests = {number: nx.generation_manifest(target)
                     for number, _, target in links}
        receipts_visible = nx.receipts_dir() is not None
        items = []
        for index, (number, link, target) in enumerate(links):
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
            # Absent on a generation that carries no manifest — which is every
            # generation on a host whose closures are built without one, and the
            # older generations on a host that started recently. Omitted, not
            # nulled: "does not record this" is not "unknown" (SPEC rule 7).
            manifest = manifests[number]
            if manifest is not None:
                previous = links[index + 1][0] if index + 1 < len(links) else None
                facts.update(self._delta_facts(number, manifest, previous, manifests))
                facts.update(self._deployment_facts(number, manifest, receipts_visible))
            # Only the running generation is positively vouched for; the rest
            # are neutral history unless a rule fires.
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
                    nx.GENERATION_MANIFEST: nx.generation_manifest(target),
                    "deployment-receipt": nx.deployment_receipt(int(number)),
                },
            }
        raise env.UnknownCollection(collection)
