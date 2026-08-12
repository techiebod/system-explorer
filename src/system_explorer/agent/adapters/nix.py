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

import hashlib
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
# Ceiling on hashing one real file under /etc. The sidecars there are bytes; this
# only bounds the unexpected.
ETC_HASH_LIMIT = 1 << 20
# Depth ceiling and the size at which a changed directory is reported as itself
# rather than as its members. terminfo alone is ~2500 files that move together.
ETC_MAX_DEPTH = 8
ETC_COLLAPSE_OVER = 12
# Above this many entries an aggregate is summarised without being read. Unit
# directories sit in the hundreds and stay enumerated; terminfo and zoneinfo are
# thousands and are databases whose individual members mean nothing here.
ETC_ENUMERATE_OVER = 1000


def _input_identity(entry: object) -> str | None:
    """How an input is identified for comparison: its revision, or its content
    hash where it has no revision (a path or tarball input has no commit)."""
    if not isinstance(entry, dict):
        return None
    return entry.get("revision") or entry.get("narHash")


def _package_rows(older: dict[str, str], newer: dict[str, str]) -> list[dict]:
    """Which packages moved between two generations' system environments.

    Keyed on the name so an upgrade is one row with both versions rather than an
    add and a remove that the reader has to pair up themselves. A package present
    on one side only gets a null on the other.
    """
    def by_name(paths: dict[str, str]) -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        for name_version in paths:
            match = NAME_VERSION_RE.match(name_version)
            name, version = (match.group(1), match.group(2)) if match else (name_version, None)
            out[name] = version
        return out

    old_versions, new_versions = by_name(older), by_name(newer)
    rows = []
    for name in sorted(set(old_versions) | set(new_versions)):
        before, after = old_versions.get(name), new_versions.get(name)
        if before != after or (name in old_versions) != (name in new_versions):
            rows.append({"Kind": "package", "Name": name, "From": before, "To": after})
    return rows


def _etc_identity(path: str | None) -> str | None:
    """The store directory a generation's /etc came out of, hash included.

    Not the basename of the path: a generation symlinks $out/etc at
    `<store path>/etc`, so basename is the literal "etc" for every generation ever
    built, and a row reporting a change rendered as "etc -> etc". The store
    directory name is what distinguishes them.
    """
    if not path:
        return None
    match = nx.STORE_RE.match(path)
    return os.path.basename(match.group(1)) if match else path


def _short_identity(value: str | None) -> str | None:
    """A comparable label for one /etc entry.

    Store paths reduce to their hash, so a changed file reads as one short token
    rather than a 60-character path whose only varying part is at the front. A
    content hash is already in that form.
    """
    if value is None:
        return None
    match = nx.STORE_RE.match(value)
    if match:
        return os.path.basename(match.group(1))[:32]
    return value


def _distinguishable(before: str | None, after: str | None) -> tuple[str | None, str | None]:
    """Abbreviate a pair only while the short forms still tell them apart.

    Same rule the preview's Inputs section needed: abbreviating unconditionally is
    how a row reporting a change ends up rendering the two sides identically.
    """
    if not before or not after:
        return before, after
    if before[:12] == after[:12]:
        return before, after
    return before[:12], after[:12]


def _file_identity(path: str) -> str:
    """Content hash of a real file under /etc, bounded.

    A NixOS /etc holds a dozen tiny sidecars recording ownership and mode, so
    hashing them is nothing. The cap exists because this reads whatever the tree
    actually contains, and an unbounded read is not something to leave to chance.
    """
    try:
        with open(path, "rb") as handle:
            data = handle.read(ETC_HASH_LIMIT + 1)
    except OSError:
        return "unreadable"
    if len(data) > ETC_HASH_LIMIT:
        try:
            return f"size:{os.path.getsize(path)}"
        except OSError:
            return "unreadable"
    return hashlib.sha256(data).hexdigest()[:16]


def _etc_entries(etc_root: str | None) -> dict[str, str]:
    """One level of a generation's /etc: symlinks as leaves, real files hashed.

    Deliberately NOT recursive through symlinks. An earlier version followed them
    and turned a 170-entry walk into 6190 entries per generation, 2899 of which
    are terminfo files it then hashed — across 29 generations that made this
    collection take 4.9 seconds while every other one answered in under 20ms.

    It is not needed, either. A store path is input-addressed, so a symlink's
    target identifies its entire contents: two generations whose etc/terminfo
    points at the same path cannot differ underneath it. Descending is only
    informative where the target actually moved, and _aggregate_rows does that for
    one pair at a time.
    """
    if not etc_root:
        return {}

    entries: dict[str, str] = {}

    def walk(base: str, prefix: str, depth: int) -> None:
        if depth > ETC_MAX_DEPTH:
            return
        try:
            found = list(os.scandir(base))
        except OSError:
            return
        for entry in found:
            name = f"{prefix}{entry.name}"
            if entry.is_symlink():
                try:
                    entries[name] = os.readlink(entry.path)
                except OSError:
                    entries[name] = "unreadable"
            elif entry.is_dir(follow_symlinks=False):
                walk(entry.path, f"{name}/", depth + 1)
            else:
                entries[name] = _file_identity(entry.path)

    walk(etc_root, "", 0)
    return entries


def _tree_entries(root: str, cache: dict[str, dict[str, str]]) -> dict[str, str]:
    """Everything under one store directory, recursively, memoised by path.

    Only reached for an aggregate whose identity moved. Store paths are immutable,
    so memoising by path is sound for the life of the process and two adjacent
    generations sharing one aggregate walk it once.

    Bounded against a symlink cycle by realpath, since a cycle is the one shape
    here that is unbounded rather than merely large.
    """
    if root in cache:
        return cache[root]
    entries: dict[str, str] = {}
    visited: set[str] = set()

    def walk(base: str, prefix: str, depth: int) -> None:
        if depth > ETC_MAX_DEPTH:
            return
        try:
            real = os.path.realpath(base)
        except OSError:
            return
        if real in visited:
            return
        visited.add(real)
        try:
            found = list(os.scandir(base))
        except OSError:
            return
        for entry in found:
            name = f"{prefix}{entry.name}"
            if entry.is_symlink():
                try:
                    entries[name] = os.readlink(entry.path)
                except OSError:
                    entries[name] = "unreadable"
                if entry.is_dir():
                    walk(entry.path, f"{name}/", depth + 1)
            elif entry.is_dir(follow_symlinks=False):
                walk(entry.path, f"{name}/", depth + 1)
            else:
                entries[name] = _file_identity(entry.path)

    walk(root, "", 0)
    cache[root] = entries
    return entries


def _tree_size(root: str) -> int:
    """How many entries are under a store directory, by scandir alone.

    No readlink and no reads: deciding whether an aggregate is worth enumerating
    must not cost what enumerating it would. Counting all of terminfo this way is
    about a millisecond; hashing it is a hundred times that.
    """
    total = 0
    visited: set[str] = set()
    stack = [(root, 0)]
    while stack:
        base, depth = stack.pop()
        if depth > ETC_MAX_DEPTH:
            continue
        try:
            real = os.path.realpath(base)
        except OSError:
            continue
        if real in visited:
            continue
        visited.add(real)
        try:
            found = list(os.scandir(base))
        except OSError:
            continue
        for entry in found:
            total += 1
            # Descend exactly where _tree_entries would, symlinked directories
            # included. A gate that measures something other than what it gates
            # does not gate it: counting without following left terminfo looking
            # like 26 entries, so it sailed under the limit and was then walked
            # and hashed in full anyway.
            if entry.is_symlink():
                if entry.is_dir():
                    stack.append((entry.path, depth + 1))
            elif entry.is_dir(follow_symlinks=False):
                stack.append((entry.path, depth + 1))
    return total


def _aggregate_rows(path: str, older_target: str, newer_target: str,
                    cache: dict[str, dict[str, str]]) -> list[dict]:
    """Members of one moved aggregate directory, or a labelled summary of it.

    NixOS builds etc/systemd/system and friends as a single store symlink
    precisely so /etc can declare their contents, so naming the units inside is
    the whole point. Two shapes are not worth enumerating: a database that moved
    wholesale, and one that did not really move at all.
    """
    def row(name: str, before: str | None, after: str | None) -> dict:
        label_before, label_after = _distinguishable(_short_identity(before),
                                                     _short_identity(after))
        return {"Kind": "etc", "Name": name, "From": label_before, "To": label_after}

    # Some aggregates are databases, not configuration. terminfo is 2899 files
    # that move together whenever ncurses is rebuilt, and enumerating it can only
    # ever produce the collapsed row below — so measure first, cheaply, and skip
    # reading 35,000 files across a generation list to reach a foregone
    # conclusion. Sized rather than named, because a size rule keeps working when
    # the next such directory appears under a name nobody predicted.
    size = max(_tree_size(older_target), _tree_size(newer_target))
    if size > ETC_ENUMERATE_OVER:
        return [row(f"etc/{path} ({size} entries, not enumerated)",
                    older_target, newer_target)]

    older = _tree_entries(older_target, cache)
    newer = _tree_entries(newer_target, cache)
    changed = [name for name in sorted(set(older) | set(newer))
               if older.get(name) != newer.get(name)]

    # Store paths are input-addressed, so a rebuild relocates byte-identical
    # content: terminfo moves whenever ncurses does and says nothing about the
    # machine. Reported, because it moved, but labelled, so nobody goes looking.
    if not changed:
        return [row(f"etc/{path} (identity moved, contents identical)",
                    older_target, newer_target)]
    # A database that changed wholesale would bury the units an operator wants.
    # A summary that states its count, not a silent truncation.
    if len(changed) > ETC_COLLAPSE_OVER:
        return [row(f"etc/{path} ({len(changed)} entries changed)",
                    older_target, newer_target)]
    return [row(f"etc/{path}/{name}", older.get(name), newer.get(name))
            for name in changed]


def _both_directories(older_target: str, newer_target: str) -> bool:
    """Whether an /etc entry is a directory on both sides, so worth expanding."""
    try:
        return os.path.isdir(older_target) and os.path.isdir(newer_target)
    except OSError:
        return False


def _etc_rows(older_root: str | None, newer_root: str | None,
              older: dict[str, str], newer: dict[str, str],
              cache: dict[str, dict[str, str]]) -> list[dict]:
    """Which files under /etc changed, one row each.

    The first version reported a single row carrying the two /etc store paths,
    which is a true statement an administrator can do nothing with: it says
    something under /etc moved and refuses to say what. Naming the paths is the
    whole value, and it is readable directly out of both closures.

    A changed entry that is a directory on both sides is expanded here and only
    here — one pair, one aggregate, on demand.

    What changed *inside* a file is a further question.
    """
    rows = []
    for path in sorted(set(older) | set(newer)):
        before, after = older.get(path), newer.get(path)
        if before == after:
            continue
        if before and after and _both_directories(before, after):
            rows += _aggregate_rows(path, before, after, cache)
            continue
        label_before, label_after = _distinguishable(_short_identity(before),
                                                     _short_identity(after))
        rows.append({"Kind": "etc", "Name": f"etc/{path}",
                     "From": label_before, "To": label_after})

    # The trees are content-addressed, so differing roots with no file-level
    # explanation means this walk missed something. Say that rather than nothing.
    if not rows and older_root and newer_root and older_root != newer_root:
        rows.append({"Kind": "etc", "Name": "/etc (no file-level difference found)",
                     "From": _etc_identity(older_root), "To": _etc_identity(newer_root)})
    return rows


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
    old_revision, new_revision = older.get("revision"), newer.get("revision")
    if old_revision != new_revision:
        rows.append({"Kind": "revision", "Name": "configuration",
                     "From": old_revision, "To": new_revision})
    old_inputs = older.get("inputs") if isinstance(older.get("inputs"), dict) else {}
    new_inputs = newer.get("inputs") if isinstance(newer.get("inputs"), dict) else {}
    for name in sorted(set(old_inputs) | set(new_inputs)):
        before = _input_identity(old_inputs.get(name))
        after = _input_identity(new_inputs.get(name))
        if before == after:
            continue
        # The configuration's own source is usually also one of its inputs, so
        # reporting both restates one change as two. Suppressed by matching the
        # pair rather than by the input's name, which no contract fixes.
        if (before, after) == (old_revision, new_revision):
            continue
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
    def _delta_facts(self, number: int, previous: int | None,
                     manifests: dict[int, dict | None],
                     sw_paths: dict[int, str | None],
                     etc_paths: dict[int, str | None],
                     environments: dict[str, dict[str, str]],
                     etc_trees: dict[str, dict[str, str]],
                     aggregate_cache: dict[str, dict[str, str]],
                     detailed: bool) -> dict:
        """What this generation changed, against the previous one still present.

        "Previous" is the next generation number that has not been collected, not
        necessarily number - 1, so it is named in a fact rather than implied — a
        delta against generation 84 when 85 was garbage-collected is a true
        statement about a different span than the reader would assume.

        The rows themselves are carried only on an opened object. A nixpkgs bump
        moves hundreds of packages, and a collection page is asked for a hundred
        generations at a time; DeltaCounts is what a row needs and is always
        present. This is a payload decision, not an acquisition one — the walk has
        already happened either way — so both surfaces agree on the counts and
        neither can disagree about severity.
        """
        if previous is None:
            return {"DeltaFromPrevious": None,
                    "DeltaFromPreviousUnobservable":
                        f"Generation {number} is the oldest still present on this "
                        "host, so there is nothing here to compare it against."}

        facts: dict = {"ComparedWithGeneration": previous}
        rows: list[dict] = []
        older, newer = manifests.get(previous), manifests.get(number)
        if older is not None and newer is not None:
            rows += _delta_rows(older, newer)
        else:
            missing = previous if older is None else number
            facts["DeltaFromPreviousPartial"] = (
                f"Package and /etc changes below are read from the closures "
                f"themselves, so they are complete. Generation {missing} carries no "
                f"{nx.GENERATION_MANIFEST} though, so the configuration revision and "
                "flake inputs could not be compared.")
        def walked(path: str | None, cache: dict[str, dict[str, str]],
                   reader) -> dict[str, str]:
            if not path:
                return {}
            if path not in cache:
                cache[path] = reader(path)
            return cache[path]

        older_etc, newer_etc = etc_paths.get(previous), etc_paths.get(number)
        if older_etc != newer_etc:
            rows += _etc_rows(older_etc, newer_etc,
                              walked(older_etc, etc_trees, _etc_entries),
                              walked(newer_etc, etc_trees, _etc_entries),
                              aggregate_cache)
        older_sw, newer_sw = sw_paths.get(previous), sw_paths.get(number)
        if older_sw != newer_sw:
            rows += _package_rows(walked(older_sw, environments, nx.store_paths),
                                  walked(newer_sw, environments, nx.store_paths))

        counts: dict[str, int] = {}
        for row in rows:
            counts[row["Kind"]] = counts.get(row["Kind"], 0) + 1
        facts["DeltaCounts"] = counts
        if detailed:
            facts["DeltaFromPrevious"] = rows
        return facts

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

    def _generation_items(self, detailed: bool = False) -> list[dict]:
        pointers = nx.pointers()
        links = nx.generation_links()
        # Read each source once: every generation's delta needs its neighbour's.
        manifests = {number: nx.generation_manifest(target)
                     for number, _, target in links}
        # The link farm and the /etc symlink are inside every closure, so these
        # two comparisons work where no manifest does — including retroactively,
        # for generations built before se-generation.json existed at all.
        # Both of these are store symlinks, so comparing the targets is a cheap
        # proxy for comparing what is under them: identical targets cannot differ.
        # Walking is deferred to the pairs that actually moved, memoised by path,
        # because a store path is immutable and 29 generations share many of them.
        sw_paths = {number: nx.realpath(f"{target}/sw")
                    for number, _, target in links}
        etc_paths = {number: nx.realpath(f"{target}/etc")
                     for number, _, target in links}
        environments: dict[str, dict[str, str]] = {}
        etc_trees: dict[str, dict[str, str]] = {}
        aggregate_cache: dict[str, dict[str, str]] = {}
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
            previous = links[index + 1][0] if index + 1 < len(links) else None
            facts.update(self._delta_facts(number, previous, manifests,
                                           sw_paths, etc_paths, environments,
                                           etc_trees, aggregate_cache, detailed))
            # Deployment facts are absent on a generation that carries no manifest
            # — every generation on a host whose closures are built without one,
            # and the older ones on a host that started recently. Omitted, not
            # nulled: "does not record this" is not "unknown" (SPEC rule 7).
            manifest = manifests[number]
            if manifest is not None:
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

    def _items(self, collection: str, detailed: bool = False) -> list[dict]:
        if collection != "generations":
            raise env.UnknownCollection(collection)
        return self._generation_items(detailed)

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        """The full materialisation, shared: collect() pages it and main.py's
        status/snapshot/changes sweeps consume it directly instead of
        re-acquiring per page. Single-flighted so concurrent callers ride one
        acquisition (envelope.single_flight — coalescing, not caching).

        Summary payload only: DeltaCounts, never the delta rows themselves —
        the payload decision _delta_facts records. get_object() runs its own
        detailed walk for exactly that reason, so it does not route here.
        """
        # The link-farm and profile scandir walks are synchronous filesystem
        # work — off the event loop like every other adapter's acquisition
        # (backlog note, 2026-08-09: async hygiene).
        return await anyio.to_thread.run_sync(self._items, collection)

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        fetched = await self.acquire(collection)
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
        # Not routed through acquire(): the detailed flag carries the
        # DeltaFromPrevious rows only an opened object shows, so this walk is
        # the same acquisition with a different payload, not a duplicate of it.
        fetched = await anyio.to_thread.run_sync(self._items, collection, True)
        match = next((i for i in fetched if i["id"] == object_id), None)
        if match is None:
            raise env.UnknownObject(object_id)
        rule = self._RULES.get(collection)
        opinions = rule(match["facts"]) if rule else []
        return env.observation(
            self.subsystem,
            env.obj_ref(object_id, match["type"], match["native_id"]),
            self._source(collection), match["facts"], opinions=opinions,
            evidence_ref=env.evidence_ref("nix", collection, object_id))

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
