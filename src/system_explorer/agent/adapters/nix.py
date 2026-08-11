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
    """Every path under a generation's /etc, mapped to an exact identity.

    A NixOS /etc is mostly symlinks into the store plus a handful of tiny files,
    so a symlink's target and a small file's content hash are both exact
    identities and a per-file comparison needs no diff tool and no subprocess.

    Symlinked directories are followed, and both the link and what is under it are
    recorded. Stopping at them was the first attempt and it reported
    "etc/systemd/system changed" without naming a unit — the same withholding as
    the single /etc row it replaced, one level down. NixOS builds those aggregates
    precisely so /etc can declare their contents, so their contents are what /etc
    declares.

    Bounded against a symlink cycle by realpath rather than by depth alone, since a
    cycle is the one shape here that is unbounded rather than merely large.
    """
    if not etc_root:
        return {}

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
                # Record the link itself AND descend, so a changed aggregate can
                # be reported either as its members or, when there are too many,
                # as itself.
                if entry.is_dir():
                    walk(entry.path, f"{name}/", depth + 1)
            elif entry.is_dir(follow_symlinks=False):
                walk(entry.path, f"{name}/", depth + 1)
            else:
                entries[name] = _file_identity(entry.path)

    walk(etc_root, "", 0)
    return entries


def _has_members(path: str, older: dict[str, str], newer: dict[str, str]) -> bool:
    """Whether this entry is a directory with contents on both sides."""
    prefix = f"{path}/"
    return (any(p.startswith(prefix) for p in older)
            and any(p.startswith(prefix) for p in newer))


def _etc_rows(older_root: str | None, newer_root: str | None,
              older: dict[str, str], newer: dict[str, str]) -> list[dict]:
    """Which files under /etc changed, one row each.

    The first version reported a single row carrying the two /etc store paths,
    which is a true statement an administrator can do nothing with: it says
    something under /etc moved and refuses to say what. Naming the paths is the
    whole value, and it is readable directly out of both closures.

    A directory whose members nearly all moved is reported as itself with a count.
    /etc/terminfo is one symlink to a database of some 2500 files that all change
    together whenever ncurses moves, and listing them would bury the four unit
    files an operator actually wants to see. The collapse is stated in the row, so
    it is a summary rather than a silent truncation.

    What changed *inside* a file is a further question, and `make config-diff`
    answers it against a candidate.
    """
    differing = [path for path in sorted(set(older) | set(newer))
                 if older.get(path) != newer.get(path)]
    changed = set(differing)

    # Longest first, so a nested aggregate collapses before its parent does.
    collapsed: list[tuple[str, int]] = []
    for path in sorted(differing, key=len, reverse=True):
        members = [p for p in changed if p.startswith(f"{path}/")]
        if len(members) > ETC_COLLAPSE_OVER:
            collapsed.append((path, len(members)))

    def inside_collapsed(path: str) -> bool:
        return any(path.startswith(f"{prefix}/") for prefix, _ in collapsed)

    def row(name: str, before: str | None, after: str | None) -> dict:
        label_before, label_after = _distinguishable(_short_identity(before),
                                                     _short_identity(after))
        return {"Kind": "etc", "Name": name, "From": label_before, "To": label_after}

    collapsed_names = {prefix for prefix, _ in collapsed}
    rows = []
    for path in differing:
        if inside_collapsed(path):
            continue
        if path in collapsed_names:
            count = next(n for prefix, n in collapsed if prefix == path)
            rows.append(row(f"etc/{path} ({count} entries changed)",
                            older.get(path), newer.get(path)))
            continue
        # A directory whose members are listed individually adds nothing itself.
        members = [p for p in changed if p.startswith(f"{path}/")]
        if members:
            continue
        # An aggregate whose identity moved while every member stayed identical.
        # Store paths are input-addressed, so a rebuild relocates byte-identical
        # content: /etc/terminfo moves whenever ncurses is rebuilt and says
        # nothing about the machine. Reported, because it did move, but labelled,
        # because "terminfo changed" would send an operator looking for a change
        # that is not there.
        if path in older and path in newer and _has_members(path, older, newer):
            rows.append(row(f"etc/{path} (identity moved, contents identical)",
                            older.get(path), newer.get(path)))
            continue
        rows.append(row(f"etc/{path}", older.get(path), newer.get(path)))

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
                     environments: dict[int, dict[str, str]],
                     etc_paths: dict[int, str | None],
                     etc_trees: dict[int, dict[str, str]],
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
        rows += _etc_rows(etc_paths.get(previous), etc_paths.get(number),
                          etc_trees.get(previous, {}), etc_trees.get(number, {}))
        rows += _package_rows(environments.get(previous, {}), environments.get(number, {}))

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
        environments = {number: nx.store_paths(f"{target}/sw")
                        for number, _, target in links}
        etc_paths = {number: nx.realpath(f"{target}/etc")
                     for number, _, target in links}
        etc_trees = {number: _etc_entries(path) for number, path in etc_paths.items()}
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
                                           environments, etc_paths, etc_trees,
                                           detailed))
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
