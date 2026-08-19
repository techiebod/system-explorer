"""packages subsystem: what is installed, whoever installed it.

Split out of `nix` on the second day of the portability work, because the
question is universal and only the answer is not. `nix/packages` read the
/run/current-system/sw link farm, so on Debian the product had NO package
inventory at all — it declined the whole subsystem honestly and left an operator
with no way to ask a question every host can answer. Honest absence is right for
something a host genuinely cannot do; it is the wrong answer to "which packages
are installed", which dpkg and rpm answer as readily as the Nix store.

`nix` keeps generations, which really is Nix-only and has no equivalent
elsewhere. Packages come here with a Manager fact saying who is speaking, so the
operator asks one question and the answer names its own provenance.

Acquisition, in the order preferred where more than one exists:

  nix     the /run/current-system/sw link farm — no subprocess at all, the
          store IS the structured interface.
  dpkg    dpkg-query -W with an explicit -f format string.
  rpm     rpm -qa with an explicit --qf format string.

The two subprocess forms are the opposite of parsing human output: the format is
supplied by this file, so the fields and their order are ours and cannot drift
under a locale or a version. That is why they are allow-listed on their format
flags (conformance/common.py) rather than on a --json neither tool has.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

import anyio

from .. import envelope as env
from .. import nixos as nx

# Tab-separated because a package version can contain almost anything except a
# tab, and a field count we chose is a contract we can check.
DPKG_FORMAT = "${Package}\\t${Version}\\t${Architecture}\\t${db:Status-Status}\\n"
RPM_FORMAT = "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{ARCH}\\n"

STORE_RE = re.compile(r"(/nix/store/[a-z0-9]{32}-([^/]+))")
NAME_VERSION_RE = re.compile(r"(.+?)-([0-9].*)")
# One definition, in the module that owns the NixOS read surface.
SW_SUBDIRS = nx.SW_SUBDIRS

REFERENCE = {
    "nix": ["ls /run/current-system/sw/bin",
            "readlink /run/current-system/sw/bin/<command>"],
    "dpkg": ["dpkg-query -W", "dpkg -l"],
    "rpm": ["rpm -qa"],
}


def _dpkg_rows() -> list[list[str]]:
    proc = subprocess.run(["dpkg-query", "-W", "-f", DPKG_FORMAT],
                          capture_output=True, text=True, timeout=30, check=True)
    return [line.split("\t") for line in proc.stdout.splitlines() if line.strip()]


def _rpm_rows() -> list[list[str]]:
    proc = subprocess.run(["rpm", "-qa", "--qf", RPM_FORMAT],
                          capture_output=True, text=True, timeout=60, check=True)
    return [line.split("\t") for line in proc.stdout.splitlines() if line.strip()]


def _nix_store_paths() -> dict[str, str]:
    """name-version → store path for the running system environment.

    The walk itself lives in agent/nixos.py, parameterised by environment root,
    because `nix` needs the identical read against `<generation>/sw` to compare
    two generations' package sets. One reader, two callers, rather than an
    adapter importing another adapter.
    """
    return nx.store_paths(nx.SW)


def _detect() -> str | None:
    """Which manager can answer here. Nix first where a closure is activated:
    on NixOS it is the truth about the system environment, and dpkg is not
    installed at all."""
    if nx.is_nixos() and os.path.isdir(nx.SW):
        return "nix"
    if shutil.which("dpkg-query"):
        return "dpkg"
    if shutil.which("rpm"):
        return "rpm"
    return None


class Adapter:
    subsystem = "packages"

    def __init__(self) -> None:
        # Probed once per request rather than cached: SPEC rule 4 forbids
        # carrying a capability answer between requests, and shutil.which on
        # two names is not a cost worth breaking that for.
        pass

    def collections(self) -> list[str]:
        return ["packages"]

    async def capability(self) -> dict:
        manager = await anyio.to_thread.run_sync(_detect)
        if manager is None:
            return {"available": False,
                    "reason": "no package manager this agent can read: neither an "
                              "activated Nix system closure, nor dpkg-query, nor "
                              "rpm is present"}
        return {"available": True, "collections": self.collections(),
                "manager": manager}

    def _check(self, collection: str) -> None:
        if collection != "packages":
            raise env.UnknownCollection(collection)

    @staticmethod
    def _items(manager: str) -> list[dict]:
        items: list[dict] = []
        if manager == "nix":
            for name_version, store_path in sorted(_nix_store_paths().items()):
                match = NAME_VERSION_RE.match(name_version)
                items.append(env.item_summary(
                    f"package:{name_version}", "package", name_version, {
                        "Name": match.group(1) if match else name_version,
                        "Version": match.group(2) if match else None,
                        "Manager": "nix",
                        "StorePath": store_path,
                    }))
        elif manager == "dpkg":
            for row in _dpkg_rows():
                name, version, arch, status = (row + ["", "", ""])[:4]
                # dpkg keeps rows for packages that are removed-but-configured.
                # Only installed ones are installed, which is the question.
                if status and status != "installed":
                    continue
                items.append(env.item_summary(
                    f"package:{name}", "package", name, {
                        "Name": name, "Version": version or None,
                        "Manager": "dpkg", "Architecture": arch or None,
                    }))
        elif manager == "rpm":
            for row in _rpm_rows():
                name, version, arch = (row + ["", ""])[:3]
                items.append(env.item_summary(
                    f"package:{name}", "package", name, {
                        "Name": name, "Version": version or None,
                        "Manager": "rpm", "Architecture": arch or None,
                    }))
        else:
            # A manager this collector does not read is NOT an empty inventory.
            #
            # RULED 2026-08-19: an empty commit is authoritative-empty and
            # retires, so it is not available to a collector that could not
            # read. Falling through these branches used to return [], and
            # `acquire` handed that to the caller as a successful reading — so
            # a host whose manager this code does not recognise had its ENTIRE
            # package inventory retired on the strength of a word nobody
            # understood, with no decline record anywhere to say so. Reproduced
            # by staging a manager of "pacman".
            #
            # Raising is what the Go port already does ("I could not run"), and
            # over the HTTP contract it is correctly an error envelope. Neither
            # establishes anything, which is the truth here.
            raise RuntimeError(
                f"package manager {manager!r} was detected but this collector "
                "cannot read it — no inventory was established, and an empty "
                "one would retire every package this host has published"
            )
        items.sort(key=lambda i: (i["facts"]["Name"], i["native_id"]))
        return items

    def _source(self, manager: str) -> dict:
        interface = {"nix": "/run/current-system/sw (filesystem)",
                     "dpkg": "dpkg database",
                     "rpm": "rpm database"}[manager]
        return env.source(f"{manager}-packages", interface, REFERENCE[manager])

    async def _manager(self) -> str:
        manager = await anyio.to_thread.run_sync(_detect)
        if manager is None:
            # main.py gates on capability() first, so reaching here means the
            # manager vanished between the two — an error envelope, not a crash.
            raise RuntimeError("no readable package manager on this host")
        return manager

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        """The full materialisation, shared: collect() pages it, get_object
        searches it, and main.py's status/snapshot/changes sweeps consume it
        directly instead of re-acquiring per page. Single-flighted so
        concurrent callers ride one acquisition (envelope.single_flight —
        coalescing, not caching)."""
        self._check(collection)
        manager = await self._manager()
        return await anyio.to_thread.run_sync(self._items, manager)

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        fetched = await self.acquire(collection)
        manager = await self._manager()
        items = env.apply_fact_filters(fetched, query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection,
                                   self._source(manager), page, applied,
                                   next_cursor, requested_limit=limit,
                                   total=total, filters=query or None)

    async def get_object(self, collection: str, object_id: str) -> dict:
        self._check(collection)
        manager = await self._manager()
        fetched = await self.acquire(collection)
        match = next((i for i in fetched if i["id"] == object_id), None)
        if match is None:
            raise env.UnknownObject(object_id)
        # No opinions: an inventory has no health. Same stance as before the
        # split, and the roll-up declines it with that reason.
        return env.observation(
            self.subsystem, env.obj_ref(object_id, "package", match["native_id"]),
            self._source(manager), match["facts"],
            evidence_ref=env.evidence_ref("packages", "packages", object_id))

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        self._check(collection)
        manager = await self._manager()
        name = object_id.removeprefix("package:")
        payload: dict = {"manager": manager}
        if manager == "nix":
            store_path = _nix_store_paths().get(name)
            if store_path is None:
                raise env.UnknownObject(object_id)
            links = {}
            for sub in SW_SUBDIRS:
                try:
                    for entry in os.scandir(os.path.join(nx.SW, sub)):
                        if entry.is_symlink():
                            target = os.readlink(entry.path)
                            if target.startswith(store_path + "/"):
                                links[f"{sub}/{entry.name}"] = target
                except OSError:
                    continue
            payload.update({"store_path": store_path, "links": links})
        else:
            rows = await anyio.to_thread.run_sync(
                _dpkg_rows if manager == "dpkg" else _rpm_rows)
            row = next((r for r in rows if r and r[0] == name), None)
            if row is None:
                raise env.UnknownObject(object_id)
            payload["fields"] = row
            payload["format"] = DPKG_FORMAT if manager == "dpkg" else RPM_FORMAT
        return {
            "object_id": object_id,
            "captured_at": env.utc_now(),
            "interface": self._source(manager)["interface"],
            "payload": json.loads(json.dumps(payload)),
        }
