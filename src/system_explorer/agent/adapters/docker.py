"""docker subsystem: containers, volumes, networks via the Engine API.

Read-only by construction: this adapter issues only GET requests over the
unix socket. The compose project label yields the cross-subsystem edge to the
compose-stack-<project>.service unit that manages the container.

The containers collection folds published port mappings into a Ports fact —
the /containers/json listing the rows are already built from carries them, so
no extra call is spent.
Answers: how do I connect to this container from the network.

Evidence redaction: a container inspect document carries Config.Env, which
routinely contains decrypted secrets. Evidence keeps the variable
NAMES (diagnostically useful) and redacts the values, and the envelope
records which paths were altered — redaction that hides its own existence
would violate the provenance contract.
"""

from __future__ import annotations

import copy

import httpx

from .. import envelope as env
from ..rules.docker import container_opinions

SOCKET = "/var/run/docker.sock"
# The container states that have processes, and therefore a live scope
# cgroup. `restarting` and `paused` keep theirs; `created`, `exited`,
# `dead` and `removing` do not. Docker's own vocabulary, not ours.
_SCOPED_STATES = ("running", "restarting", "paused")
COMPOSE_PROJECT = "com.docker.compose.project"
BRIDGE_NAME_OPTION = "com.docker.network.bridge.name"


def _bridge_interface(raw: dict) -> str | None:
    """The host bridge this docker network is plumbed onto, or None.

    Two sources, in order of authority. Docker records the name explicitly for
    the default bridge (`com.docker.network.bridge.name: docker0`), and for
    every other bridge network the interface is `br-` plus the first 12
    characters of the network id — Docker's documented naming, verified on a
    live host against both of its user-defined bridges.

    This is the edge that stops network/links being a wall of anonymous
    plumbing: a `br-56a84c7a9838` row means nothing, and "the paperless
    stack's network" means everything. host and null drivers plumb no
    interface, so they get no claim.
    """
    named = (raw.get("Options") or {}).get(BRIDGE_NAME_OPTION)
    if named:
        return named
    if raw.get("Driver") != "bridge":
        return None
    ident = raw.get("Id") or ""
    return f"br-{ident[:12]}" if len(ident) >= 12 else None

# Every Engine API endpoint this adapter calls, named (SPEC rule 5): the CLI
# verbs cover the three list endpoints and the three per-object inspects
# (`docker inspect` resolves any object type; the volume/network forms are the
# precise verbs). /_ping has no CLI verb of its own, so the capability probe
# is named by the curl that reproduces it exactly.
REFERENCE = ["docker ps -a", "docker inspect <name>",
             "docker volume ls", "docker volume inspect <name>",
             "docker network ls", "docker network inspect <name>",
             "curl --unix-socket /var/run/docker.sock http://localhost/_ping"]


# Env values are always secrets-adjacent; Cmd/Entrypoint tokens only when they
# carry a value ("--password=x") — bare tokens and flags stay legible
# (deny-by-default, vision §11 redaction stance).
SECRET_LIST_KEYS = ("Env", "Cmd", "Entrypoint")


def _redact_env(payload: dict) -> tuple[dict, list[str]]:
    """Replace values of every Env list ('K=V' entries) in an inspect
    document, keeping the keys. Returns (redacted copy, altered paths).

    Lists are descended, not just dicts. The docstring has always said "every
    Env list in an inspect document" while the walk returned on anything that
    was not a dict, so a list of mounts or attachments carrying one would have
    been served whole. Nothing in today's payload sits that way; the promise
    was the thing that was wrong.
    """
    redacted = copy.deepcopy(payload)
    paths: list[str] = []

    def walk(node, trail: str) -> None:
        if isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, f"{trail}.{index}" if trail else str(index))
            return
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            here = f"{trail}.{key}" if trail else key
            if key in SECRET_LIST_KEYS and isinstance(value, list):
                node[key], changed = env.redact_assignments(value)
                if changed:
                    paths.append(here)
            else:
                walk(value, here)

    walk(redacted, "")
    return redacted, paths


def _scope_unit(container_id: str, state: object = None) -> str | None:
    """The systemd scope a container's processes run in, named from its id.

    This is the link from a container to its own resource accounting: the
    kernel keeps CPU, memory and I/O pressure per cgroup, systemd gives that
    scope a cgroup, and units/units already reports the numbers per unit. It
    is also the only handle that turns those rows back into something a
    reader recognises — a `docker-6abfe5….scope` row carries no name, the
    scope's Description is dockerd's own "libcontainer container <the same
    id>", and cgroupfs holds no name at all. Only the daemon knows the name,
    which is why this half of the join has to be published here.

    ASSUMPTION, stated because it is derived rather than observed: the daemon
    runs with the systemd cgroup driver, which names the transient scope
    docker-<full id>.scope — the full id, not the short form the rows carry
    as ContainerID. Under the cgroupfs driver docker places the container at
    /sys/fs/cgroup/docker/<id> and creates no scope unit at all, so this name
    would resolve to nothing: a join that finds no row, rather than one that
    finds the wrong one. The daemon's /info reports CgroupDriver and would
    settle it; it is not fetched, because that is a second round trip on
    every listing to qualify a name whose failure mode is already empty.
    """
    # Only while the container HAS processes, which the same row states.
    # The scope is transient: systemd deletes it when the last process
    # exits, and a created-but-never-started container never had one. On
    # an exited row this would name a unit `systemctl status` answers
    # "could not be found" for, and hang the runs edge on a target
    # units/units cannot serve — so it is omitted there, which under
    # rule 7 reads as "does not apply", not as "unknown".
    if state is not None and state not in _SCOPED_STATES:
        return None
    return f"docker-{container_id}.scope" if container_id else None


def _go_time(value: object) -> str | None:
    """Docker reports Go's zero time (0001-01-01T00:00:00Z) where an event
    never happened — FinishedAt on a never-exited container, StartedAt on a
    created-but-unstarted one. That sentinel passed through raw (2026-08-10
    audit), priming any future age rule to compute a 2000-year staleness;
    year <= 1 means "never", which is null."""
    if not isinstance(value, str) or not value:
        return None
    try:
        if int(value.split("-", 1)[0]) <= 1:
            return None
    except ValueError:
        pass
    return value


def _port_mappings(ports: list | None) -> list[str] | None:
    """The Ports member of a /containers/json row, rendered as strings an
    administrator can act on: "0.0.0.0:8080->80/tcp" is host address and
    port -> container port/protocol. None when the container has no ports
    at all — the fact is only set when there is something to say.

    Decisions, each stated because it drops or reshapes wire data:

    * Docker lists a dual-stack publish twice (IP "0.0.0.0" and "::"); the
      pair collapses into the one 0.0.0.0 rendering when host port, container
      port and protocol all match. When they differ the entries are different
      claims and both stay.
    * Exposed-but-unpublished ports (no PublicPort) render as "80/tcp
      (exposed)" rather than being omitted: the admin asking "why can't I
      reach this" is told the port exists but was never published — reachable
      only from other containers, and hiding that would mask the very absence
      they are chasing.
    * Specific host addresses render verbatim; IPv6 addresses are bracketed
      ("[::]:8080->80/tcp") so the string pastes into curl.
    * Published mappings sort before exposed ones; each group sorts by
      container port, protocol, host port, then address — the daemon lists in
      arbitrary order and a stable rendering is what makes rows diffable.
    """
    published: dict[tuple[int, str, int], set[str]] = {}
    exposed: set[tuple[int, str]] = set()
    for entry in ports or []:
        private = entry.get("PrivatePort")
        if private is None:
            continue
        proto = entry.get("Type") or "tcp"
        public = entry.get("PublicPort")
        if public is None:
            exposed.add((private, proto))
        else:
            published.setdefault((private, proto, public),
                                 set()).add(entry.get("IP") or "0.0.0.0")
    out: list[str] = []
    for (private, proto, public), addresses in sorted(published.items()):
        if "0.0.0.0" in addresses:
            addresses.discard("::")  # the dual-stack duplicate
        for ip in sorted(addresses):
            host = f"[{ip}]" if ":" in ip else ip
            out.append(f"{host}:{public}->{private}/{proto}")
    out.extend(f"{private}/{proto} (exposed)"
               for private, proto in sorted(exposed))
    return out or None


def _source(method: str) -> dict:
    return env.source("docker-api", "docker-engine-api", REFERENCE, method=f"GET {method}")


# One entry so far, deliberately: the facts an opinion already cites are
# carried in test_fact_dictionary's UNDOCUMENTED_EVIDENCE debt register, and
# documenting them here is that list's work to retire, not this change's.
_CONTAINER_GLOSSARY = {
    "Ports": "How to reach the container from the host network: each entry "
             "maps a published host address and port to the container port "
             "behind it, and a port marked (exposed) was never published, so "
             "it is reachable only from other containers.",
    "ScopeUnit": "The systemd unit the container's processes run in while "
                 "it has any, which is where the host keeps their resource "
                 "accounting: the kernel measures CPU, memory and I/O "
                 "pressure per cgroup, and this scope is the container's. "
                 "The name is derived from the container id, so it is also "
                 "the way back — a host-side row named for a hexadecimal id "
                 "and nothing else becomes this container. Absent on a "
                 "stopped container, whose scope systemd deleted with its "
                 "last process.",
    "NetworkMode": "The container's network namespace as docker runs it: a "
                   "bridge or network name means ports reach it only via "
                   "published mappings, while \"host\" means it shares the "
                   "host's stack — every port the process binds is open on "
                   "the host's own addresses, which is why such a row "
                   "carries no Ports fact.",
}


def _container_facts(raw: dict) -> dict:
    """One container's facts, with the ones that do not apply OMITTED.

    A running container was being given the whole of dockerd's State
    document: ExitCode 0, OOMKilled false, Error null, FinishedAt null,
    Health null. Those are not measurements — they are the defaults of a run
    that has not happened, and `ExitCode: 0` positively asserts a clean exit
    for a process that never exited. An operator reading it saw five of
    fourteen rows say nothing, and a model over MCP read a successful exit
    code beside `State: running` and had to reconcile them.

    So the last-run block appears only where a run has actually ENDED, and
    dockerd's own FinishedAt is the discriminator rather than a state name
    this adapter would have to keep a list of. Health appears only where the
    image declares a healthcheck; a container with none has no health, which
    is different from unhealthy and from unknown.

    Pure, so conformance can fixture it per state — the same reason the rules
    modules are pure. Applicability is semantics, and semantics belong to the
    side that has the document.
    """
    state = raw.get("State") or {}
    labels = (raw.get("Config") or {}).get("Labels") or {}
    image = (raw.get("Config") or {}).get("Image")
    image_id = raw.get("Image")
    facts: dict = {
        "State": state.get("Status"),
        "RestartCount": raw.get("RestartCount"),
        "Image": image,
        "ComposeProject": labels.get(COMPOSE_PROJECT),
        "NetworkMode": (raw.get("HostConfig") or {}).get("NetworkMode"),
        "ContainerID": (raw.get("Id") or "")[:12] or None,
        "ScopeUnit": _scope_unit(raw.get("Id") or "", state.get("Status")),
    }
    # A digest-pinned reference already ENDS with the image id, so carrying
    # both put the same 71-character sha256 on the screen twice, under two
    # names, one line apart. Where the reference is a bare tag it does not,
    # and then the id is the only thing on the row that says which build is
    # actually running — so this collapses the duplicate rather than dropping
    # the fact.
    if image_id and not (isinstance(image, str) and image.endswith(f"@{image_id}")):
        facts["ImageID"] = image_id
    started = _go_time(state.get("StartedAt"))
    if started:
        facts["StartedAt"] = started
    # THE DISCRIMINATOR IS DOCKER'S OWN RECORD OF AN ENDING, not a list of
    # state names kept here: a container that has never stopped carries the
    # zero time, which _go_time already reads as absent.
    finished = _go_time(state.get("FinishedAt"))
    if finished:
        facts["FinishedAt"] = finished
        facts["ExitCode"] = state.get("ExitCode")
        if state.get("OOMKilled"):
            # False is dockerd's default for every container that was not
            # OOM-killed, and carrying it puts the word OOMKilled on the
            # screen of every healthy container in the estate.
            facts["OOMKilled"] = True
    if state.get("Error"):
        facts["Error"] = state["Error"]
    health = (state.get("Health") or {}).get("Status")
    if health:
        # Absent where the image declares no healthcheck — which is not the
        # same as unhealthy, and not the same as unknown.
        facts["Health"] = health
    return facts


class Adapter:
    subsystem = "docker"

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    def collections(self) -> list[str]:
        return ["containers", "volumes", "networks"]

    def fact_glossary(self, collection: str) -> dict:
        return _CONTAINER_GLOSSARY if collection == "containers" else {}

    async def capability(self) -> dict:
        """Socket existence, reachability and permission are different
        failures; probe /_ping so the reason names the real one."""
        import os
        if not os.path.exists(SOCKET):
            return {"available": False, "reason": f"no docker socket at {SOCKET}"}
        try:
            await self._get("/_ping")
        except PermissionError:
            return {"available": False,
                    "reason": f"{SOCKET} exists but permission was denied "
                              "(agent not in the docker group?)"}
        except Exception as exc:  # noqa: BLE001 - daemon down, socket stale, …
            return {"available": False,
                    "reason": env.reason(
                        f"{SOCKET} exists but the daemon did not answer /_ping: "
                        f"{type(exc).__name__}: {exc}")}
        return {"available": True, "collections": self.collections()}

    async def _get(self, path: str) -> httpx.Response:
        if self._client is None:
            self._client = httpx.AsyncClient(
                transport=httpx.AsyncHTTPTransport(uds=SOCKET),
                base_url="http://docker", timeout=10.0,
            )
        response = await self._client.get(path)
        response.raise_for_status()
        return response

    @staticmethod
    def _container_name(raw: dict) -> str:
        names = raw.get("Names") or ["?"]
        return names[0].lstrip("/")

    async def _container_items(self) -> list[dict]:
        raw = (await self._get("/containers/json?all=1")).json()
        items = []
        for c in raw:
            name = self._container_name(c)
            facts = {
                "State": c.get("State"), "Status": c.get("Status"),
                "Image": c.get("Image"),
                "Created": env.usec_to_iso(int(c.get("Created", 0)) * 1_000_000),
                "ComposeProject": (c.get("Labels") or {}).get(COMPOSE_PROJECT),
                # Why a row may carry no Ports: "host" means every port the
                # process binds is open on the host's own addresses, which
                # must never read the same as nothing-reachable.
                "NetworkMode": (c.get("HostConfig") or {}).get("NetworkMode"),
                # The instance identity; the name stays the object id because
                # compose names outlive recreations while IDs churn.
                "ContainerID": (c.get("Id") or "")[:12] or None,
                "ScopeUnit": _scope_unit(c.get("Id") or "", c.get("State")),
            }
            # Only when at least one mapping exists: a portless container
            # (host networking, batch jobs) says nothing rather than [] —
            # NetworkMode above states which portless shape this is.
            if mappings := _port_mappings(c.get("Ports")):
                facts["Ports"] = mappings
            # Severity from the shared evaluator (agent/rules/docker.py):
            # running is the only positively-healthy state; created and
            # cleanly-exited containers are neutral rows, not warnings.
            items.append(env.item_summary(
                f"container:{name}", "container", name, facts,
                opinions=container_opinions(facts),
                healthy="ok" if facts["State"] == "running" else "info"))
        return items

    async def _volume_items(self) -> list[dict]:
        raw = (await self._get("/volumes")).json()
        return [
            env.item_summary(
                f"volume:{v['Name']}", "volume", v["Name"],
                {"Driver": v.get("Driver"), "Mountpoint": v.get("Mountpoint"),
                 "ComposeProject": (v.get("Labels") or {}).get(COMPOSE_PROJECT)})
            for v in raw.get("Volumes") or []
        ]

    async def _network_items(self) -> list[dict]:
        raw = (await self._get("/networks")).json()
        return [
            env.item_summary(
                f"docker-network:{n['Name']}", "network", n["Name"],
                {"Driver": n.get("Driver"), "Scope": n.get("Scope"),
                 "Internal": n.get("Internal"),
                 "BridgeInterface": _bridge_interface(n),
                 "ComposeProject": (n.get("Labels") or {}).get(COMPOSE_PROJECT)})
            for n in raw
        ]

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        """The full materialisation, shared: collect() pages it and main.py's
        status/snapshot/changes sweeps consume it directly (envelope.
        single_flight — coalescing, not caching). get_object() deliberately
        does NOT come through here: the Engine API has a per-object inspect
        endpoint, and one targeted GET beats listing a collection to find
        one name in it."""
        fetch = {"containers": self._container_items, "volumes": self._volume_items,
                 "networks": self._network_items}
        if collection not in fetch:
            raise env.UnknownCollection(collection)
        return await fetch[collection]()

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        items = env.apply_fact_filters(await self.acquire(collection), query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection, _source(f"/{collection}/json"),
                                   page, applied, next_cursor, requested_limit=limit,
                                   total=total, filters=query or None)

    async def _inspect(self, collection: str, object_id: str) -> dict:
        prefix, _, native = object_id.partition(":")
        paths = {"containers": f"/containers/{native}/json",
                 "volumes": f"/volumes/{native}",
                 "networks": f"/networks/{native}"}
        if collection not in paths:
            raise env.UnknownCollection(collection)
        try:
            return (await self._get(paths[collection])).json()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 404:
                raise env.UnknownObject(object_id) from exc
            raise

    async def get_object(self, collection: str, object_id: str) -> dict:
        raw = await self._inspect(collection, object_id)

        if collection == "containers":
            name = raw["Name"].lstrip("/")
            facts = _container_facts(raw)
            project = facts.get("ComposeProject")
            # Opinions from the shared evaluator (agent/rules/docker.py) —
            # the same function the collection rows go through, so a
            # restarting container is critical in both views.
            opinions = container_opinions(facts)
            relationships = []
            # The scope RUNS this container: the same edge units.py emits from
            # a libvirt scope to its domain, in the only direction that can be
            # emitted. units.py deliberately does not emit the mirror, because
            # the edge needs container:<name> and the scope name carries an id
            # — nothing in cgroupfs or in systemd's properties turns that id
            # into a name, and the daemon is not that adapter's acquisition
            # path. So the container side is where this edge exists or it
            # exists nowhere, and a graph walk from a stalling unit reaches
            # the workload only through here.
            if facts["ScopeUnit"]:
                relationships.append(env.rel("runs", "in",
                                             f"unit:{facts['ScopeUnit']}",
                                             subsystem="units"))
            if project:
                relationships.append(env.rel("member-of", "out",
                                             f"unit:compose-stack-{project}.service",
                                             subsystem="units"))
            for mount in raw.get("Mounts") or []:
                if mount.get("Type") == "volume" and mount.get("Name"):
                    relationships.append(env.rel("mounts", "out", f"volume:{mount['Name']}"))
            for net_name in ((raw.get("NetworkSettings") or {}).get("Networks") or {}):
                relationships.append(env.rel("attached-to", "out", f"docker-network:{net_name}"))
            obj = env.obj_ref(object_id, "container", name)

        elif collection == "volumes":
            facts = {"Driver": raw.get("Driver"), "Mountpoint": raw.get("Mountpoint"),
                     "CreatedAt": raw.get("CreatedAt"),
                     "ComposeProject": (raw.get("Labels") or {}).get(COMPOSE_PROJECT)}
            opinions, relationships = [], []
            obj = env.obj_ref(object_id, "volume", raw["Name"])

        else:
            containers = raw.get("Containers") or {}
            bridge = _bridge_interface(raw)
            # Each attachment's MAC, which is the other half of naming a veth:
            # the bridge learns this address on the port the container is behind
            # (network adapter, PeerMACAddresses), so the two join. Only the
            # inspect payload carries it — /networks omits Containers entirely,
            # and /containers/json returns an EMPTY MacAddress for any container
            # attached to more than one network, so neither list endpoint can
            # stand in for this one.
            endpoints = [
                {"Name": c.get("Name"), "MACAddress": c.get("MacAddress") or None,
                 "IPv4Address": c.get("IPv4Address") or None}
                for c in containers.values() if c.get("Name")
            ]
            facts = {"Driver": raw.get("Driver"), "Scope": raw.get("Scope"),
                     "Internal": raw.get("Internal"), "AttachedContainers": len(containers),
                     "BridgeInterface": bridge,
                     "ComposeProject": (raw.get("Labels") or {}).get(COMPOSE_PROJECT),
                     "ContainerEndpoints": sorted(endpoints, key=lambda e: e["Name"])}
            opinions = []
            relationships = [env.rel("attached-to", "in", f"container:{c['Name']}")
                             for c in containers.values() if c.get("Name")]
            if bridge:
                relationships.append(
                    env.rel("plumbed-onto", "out", f"link:{bridge}", subsystem="network"))
            obj = env.obj_ref(object_id, "network", raw["Name"])

        return env.observation(
            self.subsystem, obj, _source(f"/{collection}/inspect"),
            facts, opinions=opinions, relationships=relationships,
            evidence_ref=env.evidence_ref("docker", collection, object_id),
        )

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        raw = await self._inspect(collection, object_id)
        payload, redacted = _redact_env(raw)
        out = {
            "object_id": object_id,
            "captured_at": env.utc_now(),
            "interface": "docker-engine-api",
            "method": "GET inspect",
            "payload": payload,
        }
        if redacted:
            out["redacted"] = redacted
        return out
