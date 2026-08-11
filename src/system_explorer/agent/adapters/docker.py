"""docker subsystem: containers, volumes, networks via the Engine API.

Read-only by construction: this adapter issues only GET requests over the
unix socket. The compose project label yields the cross-subsystem edge to the
compose-stack-<project>.service unit that manages the container.

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
from ..rules import worst_level
from ..rules.docker import container_opinions

SOCKET = "/var/run/docker.sock"
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

REFERENCE = ["docker ps -a", "docker inspect <name>", "docker volume ls", "docker network ls"]


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


def _source(method: str) -> dict:
    return env.source("docker-api", "docker-engine-api", REFERENCE, method=f"GET {method}")


class Adapter:
    subsystem = "docker"

    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None

    def collections(self) -> list[str]:
        return ["containers", "volumes", "networks"]

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
                # The instance identity; the name stays the object id because
                # compose names outlive recreations while IDs churn.
                "ContainerID": (c.get("Id") or "")[:12] or None,
            }
            # Severity from the shared evaluator (agent/rules/docker.py):
            # running is the only positively-healthy state; created and
            # cleanly-exited containers are neutral rows, not warnings.
            worst = worst_level(container_opinions(facts),
                                healthy="ok" if facts["State"] == "running" else "info")
            items.append(env.item_summary(f"container:{name}", "container", name, facts,
                                          worst_opinion_level=worst))
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

    async def collect(self, collection: str, query: dict, limit: int | None, cursor: str | None) -> dict:
        fetch = {"containers": self._container_items, "volumes": self._volume_items,
                 "networks": self._network_items}
        if collection not in fetch:
            raise env.UnknownCollection(collection)
        items = env.apply_fact_filters(await fetch[collection](), query)
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
            state = raw.get("State") or {}
            labels = (raw.get("Config") or {}).get("Labels") or {}
            project = labels.get(COMPOSE_PROJECT)
            facts = {
                "State": state.get("Status"),
                "ExitCode": state.get("ExitCode"),
                "Error": state.get("Error") or None,
                "OOMKilled": state.get("OOMKilled"),
                "Health": (state.get("Health") or {}).get("Status"),
                "RestartCount": raw.get("RestartCount"),
                "Image": (raw.get("Config") or {}).get("Image"),
                "ImageID": raw.get("Image"),
                "StartedAt": _go_time(state.get("StartedAt")),
                "FinishedAt": _go_time(state.get("FinishedAt")),
                "ComposeProject": project,
                "ContainerID": (raw.get("Id") or "")[:12] or None,
            }
            # Opinions from the shared evaluator (agent/rules/docker.py) —
            # the same function the collection rows go through, so a
            # restarting container is critical in both views.
            opinions = container_opinions(facts)
            relationships = []
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
            evidence_ref=f"/v1/docker/{collection}/{object_id}/evidence",
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
