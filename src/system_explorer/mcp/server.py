"""se-mcp: the System Explorer MCP aggregator (SPEC section 9).

Host agents stay single-host; this component aggregates them for MCP
clients. Tool responses are envelopes verbatim — no summarisation layer:
the agent consuming them decides what matters. Read-only by construction,
like everything upstream of it: every tool maps to a GET.

Configuration is environment-only so the same package runs anywhere:

  SE_MCP_AGENTS     comma-separated name=url pairs, e.g.
                    "host-a=http://127.0.0.1:8091,host-b=http://host-b:8091"
  SE_MCP_HOST       bind address (default 127.0.0.1)
  SE_MCP_PORT       port (default 8092)
  SE_MCP_TRANSPORT  streamable-http (default) or sse — sse serves the
                    legacy /sse + /messages/ pair that older brokers and
                    hostname-per-backend proxy layouts expect
"""

from __future__ import annotations

import asyncio
import os
from urllib.parse import quote

import httpx
from mcp.server.fastmcp import FastMCP

from ..text import one_line


def _agents_from_env() -> dict[str, str]:
    raw = os.environ.get("SE_MCP_AGENTS", "")
    agents: dict[str, str] = {}
    for pair in filter(None, (p.strip() for p in raw.split(","))):
        name, _, url = pair.partition("=")
        if name and url:
            agents[name.strip()] = url.strip().rstrip("/")
    return agents


AGENTS = _agents_from_env()

mcp = FastMCP(
    "system-explorer",
    host=os.environ.get("SE_MCP_HOST", "127.0.0.1"),
    port=int(os.environ.get("SE_MCP_PORT", "8092")),
)

_client = httpx.AsyncClient(timeout=20.0)


async def _get(host: str, path: str, params: dict | None = None) -> dict:
    """One agent GET. Unknown hosts and unreachable agents come back as
    structured errors, not exceptions — an MCP client should always get an
    answer it can reason about."""
    base = AGENTS.get(host)
    if base is None:
        return {"error": f"unknown host {host!r}", "known_hosts": sorted(AGENTS)}
    try:
        response = await _client.get(f"{base}{path}", params=params or None)
        response.raise_for_status()
        return response.json()
    except httpx.HTTPStatusError as exc:
        detail = one_line(exc.response.text)
        return {"error": f"agent returned HTTP {exc.response.status_code}",
                "host": host, "path": path, "detail": detail}
    except httpx.HTTPError as exc:
        return {"error": one_line(f"agent unreachable: {type(exc).__name__}: {exc}"),
                "host": host, "url": f"{base}{path}"}


def _idpath(object_id: str) -> str:
    # Object ids carry ':' and '/' meaningfully (unit:sshd.service,
    # lookup:route-get/1.1.1.1); everything else gets percent-encoded.
    return quote(object_id, safe=":/")


@mcp.tool()
async def list_hosts() -> dict:
    """Configured System Explorer hosts and their live capabilities.

    Start here: the response says which subsystems and collections each
    host can answer for, with a reason for anything unavailable."""
    # Fan out concurrently: one dead host costs one timeout, not one
    # timeout per host behind it in the sequence.
    names = list(AGENTS)
    capabilities = await asyncio.gather(*(_get(name, "/v1/capabilities") for name in names))
    return {"hosts": dict(zip(names, capabilities))}


@mcp.tool()
async def get_status(host: str | None = None) -> dict:
    """What needs attention: the per-collection severity roll-up
    (se.status/1) for one host, or every configured host at once.

    Ask this before browsing. Each collection reports its worst level and
    counts by level, so a single call says where to look; collections
    with no honest current health (the journal, lookup catalogs) decline
    with a reason rather than claiming ok, and an acquisition failure is
    an entry plus a partial envelope, never a missing answer."""
    if host is not None:
        return await _get(host, "/v1/status")
    names = list(AGENTS)
    rollups = await asyncio.gather(*(_get(name, "/v1/status") for name in names))
    return {"hosts": dict(zip(names, rollups))}


@mcp.tool()
async def get_collection(host: str, subsystem: str, collection: str,
                         filters: dict[str, str] | None = None,
                         limit: int | None = None,
                         cursor: str | None = None) -> dict:
    """One collection page (se.collection/1 envelope) from one host.

    Fact-equality filters pass through, e.g. {"ActiveState": "failed"} on
    units/units or {"Name": "vim"} on nix/packages. Pagination is
    explicit via limit/cursor; the envelope's next_cursor says whether
    more exists. Without an explicit limit, 100 items are requested —
    LLM context is the constraint, so ask for larger pages only when you
    really want them (filters usually serve better)."""
    params: dict = dict(filters or {})
    # The agents default to 500-item pages, sized for the UI. Over MCP the
    # reader is a context window, so the unasked-for default is smaller
    # (backlog note, 2026-08-09); next_cursor still says whether more exists.
    params["limit"] = limit if limit is not None else 100
    if cursor is not None:
        params["cursor"] = cursor
    return await _get(host, f"/v1/{subsystem}/{collection}", params)


@mcp.tool()
async def get_object(host: str, subsystem: str, collection: str,
                     object_id: str) -> dict:
    """One observation (se.observation/1) — facts, evidence-cited opinions,
    and typed relationships to other objects, e.g. unit:sshd.service in
    units/units or generation:57 in nix/generations."""
    return await _get(host, f"/v1/{subsystem}/{collection}/{_idpath(object_id)}")


@mcp.tool()
async def get_evidence(host: str, subsystem: str, collection: str,
                       object_id: str) -> dict:
    """The raw native payload behind an observation (D-Bus reply, inspect
    document, sysfs walk), captured fresh at request time. Payloads may
    carry a 'redacted' list naming paths whose values were withheld."""
    return await _get(host, f"/v1/{subsystem}/{collection}/{_idpath(object_id)}/evidence")


@mcp.tool()
async def lookup(host: str, name: str, input: str, subsystem: str = "network") -> dict:
    """Run a parameterised read-only lookup and return its observation.

    Current lookups (subsystem network): route-get takes an IP address and
    answers with the kernel's routing decision; resolve takes a hostname
    (or an IP, for reverse) and answers with the resolver's response.
    GET /v1/{subsystem}/lookups on a host lists what it supports."""
    return await _get(host, f"/v1/{subsystem}/lookups/lookup:{name}/{_idpath(input)}")


@mcp.tool()
async def what_changed(host: str, since: str,
                       subsystem: str | None = None) -> dict:
    """What changed on a host since a moment (se.changes/1 envelope):
    added/removed object ids and changed objects with the fact paths that
    differ, per collection, diffed between the newest stored snapshot
    at-or-before `since` and live state now.

    since is UTC ISO 8601 or relative like -24h. rebooted says whether a
    boot boundary lies inside the span; baseline.fallback means nothing
    stored was that old and the oldest snapshot stood in. Optional
    subsystem narrows the diff."""
    params: dict = {"since": since}
    if subsystem is not None:
        params["subsystem"] = subsystem
    return await _get(host, "/v1/changes", params)


def main() -> None:
    transport = os.environ.get("SE_MCP_TRANSPORT", "streamable-http")
    if not AGENTS:
        raise SystemExit("SE_MCP_AGENTS is empty — set name=url pairs")
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
