"""se-hub: the site hub, federated into an estate view (ROADMAP slice 1, §6).

One URL fronts a site's host agents: the hub proxies GETs to the named
agent verbatim and serves the same operator UI, so every host at a site is
navigable from one address. Responses pass through untouched — no
summarisation layer, the same rule as se-mcp (../mcp/server.py). Stateless by
design: no polling, no caching, no persistence — the last-known-good cache
is roadmap slice 2 and gets designed with findings.

**Sibling hubs make this an estate view without making it a central service.**
An estate spans sites; a site is not a small estate (ROADMAP §6). Naming peer
hubs here lets one address reach every host an operator runs, while keeping the
invariant that makes the design work: a site whose siblings are unreachable
keeps working alone and shows the rest as unreachable, because nothing it needs
lives at a sibling. That is why this federates rather than centralising — a
single estate hub would be one box whose loss costs visibility of everything.

Federation is deliberately ONE HOP. A site-scoped request for a sibling's host
is forwarded to that sibling's own local route, which cannot forward again, so
no configuration mistake can build a loop. /hub/hosts takes `local=1` for the
same reason.

Configuration is environment-only so the same package runs anywhere:

  SE_HUB_AGENTS         comma-separated name=url pairs, e.g.
                        "host-a=http://127.0.0.1:8091,host-b=http://host-b:8091"
  SE_HUB_SITE           this site's label, surfaced in /hub/hosts
  SE_HUB_SIBLINGS       comma-separated site=hub-url pairs of PEER hubs, e.g.
                        "naxos=http://tub:8090" — omit for a single-site estate
  SE_HUB_ALLOWED_HOSTS  Host-header allow-list, same semantics as the
                        agent's SE_ALLOWED_HOSTS (SPEC section 7)
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __version__
from ..text import one_line
from ..paths import UI_DIR


def _pairs_from_env(variable: str) -> dict[str, str]:
    raw = os.environ.get(variable, "")
    pairs: dict[str, str] = {}
    for pair in filter(None, (p.strip() for p in raw.split(","))):
        name, _, url = pair.partition("=")
        if name and url:
            pairs[name.strip()] = url.strip().rstrip("/")
    return pairs


AGENTS = _pairs_from_env("SE_HUB_AGENTS")
SIBLINGS = _pairs_from_env("SE_HUB_SIBLINGS")
SITE = os.environ.get("SE_HUB_SITE") or None

app = FastAPI(title="System Explorer hub", version=__version__, docs_url=None, redoc_url=None)

# DNS-rebinding defence, same reasoning as the agent (SPEC section 7): the
# hub is unauthenticated inside its network trust boundary, but a browser
# can be steered across it. Comma-separated names/IPs, no ports; unset
# leaves the check off.
_ALLOWED_HOSTS = [h.strip() for h in os.environ.get("SE_HUB_ALLOWED_HOSTS", "").split(",") if h.strip()]
if _ALLOWED_HOSTS:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=_ALLOWED_HOSTS)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # Same CSP as the agent: the UI builds all DOM via textContent, and
    # connect-src 'self' keeps working because every agent is reached
    # same-origin through the proxy routes below.
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'none'")
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

# The operator UI (SPEC section 8), served exactly as each agent serves it.
if UI_DIR.is_dir():
    app.mount("/ui", StaticFiles(directory=UI_DIR), name="ui")

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(UI_DIR / "index.html")

    @app.middleware("http")
    async def ui_cache_control(request, call_next):
        # no-cache = revalidate every load (ETag/304 keeps it cheap). Without
        # this Safari serves stale bundles across deploys until a manual
        # cache clear.
        response = await call_next(request)
        path = request.url.path
        if path == "/" or path.startswith("/ui"):
            response.headers["Cache-Control"] = "no-cache"
        return response


_client = httpx.AsyncClient(timeout=20.0)


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "site": SITE, "agents": sorted(AGENTS),
            "siblings": sorted(SIBLINGS)}


async def _local_hosts() -> dict:
    """This site's own agents with live reachability, fanned out concurrently
    so one dead agent costs its timeout, not the sum."""
    async def probe(name: str, base: str) -> tuple[str, dict]:
        try:
            response = await _client.get(f"{base}/health", timeout=3.0)
            response.raise_for_status()
            body = response.json()
            entry = {"reachable": True, "url": base, "site": SITE}
            # Identity, version and revision per host — the last two so a
            # mid-rollout estate is visible as such rather than as
            # inexplicably differing behaviour. All three only when the agent
            # actually reported them: an agent that answered without naming
            # itself is a different statement from one that could not be
            # reached, and `host: null` says neither of them clearly.
            for key in ("host", "version", "revision"):
                if body.get(key):
                    entry[key] = body[key]
            return name, entry
        except Exception as exc:  # noqa: BLE001 - unreachable is data, not an exception
            return name, {"reachable": False, "site": SITE,
                          "error": one_line(f"{type(exc).__name__}: {exc}")}
    return dict(await asyncio.gather(*(probe(n, b) for n, b in AGENTS.items())))


@app.get("/hub/hosts")
async def hub_hosts(local: int = 0) -> dict:
    """Every host in the estate: this site's, plus each sibling's own local
    view. `local=1` answers with this site alone, which is what a sibling asks
    for — and is what makes federation exactly one hop deep.

    A sibling that cannot be reached is reported as an unreachable SITE rather
    than silently contributing no hosts, because "no hosts there" and "cannot
    see there" are different statements and only one of them is a problem.
    """
    hosts = await _local_hosts()
    sites: dict[str, dict] = {}
    if SITE:
        sites[SITE] = {"reachable": True, "local": True,
                       "hosts": sorted(hosts)}
    if not local and SIBLINGS:
        async def fetch(site: str, base: str) -> tuple[str, dict, dict]:
            try:
                response = await _client.get(f"{base}/hub/hosts",
                                             params={"local": 1}, timeout=4.0)
                response.raise_for_status()
                body = response.json()
                remote = {name: {**entry, "site": entry.get("site") or site}
                          for name, entry in (body.get("hosts") or {}).items()}
                return site, {"reachable": True, "local": False, "url": base,
                              "hosts": sorted(remote)}, remote
            except Exception as exc:  # noqa: BLE001 - a dark site is data
                return site, {"reachable": False, "local": False, "url": base,
                              "error": one_line(f"{type(exc).__name__}: {exc}")}, {}
        for site, summary, remote in await asyncio.gather(
                *(fetch(s, b) for s, b in SIBLINGS.items())):
            sites[site] = summary
            # Local hosts win a name collision: this hub can verify its own.
            for name, entry in remote.items():
                hosts.setdefault(name, entry)
    return {
        "schema": "se.hub-hosts/1",
        "site": SITE,
        "observed_at": _utc_now(),
        "hosts": hosts,
        "sites": sites,
    }


async def _proxy(name: str, path: str, request: Request) -> Response:
    """One agent GET, passed through verbatim — upstream body and status
    untouched (no summarisation, mcp/server.py's rule), so an agent's
    error-envelope-with-200 arrives exactly as it was sent."""
    base = AGENTS.get(name)
    if base is None:
        return JSONResponse(status_code=404, content={
            "error": f"unknown host {name!r}", "known_hosts": sorted(AGENTS)})
    try:
        upstream = await _client.get(f"{base}{path}",
                                     params=request.query_params.multi_items() or None)
    except httpx.HTTPError as exc:
        return JSONResponse(status_code=502, content={
            "error": one_line(f"agent unreachable: {type(exc).__name__}: {exc}"),
            "host": name, "url": f"{base}{path}"})
    return Response(content=upstream.content, status_code=upstream.status_code,
                    media_type=upstream.headers.get("content-type", "application/json"))


@app.get("/agents/{name}/health")
async def agent_health(name: str, request: Request) -> Response:
    return await _proxy(name, "/health", request)


@app.get("/agents/{name}/v1/{path:path}")
async def agent_v1(name: str, path: str, request: Request) -> Response:
    return await _proxy(name, f"/v1/{path}", request)


async def _forward_to_site(site: str, name: str, suffix: str,
                           request: Request) -> Response:
    """Hand a sibling's host to the sibling that owns it.

    The target is that hub's LOCAL /agents/... route, never its site-scoped one,
    so a hop cannot be followed by another hop no matter how the estate is
    wired. That is the whole loop prevention — a rule about which URL is used,
    rather than a counter or a header anyone could forget to set.
    """
    base = SIBLINGS.get(site)
    if base is None:
        return JSONResponse(status_code=404, content={
            "error": f"unknown site {site!r}",
            "this_site": SITE, "known_sites": sorted(SIBLINGS)})
    try:
        upstream = await _client.get(
            f"{base}/agents/{name}{suffix}",
            params=request.query_params.multi_items() or None)
    except httpx.HTTPError as exc:
        # A dark sibling costs that site's hosts and nothing else: this hub
        # keeps serving its own, which is the invariant federation exists to
        # protect (ROADMAP §6).
        return JSONResponse(status_code=502, content={
            "error": one_line(f"site {site!r} hub unreachable: "
                              f"{type(exc).__name__}: {exc}"),
            "site": site, "host": name, "url": f"{base}/agents/{name}{suffix}"})
    return Response(content=upstream.content, status_code=upstream.status_code,
                    media_type=upstream.headers.get("content-type", "application/json"))


@app.get("/sites/{site}/agents/{name}/health")
async def site_agent_health(site: str, name: str, request: Request) -> Response:
    if SITE and site == SITE:
        return await _proxy(name, "/health", request)
    return await _forward_to_site(site, name, "/health", request)


@app.get("/sites/{site}/agents/{name}/v1/{path:path}")
async def site_agent_v1(site: str, name: str, path: str, request: Request) -> Response:
    """The route the UI uses for every agent call in hub mode. Naming the site
    explicitly keeps the proxy stateless: without it, a request for a host this
    hub does not own would have to ask every sibling who owns it, on every
    request, and the UI already knows the answer from /hub/hosts."""
    if SITE and site == SITE:
        return await _proxy(name, f"/v1/{path}", request)
    return await _forward_to_site(site, name, f"/v1/{path}", request)
