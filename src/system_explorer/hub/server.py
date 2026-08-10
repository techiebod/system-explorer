"""se-hub: the per-site System Explorer hub (ROADMAP slice 1).

One URL fronts a site's host agents: the hub proxies GETs to the named
agent verbatim and serves the same operator UI, so every host at a site is
navigable from one address. Responses pass through untouched — no
summarisation layer, the same rule as se-mcp (../mcp/server.py). Stateless by
design: no polling, no caching, no persistence — the last-known-good cache
is roadmap slice 2 and gets designed with findings.

Configuration is environment-only so the same package runs anywhere:

  SE_HUB_AGENTS         comma-separated name=url pairs, e.g.
                        "host-a=http://127.0.0.1:8091,host-b=http://host-b:8091"
  SE_HUB_SITE           optional site label surfaced in /hub/hosts
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
from ..paths import UI_DIR


def _agents_from_env() -> dict[str, str]:
    raw = os.environ.get("SE_HUB_AGENTS", "")
    agents: dict[str, str] = {}
    for pair in filter(None, (p.strip() for p in raw.split(","))):
        name, _, url = pair.partition("=")
        if name and url:
            agents[name.strip()] = url.strip().rstrip("/")
    return agents


AGENTS = _agents_from_env()
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
    return {"status": "ok", "site": SITE, "agents": sorted(AGENTS)}


@app.get("/hub/hosts")
async def hub_hosts() -> dict:
    """The site's host registry with live reachability, fanned out
    concurrently so one dead agent costs its timeout, not the sum."""
    async def probe(name: str, base: str) -> tuple[str, dict]:
        try:
            response = await _client.get(f"{base}/health", timeout=3.0)
            response.raise_for_status()
            return name, {"reachable": True, "host": response.json().get("host"), "url": base}
        except Exception as exc:  # noqa: BLE001 - unreachable is data, not an exception
            return name, {"reachable": False,
                          "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
    results = await asyncio.gather(*(probe(n, b) for n, b in AGENTS.items()))
    return {
        "schema": "se.hub-hosts/1",
        "site": SITE,
        "observed_at": _utc_now(),
        "hosts": dict(results),
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
            "error": f"agent unreachable: {type(exc).__name__}: {str(exc)[:200]}",
            "host": name, "url": f"{base}{path}"})
    return Response(content=upstream.content, status_code=upstream.status_code,
                    media_type=upstream.headers.get("content-type", "application/json"))


@app.get("/agents/{name}/health")
async def agent_health(name: str, request: Request) -> Response:
    return await _proxy(name, "/health", request)


@app.get("/agents/{name}/v1/{path:path}")
async def agent_v1(name: str, path: str, request: Request) -> Response:
    return await _proxy(name, f"/v1/{path}", request)
