"""se-hub: the site hub, federated into an estate view (ROADMAP slice 1, §6).

One URL fronts a site's host agents: the hub proxies GETs to the named
agent verbatim and serves the same operator UI, so every host at a site is
navigable from one address. Responses pass through untouched — no
summarisation layer, the same rule as se-mcp (../mcp/server.py). No
observation is ever served from hub state (section 6.1 rule 4): what the
hub keeps is metadata — view documents, and the findings lifecycle
registry it folds on its OWN sweep cadence, which is the founding rule's
"last-known-good belongs with findings" made real. Staleness there is
honest by construction: every record carries its stamps and the envelope
its swept_at.

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
                        "site-a=http://host-a:8090" — omit for a single-site estate
  SE_HUB_ALLOWED_HOSTS  Host-header allow-list, same semantics as the
                        agent's SE_ALLOWED_HOSTS (SPEC section 7)
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import anyio
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .. import __version__
from ..text import MAX_LENGTH, one_line
from ..paths import UI_DIR
from ..views import load_views
from .findings import (SCHEMA_TRANSITIONS, TRANSITIONS, FindingsRegistry,
                       assemble, envelope_problem, identity_key)


def _params(request) -> list[tuple[str, str | int | float | bool | None]]:
    """multi_items() as the element type httpx.get declares.

    The values really are plain strings; lists are invariant, so the
    narrower list[tuple[str, str]] is rejected by the checker despite being
    safe to pass. Restating the element type here says so once, instead of
    an ignore comment at each call site."""
    return list(request.query_params.multi_items())


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

# Where this site's view documents live (SPEC section 6.2) — the loader is
# shared with se-mcp (system_explorer/views.py), which reads the same
# deployed directory so view parity needs no hub dependency.
VIEWS_DIR = os.environ.get("SE_HUB_VIEWS") or None

# The findings registry (SPEC section 6.3): lifecycle metadata under
# systemd's StateDirectory, the agent history arrangement. No
# STATE_DIRECTORY means lifecycle is deliberately off — /hub/findings then
# serves the live sweep with an errors line saying what is missing.
_STATE_DIR = os.environ.get("STATE_DIRECTORY", "").split(":")[0]
REGISTRY = FindingsRegistry(Path(_STATE_DIR) / "findings.db") if _STATE_DIR else None
FINDINGS_RETENTION_DAYS = float(os.environ.get("SE_HUB_FINDINGS_RETENTION_DAYS", "90"))
# The write grant (section 6.3, decision 1): default off, explicit yes only.
# The route below is REGISTERED only under the grant — with it off the
# hub's route table simply has no write verb, which is the strongest
# available form of "the transition route exists only when enabled".
FINDINGS_WRITES = os.environ.get("SE_HUB_FINDINGS_WRITES", "").lower() in ("1", "true", "yes")
# The estate sweep is the hub's OWN cadence, run by a background task: a
# full fresh acquisition on every agent costs seconds by design, and paying
# it inline on every GET made the attention surface the slowest page in the
# product (operator report, 2026-08-13). The founding rule already houses
# this: "last-known-good belongs with findings" — lifecycle records ARE the
# one place staleness is honest, because every one carries its stamps, and
# the envelope's swept_at says exactly how old the sweep behind it is.
FINDINGS_SWEEP_SECONDS = float(os.environ.get("SE_HUB_FINDINGS_SWEEP_SECONDS", "60"))

# ── the budget, which is a number an operator can reason about ───────────
#
# An interval in seconds is a blunt instrument for something whose cost
# varies fivefold across an estate: one number has to serve a twelve-core
# storage server and a one-core cloud host, and picking it means guessing at
# a figure nobody had ever measured. Measured, the guess was poor — a sweep
# that cost 2.4 s of CPU every 60 s was three quarters of the smallest host's
# entire standing bill.
#
# So the cadence can be declared as a SHARE OF A CORE instead, and the hub
# derives each agent's interval from what that agent's own last sweep says it
# cost (`timing.cpu_ms`, 0.6). "One percent of a core" is a number with a
# meaning; "sixty seconds" is a number you have to have measured to justify.
#
# THREE PROPERTIES THAT MAKE IT SAFE TO TURN ON:
#
#   It can only ever SLOW a sweep down. FINDINGS_SWEEP_SECONDS stays the
#   floor, so enabling a budget cannot make any host more expensive than it
#   is today, and a host already inside its budget is swept exactly as often
#   as before.
#   It is per agent without per-agent configuration. The expensive host slows
#   and the cheap one does not, from one declared number.
#   An agent that reports no cost keeps the fixed interval. Older agents
#   predate `timing`, and guessing a cost for them would be the invention
#   this product refuses everywhere else.
FINDINGS_SWEEP_BUDGET = float(os.environ.get("SE_HUB_FINDINGS_SWEEP_BUDGET", "0"))
FINDINGS_SWEEP_MAX_SECONDS = float(
    os.environ.get("SE_HUB_FINDINGS_SWEEP_MAX_SECONDS", "900"))


def sweep_interval(cpu_ms: float | None) -> float:
    """How long to wait before sweeping this agent again.

    No budget, or no cost reported, means the configured interval — the
    behaviour every deployment has today. With both, the interval is what
    holds the declared share of one core, clamped to [configured, max]: it
    may slow a sweep and may never hurry one.
    """
    if FINDINGS_SWEEP_BUDGET <= 0 or not cpu_ms or cpu_ms <= 0:
        return FINDINGS_SWEEP_SECONDS
    wanted = (cpu_ms / 1000.0) / (FINDINGS_SWEEP_BUDGET / 100.0)
    # The FLOOR is applied last, because it is the promise. Clamping the
    # other way round means a ceiling misconfigured below the configured
    # interval sweeps faster than that interval — a budget making a host more
    # expensive, which is the one thing this must never do.
    return max(min(wanted, FINDINGS_SWEEP_MAX_SECONDS), FINDINGS_SWEEP_SECONDS)

_MACHINE_ID = re.compile(r"^[0-9a-f]{32}$")

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_findings_sweep_loop())
    yield
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


app = FastAPI(title="System Explorer hub", version=__version__, docs_url=None, redoc_url=None,
              lifespan=lifespan)

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
            # `site` is the site whose hub FRONTS this agent, and it is the
            # proxy route's own key — /sites/<site>/agents/<name> is how the
            # browser reaches it, so it answers a routing question and must
            # keep doing so.
            #
            # Which is not where the host IS. Until 2026-08-14 this was the
            # only site on the entry, so a cloud host at a different provider,
            # registered with a home hub because that is where its operator
            # looks, was listed as living at home. `agent_site` is the host's
            # own statement, present only when it makes one.
            entry = {"reachable": True, "url": base, "site": SITE}
            if body.get("site"):
                entry["agent_site"] = body["site"]
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


@app.get("/hub/views")
async def hub_views() -> dict:
    """This site's view documents (SPEC section 6.2), read fresh from the
    configured directory per request. No directory configured means a
    deployment that made no views: an empty list, not an error."""
    return load_views(VIEWS_DIR, _utc_now(), SITE)


# Per-agent sweep state: the last result and when it was taken, so an agent
# on a slower cadence contributes its own last-known-good with its OWN stamp
# rather than being absent (which reads as unswept) or being re-served under
# somebody else's fresher one. The registry already works this way — it is
# the sanctioned last-known-good of SPEC section 6.1 rule 4 — and per-agent
# stamps make that MORE honest rather than less: staleness lives on the
# record that carries its own timestamp.
_AGENT_SWEEPS: dict[str, dict] = {}
_AGENT_DUE: dict[str, float] = {}


async def _sweep_findings() -> list[dict]:
    """Every configured agent's /v1/findings, fanned out concurrently. An
    agent that cannot be swept — dark, or predating the findings surface —
    is an entry saying so, and assemble() freezes its registry rows rather
    than resolving them (hub/findings.py).

    With a budget configured, only the agents DUE are asked; the rest carry
    forward their last result and its stamp. Without one, every agent is due
    on every tick and this behaves exactly as it always has.
    """
    async def fetch(name: str, base: str) -> dict:
        try:
            response = await _client.get(f"{base}/v1/findings")
            response.raise_for_status()
            body = response.json()
        except Exception as exc:  # noqa: BLE001 - an unswept host is data
            return {"agent": name,
                    "error": one_line(f"{type(exc).__name__}: {exc}")}
        # The hub folds this envelope rather than proxying it, so shape is
        # checked at this one choke point: a 200-with-garbage answer is
        # "could not be swept" — the dark-host entry with a better error —
        # never a 500 on the estate roll-up.
        problem = envelope_problem(body)
        if problem:
            return {"agent": name,
                    "error": one_line(f"malformed findings envelope: {problem}")}
        return {"agent": name, "envelope": body}

    now = time.monotonic()
    due = [(n, b) for n, b in AGENTS.items() if _AGENT_DUE.get(n, 0.0) <= now]
    fresh = await asyncio.gather(*(fetch(n, b) for n, b in due))
    at = _utc_now()
    for entry in fresh:
        name = entry["agent"]
        entry["swept_at"] = at
        _AGENT_SWEEPS[name] = entry
        # The agent's OWN measurement of what answering cost it, which is the
        # only figure that can size its cadence. Absent on an agent predating
        # /v1/findings timing, and then the configured interval stands.
        cpu = ((entry.get("envelope") or {}).get("timing") or {}).get("cpu_ms")
        _AGENT_DUE[name] = now + sweep_interval(cpu)
    # Carried forward, in the registry's declared order, so a slower host is
    # present with its own age rather than reading as one that could not be
    # swept — those are different statements and only one is a problem.
    return [_AGENT_SWEEPS[name] for name in AGENTS if name in _AGENT_SWEEPS]


# The latest completed sweep: {"sweeps": [...], "at": iso}. Swapped whole,
# read whole; None only before the first sweep lands.
_LAST_SWEEP: dict | None = None


async def _run_findings_sweep() -> dict:
    global _LAST_SWEEP
    sweeps = await _sweep_findings()
    at = _utc_now()
    if REGISTRY is not None:
        swept = [s for s in sweeps if s.get("envelope")]
        try:
            await anyio.to_thread.run_sync(
                REGISTRY.record_sweep, at, swept, FINDINGS_RETENTION_DAYS)
        except Exception as exc:  # noqa: BLE001 - registry damage must not stop sweeping
            print(f"findings: registry write failed: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
    _LAST_SWEEP = {"sweeps": sweeps, "at": at}
    return _LAST_SWEEP


async def _findings_sweep_loop() -> None:
    """The estate sweep on its own cadence, startup-first so the panel has
    an answer immediately; failures log and the loop continues — sweeping
    must never break serving (the agent snapshot loop's rule)."""
    while True:
        try:
            await _run_findings_sweep()
        except Exception as exc:  # noqa: BLE001 - log-and-continue
            print(f"findings: sweep failed: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
        # Ticks at the FLOOR. Which agents are actually asked on a tick is
        # decided per agent by _AGENT_DUE, so a budget slows hosts without
        # slowing the loop that notices a dark one.
        await asyncio.sleep(FINDINGS_SWEEP_SECONDS)


@app.get("/hub/findings")
async def hub_findings() -> dict:
    """The estate's attention surface (SPEC section 6.3): every finding the
    site's agents derive, folded into the registry so each carries
    first_seen, last_seen and its acknowledgement history. Served from the
    LATEST completed sweep — the background loop's, on the hub's own
    cadence — so this read answers instantly, and `swept_at` says exactly
    how old the sweep behind it is. That is the founding rule's
    "last-known-good belongs with findings" done literally: no observation
    is served as current (rule 1's proxy is still the only observation
    path); lifecycle records are served as lifecycle records, stamped. The
    hub parses findings envelopes deliberately and exceptionally: the
    registry is hub metadata DERIVED from them, per section 6.1's amended
    rule 4."""
    last = _LAST_SWEEP or await _run_findings_sweep()
    now = _utc_now()
    # Advertised writability is the grant AND a registry to write to: a
    # grant with no STATE_DIRECTORY would advertise a route that answers
    # every POST with 503, and the member exists so a consumer can offer
    # acknowledgement only where it works.
    writes = FINDINGS_WRITES and REGISTRY is not None
    if REGISTRY is None:
        view = assemble(now, SITE, writes, last["sweeps"], registry_note=(
            "findings registry disabled: STATE_DIRECTORY is not set, so"
            " lifecycle (first_seen, acknowledgement) is unavailable"
            " (the NixOS module sets StateDirectory=se-hub)"))
        view["swept_at"] = last["at"]
        return view
    try:
        rows = await anyio.to_thread.run_sync(REGISTRY.rows)
        transitions = await anyio.to_thread.run_sync(REGISTRY.transitions)
    except Exception as exc:  # noqa: BLE001 - registry damage must not cost the read
        view = assemble(now, SITE, writes, last["sweeps"], registry_note=one_line(
            f"findings registry unreadable: {type(exc).__name__}: {exc}"))
        view["swept_at"] = last["at"]
        return view
    view = assemble(now, SITE, writes, last["sweeps"], rows, transitions)
    view["swept_at"] = last["at"]
    return view


if FINDINGS_WRITES:
    @app.post("/hub/findings/transitions")
    async def findings_transition(request: Request) -> dict:
        """The product's first accepted write, shaped by section 6.3: an
        appended, attributed, reversible transition on one finding's
        lifecycle. Registered only under the findingsWrites grant — no
        grant, no route. The body carries the rule-15 identity plus
        `transition` (acknowledged | unacknowledged), mandatory free-text
        `by`, and an optional note."""
        # Content-Type is a security check here, not pedantry: a browser
        # sends cross-origin POSTs without preflight only for form/text
        # content types, so requiring application/json forces a CORS
        # preflight this hub never grants — which is what stops a web page
        # acknowledging findings on an unauthenticated LAN hub from inside
        # someone's browser (the Host-header defence cannot: a direct
        # cross-site fetch carries the correct Host).
        content_type = request.headers.get("content-type", "")
        if content_type.split(";")[0].strip().lower() != "application/json":
            raise HTTPException(status_code=415,
                                detail="Content-Type must be application/json")
        try:
            body = await request.json()
        except ValueError:
            raise HTTPException(status_code=422, detail="body must be JSON") from None
        if not isinstance(body, dict):
            raise HTTPException(status_code=422, detail="body must be a JSON object")
        machine_id = body.get("machine_id")
        if not isinstance(machine_id, str) or not _MACHINE_ID.fullmatch(machine_id):
            raise HTTPException(status_code=422,
                                detail="machine_id must be 32 hex characters")
        object_id = body.get("object_id")
        opinion_key = body.get("opinion_key")
        if not isinstance(object_id, str) or not object_id:
            raise HTTPException(status_code=422, detail="object_id is required")
        if not isinstance(opinion_key, str) or not opinion_key:
            raise HTTPException(status_code=422, detail="opinion_key is required")
        for member in ("container", "app"):
            value = body.get(member)
            if value is not None and (not isinstance(value, str) or not value):
                raise HTTPException(status_code=422,
                                    detail=f"{member} must be a non-empty string when given")
        transition = body.get("transition")
        if transition not in TRANSITIONS:
            raise HTTPException(status_code=422,
                                detail=f"transition must be one of {list(TRANSITIONS)}")
        by = body.get("by")
        if not isinstance(by, str) or not by.strip():
            raise HTTPException(status_code=422, detail=(
                "a transition is attributed: 'by' is mandatory free text"
                " (SPEC section 6.3 — honest attribution without pretending"
                " it is authentication)"))
        note = body.get("note")
        if note is not None and not isinstance(note, str):
            raise HTTPException(status_code=422, detail="note must be a string")
        # Bounded on refusal, never truncation: decision 2 stores a
        # transition as given, so an oversized or control-character body is
        # rejected rather than silently rewritten. MAX_LENGTH is the
        # codebase's one declared bound for operator-facing text; without
        # it, attacker-authored megabytes would be stored verbatim and
        # re-amplified to every reader of /hub/findings.
        for label, value, allowed in (("by", by, ""), ("note", note or "", "\n\t")):
            if len(value) > MAX_LENGTH:
                raise HTTPException(status_code=422, detail=(
                    f"{label} exceeds {MAX_LENGTH} characters — the bound"
                    " every operator-facing line in this product carries"))
            if any(ord(ch) < 32 and ch not in allowed or ch == "\x7f"
                   for ch in value):
                raise HTTPException(status_code=422,
                                    detail=f"{label} contains control characters")
        if REGISTRY is None:
            raise HTTPException(status_code=503, detail=(
                "findings registry disabled: STATE_DIRECTORY is not set,"
                " so there is nothing to attach a transition to"))
        key = identity_key(machine_id, object_id, opinion_key,
                           body.get("container"), body.get("app"))
        history = await anyio.to_thread.run_sync(
            REGISTRY.append_transition, _utc_now(), key, transition,
            by.strip(), note)
        if history is None:
            raise HTTPException(status_code=404, detail=(
                "no finding with this identity in the registry — transitions"
                " attach to findings the estate has derived"))
        return {"schema": SCHEMA_TRANSITIONS,
                "finding": {"machine_id": machine_id,
                            **({"container": body["container"]} if body.get("container") else {}),
                            **({"app": body["app"]} if body.get("app") else {}),
                            "object_id": object_id, "opinion_key": opinion_key},
                "transitions": history}


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
        # What this list IS, said in the list. A registry is configuration,
        # not discovery: a host that exists and was never registered is
        # indistinguishable here from a host that does not exist, and the
        # honest place to say so is beside the answer rather than in a tool
        # description a consumer may never have read.
        #
        # Not hypothetical. Asked "are all hosts up to date", this registry
        # answered yes while the estate's only internet-facing host sat five
        # revisions behind, registered with no hub and absent from every
        # listing (2026-08-14). The scope was the whole defect: every host it
        # knew about WAS up to date.
        "scope": (
            f"the {len(AGENTS)} agent(s) this hub is configured with"
            + (f", plus {len(hosts) - len(AGENTS)} learned from siblings"
               if len(hosts) > len(AGENTS) else "")
            + ". This is a registry, not a discovery: a host nobody"
            " registered does not appear here, and its absence is"
            " indistinguishable from it not existing."),
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
                                     params=_params(request) or None)
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
            params=_params(request) or None)
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
