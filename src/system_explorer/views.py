"""View documents: operator-authored projections of the graph (SPEC §6.2).

One loader, two servers: se-hub's /hub/views route and se-mcp's get_views
tool both read the same deployed directory, so the two consumers see the
same projections without the MCP surface depending on the hub — parity by
shared configuration, not by a runtime arrow (the MCP surface must keep
working when the hub is down).

Stdlib-only and pure over (directory, now, site), the history.py stance, so
conformance exercises every shape with a tmp directory and a pinned clock.
Read fresh per request: the operator edits a file and refreshes — no
restart, no cache, and §6.1 rule 4's amended property holds (deleting the
directory loses convenience, never truth).

Validation here is structural only — presence and shape of the members the
servers and UI actually dereference. The hub must not import jsonschema for
a read that conformance and the live check already validate against the
published schema; a document that passes this gate but fails se.views/1 is
the live check's catch, not a crash. What this gate DOES refuse, loudly, is
the malformed document: a broken view silently dropped is how a curated
projection quietly loses a panel (design review, 2026-08-12), so every
refused file is an `errors` entry naming the file and the first reason.
"""

from __future__ import annotations

import json
from pathlib import Path

REQUIRED_PANEL_MEMBERS = ("key", "title", "subsystem", "collection")


def load_views(directory: str | None, now: str, site: str | None = None) -> dict:
    """Every view document the directory holds, as one se.views/1 envelope.

    None or unset directory means a deployment that made no views — the
    envelope says so with an empty list, and the UI shows no section, which
    is not an error (the deployment-receipts pattern: no default, because
    views are the operator's judgement).
    """
    out: dict = {"schema": "se.views/1", "observed_at": now}
    if site:
        out["site"] = site
    views: list[dict] = []
    errors: list[dict] = []
    if directory:
        for path in sorted(Path(directory).glob("*.json")):
            try:
                doc = json.loads(path.read_text())
            except (OSError, ValueError) as exc:
                errors.append({"file": path.name,
                               "error": f"{type(exc).__name__}: {exc}"})
                continue
            problem = view_problem(doc)
            if problem:
                errors.append({"file": path.name, "error": problem})
            else:
                views.append(doc)
    out["views"] = views
    if errors:
        out["errors"] = errors
    return out


def view_problem(doc: object) -> str | None:
    """The first structural reason a document cannot be served, or None."""
    if not isinstance(doc, dict):
        return "not a JSON object"
    if not isinstance(doc.get("name"), str) or not doc["name"]:
        return "missing name"
    if not isinstance(doc.get("title"), str) or not doc["title"]:
        return "missing title"
    panels = doc.get("panels")
    if not isinstance(panels, list) or not panels:
        return "panels must be a non-empty list"
    for index, panel in enumerate(panels):
        if not isinstance(panel, dict):
            return f"panels.{index}: not an object"
        for member in REQUIRED_PANEL_MEMBERS:
            if not isinstance(panel.get(member), str) or not panel[member]:
                return f"panels.{index}: missing {member}"
    return None
