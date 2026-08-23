"""The reference's OUTWARD surface, as a work list the port is held to.

PLAN §01 rule 7: *"a completeness guard derives its work list from the
reference, never from the port."* `comparator_work()` obeys it for
collections. Nothing did for the surface — the register's own row set is
a literal tuple transcribed by hand from PLAN's re-baseline table, so a
reference route or MCP tool missed at transcription time was invisible to
every guard in the suite, and "the register shows no unowned row" was
only ever as strong as one reading taken once.

This derives two more dimensions from the reference and holds the port to
them, deny-by-default: the agent's HTTP routes and the MCP tool set a
consumer configures against.

**An MCP tool name is a contract with an agent, not an implementation
detail.** A renamed tool breaks every session configured against the old
name, and it breaks silently — the model simply cannot call a thing it
was told exists. So a rename is a legitimate disposition and an
unrecorded one is not.

Found by an audit on 2026-08-23, which named this as the hole the
previous finding fell through.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: What became of each reference MCP tool. Deny-by-default: a tool the
#: reference exposes and this table does not name fails, so the next one
#: cannot go missing quietly.
#:
#: `served` means a port tool of that exact name exists. `renamed` names
#: the tool it became and why. `owed` names an OPEN phase.
TOOL_DISPOSITIONS: dict[str, str] = {
    "list_hosts": "served: the hub serves it under this name",
    "get_collection": "served: at both tiers, and it reaches a plugin's "
                      "collection the day one exists",
    "get_object": "served: at the collator, over the reverse channel built "
                  "2026-08-23",
    "get_evidence": "served: at the collator, over the reverse channel, "
                    "captured fresh and stored nowhere",
    "get_views": "served: at both tiers",
    "lookup": "served: at the collator, over the reverse channel",
    "what_changed": "served: at the collator, which is the tier DESIGN §06 "
                    "gives the record to",
    "get_fact_dictionary": "renamed: `fact_dictionary` at the collator. The "
                           "route is /v1/facts and the tool now matches the "
                           "route rather than the reference's verb prefix. "
                           "Recorded because a tool name is a contract with "
                           "an agent: a session configured against the old "
                           "name cannot call the new one, and it fails by "
                           "the tool simply not existing.",
    "get_status": "renamed: `host_status` at the collator. The reference's "
                  "status was one host's; this tier serves one host's and "
                  "the hub serves the estate's, so the name says which. "
                  "Recorded for the same reason as the rename above.",
    "get_findings": "owed: OWNER:R4 — the port exposes `get_opinions` (every "
                    "opinion currently held) and `get_acknowledgements`, and "
                    "neither is `findings`: a finding is an opinion at warn "
                    "or above WITH A LIFECYCLE, which is the registry's, and "
                    "no route serves the registry's open set. The lifecycle "
                    "landed at R3e and its surface did not. Until it does, "
                    "the one question the reference's attention surface "
                    "answers — what needs attention, with how long it has "
                    "been true — has no tool at either tier.",
}


#: What answers each reference ROUTE, or why nothing does. Every route
#: the reference serves must appear; deny-by-default, so a route added
#: there and never considered here fails.
ROUTE_SUBJECTS: dict[str, dict[str, object]] = {
    "/": {"tool": None,
          "why": "the shipping agent's own HTML page. Both tiers of the "
                 "rewrite render their own — page.go and surface/render.py "
                 "— and neither is an MCP tool, so there is nothing for a "
                 "tool table to name."},
    "/health": {"tool": "host_health",
                "why": "served by the collator under this name."},
    "/v1/capabilities": {"tool": "host_capabilities", "why": "served."},
    "/v1/facts": {"tool": "fact_dictionary", "why": "served, renamed."},
    "/v1/status": {"tool": "host_status", "why": "served, renamed."},
    "/v1/changes": {"tool": "what_changed",
                    "why": "served at the collator, which is the tier §06 "
                           "gives the record to."},
    "/v1/findings": {"tool": None,
                     "why": "OWED — see get_findings in TOOL_DISPOSITIONS. "
                            "The lifecycle landed at R3e and its surface did "
                            "not, so the one question the attention surface "
                            "answers has no tool at either tier."},
    "/v1/evidence/{subsystem}/{collection}/{object_id:path}": {
        "tool": "get_evidence",
        "why": "served at the collator over the reverse channel, captured "
               "fresh and stored nowhere."},
    "/v1/{subsystem}/{collection}": {"tool": "get_collection",
                                     "why": "served at both tiers."},
    "/v1/{subsystem}/{collection}/{object_id:path}": {
        "tool": "get_object",
        "why": "served at the collator over the reverse channel."},
}


def reference_tools() -> set[str]:
    source = (REPO / "src" / "system_explorer" / "mcp" / "server.py").read_text()
    return set(re.findall(r"@mcp\.tool\(\)\s*\n\s*(?:async\s+)?def\s+(\w+)", source))


def reference_routes() -> set[str]:
    source = (REPO / "src" / "system_explorer" / "agent" / "main.py").read_text()
    return set(re.findall(r'@app\.get\("([^"]+)"', source))


def port_tools() -> set[str]:
    collator = (REPO / "go" / "internal" / "collate" / "rest.go").read_text()
    hub = (REPO / "src" / "system_explorer" / "hub" / "routes.py").read_text()
    return (set(re.findall(r'"tool": "(\w+)"', collator))
            | set(re.findall(r'Route\("[^"]+",\s*"(\w+)"', hub)))


def open_phase(text: str) -> bool:
    """Whether an `owed:` disposition's stated OWNER is a phase PLAN has
    not closed.

    The owner is an explicit `OWNER:R<n>` marker rather than any phase
    named in the prose, and that distinction was learned the same day:
    a disposition legitimately cites closed phases as history — "the
    lifecycle landed at R3e and its surface did not" — so a guard reading
    the narrative fires on the history instead of the ownership, which is
    the wrong sentence to fail. Same shape as the replay-seam excuses.
    """
    plan = (REPO / "docs" / "PLAN.md").read_text()
    closed = set(re.findall(r"\*\*(R[0-9]\w*)[^*]*\*\*\s*—\s*\*\*done", plan))
    owner = re.search(r"OWNER:(R[0-9]\w*)", text)
    return bool(owner) and owner.group(1) not in closed


def test_the_reference_surface_is_not_empty() -> None:
    """Anti-vacuity. If the extraction stops matching — a decorator is
    renamed, the app is restructured — this guard would hold the port to
    nothing and report full coverage."""
    assert len(reference_tools()) >= 8, sorted(reference_tools())
    assert len(reference_routes()) >= 8, sorted(reference_routes())
    assert len(port_tools()) >= 15, sorted(port_tools())


def test_every_reference_mcp_tool_has_a_stated_disposition() -> None:
    """Derived from the REFERENCE, which is rule 7. A tool the reference
    exposes and this table does not name is a hole nothing else sees."""
    undisposed = sorted(reference_tools() - set(TOOL_DISPOSITIONS))
    assert not undisposed, (
        f"reference MCP tools with no stated disposition: {undisposed}. Say "
        f"served, renamed (naming the new tool and why) or owed (naming an "
        f"open phase) — a tool that quietly stops existing breaks every "
        f"session configured against it, silently.")


def test_no_disposition_describes_a_tool_the_reference_dropped() -> None:
    """Staleness, the other way. A disposition for a tool no longer in the
    reference is prose about something that is not there."""
    invented = sorted(set(TOOL_DISPOSITIONS) - reference_tools())
    assert not invented, (
        f"dispositions for tools the reference does not expose: {invented}")


def test_every_served_disposition_is_true() -> None:
    """`served` is checkable, so it is checked: a tool claimed served
    that no tier publishes is exactly the over-claim this file exists to
    stop."""
    published = port_tools()
    lying = sorted(name for name, text in TOOL_DISPOSITIONS.items()
                   if text.startswith("served") and name not in published)
    assert not lying, (
        f"claimed served and published by no tier: {lying}")


def test_every_renamed_disposition_names_a_tool_that_exists() -> None:
    published = port_tools()
    broken = {}
    for name, text in TOOL_DISPOSITIONS.items():
        if not text.startswith("renamed"):
            continue
        target = re.search(r"renamed: `(\w+)`", text)
        assert target, f"{name}: a rename names the tool it became"
        if target.group(1) not in published:
            broken[name] = target.group(1)
    assert not broken, (
        f"renamed to a tool no tier publishes: {broken}")


def test_every_owed_disposition_names_an_open_phase() -> None:
    """The same rule the answer rulings and the seam excuses are held to:
    work owed to a phase that has closed is owned by nobody."""
    stale = sorted(name for name, text in TOOL_DISPOSITIONS.items()
                   if text.startswith("owed") and not open_phase(text))
    assert not stale, (
        f"owed to a closed phase, or to no phase at all: {stale}")


def test_the_reference_route_set_is_reachable_by_some_tier() -> None:
    """The routes, held more loosely than the tools and deliberately so.

    The tiers changed and so did the shape (DESIGN appendix B), so a
    route-for-route match would be asserting the rewrite did not happen.
    What must hold is that every QUESTION the reference's routes answer
    is answerable somewhere — and the honest mechanical part of that is
    the tool table above, which is the consumer-facing name. This test
    holds the one property that survives the reshape: the reference
    serves no route whose whole subject has vanished.
    """
    # DERIVED from the reference, which is the whole point and was not
    # true of this test until 2026-08-23: `subjects` was a literal of
    # five paths and `reference_routes()` was computed and read only by
    # the anti-vacuity check, so five of the reference's ten routes were
    # in no work list at all. A hand-written map inside a test whose
    # subject is "derive the work list from the reference" is the defect
    # it exists to catch, wearing the test's own clothes.
    published = port_tools()
    unaccounted = []
    for route in sorted(reference_routes()):
        disposition = ROUTE_SUBJECTS.get(route)
        if disposition is None:
            unaccounted.append(route)
            continue
        if disposition["tool"] is not None and disposition["tool"] not in published:
            unaccounted.append(f"{route} (claims {disposition['tool']}, "
                               f"which no tier publishes)")
    assert not unaccounted, (
        f"reference routes with no stated subject, or claiming a tool no "
        f"tier serves: {unaccounted}. Every route the reference serves is "
        f"either answered somewhere or owed, and a route in neither list "
        f"is one nobody has looked at.")
    # And the owed one is owed in the table rather than merely absent
    # here, so it cannot be forgotten by being left out of this map.
    assert TOOL_DISPOSITIONS["get_findings"].startswith("owed"), (
        "the findings surface is owed and must say so in the tool table")


def test_no_route_subject_describes_a_route_the_reference_dropped() -> None:
    invented = sorted(set(ROUTE_SUBJECTS) - reference_routes())
    assert not invented, (
        f"subjects for routes the reference does not serve: {invented}")
