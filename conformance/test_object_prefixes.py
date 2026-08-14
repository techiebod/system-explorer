"""How to open an object id, held to the ids that are actually minted.

This map lived in the browser until 2026-08-14 as `PREFIX_ROUTE`, and it is
the fourth-copy failure the fact dictionary exists to prevent, caught in the
act: the entire application tier was missing from it, so every app-tier
relationship chip and every fact value naming an app object rendered as dead
text. Nothing could have noticed — the browser's table was answerable to
nobody, and the adapters minting the ids never consulted it.

So the map moved to the agent, and this file is what keeps it true. Three
checks, and the third is the one with teeth:

1. Every prefix an adapter is SEEN minting is in the map, with a home naming
   that adapter. Seen means visible to an AST walk of `item_summary`/
   `obj_ref` first arguments — one-directional, like SPEC section 4's table,
   because an id assembled through a variable is invisible here and is
   covered by check 2 instead.
2. Every home in the map names a collection its subsystem actually serves.
   A route into nothing is how the browser's copy rotted.
3. A relationship whose target prefix belongs to ANOTHER subsystem must pass
   `subsystem=`. Five prefixes are claimed twice — `unit` by units and
   resources, `socket` by two network collections, `daemon` by kea and
   unbound, `instance` and `overview` likewise — so an unqualified
   cross-subsystem edge is not merely untidy: it resolves to whichever
   claimant happens to be canonical, which is a link to the wrong object.
"""

from __future__ import annotations

import ast
import re

import pytest

from common import AGENT_DIR

from system_explorer.agent.adapters import build_adapters
from system_explorer.agent.envelope import OBJECT_PREFIXES, object_prefixes

ADAPTERS_DIR = AGENT_DIR / "adapters"
ADAPTERS = build_adapters()

_PREFIX = re.compile(r"^([a-z][a-z0-9-]*):")

# Which subsystems claim each prefix, from the map, in declared order.
_CLAIMANTS = {prefix: [subsystem for subsystem, _collection in homes]
              for prefix, homes in OBJECT_PREFIXES.items()}


def _literal_prefix(node: ast.expr) -> str | None:
    """The prefix of an id literal, whether plain or an f-string.

    Ids are minted as `f"pool:{name}"` or as bare `"overview:host"`, and both
    put the prefix in a leading constant. Anything else — an id passed in
    through a variable, as the derived port-exposure collection does when it
    reuses the socket's — yields nothing here rather than a guess.
    """
    if isinstance(node, ast.JoinedStr):
        head = node.values[0] if node.values else None
        text = head.value if isinstance(head, ast.Constant) else None
    elif isinstance(node, ast.Constant):
        text = node.value
    else:
        text = None
    if not isinstance(text, str):
        return None
    match = _PREFIX.match(text)
    return match.group(1) if match else None


def _minted() -> dict[str, set[str]]:
    """{module stem: prefixes it is seen minting ids with}."""
    out: dict[str, set[str]] = {}
    for path in sorted(ADAPTERS_DIR.rglob("*.py")):
        found: set[str] = set()
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            name = (func.attr if isinstance(func, ast.Attribute)
                    else getattr(func, "id", ""))
            if name not in ("item_summary", "obj_ref"):
                continue
            if prefix := _literal_prefix(node.args[0]):
                found.add(prefix)
        if found:
            out[path.stem] = found
    return out


def _rel_calls() -> list[tuple[str, int, str, bool]]:
    """(module stem, line, target prefix, passes subsystem=) per env.rel()."""
    out = []
    for path in sorted(ADAPTERS_DIR.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, ast.Call) or len(node.args) < 3:
                continue
            func = node.func
            is_rel = ((isinstance(func, ast.Attribute) and func.attr == "rel")
                      or (isinstance(func, ast.Name) and func.id == "rel"))
            if not is_rel:
                continue
            if prefix := _literal_prefix(node.args[2]):
                scoped = any(kw.arg == "subsystem" for kw in node.keywords)
                out.append((path.stem, node.lineno, prefix, scoped))
    return out


def test_the_walks_still_see_something():
    """Anti-vacuity: every check below is driven by one of these two walks,
    and both would pass forever on an empty result."""
    minted = _minted()
    assert len(minted) >= 15, f"only {len(minted)} modules seen minting ids"
    assert "protection" in minted and "storage" in minted
    calls = _rel_calls()
    assert len(calls) >= 20, f"only {len(calls)} env.rel() targets parsed"
    assert any(scoped for *_rest, scoped in calls), "no subsystem= seen at all"


@pytest.mark.parametrize("module", sorted(_minted()))
def test_every_minted_prefix_is_published(module):
    for prefix in sorted(_minted()[module]):
        assert prefix in OBJECT_PREFIXES, (
            f"{module}.py mints {prefix!r} ids and envelope.OBJECT_PREFIXES "
            "does not list the prefix. An id nothing can route is one a "
            "relationship chip renders as dead text — which is exactly how "
            "the browser's copy of this map lost the whole app tier.")
        assert module in _CLAIMANTS[prefix], (
            f"{module}.py mints {prefix!r} ids and OBJECT_PREFIXES routes "
            f"that prefix to {_CLAIMANTS[prefix]} — not here.")


@pytest.mark.parametrize("prefix", sorted(OBJECT_PREFIXES))
def test_every_published_home_is_a_collection_that_exists(prefix):
    for subsystem, collection in OBJECT_PREFIXES[prefix]:
        assert subsystem in ADAPTERS, (
            f"{prefix!r} routes to subsystem {subsystem!r}, which no adapter "
            "serves")
        assert collection in ADAPTERS[subsystem].collections(), (
            f"{prefix!r} routes to {subsystem}/{collection}, which that "
            f"adapter does not serve — it serves "
            f"{sorted(ADAPTERS[subsystem].collections())}")


def test_a_cross_subsystem_edge_names_the_subsystem_it_points_into():
    """The check with teeth. `unit`, `socket`, `daemon`, `instance` and
    `overview` are each claimed by two collections, so an unqualified edge
    into another subsystem does not merely lack a hint — it resolves to
    whichever claimant is canonical, which is a link to the wrong object."""
    strays = [(module, line, prefix)
              for module, line, prefix, scoped in _rel_calls()
              if not scoped and prefix in _CLAIMANTS
              and module not in _CLAIMANTS[prefix]]
    assert not strays, (
        "relationships pointing outside their own subsystem without "
        f"subsystem=: {strays}. env.rel() takes it as a keyword; without it "
        "the consumer has only the prefix, and five prefixes are ambiguous.")


def test_a_host_never_claims_it_can_open_what_it_does_not_serve():
    """A chip leading to a 404 is worse than one that stayed plain text: the
    reader followed it. So the published map is narrowed to the collections
    the host actually answers, and a prefix with no home left leaves
    entirely rather than lingering as an empty list."""
    served = {"storage": ["pools", "datasets"], "units": ["units"]}
    published = object_prefixes(served)
    assert published["pool"] == [{"subsystem": "storage", "collection": "pools"}]
    assert "domain" not in published, "a host with no libvirt offered vms"
    assert "mount" not in published, "storage served two collections, not six"
    assert published["unit"] == [{"subsystem": "units", "collection": "units"}], (
        "resources is not served here, so unit: has one home, not two")
    assert all(homes for homes in published.values()), "an empty home list"


def test_the_shared_ids_are_published_as_shared():
    """Not a quirk to be tidied away: units/units and resources/workloads
    publish THE SAME ids, and so do network/listening and
    network/port-exposure. The second home is what lets a detail view say
    "this also appears in resources/workloads" without a second table to
    disagree with — collapsing either to one route loses that."""
    served = {name: list(ADAPTERS[name].collections()) for name in ADAPTERS}
    published = object_prefixes(served)
    assert published["unit"] == [
        {"subsystem": "units", "collection": "units"},
        {"subsystem": "resources", "collection": "workloads"}]
    assert published["socket"] == [
        {"subsystem": "network", "collection": "listening"},
        {"subsystem": "network", "collection": "port-exposure"}]
