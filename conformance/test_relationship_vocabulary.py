"""Every emitted relationship type is in the published enum — structurally.

Found live 2026-08-12: three adapters emitted types (`runs`, `plumbed-onto`,
`owns`) outside observation.schema.json's closed enum, so every live envelope
carrying one failed published-schema validation while conformance stayed
green — the fixtures are hand-written against the schema, so they cannot
drift from it; the adapters can. env.rel() deliberately does NOT validate at
runtime: main.py converts adapter exceptions into error envelopes, so a
per-edge raise would blank a whole collection page over one bad edge. The
guard belongs here, at conformance time, where a violation fails a commit
instead of a host.

Same posture as the subprocess lint: a relationship type must be a string
literal at the env.rel() call site. The one non-literal caller, units.py's
DEPENDENCY_RELS comprehension, is covered by importing that table directly —
exact, no heuristic — and any OTHER non-literal call site fails the walk: an
unenumerable relationship type cannot be linted and is therefore forbidden.
"""

import ast

from common import AGENT_DIR, SCHEMAS

from system_explorer.agent.adapters.units import DEPENDENCY_RELS

ADAPTERS_DIR = AGENT_DIR / "adapters"

SCHEMA_ENUM = set(
    SCHEMAS["se.observation/1"]["$defs"]["relationship"]["properties"]["type"]["enum"])


def _rel_type_args() -> dict[str, set[str]]:
    """{module name: relationship types that module can emit}.

    Walks recursively so an adapter moved into a subpackage stays covered,
    and matches both call spellings — `env.rel(...)` and a bare `rel(...)`
    from `from ..envelope import rel` — so an import-style refactor cannot
    walk the emission out of the lint's sight.
    """
    out: dict[str, set[str]] = {}
    for path in sorted(ADAPTERS_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text())
        found: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_rel = (isinstance(func, ast.Attribute) and func.attr == "rel") or (
                isinstance(func, ast.Name) and func.id == "rel")
            if not is_rel:
                continue
            assert node.args, f"{path.name}: env.rel() with no positional args"
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                found.add(first.value)
            else:
                assert path.name == "units.py", (
                    f"{path.name}:{node.lineno}: env.rel()'s type is not a "
                    "string literal — the only sanctioned indirection is "
                    "units.py's DEPENDENCY_RELS table, imported below; an "
                    "unenumerable relationship type cannot be linted against "
                    "the schema enum and is therefore forbidden")
                found.update(rel_type for _prop, rel_type, _dir in DEPENDENCY_RELS)
        if found:
            out[path.name] = found
    return out


def test_every_emitted_relationship_type_is_published():
    emitted = _rel_type_args()
    strays = {(module, rel_type)
              for module, types in emitted.items()
              for rel_type in types if rel_type not in SCHEMA_ENUM}
    assert not strays, (
        f"relationship types emitted but absent from observation.schema.json's "
        f"enum {sorted(SCHEMA_ENUM)}: {sorted(strays)} — widen the enum "
        "(additive, SPEC section 5.1 rule 6) and add the SPEC section 5 table row")


def test_the_walker_still_finds_the_known_emissions():
    # Anti-vacuity: if env.rel() calls stopped being visible to the AST walk,
    # the subset test above would pass forever on an empty set. These are the
    # regression that motivated the file; their absence means the walker
    # broke, not that the edges left.
    emitted = _rel_type_args()
    everything = set().union(*emitted.values())
    for known in ("runs", "plumbed-onto", "owns", "member-of", "backs",
                  "requires", "wants", "after", "dispatches-to", "tracks"):
        assert known in everything, f"walker no longer sees {known!r}"


# Every subsystem whose objects are joined to others BY THE FACTS THEY
# ALREADY CARRY. The check is one-directional, like the SPEC table's: a
# module may join more than this, and a module absent from the list is
# allowed to emit nothing (hardware's leaves genuinely name nobody).
#
# protection is the row that put this test here. It shipped three
# collections whose whole subject is a chain — target to destination, job
# to both — with the joins stated in prose facts and not one edge emitted,
# and the vocabulary test above stayed green throughout because it only
# ever asked whether the types it FOUND were legal. "Reported live
# 2026-08-14: under Protection we've lost the clickable relationships."
JOINED = {"protection.py", "storage.py", "docker.py", "units.py",
          "network.py", "vms.py"}


def test_every_subsystem_whose_facts_name_other_objects_emits_edges():
    emitting = set(_rel_type_args())
    missing = sorted(JOINED - emitting)
    assert not missing, (
        f"{missing} state joins to other objects in their facts and emit no "
        "relationship for them. A join that exists only as a name in a fact "
        "is one a reader cannot follow and an agent cannot walk — the fact "
        "keeps the native word, the edge carries the id, and both are owed.")


def test_the_dependency_table_carries_only_published_types():
    # The imported table is the one sanctioned indirection; check it at the
    # source so a new row cannot smuggle a type past the call-site walk.
    for _prop, rel_type, direction in DEPENDENCY_RELS:
        assert rel_type in SCHEMA_ENUM, rel_type
        assert direction in ("in", "out"), direction
