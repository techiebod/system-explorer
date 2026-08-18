#!/usr/bin/env python3
"""Adversary fixture — fleet round a5, defect N2: the rule-expression-only walk.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. Expected verdict: RED on network/named-map,
forever — and GREEN on every other network variant, which is the half that
makes the red mean something.

**The defect the round's own artefact carries and never enumerated.**
`a5_hardcoded_healthy.py` documents N1, the jump-only verb table, and stops
there; but its ruleset loop handles `chain` and `rule` and nothing else, so a
top-level `map` object is skipped entirely. No committed variant could see it
— not one ruleset in the corpus contained a named verdict map — so it went
into the round's defect list unwritten. corpus/network/named-map closed it, and
this fixture is what stands in the gap now.

The shape, which is the whole point of the variant: a rule dispatching through
`meta l4proto vmap @dispatch` carries the STRING "@dispatch" in its expression
and nothing else. The jump lives in the top-level map object's `elem` list,
which no rule expression contains at any depth. So descending the whole
expression tree — the cure for the INLINE vmap defect, and a cure this subject
has in full below — is still not enough. Answering needs a join: which rules
consult which named object, against what that object's elements do. A subject
without the join publishes `landing` as {RuleCount: 1, Unreferenced: true} —
a chain holding a live rule, reported as one no packet can reach.

**The one defect, and nothing else.** Everything else is a correct port on the
current wire: both verbs (goto arrives as surely as jump), full expression-tree
descent, reachability keyed on (family, table, name) because that triple is
what identifies a chain, and the reference envelope. So the red on
network/named-map is attributable to the missing join and to nothing else, and
test_adversaries_stay_red.py holds both halves.

Deliberately not sharing code with a5_goto_blind.py or
a5_name_keyed_reachability.py: two adversaries built on one helper are one
adversary, and a later tidy-up of the helper would silently un-defect both.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

BOOT_ID = "5e000000-0000-4000-8000-000000000001"


def emit(record: dict) -> None:
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))


def fail(message: str) -> None:
    """Non-zero means 'I could not run' — never a decline (DESIGN 18)."""
    print(message, file=sys.stderr)
    raise SystemExit(2)


def verdict_targets(node: object) -> list[str]:
    """Every chain this expression tree hands control to, each named once.

    Both verbs, the whole tree — this subject gets that part right, including
    the nested inline vmap that the round before this one was blind to.
    """
    found: list[str] = []

    def descend(node: object) -> None:
        if isinstance(node, dict):
            for verb in ("jump", "goto"):
                body = node.get(verb)
                if (isinstance(body, dict) and body.get("target")
                        and body["target"] not in found):
                    found.append(body["target"])
            for value in node.values():
                descend(value)
        elif isinstance(node, list):
            for value in node:
                descend(value)

    descend(node)
    return found


def chains(document: dict) -> list[tuple[str, dict]]:
    found: dict[tuple, dict] = {}
    rule_counts: dict[tuple, int] = {}
    jumped: dict[tuple, set[str]] = {}
    for entry in document.get("nftables", []):
        if "chain" in entry:
            c = entry["chain"]
            found[(c.get("family"), c.get("table"), c.get("name"))] = c
        elif "rule" in entry:
            r = entry["rule"]
            key = (r.get("family"), r.get("table"), r.get("chain"))
            rule_counts[key] = rule_counts.get(key, 0) + 1
            for target in verdict_targets(r.get("expr") or []):
                jumped.setdefault(
                    (r.get("family"), r.get("table"), target), set()
                ).add(r.get("chain"))
        # ── THE DEFECT ─────────────────────────────────────────────────────
        # A correct subject has a third branch here, for `map` entries: it
        # records each named verdict map's targets, records which rules
        # consulted which named object, and joins the two — because that is
        # the only place a map-dispatched jump is written down. This walk
        # reads rule expressions and stops, so the join never happens and a
        # chain reached only through `vmap @name` is published Unreferenced.
        # ───────────────────────────────────────────────────────────────────

    items: list[tuple[str, dict]] = []
    for (family, table, name), chain in found.items():
        key = (family, table, name)
        base = bool(chain.get("hook"))
        facts: dict = {"Family": family, "Table": table, "Name": name,
                       "BaseChain": base}
        if chain.get("handle") is not None:
            facts["Handle"] = chain["handle"]
        for fact, member in (("Hook", "hook"), ("Type", "type"),
                             ("Priority", "prio"), ("Policy", "policy")):
            if chain.get(member) is not None:
                facts[fact] = chain[member]
        facts["RuleCount"] = rule_counts.get(key, 0)
        callers = sorted(jumped.get(key, ()))
        if callers:
            facts["JumpedFrom"] = callers
        elif not base:
            facts["Unreferenced"] = True
        items.append((f"{family} {table} {name}", facts))
    return items


def parse_generations(tokens: list[str]) -> dict[str, int]:
    if not tokens:
        fail("empty collect: the request line is 'collect <collection>:<generation>…'")
    generations: dict[str, int] = {}
    for token in tokens:
        name, _, generation = token.rpartition(":")
        if not name or not generation.isdigit():
            fail(f"malformed token {token!r}: expected <collection>:<generation>")
        generations[name] = int(generation)
    return generations


def main() -> None:
    directory = Path(os.environ.get("SE_REPLAY_DIR", ""))
    if not directory.is_dir():
        fail("SE_REPLAY_DIR must name a payload directory")
    if os.environ.get("SE_REFERENCE_COLLECTOR") != "network":
        fail("this subject collects nft-chains only")

    line = sys.stdin.readline().strip().split()
    if not line or line[0] != "collect":
        fail("this subject serves collect only")
    generations = parse_generations(line[1:])

    emit({"record": "begin", "request": "replay", "batch": "replay",
          "declaration": "sha256:replay", "boot_id": BOOT_ID, "timens": 0,
          "instance": None, "generations": generations})

    payload = directory / "nft.json"
    emitted = 0
    for collection, generation in generations.items():
        if collection != "nft-chains":
            # This subject is a chains-only port, and a collector asked for a
            # collection it does not serve declines `unsupported` and does not
            # commit (DESIGN 18). Until corpus/network/rules opened two
            # collections nothing ever asked, and the loop below answered
            # every name with the chain walk — committing chain rows as rules
            # and claiming authority over a collection it had never read. The
            # staged defect is untouched; what changes is a lie about scope
            # that only a multi-collection request could expose.
            emit({"record": "decline", "collection": collection,
                  "reason": "unsupported",
                  "detail": "this subject serves nft-chains only"})
            continue
        if not payload.exists():
            emit({"record": "decline", "collection": collection,
                  "reason": "absent", "detail": "no nft on this host"})
            emit({"record": "commit", "collection": collection,
                  "generation": generation, "objects": 0, "assertions": 0,
                  "unobservable": 0})
            continue
        items = chains(json.loads(payload.read_text()))
        for name, facts in items:
            emit({"record": "object", "collection": collection, "name": name,
                  "facts": facts, "at": round(1.0 + 0.001 * emitted, 3)})
            emitted += 1
        emit({"record": "commit", "collection": collection,
              "generation": generation, "objects": len(items), "assertions": 0,
              "unobservable": 0})
    emit({"record": "end", "request": "replay", "batch": "replay",
          "cpu_ms": 0.5, "wall_ms": 1.0})


if __name__ == "__main__":
    main()
