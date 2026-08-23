#!/usr/bin/env python3
"""Adversary fixture — fleet round a5: reachability keyed on the chain name.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. Expected verdict: RED on
network/asymmetric, forever — and GREEN on every other network variant, which
is the half that makes the red mean something.

The defect: `jumped` is keyed by the target's NAME alone. A chain is
identified by (family, table, name) — nftables lets `shared` exist in an ip
table and an ip6 table of the same name, and they are two different chains —
so a walk that records "jumped to shared" answers for both copies at once. It
is then wrong about exactly one of them whichever way it errs: the dead v6
chain wears the live v4 chain's JumpedFrom and is reported reachable, or,
with the jump on the other side, a live chain is reported Unreferenced.

No committed variant could catch it before corpus/network/asymmetric. In
network/healthy the duplicated names are real — ts-input, ts-forward and
ts-postrouting each exist in both ip and ip6 — but each pair is jumped from
the same caller NAME in both families, so collapsing the key produces the
identical answer and the subject passes. That is why the deferral stood, and
why the variant that closes it had to be staged rather than found: one name,
two families, jumped in one of them.

**The one defect, and nothing else.** Everything else is a correct port on the
current wire — full expression-tree descent, the named-verdict-map join, the
reference envelope — so the red on network/asymmetric is attributable to the
key and to nothing else, and test_adversaries_stay_red.py holds both halves.
Note that the map join below is still keyed correctly by (family, table,
name): the defect is one line, in the one dict this subject looks chains up
in, which is how a real port produces it.

Deliberately not sharing code with a5_goto_blind.py: two adversaries built on
one helper are one adversary, and a later tidy-up of the helper would silently
un-defect both.
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

    Both verbs, the whole tree — this subject gets that part right.
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


def map_references(node: object) -> set[str]:
    """Every named set or map this expression consults, @ stripped."""
    found: set[str] = set()

    def descend(node: object) -> None:
        if isinstance(node, str):
            if node.startswith("@"):
                found.add(node[1:])
        elif isinstance(node, dict):
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
    # ── THE DEFECT ─────────────────────────────────────────────────────────
    # Keyed by target NAME. A correct subject keys (family, table, name),
    # because that triple is what identifies a chain.
    jumped: dict[str, set[str]] = {}
    # ───────────────────────────────────────────────────────────────────────
    map_targets: dict[tuple, list[str]] = {}
    map_users: dict[tuple, set[str]] = {}
    for entry in document.get("nftables", []):
        if "chain" in entry:
            c = entry["chain"]
            found[(c.get("family"), c.get("table"), c.get("name"))] = c
        elif "rule" in entry:
            r = entry["rule"]
            key = (r.get("family"), r.get("table"), r.get("chain"))
            rule_counts[key] = rule_counts.get(key, 0) + 1
            for target in verdict_targets(r.get("expr") or []):
                jumped.setdefault(target, set()).add(r.get("chain"))
            for ref in map_references(r.get("expr") or []):
                map_users.setdefault(
                    (r.get("family"), r.get("table"), ref), set()
                ).add(r.get("chain"))
        elif "map" in entry:
            m = entry["map"]
            map_targets[
                (m.get("family"), m.get("table"), m.get("name"))
            ] = verdict_targets(m.get("elem") or [])
    for (family, table, name), targets in map_targets.items():
        users = map_users.get((family, table, name))
        if not users:
            continue
        for target in targets:
            jumped.setdefault(target, set()).update(users)

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
        callers = sorted(jumped.get(name, ()))
        if callers:
            facts["JumpedFrom"] = callers
        elif not base:
            facts["Unreferenced"] = True
        items.append((f"{family} {table} {name}", facts))
    return items


def tables(document: dict) -> list[tuple[str, dict]]:
    """A correct nft-tables serving, so the staged defect stays the ONLY
    difference from a correct subject. nft-tables joined the corpus at R3d,
    and a subject that declined it was red for scope on every extended
    variant — a second wrongness that would stop the red on the staged
    variant being attributable to the defect."""
    order: list[tuple] = []
    chain_labels: dict[tuple, list] = {}
    rule_counts: dict[tuple, int] = {}
    for entry in document.get("nftables", []):
        if "table" in entry:
            t = entry["table"]
            key = (t.get("family"), t.get("name"))
            if key not in chain_labels:
                order.append(key)
                chain_labels[key] = []
                rule_counts[key] = 0
        elif "chain" in entry:
            c = entry["chain"]
            key = (c.get("family"), c.get("table"))
            if key in chain_labels:
                label = c.get("name") or ""
                if c.get("policy"):
                    label += f" ({c['policy']})"
                chain_labels[key].append(label)
        elif "rule" in entry:
            r = entry["rule"]
            key = (r.get("family"), r.get("table"))
            if key in rule_counts:
                rule_counts[key] += 1
    return [
        (f"{family} {name}",
         {"Family": family, "Chains": chain_labels[(family, name)],
          "ChainCount": len(chain_labels[(family, name)]),
          "RuleCount": rule_counts[(family, name)]})
        for family, name in order
    ]


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
        fail("this subject collects nft-chains and nft-tables only")

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
        if collection == "nft-tables":
            if not payload.exists():
                emit({"record": "decline", "collection": collection,
                      "reason": "absent", "detail": "no nft on this host"})
                emit({"record": "commit", "collection": collection,
                      "generation": generation, "objects": 0, "assertions": 0,
                      "unobservable": 0})
                continue
            rows = tables(json.loads(payload.read_text()))
            for name, facts in rows:
                emit({"record": "object", "collection": collection,
                      "type": "table", "name": name, "facts": facts,
                      "at": round(1.0 + 0.001 * emitted, 3)})
                emitted += 1
            emit({"record": "commit", "collection": collection,
                  "generation": generation, "objects": len(rows),
                  "assertions": 0, "unobservable": 0})
            continue
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
                  "detail": "this subject serves nft-chains and nft-tables only"})
            continue
        if not payload.exists():
            emit({"record": "decline", "collection": collection,
                  "reason": "absent", "detail": "no nft on this host"})
            emit({"record": "commit", "collection": collection,
                  "generation": generation, "objects": 0, "assertions": 0,
                  "unobservable": 0})
            continue
        items = chains(json.loads(payload.read_text()))
        edges = 0
        for name, facts in items:
            emit({"record": "object", "collection": collection, "type": "chain", "name": name,
                  "facts": facts, "at": round(1.0 + 0.001 * emitted, 3)})
            emitted += 1
            # The chain's table edge, which every chains vantage asserts
            # (DESIGN 13). Derived from the row's own facts, as the real
            # collector derives it — this subject's staged defect is about
            # reachability, and a subject that simply stopped emitting
            # relations would be failing the corpus for a second reason and
            # stop testing the first.
            emit({"record": "relation_assertion", "collection": collection,
                  "name": name, "type": "member-of", "vantage": collection,
                  "target": {"kind": "nft-table",
                             "name": f"{facts['Family']} {facts['Table']}"}})
            edges += 1
        emit({"record": "commit", "collection": collection,
              "generation": generation, "objects": len(items),
              "assertions": edges, "unobservable": 0})
    emit({"record": "end", "request": "replay", "batch": "replay",
          "cpu_ms": 0.5, "wall_ms": 1.0})


if __name__ == "__main__":
    main()
