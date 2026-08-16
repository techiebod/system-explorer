#!/usr/bin/env python3
"""Adversary fixture — fleet round a6: right about the ruleset, wrong about time.

Standing rule 6 (docs/PLAN.md §01): an adversary's passing-wrong subject joins
the suite as a permanent fixture. This is round a6's wrong-collector, adopted
with its lab paths removed. Expected verdict: RED, forever.

A plausible independent port of the nft-chains collector, written the way an
ordinary port would be: parse the payload, emit the records, fill the envelope
in from struct zero values. Every fact it states about the ruleset is correct.
Everything about WHEN and WHICH BOOT the reading came from is a placeholder:

  1. `at` is left at the zero value, so every object claims to have been read
     at boot. Freshness is destroyed.
  2. `boot_id` is the empty string, so no `at` reading can be attributed to a
     boot and a reboot is undetectable.
  3. `request`/`batch` are constants, and `end` echoes DIFFERENT ones than
     `begin` — the collator can never match the end record to its batch.
  4. no `cpu_ms` / `wall_ms` anywhere: the collector reports no self-cost.

It also predates the tokenised `<collection>:<generation>` request line, so
under the current wire its collection names are wrong too. Left as captured:
the fixture is the round's artefact, and each individual guard is proven by
its own reversion in test_guards_discriminate.py, not by this file staying
red for any one reason.
"""

import json
import os
import sys
from pathlib import Path


def emit(record):
    print(json.dumps(record, sort_keys=True, separators=(",", ":")))


def main():
    directory = Path(os.environ["SE_REPLAY_DIR"])
    line = sys.stdin.readline().strip()
    if not line.startswith("collect"):
        raise SystemExit(2)
    collections = line.split()[1:] or ["nft-chains"]

    payload = directory / "nft.json"
    generations = {c: 1 for c in collections}
    emit({"record": "begin", "request": "rq-fixed", "batch": "batch-fixed",
          "declaration": "sha256:replay", "boot_id": "", "timens": 0,
          "instance": None, "generations": generations})

    if not payload.exists():
        for collection in collections:
            emit({"record": "decline", "collection": collection,
                  "reason": "absent", "detail": "no nft on this host"})
            emit({"record": "commit", "collection": collection,
                  "generation": 1, "objects": 0})
        emit({"record": "end", "request": "rq-DIFFERENT", "batch": "batch-DIFFERENT"})
        return

    doc = json.loads(payload.read_text())
    chains, rule_counts, jumped = {}, {}, {}
    for entry in doc.get("nftables", []):
        if "chain" in entry:
            c = entry["chain"]
            chains[(c.get("family"), c.get("table"), c.get("name"))] = c
        elif "rule" in entry:
            r = entry["rule"]
            key = (r.get("family"), r.get("table"), r.get("chain"))
            rule_counts[key] = rule_counts.get(key, 0) + 1
            for statement in r.get("expr") or []:
                if not isinstance(statement, dict):
                    continue
                for verb in ("jump", "goto"):
                    body = statement.get(verb)
                    if isinstance(body, dict) and body.get("target"):
                        jumped.setdefault(
                            (r.get("family"), r.get("table"), body["target"]),
                            set()).add(r.get("chain"))

    for collection in collections:
        count = 0
        for (family, table, name), chain in chains.items():
            key = (family, table, name)
            base = bool(chain.get("hook"))
            facts = {"Family": family, "Table": table, "Name": name,
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
            emit({"record": "object", "collection": collection,
                  "name": f"{family} {table} {name}", "facts": facts,
                  "at": 0})          # <- struct zero value, never stamped
            count += 1
        emit({"record": "commit", "collection": collection,
              "generation": 1, "objects": count})
    emit({"record": "end", "request": "rq-DIFFERENT", "batch": "batch-DIFFERENT"})


if __name__ == "__main__":
    main()
