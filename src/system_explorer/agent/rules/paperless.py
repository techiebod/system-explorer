"""paperless rules: the archive's own answers, not its wrapper's.

Two incidents in one week demanded this subsystem, and both had the same
shape: a healthy container row over a broken archive — first a secret
drift that emptied the library from 38 documents to 0, then a diverged
data path with no snapshots under it. The wrapper is not the app.
DocumentCount going to zero is the fact both incidents needed on the
attention surface, and the app's own component checks (database, redis,
celery, index, classifier) are the early warnings that precede it.

Every rule is presence-driven: paperless's /api/status/ is admin-only, so
a token without that grant yields component facts absent-with-reason and
the rules simply do not evaluate them (rule 7 — absence is never a
verdict).
"""

from __future__ import annotations

from .. import envelope as env

# The app's own vocabulary for a passing check; anything else ("ERROR",
# "WARNING") is the app raising its hand.
STATUS_OK = "OK"
# The same 90/95 capacity ladder the storage rulebook declares: the app's
# view of its media volume and the host's view of the same bytes must
# judge alike. Restated rather than imported — rulebooks import only the
# envelope (test_rules holds that boundary) — and pinned to storage's
# values by a conformance cross-check, so drift fails CI instead of
# diverging silently.
CAPACITY_WARN = 90
CAPACITY_CRITICAL = 95


def _component(facts: dict, fact: str, key: str, level: str,
               concern: str) -> list[dict]:
    value = facts.get(fact)
    if value is None or value == STATUS_OK:
        return []
    evidence = [fact] + [error for error in (f"{fact.removesuffix('Status')}Error",)
                         if error in facts]
    return [env.opinion(key, level,
                        f"The instance reports its {concern} check as "
                        f"{value}.", evidence)]


def instance_opinions(facts: dict) -> list[dict]:
    opinions: list[dict] = []
    if facts.get("DocumentCount") == 0:
        opinions.append(env.opinion(
            "paperless-empty", "critical",
            "The instance reports zero documents — the emptied-library "
            "shape. Rule out data loss, and rule out a token whose user "
            "cannot see the archive (statistics are permission-scoped), "
            "before believing anything else on this screen.",
            ["DocumentCount"]))
    opinions += _component(facts, "DatabaseStatus", "paperless-database",
                           "critical", "database")
    opinions += _component(facts, "RedisStatus", "paperless-redis",
                           "critical", "redis broker")
    opinions += _component(facts, "CeleryStatus", "paperless-celery",
                           "warn", "celery worker")
    opinions += _component(facts, "IndexStatus", "paperless-index",
                           "warn", "search index")
    opinions += _component(facts, "ClassifierStatus", "paperless-classifier",
                           "warn", "classifier")
    total = facts.get("StorageTotalBytes")
    available = facts.get("StorageAvailableBytes")
    if isinstance(total, int) and isinstance(available, int) and total > 0:
        used_percent = round((total - available) * 100 / total)
        if used_percent >= CAPACITY_WARN:
            opinions.append(env.opinion(
                "paperless-storage",
                "critical" if used_percent >= CAPACITY_CRITICAL else "warn",
                f"The media storage the app sees is {used_percent}% full.",
                ["StorageTotalBytes", "StorageAvailableBytes"]))
    return opinions
