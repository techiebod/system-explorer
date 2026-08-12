"""The paperless explorer's pure halves: API parsing and the archive rules.

Parsers and rules are pure over documents (the resolv.conf arrangement).
The cases that matter most: zero documents is critical (the emptied-library
incident, twice in one week), an admin-only /api/status/ narrows the
observation instead of breaking it, and the status document's connection
URLs shed their DSN userinfo before any evidence ships.
"""

from system_explorer.agent.adapters.paperless import (_redact_url_credentials,
                                                      statistics_facts,
                                                      status_facts)
from system_explorer.agent.rules.paperless import instance_opinions

STATISTICS = {"documents_total": 38, "documents_inbox": 2, "tag_count": 11,
              "correspondent_count": 7, "document_type_count": 4,
              "character_count": 912345}

STATUS = {
    "pngx_version": "2.11.6",
    "storage": {"total": 100_000_000_000, "available": 60_000_000_000},
    "database": {"type": "postgresql",
                 "url": "postgres://paperless:hunter2@db:5432/paperless",
                 "status": "OK", "error": None},
    "tasks": {"redis_url": "redis://:sekrit@paperless-redis:6379",
              "redis_status": "OK", "redis_error": None,
              "celery_status": "OK",
              "index_status": "OK", "index_error": None,
              "classifier_status": "WARNING",
              "classifier_error": "Classifier has no training data."},
}


def test_the_inventory_and_health_parse_to_native_named_facts():
    facts = {**statistics_facts(STATISTICS), **status_facts(STATUS)}
    assert facts["DocumentCount"] == 38
    assert facts["PngxVersion"] == "2.11.6"
    assert facts["DatabaseStatus"] == "OK"
    assert facts["ClassifierStatus"] == "WARNING"
    assert facts["ClassifierError"] == "Classifier has no training data."
    # A healthy archive with an untrained classifier: one warn, nothing else.
    assert [(o["key"], o["level"]) for o in instance_opinions(facts)] == \
        [("paperless-classifier", "warn")]


def test_zero_documents_is_the_emptied_library_and_is_critical():
    facts = statistics_facts({**STATISTICS, "documents_total": 0})
    opinions = instance_opinions(facts)
    assert ("paperless-empty", "critical") in \
        {(o["key"], o["level"]) for o in opinions}


def test_an_absent_count_is_not_zero():
    # A paperless too old to state documents_total says nothing — and a
    # rule that read absence as zero would fire the data-loss alarm on
    # every such install (rule 7: absence is never a verdict).
    facts = statistics_facts({"tag_count": 3})
    assert "DocumentCount" not in facts
    assert instance_opinions(facts) == []


def test_component_errors_ride_as_facts_and_evidence():
    status = {**STATUS, "database": {**STATUS["database"], "status": "ERROR",
                                     "error": "connection refused"}}
    facts = status_facts(status)
    [opinion] = [o for o in instance_opinions(facts)
                 if o["key"] == "paperless-database"]
    assert opinion["level"] == "critical"
    assert "DatabaseError" in opinion["evidence"]
    assert facts["DatabaseError"] == "connection refused"


def test_connection_urls_shed_their_userinfo_before_evidence():
    redacted, paths = _redact_url_credentials(STATUS)
    assert "hunter2" not in str(redacted)
    assert "sekrit" not in str(redacted)
    # Scheme and host survive: the diagnostically useful halves.
    assert redacted["database"]["url"].startswith("postgres://")
    assert redacted["database"]["url"].endswith("@db:5432/paperless")
    assert sorted(paths) == ["database.url", "tasks.redis_url"]
    # The original document is untouched (a copy was redacted).
    assert "hunter2" in STATUS["database"]["url"]


def test_urls_without_userinfo_are_left_alone_and_unclaimed():
    status = {"database": {"url": "postgres://db:5432/paperless"},
              "tasks": {"redis_url": "redis://paperless-redis:6379"}}
    redacted, paths = _redact_url_credentials(status)
    assert paths == []
    assert redacted["database"]["url"] == "postgres://db:5432/paperless"


def test_the_capacity_ladder_is_storage_ladder():
    # Restated, not imported (rulebooks import only the envelope), so this
    # cross-check is what makes divergence impossible to ship.
    from system_explorer.agent.rules import paperless as paperless_rules
    from system_explorer.agent.rules import storage as storage_rules
    assert paperless_rules.CAPACITY_WARN == storage_rules.CAPACITY_WARN
    assert paperless_rules.CAPACITY_CRITICAL == storage_rules.CAPACITY_CRITICAL
