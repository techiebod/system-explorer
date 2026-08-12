"""The servarr explorer's pure halves: fleet config, parsers, mirroring.

One adapter, many instances: the shapes that matter are the fleet ones —
a named instance with missing receipts is a stated fault (never a silent
skip), hyphenated names normalise to their env receipts, ids namespace by
instance so two readarrs cannot collide, and the app's own severities are
mirrored, never re-judged.
"""

from system_explorer.agent.adapters.servarr import (health_item_facts,
                                                    instance_specs,
                                                    queue_record_facts,
                                                    status_facts)
from system_explorer.agent.rules.servarr import queue_opinions


def test_the_fleet_parses_names_versions_and_receipts(monkeypatch):
    monkeypatch.setenv("SE_SERVARR_INSTANCES",
                       "example-tv, example-books-audio, example-index:v1")
    monkeypatch.setenv("SE_EXAMPLE_TV_URL", "http://127.0.0.1:8989/")
    monkeypatch.setenv("SE_EXAMPLE_TV_API_KEY", "0123456789abcdef")
    monkeypatch.setenv("SE_EXAMPLE_INDEX_URL", "http://127.0.0.1:9696")
    specs = {spec["name"]: spec for spec in instance_specs()}
    assert set(specs) == {"example-tv", "example-books-audio", "example-index"}
    # Hyphens normalise to the env receipts; a trailing slash is trimmed.
    assert specs["example-tv"]["url"] == "http://127.0.0.1:8989"
    assert specs["example-tv"]["missing"] == []
    # prowlarr's older API family is stated in config, never probed.
    assert specs["example-index"]["api"] == "v1"
    assert specs["example-tv"]["api"] == "v3"
    # A named instance with absent receipts is RETURNED with its gaps —
    # the apps collection states the fault; silence would be a typo'd
    # name vanishing into green.
    assert specs["example-books-audio"]["missing"] == [
        "SE_EXAMPLE_BOOKS_AUDIO_URL", "SE_EXAMPLE_BOOKS_AUDIO_API_KEY"]
    assert specs["example-index"]["missing"] == ["SE_EXAMPLE_INDEX_API_KEY"]


def test_status_and_health_parse_to_native_named_facts():
    assert status_facts({"version": "4.0.10.2544", "appName": "Sonarr"}) == \
        {"Version": "4.0.10.2544", "AppName": "Sonarr"}
    facts = health_item_facts("example-tv", {
        "source": "IndexerStatusCheck", "type": "warning",
        "message": "Indexers unavailable due to failures",
        "wikiUrl": "https://wiki.servarr.com/sonarr/health#indexers"})
    assert facts["App"] == "example-tv"
    assert facts["Type"] == "warning"


def test_queue_records_keep_the_join_keys_and_the_apps_verdict():
    facts = queue_record_facts("example-tv", {
        "id": 1523, "title": "Example.Item.S01E01",
        "status": "completed",
        "trackedDownloadStatus": "warning",
        "trackedDownloadState": "importBlocked",
        "downloadClient": "transmission", "indexer": "example-index",
        "protocol": "torrent", "downloadId": "ABCDEF0123456789",
        "sizeleft": 0,
        "statusMessages": [{"title": "Example.Item.S01E01",
                            "messages": ["Found archive file, might need to"
                                         " be extracted"]}]})
    # The flow join keys ride as facts until both ends of the edge exist.
    assert facts["DownloadClient"] == "transmission"
    assert facts["DownloadId"] == "ABCDEF0123456789"
    assert facts["SizeLeftBytes"] == 0
    assert "archive file" in facts["StatusMessages"]
    [opinion] = queue_opinions(facts)
    assert (opinion["key"], opinion["level"]) == ("queue-item-stuck", "warn")
    assert "warning" in opinion["message"]


def test_a_clean_record_and_a_missing_verdict_both_stay_quiet():
    assert queue_opinions(queue_record_facts("x", {
        "id": 1, "title": "t", "status": "downloading",
        "trackedDownloadStatus": "ok"})) == []
    # No verdict member at all (older API): no claim (rule 7).
    assert queue_opinions(queue_record_facts("x", {"id": 2, "title": "t"})) == []


def test_queue_pagination_follows_total_records_and_404_means_no_queue():
    import asyncio
    import json as jsonlib

    import httpx

    from system_explorer.agent.adapters import servarr as servarr_adapter

    records = [{"id": i, "title": f"item{i}", "status": "downloading",
                "trackedDownloadStatus": "ok"} for i in range(300)]

    def serve(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/api/v1/queue"):
            return httpx.Response(404, content=b"{}")
        # The include-unknown union must ride every queue call: the hidden
        # records are the stuck ones (adversarial review, 2026-08-13).
        assert request.url.params.get("includeUnknownSeriesItems") == "true"
        assert request.url.params.get("includeUnknownAuthorItems") == "true"
        page = int(request.url.params.get("page", "1"))
        size = int(request.url.params.get("pageSize", "250"))
        start = (page - 1) * size
        body = {"page": page, "pageSize": size, "totalRecords": len(records),
                "records": records[start:start + size]}
        return httpx.Response(200, content=jsonlib.dumps(body),
                              headers={"content-type": "application/json"})

    adapter = servarr_adapter.Adapter.__new__(servarr_adapter.Adapter)
    client = httpx.AsyncClient(transport=httpx.MockTransport(serve))
    adapter.specs = [
        {"name": "example-tv", "api": "v3",
         "url": "http://tv.test", "key": "k", "missing": []},
        {"name": "example-index", "api": "v1",
         "url": "http://index.test", "key": "k", "missing": []}]
    adapter._clients = {"example-tv": client, "example-index": client}
    rows = asyncio.run(adapter._queue_rows(adapter.specs[0]))
    assert len(rows) == 300  # both pages, ids namespaced per instance
    assert rows[0]["id"] == "queue:example-tv/0"
    # An instance without the endpoint at all (prowlarr) has no queue —
    # zero rows, not an error.
    assert asyncio.run(adapter._queue_rows(adapter.specs[1])) == []


def test_duplicates_and_slashed_names_are_stated_faults(monkeypatch):
    monkeypatch.setenv("SE_SERVARR_INSTANCES", "example-tv,example-tv:v1,bad/name")
    monkeypatch.setenv("SE_EXAMPLE_TV_URL", "http://127.0.0.1:8989")
    monkeypatch.setenv("SE_EXAMPLE_TV_API_KEY", "0123456789abcdef")
    specs = {spec["name"]: spec for spec in instance_specs()}
    assert specs["example-tv"]["duplicates"] == ["example-tv:v1"]
    assert any("contains '/'" in gap for gap in specs["bad/name"]["missing"])


def test_a_notice_grade_mirrors_as_info_and_stays_off_attention():
    from system_explorer.agent.rules.servarr import health_opinions
    facts = health_item_facts("example-tv", {
        "source": "UpdateCheck", "type": "notice",
        "message": "New update is available"})
    [opinion] = health_opinions(facts)
    assert opinion["level"] == "info"
    # ok-grade items mirror as nothing at all.
    assert health_opinions(health_item_facts("example-tv", {
        "source": "Check", "type": "ok", "message": "fine"})) == []
