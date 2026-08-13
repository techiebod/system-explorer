"""The acquisition trail's pure half: a history record to native-named facts.

One page per app, newest first, and only the members the app itself
states: eventType rides verbatim (grabbed, downloadFolderImported,
downloadFailed, trackFileImported — the apps' vocabulary, never a
translation), the indexer and download client come from the event's own
data block, and an absent member is an absent fact rather than an
invented one. Plus the two contracts the trail's evidence carries: every
URL a record states — embedded mid-sentence or whole-value, well-formed
or refused by the parser — loses everything after its host, and every
native id the rows can mint (index-N included) is admitted by the
evidence route's membership check.
"""

import asyncio
import json

import httpx

from system_explorer.agent.adapters.servarr import (Adapter,
                                                    _redact_history_urls,
                                                    history_record_facts)
from system_explorer.agent import envelope as env


def test_a_grabbed_event_states_the_full_acquisition():
    facts = history_record_facts("example-tv", {
        "id": 4021,
        "sourceTitle": "Example.Item.S01E01.1080p.WEB-DL",
        "eventType": "grabbed",
        "date": "2026-08-13T02:11:47Z",
        "downloadId": "ABCDEF0123456789",
        "quality": {"quality": {"id": 3, "name": "WEBDL-1080p"}},
        "data": {"indexer": "example-index",
                 "downloadClient": "Transmission",
                 "protocol": "torrent"}})
    assert facts == {
        "App": "example-tv",
        "EventType": "grabbed",
        "Title": "Example.Item.S01E01.1080p.WEB-DL",
        "Indexer": "example-index",
        "DownloadClient": "Transmission",
        "DownloadId": "ABCDEF0123456789",
        "Quality": "WEBDL-1080p",
        "Date": "2026-08-13T02:11:47Z"}


def test_an_import_event_keeps_the_apps_vocabulary_verbatim():
    # lidarr spells this trackFileImported; sonarr says
    # downloadFolderImported — each rides exactly as its app wrote it.
    facts = history_record_facts("example-music", {
        "id": 118,
        "sourceTitle": "/downloads/example-album/01-example.flac",
        "eventType": "trackFileImported",
        "date": "2026-08-13T02:14:02Z",
        "downloadId": "ABCDEF0123456789",
        "data": {"downloadClient": "Transmission",
                 "importedPath": "/music/example-album/01-example.flac"}})
    assert facts["EventType"] == "trackFileImported"
    assert facts["DownloadClient"] == "Transmission"
    assert facts["Title"].endswith("01-example.flac")
    assert facts["DownloadId"] == "ABCDEF0123456789"
    # An import states no indexer: the fact is absent, never inferred from
    # the grab that preceded it.
    assert "Indexer" not in facts


def test_a_failed_event_is_stated_not_softened():
    facts = history_record_facts("example-movies", {
        "id": 87,
        "sourceTitle": "Example.Movie.2026.2160p",
        "eventType": "downloadFailed",
        "date": "2026-08-12T23:58:10Z",
        "downloadId": "0011223344556677",
        "data": {"message": "Download client reported a failure"}})
    assert facts["EventType"] == "downloadFailed"
    assert facts["Title"] == "Example.Movie.2026.2160p"
    assert facts["DownloadId"] == "0011223344556677"
    # This record states no client or quality; neither fact appears.
    assert "DownloadClient" not in facts
    assert "Quality" not in facts


def test_unknown_members_are_omitted_never_invented():
    assert history_record_facts("example-tv", {"id": 7}) == {
        "App": "example-tv"}
    # Malformed shapes yield no fact at all rather than a mangled one.
    facts = history_record_facts("example-tv", {
        "id": 8, "quality": {"quality": "not-a-dict"}, "data": "not-a-dict"})
    assert facts == {"App": "example-tv"}


def test_evidence_urls_lose_everything_after_the_host():
    # A grab's downloadUrl is where indexer credentials live: a newznab
    # api key in the query, a private tracker's passkey in the path.
    page = {"records": [
        {"id": 1, "data": {
            "indexer": "example-index",
            "downloadUrl": "https://indexer.example:8443/api?t=get&id=9"
                           "&apikey=0123456789abcdef",
            "nzbInfoUrl": "https://indexer.example/details/9"}},
        {"id": 2, "data": {"downloadClient": "Transmission"}}]}
    out, paths = _redact_history_urls(page)
    assert out["records"][0]["data"]["downloadUrl"] == \
        f"https://indexer.example:8443/{env.REDACTED}"
    assert out["records"][0]["data"]["nzbInfoUrl"] == \
        f"https://indexer.example/{env.REDACTED}"
    assert "apikey" not in str(out)
    # Non-URL members ride untouched; declared paths name only what
    # actually changed.
    assert out["records"][0]["data"]["indexer"] == "example-index"
    assert out["records"][1]["data"] == {"downloadClient": "Transmission"}
    assert paths == ["records.0.data.downloadUrl", "records.0.data.nzbInfoUrl"]
    # The fetched document itself is never mutated.
    assert "apikey=0123456789abcdef" in page["records"][0]["data"]["downloadUrl"]


def test_a_url_embedded_in_a_failure_message_is_still_cut():
    """Failed events are the real credential carrier: sabnzbd's URL-fetch
    failure text embeds the full source URL mid-sentence, and a
    whole-value gate let it ride out apikey intact and undeclared."""
    page = {"records": [{"id": 87, "eventType": "downloadFailed", "data": {
        "message": "Download client sabnzbd reported: URL Fetching failed;"
                   " https://indexer.example/getnzb/abc123?apikey=SECRETKEY1234"
                   " retrying"}}]}
    out, paths = _redact_history_urls(page)
    # The URL is clipped to scheme+host; the surrounding text is intact.
    assert out["records"][0]["data"]["message"] == (
        "Download client sabnzbd reported: URL Fetching failed;"
        f" https://indexer.example/{env.REDACTED} retrying")
    assert "SECRETKEY1234" not in str(out)
    assert paths == ["records.0.data.message"]


def test_a_url_the_parser_refuses_is_withheld_never_skipped():
    """urlsplit refuses indexer-authored junk (an uncastable port raises
    at .port, an unclosed IPv6 bracket at the split itself). A refusal is
    not a clearance: the route must neither raise — one poisoned record
    used to kill evidence for every history object of the instance — nor
    skip, which would ship the credential the function exists to
    withhold."""
    page = {"records": [{"id": 1, "data": {
        "downloadUrl": "https://good.example:8443/get?apikey=aaa111",
        "infoUrl": "http://junkport.example:8080abc/get?apikey=bbb222",
        "nzbInfoUrl": "http://[::1/x?passkey=ccc333"}}]}
    out, paths = _redact_history_urls(page)
    data = out["records"][0]["data"]
    assert data["downloadUrl"] == f"https://good.example:8443/{env.REDACTED}"
    # A junk port keeps the host, drops the port; the tail still goes.
    assert data["infoUrl"] == f"http://junkport.example/{env.REDACTED}"
    # A parse refusal withholds the whole match — deny, never skip.
    assert data["nzbInfoUrl"] == f"http://{env.REDACTED}"
    assert paths == ["records.0.data.downloadUrl", "records.0.data.infoUrl",
                     "records.0.data.nzbInfoUrl"]
    for credential in ("apikey", "passkey", "aaa111", "bbb222", "ccc333"):
        assert credential not in str(out)


def test_a_bare_scheme_and_host_rides_untouched_and_undeclared():
    """Nothing after the host means nothing to withhold: rewriting a bare
    URL would fabricate a path segment the source never contained, and
    declaring it would leave a reader unable to tell 'credential tail
    removed' from 'there never was a tail'. Userinfo is the exception —
    there the rewrite genuinely withholds."""
    page = {"records": [{"id": 3, "data": {
        "infoUrl": "https://example.org",
        "rootUrl": "https://example.org/",
        "portedUrl": "http://example.org:8080",
        "authedUrl": "https://user:hunter2@example.org"}}]}
    out, paths = _redact_history_urls(page)
    data = out["records"][0]["data"]
    assert data["infoUrl"] == "https://example.org"
    assert data["rootUrl"] == "https://example.org/"
    assert data["portedUrl"] == "http://example.org:8080"
    # A bare-but-authed URL carries a credential BEFORE the host: the
    # rewrite really differs, so it is declared.
    assert data["authedUrl"] == f"https://example.org/{env.REDACTED}"
    assert "hunter2" not in str(out)
    assert paths == ["records.0.data.authedUrl"]


def _history_adapter(records: list) -> Adapter:
    """An adapter over a mock transport serving one history page — the
    same construction test_servarr.py uses for the queue walk."""
    def serve(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/system/status"):
            body: dict = {"appName": "Sonarr", "version": "4.0.0.0"}
        else:
            assert request.url.path.endswith("/history")
            body = {"page": 1, "pageSize": 100,
                    "totalRecords": len(records), "records": records}
        return httpx.Response(200, content=json.dumps(body),
                              headers={"content-type": "application/json"})

    adapter = Adapter.__new__(Adapter)
    adapter.specs = [{"name": "example-tv", "api": "v3",
                      "url": "http://tv.test", "key": "k",
                      "missing": [], "duplicates": []}]
    adapter._clients = {"example-tv": httpx.AsyncClient(
        transport=httpx.MockTransport(serve))}
    adapter._sweep_failures = {}
    return adapter


def test_an_id_less_records_index_row_gets_evidence():
    """A record without an id mints history:<app>/index-N, and the
    evidence route's membership set must admit exactly the natives the
    rows mint (_history_natives is the one shared minting) — or the
    product serves an object whose own evidence denies it, a 404 for a
    record the fetched page document plainly contains."""
    records = [{"eventType": "grabbed", "sourceTitle": "Example.Item",
                "data": {}},               # no id -> index-0
               "not-a-record",             # non-dict positions still count
               {"id": 42, "eventType": "grabbed"}]
    adapter = _history_adapter(records)
    rows = asyncio.run(adapter._history_rows(adapter.specs[0]))
    assert [row["id"] for row in rows] == [
        "history:example-tv/index-0", "history:example-tv/42"]
    evidence = asyncio.run(adapter.get_evidence(
        "history", "history:example-tv/index-0"))
    assert evidence["object_id"] == "history:example-tv/index-0"
    assert evidence["payload"]["records"][0]["sourceTitle"] == "Example.Item"
