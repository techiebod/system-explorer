"""The plex-family and bazarr pure halves: parsers over API documents.

The shapes that matter: seerr's numeric status enum maps to its own
words, Plex epoch stamps become the envelope's UTC ISO, a session titles
itself with its series when it has one, and bazarr's ungraded issue list
folds to bounded sentences.
"""

from system_explorer.agent.adapters.bazarr import health_facts
from system_explorer.agent.adapters.bazarr import status_facts as bazarr_status
from system_explorer.agent.adapters.plex import (library_facts, request_facts,
                                                 server_facts, session_facts)


def test_plex_server_and_library_parse_native_members():
    facts = server_facts({"MediaContainer": {
        "friendlyName": "example-media", "version": "1.41.0.8994",
        "platform": "Linux"}})
    assert facts["FriendlyName"] == "example-media"
    lib = library_facts({"title": "Movies", "type": "movie",
                         "refreshing": False, "scannedAt": 1755000000})
    assert lib["Type"] == "movie"
    assert lib["ScannedAt"].endswith("Z")  # epoch in, envelope ISO out


def test_a_session_titles_itself_with_its_series():
    facts = session_facts({"title": "Pilot", "grandparentTitle": "Example Show",
                           "type": "episode", "User": {"title": "henry-like"},
                           "Player": {"product": "Plex Web", "state": "playing"},
                           "TranscodeSession": {"videoDecision": "transcode"}})
    assert facts["Title"] == "Example Show — Pilot"
    assert facts["VideoDecision"] == "transcode"
    # A movie has no grandparent and keeps its own name.
    assert session_facts({"title": "Example Film", "type": "movie"})["Title"] \
        == "Example Film"


def test_seerr_status_numbers_become_seerrs_own_words():
    assert request_facts({"status": 1, "type": "movie"})["Status"] == "pending"
    assert request_facts({"status": 2, "type": "tv"})["Status"] == "approved"
    # failed is the one fault-shaped state (dispatch to the managers
    # failed) — a triager must read the word seerr's own UI shows, not an
    # opaque digit (adversarial review, 2026-08-13).
    assert request_facts({"status": 4})["Status"] == "failed"
    assert request_facts({"status": 5})["Status"] == "completed"
    # An unknown future number passes through as itself, never invented.
    assert request_facts({"status": 9})["Status"] == "9"


def test_a_request_states_what_was_asked_for():
    facts = request_facts({"status": 2, "type": "tv",
                           "media": {"tmdbId": 88469},
                           "seasons": [{"seasonNumber": 0},
                                       {"seasonNumber": 1}]})
    assert facts["TmdbId"] == 88469
    assert facts["Seasons"] == [0, 1]  # specials ride as season 0
    assert "Seasons" not in request_facts(
        {"status": 1, "type": "movie", "media": {"tmdbId": 389}})


def test_titles_resolve_once_and_the_memo_holds():
    # The request document states only ids (stock overseerr shape); the
    # WHAT comes from seerr's details endpoints — the TV one keyed by
    # the TMDB id, NOT the tvdbId (the predictable trap) — and the
    # identity memo answers every later sweep without re-asking.
    import asyncio
    import json as jsonlib

    import httpx

    from system_explorer.agent.adapters import plex as mod

    calls: list[str] = []

    def serve(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/v1/movie/404404":
            return httpx.Response(404)  # deleted from TMDB: a definitive miss
        payloads = {
            "/api/v1/request": {
                "pageInfo": {"pages": 1, "results": 3},
                "results": [
                    {"id": 1, "status": 2, "type": "movie",
                     "media": {"tmdbId": 389}},
                    {"id": 2, "status": 1, "type": "tv",
                     "media": {"tmdbId": 88469},
                     "seasons": [{"seasonNumber": 1}]},
                    {"id": 3, "status": 2, "type": "movie",
                     "media": {"tmdbId": 404404}},
                ]},
            "/api/v1/movie/389": {"title": "12 Angry Men"},
            "/api/v1/tv/88469": {"name": "Example Series"},
        }
        return httpx.Response(
            200, content=jsonlib.dumps(payloads[request.url.path]),
            headers={"content-type": "application/json"})

    adapter = mod.Adapter.__new__(mod.Adapter)
    adapter.seerr_url = "http://s.test"
    adapter._seerr = httpx.AsyncClient(transport=httpx.MockTransport(serve))
    adapter._titles = {}

    items = asyncio.run(adapter._request_items())
    assert [item["facts"].get("Title") for item in items] == \
        ["12 Angry Men", "Example Series", None]
    assert "/api/v1/tv/88469" in calls  # tmdbId, never tvdbId
    first = [path for path in calls if "/movie/" in path or "/tv/" in path]
    assert first.count("/api/v1/movie/404404") == 1
    asyncio.run(adapter._request_items())
    second = [path for path in calls if "/movie/" in path or "/tv/" in path]
    # The memo answered — including the 404, memoised as a definitive
    # miss so a dead id can never starve the rows queued behind it.
    assert first == second


def test_bazarr_folds_its_ungraded_issue_list_to_sentences():
    assert bazarr_status({"data": {"bazarr_version": "1.4.5",
                                   "sonarr_version": "4.0.10"}}) == \
        {"Version": "1.4.5", "SonarrVersion": "4.0.10"}
    issues = health_facts({"data": [
        {"object": "Sonarr", "issue": "is not available"},
        {"object": "wanted", "issue": "search failed"}]})
    assert issues == ["Sonarr: is not available", "wanted: search failed"]
    assert health_facts({"data": []}) == []
