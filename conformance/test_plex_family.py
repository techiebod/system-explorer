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


def test_bazarr_folds_its_ungraded_issue_list_to_sentences():
    assert bazarr_status({"data": {"bazarr_version": "1.4.5",
                                   "sonarr_version": "4.0.10"}}) == \
        {"Version": "1.4.5", "SonarrVersion": "4.0.10"}
    issues = health_facts({"data": [
        {"object": "Sonarr", "issue": "is not available"},
        {"object": "wanted", "issue": "search failed"}]})
    assert issues == ["Sonarr: is not available", "wanted: search failed"]
    assert health_facts({"data": []}) == []
