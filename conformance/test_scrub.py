"""Failure text cannot carry credentials — the Phase 2.5 gate.

Built BEFORE the first credentialed adapter exists, which is the only
acceptable time: httpx stringifies errors with full request URLs, two
planned upstreams take their API key only as a query parameter, and
capability reasons flow verbatim into the two most-polled unauthenticated
routes. The scrub lives at the envelope boundary so adapter sixteen
inherits what adapter one never had to remember.
"""

import pytest

from system_explorer import text
from system_explorer.agent import envelope as env


def test_query_strings_are_stripped_wholesale():
    scrubbed = text.scrub(
        "HTTPStatusError: 401 for url "
        "http://tautulli:8181/api/v2?apikey=abcd1234efgh&cmd=get_activity")
    assert "apikey" not in scrubbed
    assert "?[query-stripped]" in scrubbed
    assert "http://tautulli:8181/api/v2" in scrubbed  # the path still diagnoses


def test_secret_env_values_are_substituted_by_name(monkeypatch):
    monkeypatch.setenv("TAUTULLI_API_KEY", "s3cr3tvalue123")
    scrubbed = text.scrub("upstream said: bad key s3cr3tvalue123 rejected")
    assert "s3cr3tvalue123" not in scrubbed
    assert "[redacted:$TAUTULLI_API_KEY]" in scrubbed


def test_short_env_values_are_not_treated_as_secrets(monkeypatch):
    # A "secret" of seven characters would turn scrubbing into text mangling
    # (imagine PASS=on); the length floor keeps substitution meaningful.
    monkeypatch.setenv("X_PASS", "on")
    assert text.scrub("the fan is on") == "the fan is on"


def test_nested_secrets_replace_longest_first(monkeypatch):
    monkeypatch.setenv("A_TOKEN", "abcd1234")
    monkeypatch.setenv("B_TOKEN", "xyzabcd1234xyz9")
    scrubbed = text.scrub("saw xyzabcd1234xyz9 here")
    assert scrubbed == "saw [redacted:$B_TOKEN] here"


def test_error_envelopes_scrub_at_the_boundary(monkeypatch):
    monkeypatch.setenv("SVC_API_KEY", "deadbeefcafe")
    page = env.collection_page(
        "servarr", "indexers",
        env.source("servarr-api", "servarr-v3", ["curl <api>/indexer"]),
        [], applied_limit=100, next_cursor=None,
        status="error",
        errors=["HTTPStatusError: 401 Unauthorized for url "
                "http://sabnzbd:8080/api?apikey=deadbeefcafe&mode=queue"])
    joined = " ".join(page["errors"])
    assert "deadbeefcafe" not in joined
    assert "apikey" not in joined


def test_reason_scrubs_capability_text(monkeypatch):
    monkeypatch.setenv("SVC_API_KEY", "deadbeefcafe")
    assert "deadbeefcafe" not in env.reason(
        "probe failed: 401 at /api?apikey=deadbeefcafe")
