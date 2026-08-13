"""The downloaders explorer's pure halves, and the transfer join contract.

The join contract is the load-bearing case: transfer ids must be exactly
what a manager's tracks edge computes from its own downloadId — lowercase
info-hashes for torrents (the managers uppercase them, transmission
lowers them), sabnzbd nzo ids verbatim — or the estate's first flow edges
point at nothing.
"""

import asyncio
import json as jsonlib

import httpx

from system_explorer.agent.adapters.downloaders import (sab_queue_client_facts,
                                                        sab_slot_facts,
                                                        torrent_facts)
from system_explorer.agent.adapters.servarr import queue_record_facts
from system_explorer.agent.adapters.servarr import Adapter as ServarrAdapter
from system_explorer.agent.rules.downloaders import (client_opinions,
                                                     transfer_opinions)


def test_torrent_facts_speak_transmissions_own_vocabulary():
    facts = torrent_facts({"hashString": "ABCDEF0123", "name": "example",
                           "status": 4, "percentDone": 0.42,
                           "rateDownload": 1_000_000, "error": 0,
                           "isStalled": False})
    assert facts["Status"] == "download"  # their enum name, not our invention
    assert facts["PercentDone"] == 42.0
    assert "ErrorString" not in facts  # error 0 carries no text
    assert transfer_opinions(facts) == []


def test_sab_units_convert_once_and_the_ladder_matches_storage():
    from system_explorer.agent.rules import downloaders as rules
    from system_explorer.agent.rules import storage as storage_rules
    assert rules.CAPACITY_WARN == storage_rules.CAPACITY_WARN
    assert rules.CAPACITY_CRITICAL == storage_rules.CAPACITY_CRITICAL
    facts = sab_queue_client_facts({
        "version": "4.3.3", "paused": False, "kbpersec": "2048.0",
        "noofslots_total": 3, "diskspace1": "50.0",
        "diskspacetotal1": "100.0"})
    assert facts["DownloadRateBytes"] == 2048 * 1024
    assert facts["DiskFreeBytes"] == 50 * 1024 ** 3
    assert client_opinions(facts) == []  # 50% used: quiet
    slot = sab_slot_facts({"nzo_id": "SABnzbd_nzo_x", "filename": "item",
                           "status": "Downloading", "percentage": "42",
                           "mb": "1024.0", "mbleft": "512.0",
                           "timeleft": "0:10:00"})
    assert slot["PercentDone"] == 42.0 and slot["LeftMB"] == 512.0


def test_the_tracks_join_key_matches_the_transfer_id():
    # The manager states downloadId UPPERCASE for torrents; transmission
    # states hashString lowercase. Both sides normalise to lowercase, so
    # the edge target equals the transfer id character for character.
    facts = queue_record_facts("example-tv", {
        "id": 9, "title": "x", "protocol": "torrent",
        "downloadClient": "Transmission",
        "downloadId": "ABCDEF0123456789ABCDEF0123456789ABCDEF01"})
    [edge] = ServarrAdapter._queue_relationships(facts)
    assert edge["type"] == "tracks"
    assert edge["target"]["subsystem"] == "downloaders"
    assert edge["target"]["id"] == \
        "transfer:transmission/abcdef0123456789abcdef0123456789abcdef01"
    # usenet ids are case-sensitive and pass verbatim.
    facts = queue_record_facts("example-tv", {
        "id": 10, "title": "y", "protocol": "usenet",
        "downloadClient": "SABnzbd", "downloadId": "SABnzbd_nzo_kzp02y"})
    [edge] = ServarrAdapter._queue_relationships(facts)
    assert edge["target"]["id"] == "transfer:sabnzbd/SABnzbd_nzo_kzp02y"
    # No stated client or id: no edge, never a guessed one.
    assert ServarrAdapter._queue_relationships(
        queue_record_facts("example-tv", {"id": 11, "title": "z"})) == []


def test_the_rpc_handshake_retries_exactly_once():
    from system_explorer.agent.adapters import downloaders as mod
    calls = []

    def serve(request: httpx.Request) -> httpx.Response:
        calls.append(request.headers.get("X-Transmission-Session-Id"))
        if len(calls) == 1:
            return httpx.Response(409, headers={
                "X-Transmission-Session-Id": "sess-42"})
        body = jsonlib.loads(request.content)
        assert body["method"] == "session-get"
        return httpx.Response(200, content=jsonlib.dumps(
            {"result": "success", "arguments": {"version": "4.0.6"}}),
            headers={"content-type": "application/json"})

    adapter = mod.Adapter.__new__(mod.Adapter)
    adapter.transmission_url = "http://t.test"
    adapter._session_id = None
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(serve))
    result = asyncio.run(adapter._rpc("session-get"))
    assert result["version"] == "4.0.6"
    assert calls == [None, "sess-42"]  # refused once, echoed once


def test_a_whitespace_label_mints_no_edge_but_keeps_its_fact():
    # "Transmission (VPN)" is one UI rename away, and a spaced target id
    # fails the published objectId pattern — an invalid envelope is worse
    # than a missing arrow (adversarial review, 2026-08-13). The label
    # itself survives as the DownloadClient fact.
    facts = queue_record_facts("example-tv", {
        "id": 12, "title": "x", "protocol": "torrent",
        "downloadClient": "Transmission (VPN)", "downloadId": "ABCDEF01"})
    assert ServarrAdapter._queue_relationships(facts) == []
    assert facts["DownloadClient"] == "Transmission (VPN)"


def test_an_emitted_edge_satisfies_the_published_id_pattern():
    import re
    facts = queue_record_facts("example-tv", {
        "id": 13, "title": "y", "protocol": "torrent",
        "downloadClient": "Transmission", "downloadId": "ABCDEF01"})
    [edge] = ServarrAdapter._queue_relationships(facts)
    assert re.fullmatch(r"[a-z][a-z0-9-]*:\S+", edge["target"]["id"])


def test_the_tracks_target_resolves_the_label_to_its_implementation():
    # The estate's labels are pet names (LocalTransmission); the
    # downloaders adapter files rows under the product. The app's own
    # /downloadclient list states implementation beside name, and the
    # edge must land on the row that exists — label-minted targets
    # dangled on the first real estate (live repro, 2026-08-13).
    facts = queue_record_facts("example-tv", {
        "id": 14, "title": "x", "protocol": "torrent",
        "downloadClient": "LocalTransmission", "downloadId": "ABCDEF01"})
    [edge] = ServarrAdapter._queue_relationships(
        facts, {"localtransmission": "transmission"})
    assert edge["target"]["id"] == "transfer:transmission/abcdef01"
    # A spaced label that resolves through the map mints a clean id too;
    # the whitespace guard is the fallback's guard, not the map's.
    facts = queue_record_facts("example-tv", {
        "id": 15, "title": "y", "protocol": "torrent",
        "downloadClient": "Transmission (VPN)", "downloadId": "ABCDEF01"})
    [edge] = ServarrAdapter._queue_relationships(
        facts, {"transmission (vpn)": "transmission"})
    assert edge["target"]["id"] == "transfer:transmission/abcdef01"
    # And the map builds from exactly the shape the API states.
    assert ServarrAdapter._impl_by_label([
        {"name": "LocalTransmission", "implementation": "Transmission",
         "enable": True}]) == {"localtransmission": "transmission"}


def test_a_keyless_sab_is_a_named_transfer_failure_not_a_silent_gap():
    # SE_SABNZBD_URL without its key must NOT make "sab has no transfers"
    # and "sab could not be asked" byte-identical envelopes: the sweep
    # degrades to status partial with a line naming sabnzbd, while
    # transmission's rows still ship (adversarial review, 2026-08-13).
    from system_explorer.agent.adapters import downloaders as mod

    def serve(request: httpx.Request) -> httpx.Response:
        body = jsonlib.loads(request.content)
        assert body["method"] == "torrent-get"
        return httpx.Response(200, content=jsonlib.dumps(
            {"result": "success", "arguments": {"torrents": [
                {"hashString": "ABCDEF01", "name": "example",
                 "status": 4, "error": 0}]}}),
            headers={"content-type": "application/json"})

    adapter = mod.Adapter.__new__(mod.Adapter)
    adapter.transmission_url = "http://t.test"
    adapter.sab_url = "http://s.test"
    adapter.sab_key = None
    adapter._session_id = "sess"
    adapter._client = httpx.AsyncClient(transport=httpx.MockTransport(serve))
    adapter._sweep_failures = {}
    page = asyncio.run(adapter.collect("transfers", {}, None, None))
    assert page["status"] == "partial"
    assert [item["id"] for item in page["items"]] == \
        ["transfer:transmission/abcdef01"]
    [line] = page["errors"]
    assert "sabnzbd" in line and "SE_SABNZBD_API_KEY" in line
