"""Tailnet peer ids obey the object-id grammar whatever the peer calls itself.

Found by the live check on its first run (2026-08-12): every deployed host
with the tailscale grant emitted `tailscale:Henry\u2019s MacBook Pro` — a space
and a typographic apostrophe inside an id whose published grammar the
schemas own — because the adapter preferred the peer's self-reported
HostName over the tailnet's DNS label. Display names are free text and
unstable identity; the DNS label is the coordination map's canonical
machine name, and a peer without one is skipped rather than given a
patched-up free-text id (review verdict over the first draft's fallback).
"""

import re

from common import SCHEMAS

from system_explorer.agent.adapters.network import peer_native_id

# The grammar is read from the published schema, not restated: a fourth
# hand-spelled copy is a fourth thing to disagree with it.
OBJECT_ID = re.compile(SCHEMAS["se.observation/1"]["$defs"]["objectId"]["pattern"])


def test_the_dns_label_wins_over_the_display_name():
    peer = {"DNSName": "henrys-macbook-pro.tail1234.ts.net.",
            "HostName": "Henry\u2019s MacBook Pro"}
    assert peer_native_id(peer) == "henrys-macbook-pro"


def test_a_peer_with_no_dns_label_is_skipped_not_renamed():
    # Free text never becomes an id; the caller's `if not name: continue`
    # drops the peer, one fewer id shape in the world.
    assert peer_native_id({"DNSName": "", "HostName": "Henry\u2019s MacBook Pro"}) is None
    assert peer_native_id({}) is None


def test_ordinary_server_peers_pass_through_unchanged():
    peer = {"DNSName": "some-host.tail1234.ts.net.", "HostName": "some-host"}
    native = peer_native_id(peer)
    assert native == "some-host"
    assert OBJECT_ID.match(f"tailscale:{native}")
