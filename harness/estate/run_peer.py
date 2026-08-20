#!/usr/bin/env python3
"""Federation between two lab guests, each acting as its own site.

  run_peer.py serve <site> <bind-port>   the member that ACCEPTS
  run_peer.py dial  <site> <host:port>   the member that ORIGINATES

Which side dials is stated per pair rather than assumed symmetric — a
site behind NAT can only originate, and that is a deployment fact this
script takes as an argument for exactly that reason.
"""
from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from sehub.federation import offer, peer_session, review
from sehub.intent import Intent

INTENT = {
    "schema": "se.intent/1", "estate": "home", "revision": 41,
    "reviewed": "2026-08-20", "estate_hub": "site-a",
    "membership": {"hosts": {"lab-a": {"roles": ["host"]},
                             "lab-b": {"roles": ["host"]}}},
}

mode, site = sys.argv[1], sys.argv[2]
# A divergent revision is how the refusal path is exercised on demand.
if len(sys.argv) > 4 and sys.argv[4] == "--divergent":
    INTENT = {**INTENT, "revision": 42}
intent = Intent.load(INTENT)

if mode == "serve":
    port = int(sys.argv[3])
    with socket.create_server(("0.0.0.0", port)) as listener:
        # Bounded: a member that waited for ever would hang whatever is
        # orchestrating it, and a federation pair that never connects must
        # report that rather than stall.
        listener.settimeout(120)
        try:
            conn, peer = listener.accept()
        except TimeoutError:
            print(json.dumps({"mode": "serve", "site": site,
                              "refusal": "no-peer-connected"}))
            sys.exit(0)
        with conn, conn.makefile("rb") as rx, conn.makefile("wb") as tx:
            refusal = peer_session(
                rx, tx, offer(site, intent), site,
                answer=lambda request: {"site": site, "hosts": ["lab-b"]},
            )
    print(json.dumps({
        "mode": "serve", "site": site, "peer": peer[0],
        "intent_hash": intent.hash,
        "refusal": None if refusal is None else refusal.reason,
    }))
    sys.exit(0)

target = sys.argv[3]
addr, _, port = target.partition(":")
result: dict = {"mode": "dial", "site": site, "intent_hash": intent.hash}
with socket.create_connection((addr, int(port)), timeout=30) as conn:
    with conn.makefile("rb") as rx, conn.makefile("wb") as tx:
        theirs = json.loads(rx.readline())
        result["peer_site"] = theirs.get("site")
        result["peer_intent_hash"] = theirs.get("intent_hash")
        tx.write((json.dumps({"record": "handshake",
                              **offer(site, intent).as_wire()}) + "\n").encode())
        tx.flush()
        verdict = json.loads(rx.readline())
        result["handshake"] = verdict.get("record")
        result["handshake_reason"] = verdict.get("reason")
        result["handshake_detail"] = verdict.get("detail", "")[:200]
        if verdict.get("record") == "agreed":
            replies = []
            for for_site in ("site-b", "site-c"):
                tx.write((json.dumps({"record": "request", "origin_site": site,
                                      "for_site": for_site}) + "\n").encode())
                tx.flush()
                reply = json.loads(rx.readline())
                replies.append({"for_site": for_site, "record": reply.get("record"),
                                "reason": reply.get("reason"),
                                "body": reply.get("body")})
            result["replies"] = replies
        conn.shutdown(socket.SHUT_WR)
print(json.dumps(result, indent=1))
