#!/usr/bin/env python3
"""Run the rewrite on a lab guest and LEAVE IT RUNNING, so a person can
open it.

Everything else in this directory is a one-shot vehicle for judging a
gate. This is the other thing a surface needs and automated assertions
cannot supply: somebody looking at it. A page can satisfy every test in
the suite and still be unreadable, and the only way to find that out is
to open it.

Two roles:

    lab-serve.py collator <host> <hub-host:port> [listen-port]
    lab-serve.py hub <session-port> <http-port>

The collator role serves its OWN page as well as dialling the hub, which
is the property worth seeing with your own eyes: the host page answers
whether or not the hub is reachable, and you can prove that by stopping
the hub and reloading.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

LAB = Path(__file__).resolve().parent
sys.path.insert(0, str(LAB))

ROLE = sys.argv[1]


def serve_collectors(work: Path) -> dict[str, Path]:
    """Every collector binary present, each on its own unix socket.

    The collector contract is one request line on stdin and the response
    on stdout — what systemd hands it per accepted connection — so this is
    that, and the binary under test is unchanged.
    """
    sockets: dict[str, Path] = {}
    for binary in sorted(LAB.glob("se-collect-*")):
        name = binary.name.removeprefix("se-collect-")
        path = work / f"{name}.sock"
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path))
        server.listen(16)
        sockets[name] = path

        def loop(binary: Path = binary, server: socket.socket = server) -> None:
            while True:
                try:
                    conn, _ = server.accept()
                except OSError:
                    return
                with conn:
                    try:
                        subprocess.run([str(binary)], stdin=conn.fileno(),
                                       stdout=conn.fileno(),
                                       stderr=subprocess.DEVNULL, timeout=120)
                    except Exception:
                        pass

        threading.Thread(target=loop, daemon=True).start()
    return sockets


if ROLE == "collator":
    host, hub = sys.argv[2], sys.argv[3]
    listen = sys.argv[4] if len(sys.argv) > 4 else "0.0.0.0:8095"
    work = Path(tempfile.mkdtemp(prefix="se-lab-collator"))
    sockets = serve_collectors(work)
    if not sockets:
        raise SystemExit("no se-collect-* binary beside this script")
    print(f"[{host}] collectors: {', '.join(sorted(sockets))}", flush=True)
    print(f"[{host}] host page: http://{listen}/", flush=True)
    # NOT exec: this process IS the collectors' socket server, and
    # replacing its image would take the serving threads with it, leaving
    # the socket files in place with nothing behind them. The collator
    # then reports "connection refused" on every collector and sends the
    # hub a session with no declarations at all — which is exactly what
    # happened the first time this ran on a guest, and what no unit test
    # could have shown, because in a test the collector is a fixture in
    # the same process rather than a child of it.
    collator = subprocess.Popen([str(LAB / "se-collate")], env={
        "PATH": os.environ["PATH"],
        "SE_STATE_DIR": str(work / "state"),
        "SE_COLLECTORS": ",".join(f"{n}={p}" for n, p in sorted(sockets.items())),
        "SE_LISTEN": listen,
        "SE_HUB_ADDR": hub,
        "SE_HOST": host,
        "SE_HUB_INSECURE": "1",
    })
    raise SystemExit(collator.wait())

if ROLE != "hub":
    raise SystemExit(f"unknown role {ROLE!r}")

from sehub.checkpoint import Estate            # noqa: E402
from sehub.http import reading, serve          # noqa: E402
from sehub.intent import Intent                # noqa: E402
from sehub.listener import serve as serve_session  # noqa: E402
from sehub.session import Declarations         # noqa: E402

session_port, http_port = int(sys.argv[2]), int(sys.argv[3])
INTENT = json.loads((LAB / "intent.json").read_text())
intent = Intent.load(INTENT)
estate = Estate(declared=tuple(intent.declared_hosts()))
declarations = Declarations()

listener = socket.create_server(("0.0.0.0", session_port))


def accept_forever() -> None:
    while True:
        try:
            conn, peer = listener.accept()
        except OSError:
            return
        with conn, conn.makefile("rb") as stream:
            served = serve_session(stream, estate, declarations)
        print(f"[hub] session from {peer[0]}: host={served.host} "
              f"promoted={served.promoted is not None} "
              f"refusal={served.refusal.reason if served.refusal else None}",
              flush=True)


threading.Thread(target=accept_forever, daemon=True).start()
http = serve(("0.0.0.0", http_port), lambda: reading(estate, intent, declarations))
print(f"[hub] intent {intent.hash}", flush=True)
print(f"[hub] estate page: http://0.0.0.0:{http_port}/", flush=True)
print(f"[hub] collators dial: {session_port}", flush=True)
http.serve_forever()
