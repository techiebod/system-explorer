#!/usr/bin/env python3
"""One hub on one lab guest, receiving both guests' collators.

  run_estate.py hub <bind-port> <expected-sessions>
  run_estate.py collator <host> <hub-addr:port>

This is the two-guest estate: two real machines, two kernels, two real
collectors reading two real hosts, one hub, one view.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
LAB = Path(__file__).resolve().parent

mode = sys.argv[1]

if mode == "collator":
    host, hub = sys.argv[2], sys.argv[3]
    work = Path(tempfile.mkdtemp(prefix="se-collator"))
    # Whichever collectors this guest actually has. A guest without the
    # nix collector runs one, which is not a degraded lab — it is the
    # unevenness the matrix exists for, and it is what makes a decline of
    # `unsupported` reachable at the hub.
    names = [n for n in ("system", "nix") if (LAB / f"se-collect-{n}").exists()]
    stop = threading.Event()
    sockets = {}
    for name in names:
        path = work / f"{name}.sock"
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(str(path))
        s.listen(16)
        sockets[name] = (s, path)

    def serve_collector(collector: str, s: socket.socket) -> None:
        while not stop.is_set():
            try:
                conn, _ = s.accept()
            except OSError:
                return
            with conn:
                try:
                    subprocess.run([str(LAB / f"se-collect-{collector}")],
                                   stdin=conn.fileno(), stdout=conn.fileno(),
                                   stderr=subprocess.DEVNULL, timeout=120)
                except Exception:
                    pass

    for name, (s, _p) in sockets.items():
        threading.Thread(target=serve_collector, args=(name, s), daemon=True).start()
    spec = ",".join(f"{name}={p}" for name, (_s, p) in sockets.items())
    run = subprocess.run(
        [str(LAB / "se-collate")],
        env={"PATH": os.environ["PATH"], "SE_STATE_DIR": str(work / "state"),
             "SE_COLLECTORS": spec, "SE_ONESHOT": "1",
             "SE_HUB_ADDR": hub, "SE_HOST": host, "SE_HUB_INSECURE": "1"},
        capture_output=True, text=True, timeout=300,
    )
    stop.set()
    for _name, (s, _p) in sockets.items():
        s.close()
    print(json.dumps({"host": host, "collectors": names, "rc": run.returncode,
                      "stderr": run.stderr.strip()[:300]}))
    sys.exit(run.returncode)

from sehub.answer import estate_current
from sehub.checkpoint import Estate
from sehub.intent import Intent
from sehub.listener import serve
from sehub.rollup import assemble
from sehub.session import Declarations

port, expected = int(sys.argv[2]), int(sys.argv[3])
estate = Estate(declared=("lab-a", "lab-b"))
declarations = Declarations()
served: list = []

with socket.create_server(("0.0.0.0", port)) as listener:
    listener.settimeout(180)
    for _ in range(expected):
        try:
            conn, _peer = listener.accept()
        except TimeoutError:
            break
        with conn, conn.makefile("rb") as stream:
            served.append(serve(stream, estate, declarations))

intent = Intent.load({
    "schema": "se.intent/1", "estate": "home", "revision": 41,
    "reviewed": "2026-08-20", "estate_hub": "site-a",
    "membership": {"hosts": {"lab-a": {"roles": ["host"]},
                             "lab-b": {"roles": ["host"]}}},
})
view = assemble(estate, intent, declarations)
answer = estate_current(view, estate, intent)

print(json.dumps({
    "sessions": len(served),
    "refusals": [s.refusal.reason for s in served if s.refusal],
    "hosts_promoted": sorted(s.host for s in served if s.promoted),
    "reach": {h: r.value for h, r in view.reach.items()},
    "rows": [r.id for r in view.rows],
    "facts": {r.id: dict(sorted(r.facts.items())[:3]) for r in view.rows},
    "undeclared": sorted({f for r in view.rows for f in r.undeclared}),
    "coverage": {"declared": list(view.coverage.declared),
                 "unclassified": list(view.coverage.unclassified)},
    "answer": {k: answer[k] for k in
               ("question", "answer", "verdict", "epistemic", "freshness")},
    "answer_reach": answer["reach"],
}, indent=1))
