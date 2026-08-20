"""The connection reverses: a real Go collator dials a real Python hub.

Over a socket, end to end, with the protocol judged without a certificate
authority in the path — and mutual TLS asserted separately, so the
protocol's own rules are not provable only where openssl exists.
"""

from __future__ import annotations

import io as _io
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest

from system_explorer.hub.checkpoint import Estate, Reach
from system_explorer.hub.listener import Served, serve, server_context
from system_explorer.hub.session import Declarations

REPO = Path(__file__).resolve().parent.parent

NIX_DECLARATION = json.dumps({
    "schema": "se.declaration/1", "collector": "nix", "version": "0.7.0",
    "collections": [{
        "name": "generations", "question": "what has this host been?",
        "prefix": "generation", "freshness": "300s",
        "perishability": "reconstructible", "answer": ["ConfigurationRevision"],
        "facts": {"ConfigurationRevision": {
            "type": "string", "temperament": "configuration", "kind": "observed",
            "discloses": "nothing", "sentence": "."}},
    }],
}, separators=(",", ":")).encode()


@pytest.fixture
def collector_socket():
    """A real collector on a unix socket, from the collator harness — so
    the daemon under test acquires the way it always does."""
    import hashlib

    from collator import driver

    fake = driver.FakeCollector(NIX_DECLARATION)
    digest = "sha256:" + hashlib.sha256(NIX_DECLARATION).hexdigest()
    batch = [
        {"record": "begin", "batch": "01JC8M0000000000000000000X",
         "collector": "nix", "declaration": digest,
         "boot_id": "5e000000-0000-4000-8000-000000000001", "timens": 0,
         "instance": None, "generations": {"generations": 1}},
        {"record": "object", "collection": "generations", "name": "7",
         "facts": {"ConfigurationRevision": "4f9c2e1"}, "at": 10.0},
        {"record": "commit", "collection": "generations", "generation": 1,
         "objects": 1},
    ]
    fake.queue(driver.render(batch))
    try:
        yield fake.socket_path
    finally:
        fake.close()



def _build_collate() -> Path:
    go = shutil.which("go")
    if go is None:
        pytest.skip("go toolchain not present")
    out = Path(tempfile.mkdtemp(prefix="se-collate-bin")) / "se-collate"
    build = subprocess.run([go, "build", "-o", str(out), "./cmd/se-collate"],
                           cwd=REPO / "go", capture_output=True, text=True)
    assert build.returncode == 0, f"{build.stdout}\n{build.stderr}"
    return out


@pytest.fixture(scope="module")
def collate_binary() -> Path:
    """The real daemon. Not a test program that calls the same function:
    the thing the estate runs is what has to reach the hub, and a
    purpose-built dialler would be a second path free to drift."""
    return _build_collate()


def accept_one(sock, estate: Estate, declarations: Declarations,
               result: list[Served]) -> None:
    conn, _ = sock.accept()
    with conn, conn.makefile("rb") as stream:
        result.append(serve(stream, estate, declarations))


def test_a_collator_dials_the_hub_and_the_hub_promotes(
    collate_binary, tmp_path, collector_socket
) -> None:
    estate = Estate(declared=("storage-1",))
    declarations = Declarations()
    result: list[Served] = []
    with socket.create_server(("127.0.0.1", 0)) as sock:
        port = sock.getsockname()[1]
        thread = threading.Thread(target=accept_one,
                                  args=(sock, estate, declarations, result))
        thread.start()
        run = subprocess.run(
            [str(collate_binary)],
            env={
                "PATH": os.environ["PATH"],
                "SE_STATE_DIR": str(tmp_path / "state"),
                "SE_COLLECTORS": f"nix={collector_socket}",
                "SE_ONESHOT": "1",
                "SE_HUB_ADDR": f"127.0.0.1:{port}",
                "SE_HOST": "storage-1",
                "SE_HUB_INSECURE": "1",
            },
            capture_output=True, text=True, timeout=120,
        )
        thread.join(timeout=60)
    assert run.returncode == 0, run.stderr
    assert result and result[0].refusal is None, result
    assert result[0].host == "storage-1"
    assert result[0].promoted is not None
    assert estate.visible("storage-1") is not None
    # The collator closed. That is `dark`, not `connected` — closing makes
    # the honest reading the automatic one.
    assert estate.reach("storage-1") is Reach.DARK
    assert declarations.facts("storage-1", "generations") == frozenset(
        {"ConfigurationRevision"}
    )


def test_a_stream_the_hub_lost_its_place_in_is_not_guessed_at() -> None:
    """Skipping an unparseable line is how half a checkpoint gets
    promoted, so the session ends instead."""
    served = serve(_io.BytesIO(b'{"record":"declaration"\n'), Estate(), Declarations())
    assert served.refusal is not None
    assert served.refusal.reason == "unparseable-record"
    assert served.promoted is None


def test_a_refusal_ends_one_session_and_not_the_estate() -> None:
    estate = Estate(declared=("storage-1", "edge-1"))
    bad = _io.BytesIO(
        b'{"record":"terminal","checkpoint":"x","collections":0,"history_gap":null}\n')
    served = serve(bad, estate, Declarations())
    assert served.refusal is not None
    assert estate.reach("edge-1") is Reach.UNSWEPT, (
        "one collator getting the protocol wrong must not take the estate "
        "view down with it"
    )


def test_the_hub_requires_a_client_certificate(tmp_path) -> None:
    """Outbound-only removes the network as a containment layer, so the
    hub's identity — and the collator's — is the only thing left."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl not present; the mTLS assertion needs a CA")
    ca_key, ca_crt = tmp_path / "ca.key", tmp_path / "ca.crt"
    srv_key, srv_crt = tmp_path / "srv.key", tmp_path / "srv.crt"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(ca_key), "-out", str(ca_crt), "-days", "1",
                    "-subj", "/CN=test-ca"], check=True, capture_output=True)
    subprocess.run([openssl, "req", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(srv_key), "-out", str(tmp_path / "srv.csr"),
                    "-subj", "/CN=localhost"], check=True, capture_output=True)
    subprocess.run([openssl, "x509", "-req", "-in", str(tmp_path / "srv.csr"),
                    "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial",
                    "-out", str(srv_crt), "-days", "1"], check=True, capture_output=True)

    context = server_context(str(srv_crt), str(srv_key), str(ca_crt))
    assert context.verify_mode is ssl.CERT_REQUIRED, (
        "a hub accepting a session without a client certificate reversed the "
        "connection and kept none of what the reversal was supposed to buy"
    )
    assert context.minimum_version is ssl.TLSVersion.TLSv1_3

    refused: list[Exception] = []

    def accept(sock):
        try:
            conn, _ = sock.accept()
            with conn:
                context.wrap_socket(conn, server_side=True)
        except Exception as exc:  # noqa: BLE001 - the refusal IS the assertion
            refused.append(exc)

    with socket.create_server(("127.0.0.1", 0)) as sock:
        port = sock.getsockname()[1]
        thread = threading.Thread(target=accept, args=(sock,))
        thread.start()
        client = ssl.create_default_context(cafile=str(ca_crt))
        with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
            with pytest.raises(ssl.SSLError):
                with client.wrap_socket(raw, server_hostname="localhost") as tls:
                    tls.send(b"{}\n")
                    tls.recv(1)
        thread.join(timeout=10)
    assert refused, "the hub must refuse a session from an unidentified machine"
