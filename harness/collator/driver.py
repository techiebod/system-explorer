"""The collator fixture driver: recorded streams in, exhaustive assertions out.

This is the driver README.md promised. One fixture is one scenario: a fake
collector serves the fixture's recorded streams verbatim over a real unix
socket, the real se-collate binary is run against it, and the fixture's
`expect` block is judged against the durable store (and, where the fixture
says so, the read API). Nothing here re-implements collator logic — the
subject is the binary, spawned the way systemd would spawn it, because a
collator simulated inside the test process proves recovery of nothing.

`expect` is judged EXHAUSTIVELY: every object the collator minted must be
listed and every listed object must exist, because a judge that only checked
what it expected would never catch an invented object (README.md). The same
both-directions rule covers collections, rejections and acknowledgements —
a fixture that could pass while the collator did something unlisted would be
the subset guard this repo keeps refusing.

Two regimes of failure are kept apart on purpose: a defective fixture raises
FixtureError (the fixture is wrong), a defective collator raises
AssertionError (the subject is wrong). The must-fail self-test relies on the
split — a broken fixture must not masquerade as a judged red.

One seam is simulated rather than real, and the simulation is declared where
it is used: a stream may carry `wind_issued`, which sets a collection's
issued-generation counter in the store between rounds so the next acquisition
mints a number that was already used. The wire's generation-echo check
(correctly) makes it impossible for a counterparty to deliver a foreign
generation from outside, so the batch authority's below/equal branches —
DESIGN 19's refusal, no-op and protocol-error rules — are reachable from
outside the process only by making the authority re-mint a used number, which
is exactly the "somebody reused it" event those rules exist to judge.

Fixture members beyond the README's sketch, all judged by the loader:
  declaration      exact bytes the fake serves for `declare`; every begin
                   record's `declaration` member must carry its sha256
  concurrent       feed the streams' responses interleaved: generations are
                   issued in stream order, responses delivered in reverse,
                   each held until the later batch is acknowledged — the
                   watch-fires/schedule-fires hazard of DESIGN 19
  wind_issued      per-stream, see above; never on the first stream and
                   never in a concurrent fixture
  expect.acked     the acknowledged batch ids, as a set — what proves a
                   silently-skipped round cannot pass as a no-op
  expect.age_from_oldest
                   collection names whose served age_s must derive from
                   oldest_at (acceptance item 5), judged over the read API —
                   the daemon is spawned with SE_BOOT_ID set to the streams'
                   own boot id, because age is same-domain arithmetic and the
                   serving process did not boot with the fixture
  expect.cross_boot
                   collection names the read API must serve WITHOUT age_s and
                   WITH cross_boot: true when the daemon's own boot id (again
                   via SE_BOOT_ID) differs from the one the applied batch
                   carried — DESIGN 09: a mismatch is stated, never
                   subtracted through
  must_fail        marks a self-test fixture the judge must red; excluded
                   from the real run and exercised by the loader self-test

Fixture numbers should use plain lexemes (no exponents, no HTML-significant
characters in strings): facts are compared through one canonical JSON
round-trip on both sides, which keeps 20 and 20.0 distinct but would let
exotic spellings differ from Go's re-marshalling.
"""

from __future__ import annotations

import functools
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

REPO = Path(__file__).resolve().parents[2]
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# How long any single wait may take before the driver declares the run
# wedged. Generous because CI machines stall; never load-bearing for a
# passing run, which polls its way out in milliseconds.
WAIT_S = 30.0

_COLLECTION_NAME = re.compile(r"^[a-z][a-z0-9-]*$")

# Phase 2's store holds objects, generations, rejections and acks; joins
# and opinions are later phases. A fixture expecting them would be judged
# by nothing, so the loader refuses it rather than passing it vacuously.
_UNJUDGEABLE_YET = ("relations", "opinions")


class FixtureError(Exception):
    """The fixture itself is defective — distinct from a judged red."""


# ── building the subject ─────────────────────────────────────────────────


@functools.lru_cache(maxsize=1)
def collate_binary() -> Path:
    """Build se-collate once per test process, for the host platform.

    CGO_ENABLED=0 on the host too: the deploy target is pure-Go
    cross-compiled, so a harness that quietly leaned on cgo would be
    testing a binary nobody ships.
    """
    go = shutil.which("go") or "/opt/homebrew/bin/go"
    out = Path(tempfile.mkdtemp(prefix="se-collate-bin")) / "se-collate"
    env = dict(os.environ, CGO_ENABLED="0")
    build = subprocess.run(
        [go, "build", "-o", str(out), "./cmd/se-collate"],
        cwd=REPO / "go",
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if build.returncode != 0:
        raise RuntimeError(f"go build se-collate failed:\n{build.stderr}")
    return out


# ── the fixture loader ───────────────────────────────────────────────────


@functools.lru_cache(maxsize=1)
def _stream_validator() -> Draft202012Validator:
    registry = Registry()
    for path in sorted((REPO / "contract").glob("*.json")):
        schema = json.loads(path.read_text())
        registry = registry.with_resource(schema["$id"], Resource.from_contents(schema))
    return Draft202012Validator(
        json.loads((REPO / "contract" / "se.stream.1.json").read_text()),
        registry=registry,
    )


@dataclass
class Stream:
    records: list[dict]
    instance: str | None = None
    wind_issued: dict[str, int] = field(default_factory=dict)

    @property
    def batch(self) -> str:
        return self.records[0]["batch"]


@dataclass
class Fixture:
    path: Path
    name: str
    acceptance_item: int
    note: str
    declaration: bytes
    collections: list[str]
    streams: list[Stream]
    expect: dict
    concurrent: bool
    must_fail: str | None


def _refuse_unknown(members: dict, allowed: set[str], where: str) -> None:
    unknown = set(members) - allowed
    if unknown:
        raise FixtureError(f"{where}: unknown members {sorted(unknown)}")


def _require(members: dict, required: set[str], where: str) -> None:
    missing = required - set(members)
    if missing:
        raise FixtureError(f"{where}: missing required members {sorted(missing)}")


def load_fixture(path: Path) -> Fixture:
    try:
        doc = json.loads(path.read_text())
    except json.JSONDecodeError as err:
        raise FixtureError(f"{path.name}: not JSON: {err}") from err
    if not isinstance(doc, dict):
        raise FixtureError(f"{path.name}: a fixture is a JSON object")
    _refuse_unknown(
        doc,
        {"name", "acceptance_item", "note", "declaration", "streams", "expect",
         "concurrent", "must_fail"},
        path.name,
    )
    _require(doc, {"name", "acceptance_item", "note", "declaration", "streams", "expect"}, path.name)
    if doc["name"] != path.stem:
        raise FixtureError(
            f"{path.name}: fixture names itself {doc['name']!r} — the name and "
            "the filename must agree or a directory listing lies about coverage"
        )
    if not isinstance(doc["note"], str) or not doc["note"].strip():
        raise FixtureError(f"{path.name}: the note says why the scenario exists; it may not be empty")
    if not isinstance(doc["acceptance_item"], int):
        raise FixtureError(f"{path.name}: acceptance_item must be the item number")

    declaration = _load_declaration(doc, path.name)
    collections = [c["name"] for c in json.loads(declaration)["collections"]]
    concurrent = doc.get("concurrent", False)
    if not isinstance(concurrent, bool):
        raise FixtureError(f"{path.name}: concurrent must be a boolean")

    streams = _load_streams(doc, declaration, collections, concurrent, path.name)
    if concurrent and len(streams) < 2:
        raise FixtureError(f"{path.name}: a concurrent fixture interleaves at least two streams")

    expect = _load_expect(doc["expect"], path.name)

    must_fail = doc.get("must_fail")
    if must_fail is not None and (not isinstance(must_fail, str) or not must_fail.strip()):
        raise FixtureError(f"{path.name}: must_fail carries the reason the judge must red this")

    return Fixture(
        path=path,
        name=doc["name"],
        acceptance_item=doc["acceptance_item"],
        note=doc["note"],
        declaration=declaration,
        collections=collections,
        streams=streams,
        expect=expect,
        concurrent=concurrent,
        must_fail=must_fail,
    )


def _load_declaration(doc: dict, where: str) -> bytes:
    if not isinstance(doc["declaration"], str):
        raise FixtureError(
            f"{where}: declaration is the exact bytes the fake serves, as a string — "
            "begin's hash commits to bytes, so the fixture pins bytes"
        )
    declaration = doc["declaration"].encode()
    try:
        parsed = json.loads(declaration)
    except json.JSONDecodeError as err:
        raise FixtureError(f"{where}: declaration does not parse: {err}") from err
    cols = parsed.get("collections")
    if not isinstance(cols, list) or not cols:
        raise FixtureError(f"{where}: declaration names no collections")
    for col in cols:
        if not isinstance(col, dict) or not col.get("name") or not col.get("freshness"):
            raise FixtureError(f"{where}: every declared collection carries name and freshness")
        if not _COLLECTION_NAME.match(col["name"]):
            raise FixtureError(f"{where}: collection name {col['name']!r}")
    return declaration


def _load_streams(
    doc: dict, declaration: bytes, collections: list[str], concurrent: bool, where: str
) -> list[Stream]:
    if not isinstance(doc["streams"], list) or not doc["streams"]:
        raise FixtureError(f"{where}: streams must be a non-empty list")
    decl_hash = "sha256:" + hashlib.sha256(declaration).hexdigest()
    validator = _stream_validator()
    streams: list[Stream] = []
    for i, raw in enumerate(doc["streams"]):
        label = f"{where} stream {i}"
        if not isinstance(raw, dict):
            raise FixtureError(f"{label}: a stream is an object")
        _refuse_unknown(raw, {"records", "instance", "collector", "wind_issued"}, label)
        records = raw.get("records")
        if not isinstance(records, list) or not records:
            raise FixtureError(f"{label}: records must be a non-empty list")
        for j, record in enumerate(records):
            errors = sorted(validator.iter_errors(record), key=str)
            if errors:
                raise FixtureError(
                    f"{label} record {j}: not a legal stream record:\n"
                    + "\n".join(f"- {e.json_path}: {e.message}" for e in errors)
                )
        if records[0].get("record") != "begin" or records[-1].get("record") != "end":
            raise FixtureError(
                f"{label}: a recorded stream opens with begin and closes with end — "
                "a severed stream is the crash harness's subject, not a fixture's"
            )
        begin = records[0]
        if begin["declaration"] != decl_hash:
            raise FixtureError(
                f"{label}: begin declares {begin['declaration']} but the fixture's "
                f"declaration bytes hash to {decl_hash} — the collator would hold "
                "this batch as unknown, which is a different scenario"
            )
        instance = raw.get("instance")
        if begin["instance"] != instance:
            raise FixtureError(
                f"{label}: begin.instance is {begin['instance']!r} but the stream "
                f"says {instance!r} — the two must agree or the fixture argues with itself"
            )
        wind = raw.get("wind_issued", {})
        if wind:
            if concurrent:
                raise FixtureError(
                    f"{label}: wind_issued in a concurrent fixture — interleaving is "
                    "that scenario's vehicle for generation disorder, not the store"
                )
            if i == 0:
                raise FixtureError(
                    f"{label}: wind_issued before any round has run — there is no "
                    "store to wind yet"
                )
            if not isinstance(wind, dict):
                raise FixtureError(f"{label}: wind_issued must map collection to integer")
            for name, value in wind.items():
                if name not in collections:
                    raise FixtureError(f"{label}: wind_issued names undeclared collection {name!r}")
                if not isinstance(value, int) or value < 0:
                    raise FixtureError(f"{label}: wind_issued.{name} must be a non-negative integer")
        streams.append(Stream(records=records, instance=instance, wind_issued=dict(wind)))
    return streams


def _load_expect(expect: dict, where: str) -> dict:
    label = f"{where} expect"
    if not isinstance(expect, dict):
        raise FixtureError(f"{label}: expect is an object")
    _refuse_unknown(
        expect,
        {"objects", "collections", "rejected", "acked", "relations", "opinions",
         "age_from_oldest", "cross_boot"},
        label,
    )
    # objects, collections, rejected and acked are REQUIRED, even when empty:
    # an omitted key would be an unjudged surface, and a fixture that could
    # pass while the store held something unlisted is the subset guard again.
    _require(expect, {"objects", "collections", "rejected", "acked"}, label)
    for key in _UNJUDGEABLE_YET:
        if expect.get(key, []) != []:
            raise FixtureError(
                f"{label}: {key} cannot be judged yet — the phase-2 store holds "
                "none; a non-empty expectation here would pass without being checked"
            )
    for entry in expect["objects"]:
        _refuse_unknown(entry, {"collection", "id", "name", "facts", "at", "scope"}, f"{label}.objects")
        _require(entry, {"collection", "id", "name", "facts"}, f"{label}.objects")
    for entry in expect["collections"]:
        _refuse_unknown(
            entry,
            {"name", "generation", "stale", "stale_reason", "object_count", "oldest_at"},
            f"{label}.collections",
        )
        _require(entry, {"name", "generation", "stale"}, f"{label}.collections")
        if entry["stale"] and "stale_reason" not in entry:
            raise FixtureError(
                f"{label}.collections: {entry['name']} expects stale without naming "
                "the reason — staleness is always attributed (DESIGN 19)"
            )
    for entry in expect["rejected"]:
        _refuse_unknown(entry, {"collection", "reason", "batch"}, f"{label}.rejected")
        _require(entry, {"collection", "reason"}, f"{label}.rejected")
    if not isinstance(expect["acked"], list) or not all(isinstance(b, str) for b in expect["acked"]):
        raise FixtureError(f"{label}: acked is a list of batch ids")
    age = expect.get("age_from_oldest")
    if age is not None:
        named = {entry["name"] for entry in expect["collections"]}
        if not isinstance(age, list) or len(age) < 2:
            raise FixtureError(
                f"{label}: age_from_oldest needs at least two collections — the check "
                "compares age_s + oldest_at across rows, and one row agrees with itself"
            )
        for name in age:
            if name not in named:
                raise FixtureError(f"{label}: age_from_oldest names {name!r}, absent from expect.collections")
    cross = expect.get("cross_boot")
    if cross is not None:
        named = {entry["name"] for entry in expect["collections"]}
        if not isinstance(cross, list) or not cross:
            raise FixtureError(f"{label}: cross_boot is a non-empty list of collection names")
        for name in cross:
            if name not in named:
                raise FixtureError(f"{label}: cross_boot names {name!r}, absent from expect.collections")
    return expect


def discover(directory: Path = FIXTURES_DIR) -> tuple[list[Fixture], list[Fixture]]:
    """All fixtures, partitioned into (real, must-fail self-tests)."""
    real: list[Fixture] = []
    self_tests: list[Fixture] = []
    for path in sorted(directory.glob("*.json")):
        fixture = load_fixture(path)
        (self_tests if fixture.must_fail else real).append(fixture)
    return real, self_tests


# ── the fake collector ───────────────────────────────────────────────────


@dataclass
class _Collect:
    payload: bytes
    arrived: threading.Event = field(default_factory=threading.Event)
    release: threading.Event | None = None


class FakeCollector:
    """A scripted collector on a real unix socket.

    It answers `declare` with the fixture's declaration bytes and each
    `collect` with the next queued payload, verbatim. Gates (declare_gate,
    per-payload release events) exist so a concurrent fixture can decide
    the order in which generations are issued and the order in which
    batches finish — the two orders whose disagreement is the scenario.

    Every deviation it notices lands in .errors, and check() raises them:
    a fake that swallowed its own confusion would let a fixture pass while
    serving nothing.
    """

    def __init__(self, declaration: bytes, sock_dir: str | None = None):
        # Unix socket paths are length-bounded (104 bytes on darwin), so the
        # socket lives under a deliberately short mkdtemp, not the test tmp.
        self._own_dir = sock_dir is None
        self._dir = sock_dir or tempfile.mkdtemp(prefix="se")
        self.socket_path = os.path.join(self._dir, "c.sock")
        self.declaration = declaration
        self.declare_gate: threading.Event | None = None
        self.errors: list[str] = []
        self._queue: list[_Collect] = []
        self._lock = threading.Lock()
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.socket_path)
        self._server.listen(8)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def queue(self, payload: bytes, hold: bool = False) -> _Collect:
        entry = _Collect(payload=payload, release=threading.Event() if hold else None)
        with self._lock:
            self._queue.append(entry)
        return entry

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._server.accept()
            except OSError:
                return  # closed
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            line = b""
            while b"\n" not in line and len(line) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                line += chunk
            verb = line.split(b"\n", 1)[0].split(b" ", 1)[0].decode(errors="replace")
            if verb == "declare":
                gate = self.declare_gate
                if gate is not None and not gate.wait(WAIT_S):
                    self.errors.append("declare gate never released")
                    return
                conn.sendall(self.declaration)
            elif verb == "collect":
                with self._lock:
                    entry = self._queue.pop(0) if self._queue else None
                if entry is None:
                    self.errors.append(
                        "a collect arrived with no stream queued — the collator "
                        "asked one more time than the fixture scripted"
                    )
                    return
                entry.arrived.set()
                if entry.release is not None and not entry.release.wait(WAIT_S):
                    self.errors.append("a held collect was never released")
                    return
                conn.sendall(entry.payload)
            else:
                self.errors.append(f"unexpected verb {verb!r}")
        except OSError as err:
            self.errors.append(f"socket error: {err}")
        finally:
            conn.close()

    def check(self) -> None:
        if self.errors:
            raise AssertionError("fake collector: " + "; ".join(self.errors))

    def close(self) -> None:
        try:
            self._server.close()
        finally:
            if self._own_dir:
                shutil.rmtree(self._dir, ignore_errors=True)


def render(records: list[dict]) -> bytes:
    """Records to NDJSON, exactly as a collector's encoder would write them."""
    return ("\n".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) for r in records) + "\n").encode()


# ── running the subject ──────────────────────────────────────────────────


def _env(state_dir: str, collectors: dict[str, str], **extra: str) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("SE_")}
    env["SE_STATE_DIR"] = state_dir
    env["SE_COLLECTORS"] = ",".join(f"{name}={sock}" for name, sock in collectors.items())
    env.update(extra)
    return env


def run_oneshot(
    binary: Path, state_dir: str, collectors: dict[str, str], crash_at: str = ""
) -> subprocess.CompletedProcess:
    """One acquisition round: the daemon's SE_ONESHOT vehicle."""
    extra = {"SE_ONESHOT": "1"}
    if crash_at:
        extra["SE_CRASH_AT"] = crash_at
    return subprocess.run(
        [str(binary)],
        env=_env(state_dir, collectors, **extra),
        capture_output=True,
        text=True,
        timeout=60,
    )


def spawn_daemon(
    binary: Path, state_dir: str, collectors: dict[str, str], listen: str,
    **extra: str,
) -> subprocess.Popen:
    return subprocess.Popen(
        [str(binary)],
        env=_env(state_dir, collectors, SE_LISTEN=listen, **extra),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _stop(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


# ── reading the store ────────────────────────────────────────────────────


def db_path(state_dir: str) -> str:
    return os.path.join(state_dir, "collate.db")


def _connect_ro(path: str) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)


def snapshot(path: str) -> dict:
    """The store's whole observable state, read cross-process through WAL."""
    con = _connect_ro(path)
    try:
        collections = {
            row[0]: {
                "generation": row[1],
                "stale": bool(row[2]),
                "stale_reason": row[3],
            }
            for row in con.execute(
                "SELECT name, applied_gen, stale, stale_reason FROM collections"
            )
        }
        objects = [
            {
                "collection": row[0],
                "scope": row[1],
                "id": row[2],
                "name": row[3],
                "facts": json.loads(row[4]),
                "at": row[5],
            }
            for row in con.execute(
                "SELECT collection, scope, id, name, facts, at FROM objects ORDER BY collection, scope, id"
            )
        ]
        rejections = [
            {"collection": row[0], "batch": row[1], "reason": row[2], "detail": row[3]}
            for row in con.execute(
                "SELECT COALESCE(collection,''), COALESCE(batch,''), reason, COALESCE(detail,'') "
                "FROM rejections ORDER BY seq"
            )
        ]
        acked = {row[0] for row in con.execute("SELECT batch FROM acks")}
        oldest = {
            row[0]: row[1]
            for row in con.execute("SELECT collection, MIN(at) FROM objects GROUP BY collection")
        }
        return {
            "collections": collections,
            "objects": objects,
            "rejections": rejections,
            "acked": acked,
            "oldest": oldest,
        }
    finally:
        con.close()


def wind_issued(path: str, collection: str, value: int) -> None:
    """Set a collection's issued-generation counter, simulating reuse.

    See the module docstring: the batch authority's below/equal branches
    are reachable from outside only by making it re-mint a used number.
    This touches issued_gen alone — applied state, hashes and objects are
    the subject's and stay untouched.
    """
    con = sqlite3.connect(path, timeout=5)
    try:
        cur = con.execute(
            "UPDATE collections SET issued_gen = ? WHERE name = ?", (value, collection)
        )
        con.commit()
        if cur.rowcount != 1:
            raise FixtureError(
                f"wind_issued: collection {collection!r} is not in the store — "
                "no earlier round created it, so there is nothing to wind"
            )
    finally:
        con.close()


def wait_for(predicate, what: str, timeout: float = WAIT_S) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except sqlite3.OperationalError:
            pass  # the daemon has not created or checkpointed the store yet
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


# ── the judge ────────────────────────────────────────────────────────────


def _canon(value) -> str:
    """One canonical spelling for typed comparison: 20 and 20.0 differ."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def assert_expect(fixture: Fixture, state: dict) -> None:
    """Judge the expect block against a store snapshot, exhaustively."""
    expect = fixture.expect
    label = fixture.name

    # Objects: both directions, keyed by (collection, scope, id).
    actual = {(o["collection"], o["scope"], o["id"]): o for o in state["objects"]}
    expected = {
        (e["collection"], e.get("scope", ""), e["id"]): e for e in expect["objects"]
    }
    invented = sorted(set(actual) - set(expected))
    assert not invented, (
        f"{label}: the collator minted objects the fixture does not list: {invented} — "
        "an unlisted minted object is a failure (README.md)"
    )
    missing = sorted(set(expected) - set(actual))
    assert not missing, f"{label}: expected objects are not in the store: {missing}"
    for key, want in expected.items():
        got = actual[key]
        assert got["name"] == want["name"], (
            f"{label}: object {key}: name {got['name']!r}, want {want['name']!r}"
        )
        assert _canon(got["facts"]) == _canon(want["facts"]), (
            f"{label}: object {key}: facts {_canon(got['facts'])}, want {_canon(want['facts'])}"
        )
        if "at" in want:
            assert got["at"] == want["at"], (
                f"{label}: object {key}: at {got['at']!r}, want {want['at']!r} — "
                "the stamp is carried verbatim, never re-derived"
            )

    # Collections: both directions by name.
    actual_cols = state["collections"]
    expected_cols = {e["name"]: e for e in expect["collections"]}
    assert set(actual_cols) == set(expected_cols), (
        f"{label}: store knows collections {sorted(actual_cols)}, "
        f"fixture lists {sorted(expected_cols)}"
    )
    for name, want in expected_cols.items():
        got = actual_cols[name]
        assert got["generation"] == want["generation"], (
            f"{label}: {name}: applied generation {got['generation']}, want {want['generation']}"
        )
        assert got["stale"] == want["stale"], (
            f"{label}: {name}: stale is {got['stale']}, want {want['stale']}"
        )
        assert got["stale_reason"] == want.get("stale_reason"), (
            f"{label}: {name}: stale_reason {got['stale_reason']!r}, want {want.get('stale_reason')!r}"
        )
        if "object_count" in want:
            count = sum(1 for o in state["objects"] if o["collection"] == name)
            assert count == want["object_count"], (
                f"{label}: {name}: {count} objects, want {want['object_count']}"
            )
        if "oldest_at" in want:
            assert state["oldest"].get(name) == want["oldest_at"], (
                f"{label}: {name}: oldest at {state['oldest'].get(name)!r}, "
                f"want {want['oldest_at']!r} — freshness derives from the oldest "
                "contributing read (acceptance item 5)"
            )

    # Rejections: the exact ordered sequence — an extra refusal is as wrong
    # as a missing one, and order is deterministic because the driver is.
    got_rejected = state["rejections"]
    want_rejected = expect["rejected"]
    brief = [(r["collection"], r["reason"]) for r in got_rejected]
    assert len(got_rejected) == len(want_rejected), (
        f"{label}: {len(got_rejected)} rejections recorded {brief}, "
        f"fixture lists {len(want_rejected)}"
    )
    for i, want in enumerate(want_rejected):
        got = got_rejected[i]
        for member in ("collection", "reason", "batch"):
            if member in want:
                assert got[member] == want[member], (
                    f"{label}: rejection {i}: {member} {got[member]!r}, want {want[member]!r} "
                    f"(recorded: {brief})"
                )

    # Acks: set equality. This is what stops a skipped round passing as a
    # no-op — a batch the collator never processed was never acknowledged.
    assert state["acked"] == set(expect["acked"]), (
        f"{label}: acknowledged batches {sorted(state['acked'])}, want {sorted(expect['acked'])}"
    )


def _stream_boot_id(fixture: Fixture) -> str:
    """The boot id the applied collections carry: the LAST stream's, since
    the last apply is the one whose stamp the store serves."""
    return fixture.streams[-1].records[0]["boot_id"]


def _served_rows(binary: Path, state_dir: str, own_boot_id: str) -> dict[str, dict]:
    """Spawn the daemon claiming own_boot_id as its boot and read one
    /collections snapshot."""
    port = free_port()
    proc = spawn_daemon(binary, state_dir, {}, f"127.0.0.1:{port}",
                        SE_BOOT_ID=own_boot_id)
    try:
        base = f"http://127.0.0.1:{port}/v1"

        def _healthy() -> bool:
            try:
                with urllib.request.urlopen(base + "/health", timeout=1) as resp:
                    return resp.status == 200
            except OSError:
                return False

        wait_for(_healthy, "the read API to come up")
        with urllib.request.urlopen(base + "/collections", timeout=5) as resp:
            return {row["name"]: row for row in json.load(resp)}
    finally:
        _stop(proc)


def _assert_age_from_oldest(fixture: Fixture, state_dir: str, binary: Path) -> None:
    """Acceptance item 5 over the read API.

    age_s must equal now - oldest_at under one clock, so age_s + oldest_at
    reconstructs the same `now` on every row. A derivation from the newest
    contributing read, or from arrival time, skews that sum by the fixture's
    deliberate at-spread and fails the agreement check — no knowledge of the
    daemon's boot clock is needed, which is what makes this assertable on a
    workstation. SE_BOOT_ID pins the daemon to the streams' own boot domain,
    because an age is same-domain arithmetic and this process did not boot
    with the fixture.
    """
    names = fixture.expect["age_from_oldest"]
    rows = _served_rows(binary, state_dir, _stream_boot_id(fixture))
    sums = {}
    for name in names:
        assert name in rows, f"{fixture.name}: the read API serves no row for {name}"
        row = rows[name]
        assert row.get("age_s") is not None and row["oldest_at"] is not None, (
            f"{fixture.name}: {name} serves no age — item 5 has nothing to derive from"
        )
        assert row["age_s"] > 0, f"{fixture.name}: {name} age_s {row['age_s']} is not positive"
        sums[name] = row["age_s"] + row["oldest_at"]
    spread = max(sums.values()) - min(sums.values())
    assert spread < 0.25, (
        f"{fixture.name}: age_s + oldest_at disagrees across rows by {spread:.3f}s "
        f"({sums}) — some row's age is not derived from its oldest contributing read"
    )


# The boot id a cross-boot spawn claims as its own: valid shape, distinct
# by construction from any id a fixture stream may carry (the loader-side
# check in _assert_cross_boot enforces the distinctness).
_OTHER_BOOT_ID = "5e000000-0000-4000-8000-0000000000d2"


def _assert_cross_boot(fixture: Fixture, state_dir: str, binary: Path) -> None:
    """DESIGN 09 over the read API: a stamp from another boot's clock is a
    STATED mismatch, never age arithmetic. The daemon is spawned claiming a
    boot id no stream carried; every named collection must then serve
    cross_boot: true and no age_s at all — a negative number here was the
    exact garbage this marker replaced."""
    for stream in fixture.streams:
        if stream.records[0]["boot_id"].lower() == _OTHER_BOOT_ID:
            raise FixtureError(
                f"{fixture.name}: a stream carries the driver's own cross-boot "
                f"stand-in id {_OTHER_BOOT_ID} — the scenario needs two domains"
            )
    rows = _served_rows(binary, state_dir, _OTHER_BOOT_ID)
    for name in fixture.expect["cross_boot"]:
        assert name in rows, f"{fixture.name}: the read API serves no row for {name}"
        row = rows[name]
        assert "age_s" not in row or row["age_s"] is None, (
            f"{fixture.name}: {name} serves age_s {row.get('age_s')!r} across boot "
            "domains — cross-boot arithmetic is garbage and must be omitted"
        )
        assert row.get("cross_boot") is True, (
            f"{fixture.name}: {name} does not state the boot-domain mismatch "
            f"(row: {row}) — a mismatch is stated, never corrected or hidden"
        )


# ── the driver ───────────────────────────────────────────────────────────


def run_fixture(fixture: Fixture, binary: Path | None = None) -> None:
    """Run one fixture against the real binary and judge it. Raises on red."""
    binary = binary or collate_binary()
    state_dir = tempfile.mkdtemp(prefix="se-fx-state")
    try:
        if fixture.concurrent:
            _run_concurrent(fixture, binary, state_dir)
        else:
            _run_sequential(fixture, binary, state_dir)
        assert_expect(fixture, snapshot(db_path(state_dir)))
        if fixture.expect.get("age_from_oldest"):
            _assert_age_from_oldest(fixture, state_dir, binary)
        if fixture.expect.get("cross_boot"):
            _assert_cross_boot(fixture, state_dir, binary)
    finally:
        shutil.rmtree(state_dir, ignore_errors=True)


def _run_sequential(fixture: Fixture, binary: Path, state_dir: str) -> None:
    fake = FakeCollector(fixture.declaration)
    try:
        for i, stream in enumerate(fixture.streams):
            for collection, value in stream.wind_issued.items():
                wind_issued(db_path(state_dir), collection, value)
            fake.queue(render(stream.records))
            proc = run_oneshot(binary, state_dir, {"c0": fake.socket_path})
            assert proc.returncode == 0, (
                f"{fixture.name}: round {i} exited {proc.returncode}:\n{proc.stderr}"
            )
        fake.check()
    finally:
        fake.close()


def _run_concurrent(fixture: Fixture, binary: Path, state_dir: str) -> None:
    """Streams in fixture order get their generations issued in that order,
    then finish in reverse: each earlier response is held until every later
    batch has been acknowledged. That is DESIGN 19's live hazard — the batch
    that began first commits last — driven through the real daemon."""
    fakes: list[FakeCollector] = []
    entries: list[_Collect] = []
    proc = None
    try:
        last = len(fixture.streams) - 1
        for i, stream in enumerate(fixture.streams):
            fake = FakeCollector(fixture.declaration)
            if i > 0:
                # Held until the previous stream's collect request has
                # arrived, which proves its generations were issued first.
                fake.declare_gate = threading.Event()
            fakes.append(fake)
            entries.append(fake.queue(render(stream.records), hold=i < last))
        collectors = {f"c{i}": fake.socket_path for i, fake in enumerate(fakes)}
        proc = spawn_daemon(binary, state_dir, collectors, f"127.0.0.1:{free_port()}")

        for i in range(len(fixture.streams)):
            ok = entries[i].arrived.wait(WAIT_S)
            assert ok, f"{fixture.name}: stream {i}'s collect request never arrived"
            if i + 1 < len(fixture.streams):
                fakes[i + 1].declare_gate.set()

        path = db_path(state_dir)
        for i in range(last, -1, -1):
            batch = fixture.streams[i].batch
            if i < last:
                later = fixture.streams[i + 1].batch
                wait_for(
                    lambda later=later: later in snapshot(path)["acked"],
                    f"batch {later} to be acknowledged before releasing {batch}",
                )
                entries[i].release.set()
        wait_for(
            lambda: fixture.streams[0].batch in snapshot(path)["acked"],
            f"the held batch {fixture.streams[0].batch} to be processed",
        )
        for fake in fakes:
            fake.check()
    finally:
        if proc is not None:
            _stop(proc)
        for fake in fakes:
            fake.close()
