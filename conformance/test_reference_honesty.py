"""The reference collector earns the wire it speaks (DESIGN 18, 19).

The reference implementation is what every ported collector is judged
against, so a dishonest constant in it is not a bug — it is a wrong law. Each
test here pins one way the reference used to legislate wrongly:

- it invented generation 1 instead of echoing what the request issued, so the
  collator's newest-wins rule (DESIGN 19) was exercised by nothing;
- it stamped every object `at` 0.0 — not a clock reading, and check_stream's
  `at >= 0` accepted it, which is how a rule-governed member goes unwatched;
- its commits carried `objects` alone, although all three counts are required
  members precisely so a subject cannot disable the truncation check by
  omitting one;
- it emitted null fact values, which name none of the three statements a
  reader could take (value / absent / unobservable) — and the committed
  corpus ratified them;
- it resolved vdev devices against the REPLAYING machine's filesystem, so
  the emitted Device was a property of whatever ran the corpus, not of the
  machine that produced the payload.

Everything drives the reference as a subprocess over stdin/stdout — the same
contract socket activation gives it — so these assertions survive the port to
another language unchanged.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
REFERENCE = REPO / "harness" / "bin" / "se-reference-collector"
HEALTHY = REPO / "corpus" / "storage" / "healthy"

# The generation is arbitrary by design: the collator issues it, the collector
# echoes it. Anything the reference could not have guessed proves the echo.
REQUEST = "collect pools:117\n"


def _run(payload_dir: Path, request: str = REQUEST) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["SE_REPLAY_DIR"] = str(payload_dir)
    env["SE_REFERENCE_COLLECTOR"] = "storage"
    # The corpus's own clock pin: facts derived against *now* (ScanAgeDays)
    # must not rot between the capture and this test run.
    env["SE_REPLAY_NOW"] = json.loads((HEALTHY / "meta.json").read_text())["captured"]
    return subprocess.run([sys.executable, str(REFERENCE)], input=request,
                          capture_output=True, text=True, env=env, timeout=120)


def _stream(proc: subprocess.CompletedProcess) -> list[dict]:
    assert proc.returncode == 0, (
        f"reference exited {proc.returncode}; non-zero means 'I could not "
        f"run', never a decline\n{proc.stderr[:2000]}"
    )
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def _only(records: list[dict], kind: str) -> dict:
    matches = [r for r in records if r.get("record") == kind]
    assert len(matches) == 1, f"expected exactly one {kind}, found {len(matches)}"
    return matches[0]


@pytest.fixture()
def payloads(tmp_path: Path) -> Path:
    """The healthy capture, copied out of the corpus so a test can add or
    withhold payloads without touching the committed pair."""
    for payload in (HEALTHY / "payloads").glob("*.json"):
        shutil.copy(payload, tmp_path / payload.name)
    return tmp_path


def _leaf_paths(payload_dir: Path) -> list[str]:
    """Every disk leaf's own path field, in the payload's emission order."""
    status = json.loads((payload_dir / "status.json").read_text())
    paths: list[str] = []

    def walk(nodes: dict) -> None:
        for vdev in (nodes or {}).values():
            if vdev.get("vdev_type") == "disk" and vdev.get("path"):
                paths.append(vdev["path"])
            walk(vdev.get("vdevs") or {})

    for pool in status["pools"].values():
        walk(pool.get("vdevs") or {})
    return paths


def _plant_devlinks(payload_dir: Path) -> dict[str, str]:
    """A devlinks payload naming a kernel device for every leaf, the way the
    guest capture records it: {alias path: kernel name}."""
    links = {path: f"sd{chr(ord('a') + i)}1"
             for i, path in enumerate(_leaf_paths(payload_dir))}
    (payload_dir / "devlinks.json").write_text(json.dumps(links))
    return links


# ── the wire: issued generations, echoed ─────────────────────────────────


def test_issued_generations_are_echoed_never_invented(payloads: Path) -> None:
    """DESIGN 19: the collator decides what is newest, so a collector that
    fabricates a generation silently disables the refuse-older rule."""
    records = _stream(_run(payloads))
    begin = _only(records, "begin")
    assert begin["generations"] == {"pools": 117}, (
        f"begin.generations is {begin['generations']!r}; the request issued "
        "pools:117 and the echo is the whole of the newest-wins mechanism"
    )
    commit = _only(records, "commit")
    assert commit["generation"] == 117, (
        f"commit echoed generation {commit['generation']!r}, not the issued 117"
    )


def test_a_token_without_a_generation_is_a_malformed_request(payloads: Path) -> None:
    """A collect token is <collection>:<generation> — a bare name is the OLD
    wire, and accepting it quietly would leave two dialects live at once.
    Exit 2 is 'I could not run', which a request this side cannot parse
    genuinely was not."""
    for request in ("collect pools\n", "collect pools:abc\n", "collect\n"):
        proc = _run(payloads, request=request)
        assert proc.returncode == 2, (
            f"request {request!r} exited {proc.returncode}; a malformed "
            "request is exit 2, and a stream from a half-parsed request "
            "would commit under a generation nobody issued"
        )


def test_end_closes_the_batch_and_request_begin_opened(payloads: Path) -> None:
    """`end` is rule-governed, not byte-compared (DESIGN 19): its job is to
    close exactly what begin opened, and to carry the batch's measured cost."""
    records = _stream(_run(payloads))
    begin, end = _only(records, "begin"), _only(records, "end")
    assert end["request"] == begin["request"], "end does not echo begin's request"
    assert end["batch"] == begin["batch"], "end does not echo begin's batch"
    assert end.get("wall_ms", 0) > 0 and end.get("cpu_ms", 0) > 0, (
        f"end carries wall_ms={end.get('wall_ms')!r} cpu_ms={end.get('cpu_ms')!r}; "
        "a batch that emitted objects reports positive measured cost"
    )


# ── the stream: clock readings, counts, and the three channels ───────────


def test_per_object_at_is_a_plausible_monotonic_reading(payloads: Path) -> None:
    """`at` is stamped before the earliest contributing read (DESIGN 09/19),
    so the reference's deterministic stand-in must still LOOK like a clock:
    finite, positive, and advancing in emission order. 0.0 satisfied the
    harness's `at >= 0` and was none of those things."""
    # A second pool makes monotonicity a real assertion rather than a
    # one-element truism. The pool is addressed by whatever name the scrub
    # gave it — hardcoding the name would re-couple this suite to a corpus
    # detail the anonymiser is free to change.
    status_path = payloads / "status.json"
    status = json.loads(status_path.read_text())
    pool_name = next(iter(status["pools"]))
    clone = json.loads(json.dumps(status["pools"][pool_name]))
    clone["name"] = f"{pool_name}2"
    status["pools"][f"{pool_name}2"] = clone
    status_path.write_text(json.dumps(status))

    records = _stream(_run(payloads))
    ats = [r["at"] for r in records if r["record"] == "object"]
    assert len(ats) == 2
    for at in ats:
        assert isinstance(at, float) and math.isfinite(at) and at > 0, (
            f"at={at!r} is not a plausible monotonic reading"
        )
    assert ats == sorted(ats) and len(set(ats)) == len(ats), (
        f"per-object at values {ats} do not advance in emission order"
    )


def test_every_commit_carries_all_three_counts_and_they_are_true(payloads: Path) -> None:
    """All three counts are REQUIRED members (DESIGN 19): a subject that can
    disable the truncation check by omitting a count has defeated it. And
    they must describe the stream they close, not merely be present."""
    records = _stream(_run(payloads))
    commit = _only(records, "commit")
    for member in ("objects", "assertions", "unobservable"):
        assert isinstance(commit.get(member), int) and commit[member] >= 0, (
            f"commit lacks {member} (or it is not a count): {commit}"
        )
    for member, kind in (("objects", "object"),
                        ("assertions", "relation_assertion"),
                        ("unobservable", "unobservable")):
        actual = sum(1 for r in records if r.get("record") == kind)
        assert commit[member] == actual, (
            f"commit says {member}={commit[member]}, stream carries {actual}"
        )


def test_the_absent_decline_path_still_counts_everything(tmp_path: Path) -> None:
    """The absent decline commits zero so it can retire objects — and its
    commit is held to the same required members as any other, because a
    checker that skips the empty case is a subset guard."""
    records = _stream(_run(tmp_path))  # no payloads at all: interface absent
    decline = _only(records, "decline")
    assert decline["reason"] == "absent"
    commit = _only(records, "commit")
    assert commit["generation"] == 117, "the empty commit must still echo the issued generation"
    for member in ("objects", "assertions", "unobservable"):
        assert commit.get(member) == 0, (
            f"absent-decline commit carries {member}={commit.get(member)!r}; "
            "authoritative-empty means all three counts, all zero"
        )
    end = _only(records, "end")
    assert end["request"] == _only(records, "begin")["request"]


def _nulls_in(value: object, path: str) -> list[str]:
    if value is None:
        return [path]
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in _nulls_in(v, f"{path}/{k}")]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in _nulls_in(v, f"{path}[{i}]")]
    return []


def test_a_null_fact_value_appears_nowhere_in_the_stream(payloads: Path) -> None:
    """DESIGN 19: value, absent list and unobservable record are three
    different statements with three channels, and a null names none of them.
    Checked recursively — the shipped nulls lived NESTED, on vdev rows."""
    records = _stream(_run(payloads))
    nulls = [p for r in records for p in _nulls_in(r.get("facts", {}), r.get("name", "?"))]
    assert not nulls, f"null fact values in the stream: {nulls}"
    # The healthy pool has no status message — that is the absent list's
    # statement, and it must actually be made rather than merely not-lied.
    obj = next(r for r in records if r["record"] == "object")
    assert "StatusMessage" in obj.get("absent", []), (
        f"a genuinely missing property must appear on the absent list; "
        f"absent={obj.get('absent')!r}"
    )


# ── law 1: names, and the device-resolution seam ─────────────────────────


def test_the_pool_publishes_its_stable_names(payloads: Path) -> None:
    """Law 1's obligation lands in `names`, split by stability class. The
    hardcoded lift looked for fact keys no storage item ever carried, so no
    committed object had names and every join the collator could make was
    silently impossible. A names family holds scalars (the contract's
    name_scalar), so the pool's channel carries guid + member names and each
    leaf's fuller set (guid/wwn/devid) rides its own Vdevs row."""
    records = _stream(_run(payloads))
    status = json.loads((payloads / "status.json").read_text())
    pool_name = next(iter(status["pools"]))
    obj = next(r for r in records if r["record"] == "object")
    stable = obj.get("names", {}).get("stable", {})
    assert stable.get("guid") == str(status["pools"][pool_name]["pool_guid"]), (
        f"names.stable.guid is {stable.get('guid')!r}; the pool GUID is the "
        "one name that survives rename and import"
    )
    devices = stable.get("devices")
    assert devices and all(str(d).startswith("wwn-") for d in devices), (
        f"stable.devices is {devices!r}; the member names as ZFS records "
        "them are what a collator joins pool members to block devices on"
    )
    leaves = [v for v in obj["facts"]["Vdevs"] if v.get("Type") == "disk"]
    assert leaves
    for leaf in leaves:
        names = leaf.get("Names", {}).get("stable", {})
        assert names.get("guid"), f"a vdev leaf without its guid: {leaf}"
        assert names.get("devid"), f"a vdev leaf without its devid: {leaf}"
        assert str(names.get("wwn", "")).startswith("wwn-"), leaf


def test_device_resolution_is_fed_by_the_capture_not_the_machine(payloads: Path) -> None:
    """Defect 1's discriminating pair. With a devlinks payload, every leaf
    resolves to the CAPTURED kernel name; without one, Device is declared
    unobservable — never resolved against the replaying machine and never a
    silent null. The corpus was generated on a machine with no /dev/disk,
    which is how every committed Device came to be null."""
    # Without the payload: the acquisition is unavailable, and saying so is
    # the honest reading — reason "unavailable", one record per leaf.
    records = _stream(_run(payloads))
    missing = [r for r in records if r["record"] == "unobservable"]
    leaves = _leaf_paths(payloads)
    assert len(missing) == len(leaves), (
        f"{len(leaves)} unresolvable leaves produced {len(missing)} "
        "unobservable records; a leaf that produces none is a silent gap"
    )
    for record in missing:
        assert record["reason"] == "unavailable", record
        assert record["fact"].startswith("Vdevs/") and record["fact"].endswith("/Device"), record
    obj = next(r for r in records if r["record"] == "object")
    assert not any("Device" in v for v in obj["facts"]["Vdevs"]), (
        "a vdev row carries Device although nothing could have resolved it"
    )

    # With the payload: the same request resolves every leaf to the capture's
    # own kernel names, and the unobservable channel falls silent.
    links = _plant_devlinks(payloads)
    records = _stream(_run(payloads))
    assert not [r for r in records if r["record"] == "unobservable"], (
        "unobservable records remain although the devlinks payload was captured"
    )
    obj = next(r for r in records if r["record"] == "object")
    resolved = [v["Device"] for v in obj["facts"]["Vdevs"] if v.get("Type") == "disk"]
    assert resolved == [f"block-device:{links[path]}" for path in leaves], (
        f"resolved devices {resolved} are not the capture's own kernel names"
    )
    kernel = obj.get("names", {}).get("ephemeral", {}).get("kernel")
    assert kernel == [f"/dev/{links[path]}" for path in leaves], (
        f"ephemeral kernel names {kernel!r} do not carry the resolved paths "
        "a person would search for"
    )
