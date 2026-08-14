"""The closure walks are memoised across requests, and it is safe because of
what the keys are.

This collection was 2,023 ms of a 2,574 ms findings sweep on the estate's
smallest host — 79% of it — re-walking closure trees that had not moved since
the sweep sixty seconds earlier. The caches were per-call locals, so every
request paid for every generation pair.

WHY THIS IS NOT A CACHE OF AN OBSERVATION, which is the thing SPEC rule 4
forbids: every key is a /nix/store path, and a store path is immutable by
construction. The same path cannot ever yield a different tree. The link farm
and the profile pointers are still read fresh on every request — so a deploy
is visible on the very next one — and the only thing skipped is arithmetic
whose inputs provably have not moved. Nothing here can go stale because
nothing here can change.

The tests below pin that distinction, because the tempting version of this
change is a timer, and a timer would make a deploy invisible for an hour and
would be exactly the reasoning rule 4 exists to refuse.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from system_explorer.agent.adapters import nix


def generation(root: Path, number: int, sw: str, etc: str) -> Path:
    """One generation's link target, with the two store symlinks the delta
    walk compares. Real symlinks, because comparing their targets is the
    cheap proxy the adapter relies on."""
    target = root / f"system-{number}-link-target"
    target.mkdir(parents=True, exist_ok=True)
    for name, store in (("sw", sw), ("etc", etc)):
        link = target / name
        if link.is_symlink():
            link.unlink()
        link.symlink_to(store)
    (target / "nixos-version").write_text("26.05\n")
    return target


@pytest.fixture
def estate(tmp_path, monkeypatch):
    """Two generations sharing an /etc closure and differing in sw, which is
    the ordinary shape of a package bump."""
    store = tmp_path / "store"
    for name in ("sw-old", "sw-new", "etc-same"):
        (store / name).mkdir(parents=True)

    targets = {
        84: generation(tmp_path, 84, str(store / "sw-old"), str(store / "etc-same")),
        85: generation(tmp_path, 85, str(store / "sw-new"), str(store / "etc-same")),
    }
    links = [(85, targets[85], str(targets[85])), (84, targets[84], str(targets[84]))]

    monkeypatch.setattr(nix.nx, "generation_links", lambda: list(links))
    monkeypatch.setattr(nix.nx, "pointers",
                        lambda: {"current": str(targets[85]),
                                 "booted": str(targets[85]),
                                 "default": str(targets[85])})
    monkeypatch.setattr(nix.nx, "generation_manifest", lambda target: None)
    monkeypatch.setattr(nix.nx, "receipts_dir", lambda: None)
    return targets


@pytest.fixture
def counted(monkeypatch):
    """Counts every closure walk, which is the expensive thing."""
    calls: list[str] = []
    real_store_paths = nix.nx.store_paths
    real_etc = nix._etc_entries

    def store_paths(root):
        calls.append(f"sw:{root}")
        return real_store_paths(root)

    def etc_entries(root):
        calls.append(f"etc:{root}")
        return real_etc(root)

    monkeypatch.setattr(nix.nx, "store_paths", store_paths)
    monkeypatch.setattr(nix, "_etc_entries", etc_entries)
    return calls


# ── the point of the change ──────────────────────────────────────────────

def test_a_second_request_walks_nothing_it_walked_before(estate, counted):
    adapter = nix.Adapter()
    adapter._generation_items()
    first = len(counted)
    assert first > 0, "the fixture walked nothing; the test would pass vacuously"
    adapter._generation_items()
    assert len(counted) == first, (
        f"the second request re-walked {len(counted) - first} closures whose "
        "store paths had not moved — a store path is immutable, so the answer "
        "could not have differed")


def test_a_new_adapter_walks_again(estate, counted):
    """The memo is instance state, not module state. Two agent processes, or a
    restart, must not inherit each other's arithmetic — and the lifetime being
    the process is what keeps this a memo rather than a persistence layer."""
    nix.Adapter()._generation_items()
    first = len(counted)
    nix.Adapter()._generation_items()
    assert len(counted) > first


def test_a_deploy_is_visible_on_the_very_next_request(estate, counted, monkeypatch):
    """The reason this is not a timer. A new generation appears and its delta
    is computed immediately — not up to an hour later."""
    adapter = nix.Adapter()
    before = {item["id"] for item in adapter._generation_items()}
    assert before == {"generation:84", "generation:85"}

    root = list(estate.values())[0].parent
    store = root / "store"
    (store / "sw-newer").mkdir()
    fresh = generation(root, 86, str(store / "sw-newer"), str(store / "etc-same"))
    links = [(86, fresh, str(fresh)),
             (85, estate[85], str(estate[85])),
             (84, estate[84], str(estate[84]))]
    monkeypatch.setattr(nix.nx, "generation_links", lambda: list(links))
    monkeypatch.setattr(nix.nx, "pointers",
                        lambda: {"current": str(fresh), "booted": str(fresh),
                                 "default": str(fresh)})

    walked = len(counted)
    after = adapter._generation_items()
    assert {item["id"] for item in after} == {
        "generation:84", "generation:85", "generation:86"}
    assert len(counted) > walked, "the new generation's closure was not walked"


def test_the_pointers_are_re_read_every_time(estate, monkeypatch):
    """Current, Booted and Profile can move with the link farm untouched — a
    rollback to an existing generation does exactly that. Memoising the walk
    must not memoise these, or the page would report the wrong generation as
    running until something else changed."""
    adapter = nix.Adapter()
    by_id = {item["id"]: item["facts"] for item in adapter._generation_items()}
    assert by_id["generation:85"]["Current"] is True
    assert by_id["generation:84"]["Current"] is False

    monkeypatch.setattr(nix.nx, "pointers",
                        lambda: {"current": str(estate[84]),
                                 "booted": str(estate[84]),
                                 "default": str(estate[84])})
    by_id = {item["id"]: item["facts"] for item in adapter._generation_items()}
    assert by_id["generation:84"]["Current"] is True, (
        "a rollback was invisible — the memo swallowed a fact it does not own")
    assert by_id["generation:85"]["Current"] is False


def test_a_collected_generation_leaves_the_memo(estate, monkeypatch):
    """Bounded by what is still on the host. A garbage-collected generation's
    store paths would otherwise sit in memory for the life of the process,
    which on a long-running agent is a slow leak wearing a cache's clothes."""
    adapter = nix.Adapter()
    adapter._generation_items()
    assert len(adapter._environments) == 2

    monkeypatch.setattr(nix.nx, "generation_links",
                        lambda: [(85, estate[85], str(estate[85]))])
    adapter._generation_items()
    assert len(adapter._environments) == 1, (
        f"held {sorted(adapter._environments)} after a generation was collected")


def test_the_memo_answers_the_same_as_the_walk(estate):
    """Correctness before speed: a memoised second request must produce facts
    identical to the first, not merely faster ones."""
    adapter = nix.Adapter()
    first = adapter._generation_items()
    second = adapter._generation_items()
    assert [i["facts"] for i in first] == [i["facts"] for i in second]
