# Collator fixtures

Recorded streams in, assertions out. One fixture is one scenario:

```json
{
  "name": "two-instances-never-merge",
  "acceptance_item": 1,
  "note": "why this scenario exists, and what breaks if it regresses",
  "streams": [
    {"instance": "radarr", "records": [ ... ]},
    {"instance": "readarr", "records": [ ... ]}
  ],
  "expect": {
    "objects": [{"id": "...", "facts": {...}}],
    "relations": [{"collection": "rules", "source_name": "...", "type": "member-of",
                   "target_kind": "chain", "target_name": "...", "resolved": true,
                   "target_id": "chains:...", "observability": "asserted"}],
    "opinions": [{"object": "...", "key": "...", "level": "warn"}],
    "rejected": [{"reason": "generation-below-applied", "collection": "pools"}]
  }
}
```

`streams` are fed in order; where a scenario is about concurrency the fixture
says so (`concurrent`) and the driver interleaves them: generations are issued
in stream order, responses delivered in reverse, each held until the later
batch is acknowledged — the watch-fires/schedule-fires hazard of DESIGN 19,
driven through the real daemon. `expect` is exhaustive for the keys it names —
an object the collator minted that the fixture does not list is a failure,
because a harness that only checked what it expected would never catch an
invented object.

**The driver is `driver.py`**, run by `conformance/test_collator_fixtures.py`.
The subject is the real se-collate binary against a fake collector on a real
unix socket; the judge reads the durable store, and the read API where a
fixture says so. Its docstring is the authority on the members this format
grew when the driver arrived — `declaration` (the exact bytes `declare`
serves, hash-checked against every begin), `wind_issued` (the declared
simulation that re-mints a used generation, the only outside route to the
authority's below/equal branches), `expect.acked`, `expect.age_from_oldest`,
`expect.cross_boot` (the served statement that a stored stamp belongs to
another boot's clock, judged with the daemon's own boot id injected), and
`must_fail` — and on the stricter rule that `objects`, `relations`,
`collections`, `rejected` and `acked` are always stated, even when empty, so
no surface goes unjudged. The loader is self-tested against fixtures that must
fail, so the judge is known to discriminate before it judges anything real.

**Relations, and what a relation expectation may not say.** A relation is
matched on what the edge IS — collection, scope, source name, type, target
kind, target name, and the assertion's own facts, which are in the match
because parallel edges differ by nothing else. Resolution, the target id and
the observability state are judged as VALUES on the matched row, never as part
of the match: each of them changes as the estate learns, and a match that moved
with them could not catch an edge that silently changed state. A fixture never
writes a relation KEY, because a key is a hash of the identity and pinning it
would test the driver's arithmetic rather than the collator's behaviour. The
key is judged instead by an invariant no fixture opts into: an edge whose
identity is unchanged from one round to the next must carry the same key, which
is acceptance item 6's "an upgrade never re-keys". It is sampled at round
boundaries, so it runs on SEQUENTIAL fixtures only — a concurrent fixture has
no ordered boundary to sample at, and the in-process
TestResolutionUpgradesWithoutReKeying covers the interleaved case.

`relations` was refused outright until 2026-08-19, on a message saying the
phase-2 store held none. That had been false since `store/relations.go` landed,
so acceptance item 6 was judged only by tests written in the subject's own
language while the tier built to be independent of it turned every fixture that
would have exercised it away.
