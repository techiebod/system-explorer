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
    "relations": [{"key": "...", "observability": "asserted"}],
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
`must_fail` — and on the stricter rule that `objects`, `collections`,
`rejected` and `acked` are always stated, even when empty, so no surface goes
unjudged. The loader is self-tested against fixtures that must fail, so the
judge is known to discriminate before it judges anything real.
