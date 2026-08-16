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
says so and the driver interleaves them. `expect` is exhaustive for the keys it
names — an object the collator minted that the fixture does not list is a
failure, because a harness that only checked what it expected would never catch
an invented object.

**No driver exists yet.** The collator is phase 2; this format and its loader
are committed now so that phase has something to satisfy rather than something
to invent. The loader is self-tested against a fixture that must fail, so the
judge is known to discriminate before it judges anything real.
