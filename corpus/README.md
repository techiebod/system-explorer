# The reference corpus

Captured reference answers per native source, in variant states, versioned —
the foundation the collector declarations are written against (DESIGN 20).

A corpus entry is a **pair**, committed together and reviewed together:

- the **native payloads** a collector read, exactly as the interface produced them
- the **stream** a collector emitted from them, record for record

Replay asserts observable equivalence: same payloads in, same records out. That
checks the outside of the process, so it works for a collector written in any
language and dictates nothing about how one is built internally.

## Layout

```
corpus/<collector>/<variant>/
    meta.json          what this variant is, and what produced it
    payloads/*         the native documents, one per acquisition — .json
                       parses; anything else is the interface's own text
                       (os-release, hostname), served verbatim, because the
                       native format IS the payload (DESIGN 20)
    expected.jsonl     the stream, validated against contract/se.stream.1.json
```

One variant is one `collect` invocation, so `expected.jsonl` runs `begin` to
`end` and may carry several collections — exactly as the wire does.

## meta.json

| Member | Meaning |
|---|---|
| `collector` | the collector this variant exercises |
| `variant` | `healthy`, `degraded`, `absent`, or a named edge case |
| `os` / `os_version` | the guest that produced it |
| `source_version` | **the version of the interface itself** — a field's presence is a fact about a version, not about a tool |
| `captured` | when |
| `regenerable` | whether the lab can re-stage this variant on a new version. Drift diffs cover only the regenerable set (DESIGN 20) |
| `regenerable_on` | what a re-stage NEEDS, when the answer is not "any lab guest" — `zpool status -j` arrived in OpenZFS 2.3, so the degraded pool cannot be re-staged on a 2.2 guest, and a drift run there would skip it and still look clean |
| `anchors` | the handful of facts the staging planted, asserted at staging time and binding on both halves — the authority the generated half is not (DESIGN 20) |
| `canaries` | planted credential-shaped strings that must appear in no output channel |
| `note` | why this variant exists — especially for an edge case that broke something once |

## Rules

- **The corpus states its own coverage.** A specimen shows one machine on one
  day; found a spec on single captures and you have rebuilt the subset guard.
  Variants are named, versions are stamped, and `regenerable` is explicit —
  with `regenerable_on` where the boolean is not the whole truth, because a
  drift diff that silently omits the variants this guest cannot produce is a
  clean diff over a partial set.
- **Anonymisation preserves structure.** The same WWN appearing in three
  payloads stays the same WWN after scrubbing, or the specimens stop
  demonstrating the joins they exist to teach.
- **Canaries are planted, never real.** At least one variant per collector with
  a credential surface carries one, so the canary check discriminates.
- **The expected half is generated, then reviewed.** `se-capture` runs the
  reference implementation to produce it; a human reads the diff before it is
  committed. Generated-and-unread is not a reference answer.
