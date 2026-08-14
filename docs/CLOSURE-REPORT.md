# The closure report

**What a deployment writes so that `nix/generations` can stop computing it.**

Status: specification. Not yet implemented on either side.

---

## Why this exists

`nix/generations` publishes what changed between a generation and the one
before it — packages added, removed and upgraded, and `/etc` entries that
moved. Computing that means walking the `sw` and `etc` closure trees of both
generations and diffing them.

Measured on the estate: that walk is **3,661 ms of CPU on silo, 83.9% of the
cost of all thirty-five collections combined**, and on another host 6,524 ms of
a 6,525 ms sweep. It runs on every sweep, and its inputs have not changed since
the last deploy.

It is also the wrong layer for the work. A closure delta is a **derived** fact
about two immutable store paths. Nothing about it can change once the two
generations exist, so recomputing it every sixty seconds produces an identical
answer at a cost the smallest host in the estate cannot afford.

**The deployment already knows both ends.** It is the only moment at which the
outgoing and incoming system closures are both named, and it happens once per
deploy rather than 1,440 times a day.

## The trade this accepts

Today's implementation can compare **any** generation against whichever
generation precedes it *now* — including retroactively, after an intermediate
generation has been garbage-collected, because it walks the closures on demand.

A recorded report fixes the comparison at the moment it was written. You get
each generation's delta **against its predecessor as deployed**, and not
arbitrary pairs. That is the compromise, and it is deliberate.

---

## 1. Who computes it

**System Explorer ships the computation as a command; the deployment invokes
it.** The estate does not reimplement the diff.

```
se-closure-diff --previous <store-path> --current <store-path> [--previous-generation N]
```

Writes the document below to stdout. Exit non-zero, with a message on stderr
and nothing on stdout, if either path is unreadable.

This matters more than it looks. `nix store diff-closures` has no structured
output — the adapter's own comments record that as the reason the walk exists
at all — so a deployment computing this itself would be a second implementation
of an algorithm whose output format is System Explorer's. One of the two would
drift, and the drift would be invisible: a report in the right shape with the
wrong contents reads exactly like a correct one.

## 2. Where it goes

The **same directory as deployment receipts**, configured by
`SE_DEPLOYMENT_RECEIPTS` and set on the NixOS module as
`services.systemExplorer.deploymentReceipts`. There is deliberately no default,
for the reason already written there: an estate that keeps no records must not
have the agent inventing a path, finding nothing, and reporting the nothing as a
fact about the deployment.

```
<receipts-dir>/<generation>.closure.json
```

**A sibling of the receipt, not part of it.** They are different statements — a
receipt says *how this generation came to be*, a closure report says *what
changed in it* — they can be written by different steps, and either may exist
without the other.

The directory and the file must be readable by an unprivileged process: the
agent runs under `DynamicUser` and has no group to grant it.

## 3. The document

```json
{
  "schema": 1,
  "generation": 86,
  "storePath": "/nix/store/xxxx-nixos-system-silo-25.11",
  "comparedWith": 85,
  "comparedWithStorePath": "/nix/store/yyyy-nixos-system-silo-25.11",
  "writtenAt": "2026-08-14T15:04:11Z",
  "counts": { "package": 42, "etc": 7 },
  "rows": [
    { "Kind": "package", "Name": "hello",           "From": "2.12.1", "To": "2.12.2" },
    { "Kind": "package", "Name": "tree",            "From": null,     "To": "2.3.2"  },
    { "Kind": "etc",     "Name": "ssh/sshd_config", "From": "abc123", "To": "def456" }
  ]
}
```

| Member | Required | Meaning |
|---|---|---|
| `schema` | yes | `1`. Bumped only for a breaking change; additive members do not bump it. |
| `generation` | yes | The generation this report is *about*. Must match the filename. |
| `storePath` | yes | That generation's system closure. **The proof the file belongs where it is filed.** |
| `comparedWith` | yes | The generation number it was compared against, or `null` if it was the oldest present when written. |
| `comparedWithStorePath` | yes unless `comparedWith` is null | The other end's closure. **The proof the comparison is still the right one.** |
| `writtenAt` | yes | RFC 3339 UTC. When the report was produced, which is not when either generation was built. |
| `counts` | yes | `{kind: count}` over `rows`. Carried explicitly so a collection page need not parse the rows. |
| `rows` | yes | May be empty — two generations can genuinely differ in nothing a diff sees. |

### Rows

Exactly the shape the product publishes today, so nothing on the wire changes.

| Field | Meaning |
|---|---|
| `Kind` | `package` or `etc`. |
| `Name` | The package name, or the `/etc` path relative to the tree root. |
| `From` | The old version or content hash. `null` where the entry is new. |
| `To` | The new version or content hash. `null` where the entry was removed. |

**An upgrade is one row, never two.** A package that moved 2.12.1 → 2.12.2 has
one row with both ends, not a removal and an addition. The renderer relies on
this and there is a conformance test pinning it.

## 4. The two paths that make it verifiable

Both store paths are load-bearing and neither is decoration.

**`storePath` catches a misfiled report.** A file named `86.closure.json`
whose `storePath` is not generation 86's target is a statement about a
different generation. Treated as absent, with a reason — not read.

**`comparedWithStorePath` catches a stale comparison.** Generations are
garbage-collected. If 85 goes, 84 becomes 86's predecessor, and the recorded
report is now a comparison against something no longer present. The agent
publishes it anyway, because it remains a true statement about what the
deployment did — but says so, rather than letting it read as a comparison
against the generation that now precedes it.

## 5. Expectation, so absence means something

`se-generation.json` inside each closure gains a member alongside the existing
`receiptsExpected`:

```json
{ "schema": 2, "receiptsExpected": true, "closureReportExpected": true }
```

Same discipline, same reason. A generation built before this existed has no
report, and **its lack of one means nothing** — reporting it as a gap would
accuse a workflow that did not exist. Only a generation whose own closure says
a report was expected can be missing one.

## 6. What the agent publishes

Unchanged on the wire where a report is present: `ComparedWithGeneration`,
`DeltaCounts`, and `DeltaFromPrevious` on an opened object.

One change of **kind**, which is a real change and belongs in the fact
dictionary: these become `declared` rather than `derived`. The product no longer
computes them; it reports what a deployment recorded. A reader should know they
are trusting a record rather than an arithmetic.

Every failure gets its own fact, because they are different statements:

| Situation | Fact |
|---|---|
| Report present and verified | the facts above, `kind: declared` |
| Closure says a report was expected, none found | `DeltaFromPreviousUnrecorded` — naming the generation and the path looked at |
| Closure does not expect one | nothing. Not a gap. |
| Filename and `storePath` disagree | `DeltaFromPreviousUnrecorded`, saying the file describes a different closure |
| `comparedWith` no longer present | the facts, plus `ComparedWithGenerationCollected` naming what went |
| Malformed or unreadable | `DeltaFromPreviousUnobservable` with the parse error. **Never silence** — an unreadable record is a fault in the record, not evidence that nothing changed. |
| Oldest generation present | `DeltaFromPreviousUnobservable`, as today |

## 7. What the deployment has to do

1. Before activation, capture the outgoing system: `readlink -f /run/current-system`.
2. Activate.
3. Read the new generation number from the profile link farm.
4. Run `se-closure-diff --previous <old> --current <new>`.
5. Write stdout to `<receipts-dir>/<generation>.closure.json`, world-readable.
6. On a first-ever deploy, or where the previous closure is gone, skip steps 4–5
   and let the agent report it unrecorded. Do not write a report with invented
   contents.

Write the file **after** activation succeeds. A report for a generation that
failed to activate describes a deployment that did not happen.

## 8. What this does not solve

- **Arbitrary-pair comparison** is gone, by design (see the trade above).
- **Generations deployed outside the workflow** — by hand, or by a rollback —
  get no report and say so.
- **A rollback** produces no new generation and therefore no new report; the
  existing reports remain true of the deployments that wrote them.
