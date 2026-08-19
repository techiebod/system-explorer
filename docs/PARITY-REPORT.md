# Parity report — the reference and the port, one machine, one moment

Gate 3 asks for this: *"the parity report per collection is clean or its diffs
are named and accepted."* It is not clean. Every diff is named below, and three
of the four classes are findings rather than noise.

Produced by `harness/bin/se-compare --json`, which runs the shipping Python
adapter and the Go port against the same live interfaces in the same minute and
diffs their streams with the corpus's own comparator. Replay proves a port
reproduces a *capture*; this proves it reproduces the *reference* on shapes
nobody captured.

## What this run covers, and what it does not

| | |
|---|---|
| Host | `se-test-debian`, the lab's **sparse** guest — Debian 13, systemd 257 |
| Date | 2026-08-19 |
| Collectors compared | 18 |
| Ports built | `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`, static, shipped rather than built in place |

**The venue is the bound, and it is a large one.** The lab's own table calls
Debian *"the sparse host: most collectors must decline here"*, and that is
exactly what happened: no zpool, no nft, no docker socket, no libvirt, no
unbound or kea socket, and no app receipts. So this run compares **decline
correctness**, which is the half that retires objects, and it compares the
positive path for only five collectors.

A positive-path parity report wants the fully-provisioned Ubuntu 26.04 guest —
zpool, nft, docker, libvirt, unbound, kea, smartctl. That guest does not
currently exist, and this report does not stand in for it.

**`system` is not here at all.** It has no Python adapter, so there is no
reference to disagree with — already named in
`test_differential.PORTED_WITHOUT_A_REFERENCE`, and not a gap this report can
close. 18 compared, 19 ported, 20 collectors.

## Per collector

| Collector | Verdict | What the two sides did |
|---|---|---|
| `hardware` | **clean** | 5 commits, 20 objects, identical |
| `logs` | **clean** | 1 commit, **100 objects**, identical |
| `packages` | **clean** | 1 commit, **348 objects**, identical |
| `units` | **clean** | 1 commit, **280 objects**, identical |
| `storage` | **clean** | both decline `absent`, identically |
| `resources` | drift | 33 objects each, 4 rows differ — see class 4 |
| `bazarr` | **disagree** | reference publishes a row; port declines |
| `downloaders` | **disagree** | reference publishes 2 commits; port declines both |
| `docker` | ref raised | reference `ConnectError`; port declines `absent` ×3 |
| `kea` | ref raised | reference `ValueError`; port declines `absent` ×4 |
| `network` | ref raised | reference `FileNotFoundError: nft`; port declines `absent` ×2 |
| `vms` | ref raised | reference `libvirtError`; port declines `absent` |
| `unbound` | ref raised | reference `ValueError`; port declines `absent` |
| `protection` | ref raised | reference `RuntimeError`; port declines `absent` ×3 |
| `servarr` | ref raised | reference `RuntimeError`; port declines `absent` ×4 |
| `traefik` | ref raised | reference `UnsupportedProtocol`; port declines `absent` ×3 |
| `paperless` | ref raised | reference `UnsupportedProtocol`; port declines `absent` |
| `plex` | ref raised | reference `UnsupportedProtocol`; port declines `absent` ×3 |

Five clean, and four of those at real scale rather than on an empty machine.

## Class 1 — the reference raises where the port declines (ten collectors)

The shipping adapter throws and produces **no reading at all**; the port
declines and commits. This is the open queue item *"the three non-absent decline
reasons are mapped by nothing"*, which recorded the asymmetry on **two**
collectors and called it half-judged. It is ten, and the exception types are
seven different ones — `ConnectError`, `ValueError`, `FileNotFoundError`,
`UnsupportedProtocol`, `RuntimeError`, `libvirtError`.

The asymmetry itself is deliberate and documented: bridging arbitrary exceptions
into decline reasons inside the live reference would make the two agree *by
construction* and destroy the comparator's independence on precisely the cases
it exists to adjudicate.

**What this run adds is the second half, and it is the part that needs a
ruling.** Every one of the ten ports declines **`absent`** — and `absent` is the
reason that commits zero and **retires**. That is right where the interface
genuinely is not there: no docker socket, no `nft` binary, no libvirt, no
protection manifest. It is questionable where the trigger is a **missing
receipt** rather than a missing interface — `traefik`, `paperless`, `plex`,
`servarr`, `kea` and `unbound` all decline `absent` because a URL or a socket
path was never configured on this host. "This process was not told where to
look" and "the thing is not here" are different statements, and only one of them
should retire a row.

Nothing is currently harmed, because a host that never had the receipts never
published the objects. The shape that bites is a host that **loses** its
configuration: the objects it published yesterday are retired today on the
strength of an unset variable, and the decline record says `absent`, which reads
as though the interface went away.

This is the same family as the queue's *"an unrecognised package manager commits
zero with no decline"* — silent in the retiring direction.

## Class 2 — the reference publishes a row where the port declines (two)

`bazarr` and `downloaders` diverge the *other* way. The reference emits a real
object — bazarr's `instance` row carrying `ConfigMissing`, downloaders' two
commits — and the port declines instead.

Both are documented adapter behaviour: a configured-but-incomplete instance is
supposed to produce a row that says *what is missing*, because a row saying
"I was not told the API key" is a finding an operator can act on, and a decline
is not. The ports do not reproduce it.

`servarr/instance-config-and-failure` and `downloaders/unconfigured-client` are
already named residuals covering the fact-level half of this, and both name the
live comparator as the venue. **This is that venue reporting.** The residuals
should now record that the run happened and what it found.

## Class 3 — a collector with no reference (one)

`system` has no Python adapter. An agreement guard needs two parties and this
collector has one. Named already; unchanged by this run.

## Class 4 — the comparator cannot compare a live counter (one)

`resources` shows 4 differing rows on every run, and none of them is a defect.
The facts that differ are **monotonic CPU counters and instantaneous memory**:

```
CpuSystemUsec:  reference=10189299  port=10197299
CpuUsageUsec:   reference=27764733  port=27792733
MemoryCurrentBytes: reference=43409408  port=19333120
```

The comparator runs the reference, then the port. Between the two the machine
kept running, so every advancing counter differs by however long that took.
Proved rather than assumed: two consecutive runs gave different absolute values
(30700448, then 30928441) **and different deltas** (32000 µs, then 28000 µs). A
logical defect would repeat; drift does not.

**This is a defect in the comparator, not in `resources`.** As built, a
collector whose facts are live readings can never show clean parity — which
means a real disagreement in `resources` would arrive buried in four rows of
noise that everybody has learned to ignore. That is the shape this project calls
a guard reporting success about what it cannot see, inverted: a guard reporting
failure about what it cannot measure.

It wants a fix before `resources` parity means anything — either a declared
class of time-varying facts compared for shape rather than value, or a
comparison that brackets the two runs and accepts a value inside the window.

## What gate 3 still needs

1. A positive-path run on a fully-provisioned guest. This report is the sparse
   host only, and five clean collectors is not the fleet.
2. A ruling on class 1 — whether a missing *receipt* may decline `absent`, given
   that `absent` retires.
3. The comparator fix in class 4, or `resources` parity stays unreadable.
4. Class 2 accepted or fixed: two ports do not reproduce a row the reference
   publishes deliberately.

Until those, the honest statement is that parity is **established for five
collectors, named for thirteen, and unavailable for one**.
