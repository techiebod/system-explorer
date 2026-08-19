# Parity report — the reference and the port, one machine, one moment

Gate 3 asks for this: *"the parity report per collection is clean or its diffs
are named and accepted."* It is not clean. Every diff is named below, and each
class is a finding rather than noise.

Produced by `harness/bin/se-compare --json`, which runs the shipping Python
adapter and the Go port against the same live interfaces in the same minute and
diffs their streams with the corpus's own comparator. Replay proves a port
reproduces a *capture*; this proves it reproduces the *reference* on shapes
nobody captured.

## Two runs, and the second is the one that counts

| | sparse | provisioned |
|---|---|---|
| Host | `se-test-debian` — Debian 13 | `se-test-ubuntu2604` — Ubuntu 26.04 |
| Interfaces | journal, dpkg, busctl only | + zpool, nft, docker, libvirt, unbound, smartctl |
| Compared | 18 | 18 |
| **Clean** | **5** | **8** |

Both are kept because they answer different questions. The sparse host tests
**decline correctness**, which is the half that retires objects. The provisioned
host tests the readings, and it is where the interesting shapes live.

Ports were cross-built `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`, static, and
**shipped rather than built in place** — the comparator must measure what would
deploy, and a build hidden inside a measurement is how a stale binary gets
measured twice.

**`system` is absent from both.** It has no Python adapter, so there is no
reference to disagree with — already named in
`test_differential.PORTED_WITHOUT_A_REFERENCE`. 18 compared, 19 ported, 20
collectors.

## Clean on the provisioned host — eight, at real scale

| Collector | Objects | What it read |
|---|---|---|
| `packages` | 936 | a real dpkg database |
| `units` | 502 | a real systemd bus |
| `logs` | 100 | a real journal |
| `network` | 97 | a real ruleset — **including 13 rules with `OpaqueReason: xt`** |
| `resources` | 58 | a real cgroup tree, docker scopes included |
| `hardware` | 20 | a real sysfs walk |
| `docker` | 6 | two running containers, volumes and networks |
| `storage` | 1 | **a real pool: `mirror-0` plus a `spares` group** |

Two of those deserve naming, because they are shapes the residual ledger has
been waiting on.

**`storage` was compared against a pool with a spare in it.** That is the
configuration where the reference has lost three times, and where the group-vdev
blindness was found after four layers agreed it was fine. Both sides agreed.

**`network` was compared against a ruleset carrying `xt` statements.** The
`network/nft-rules-opaque` residual names its venue as *"a capture from a host
running iptables-nft compatibility (Docker, libvirt)"* and records that no lab
guest ran that layer. This one does — docker and libvirt between them create 43
chains across 7 tables — and 13 rule rows carried `OpaqueReason: xt`. Both sides
agreed on all 97. **The `xt` spelling is now visited.** The bare-string spelling
still is not, so that residual narrows rather than closes.

## Class 1 — the reference raises where the port declines (seven)

`kea`, `paperless`, `plex`, `protection`, `servarr`, `traefik`, `unbound`.

The shipping adapter throws and produces **no reading at all**; the port
declines and commits. This is the open queue item *"the three non-absent decline
reasons are mapped by nothing"*, which recorded the asymmetry on **two**
collectors and called it half-judged. It was ten on the sparse host and is seven
here — the three that dropped off did so because the interface arrived, which is
the point of provisioning.

The asymmetry itself is deliberate: bridging arbitrary exceptions into decline
reasons inside the live reference would make the two agree *by construction* and
destroy the comparator's independence on the cases it exists to adjudicate.

**The half that needs a ruling is what the ports decline.** All seven decline
**`absent`** — and `absent` commits zero and **retires**. On this host the
trigger is a missing **receipt**, not a missing interface: unbound is installed
and running, and the adapter still raises, because `SE_UNBOUND_SOCKET` was never
set. "This process was not told where to look" and "the thing is not here" are
different statements, and only one of them should retire a row.

Nothing is harmed today, because a host that never had the receipts never
published the objects. The shape that bites is a host that **loses** its
configuration: yesterday's rows retired on the strength of an unset variable,
under a decline record that reads as though the interface went away.

## Class 2 — the reference publishes a row where the port declines (two)

`bazarr` and `downloaders` diverge the *other* way, on both hosts. The reference
emits a real object — bazarr's `instance` row carrying `ConfigMissing`,
downloaders' two commits — and the port declines instead.

Both are documented adapter behaviour: a configured-but-incomplete instance is
supposed to produce a row saying *what is missing*, because "I was not told the
API key" is a finding an operator can act on and a decline is not. The ports do
not reproduce it.

## Class 3 — `vms`, and the queue item is now demonstrated rather than asserted

On the sparse host both sides declined and the comparison was vacuous. On this
one **libvirtd is running**, and:

```
reference:  begin, commit 1, end     — it read libvirt
port:       begin, decline 1, end    — it declined
```

The open queue item says `se-collect-vms` *"declines `unsupported` on any host
where libvirt is listening"*. That was written from reasoning about the port's
construction. It is now a measurement: on a host with libvirt up, the reference
produces a reading and the port produces a decline. The ruling owed — whether a
replay-only port counts as ported, and whether the mechanism is cgo, a
hand-written RPC client, or Python past the cut — is unchanged, but it is no
longer owed on an argument.

## Class 4 — closed: the comparator could not compare a live counter

`resources` reported four differing rows on every run of the sparse host and
none was a defect: monotonic CPU counters and instantaneous memory, moving
because the tool runs the reference and then the port. Proved rather than
assumed — two consecutive runs gave different values **and different deltas**,
32000 then 28000 µs, where a logical defect repeats.

Fixed by reading each collector's own declaration: `temperament` is already a
closed vocabulary carrying `counter` and `gauge`, so no new table was invented.
The **committed** declaration is read, never `declare` at run time — a port
asked at run time what to exempt could exempt everything. Value is excused;
presence and type are not. `resources` is clean on both hosts now, 58 objects
here.

The failure mode it replaced is worth remembering: a guard reporting failure
about what it cannot measure trains readers to ignore it, which is the same
damage as one reporting success about what it cannot see.

## What gate 3 still needs

1. **A ruling on class 1** — whether a missing *receipt* may decline `absent`,
   given that `absent` retires. Seven collectors, and the provisioned host shows
   it firing where the interface is present and merely unaddressed.
2. **Class 2 accepted or fixed** — two ports do not reproduce a row the
   reference publishes deliberately.
3. **The `vms` ruling**, now with a measurement behind it.
4. Receipts for the app collectors, so `traefik`, `paperless`, `plex`, `servarr`
   and `bazarr` get a positive-path comparison rather than a decline one. That
   is lab provisioning, not a decision.

Parity is **established for eight collectors, named for ten, and unavailable for
one**.
