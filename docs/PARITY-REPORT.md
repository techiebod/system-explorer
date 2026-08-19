# Parity report — the reference and the port, one machine, one moment

Gate 3 asks for this: *"the parity report per collection is clean or its diffs
are named and accepted."* **Seventeen of eighteen are clean.** The eighteenth is
`vms`, and it is waiting on a ruling rather than on work.

Produced by `harness/bin/se-compare --json`, which runs the shipping Python
adapter and the Go port against the same live interfaces in the same minute and
diffs their streams with the corpus's own comparator. Replay proves a port
reproduces a *capture*; this proves it reproduces the *reference* on shapes
nobody captured — which is where every finding below came from.

## Three runs, and the third is the one that counts

| | sparse | provisioned | fully provisioned |
|---|---|---|---|
| Host | `se-test-debian` | `se-test-ubuntu2604` | `se-test-ubuntu2604` |
| Interfaces | journal, dpkg, busctl | + zpool, nft, docker, libvirt, unbound, smartctl | + 11 app containers, unbound and kea control sockets, protection documents |
| Compared | 18 | 18 | 18 |
| **Clean** | **5** | **8** | **17** |

All three are kept because they answer different questions. The sparse host
tests **decline correctness**, which is the half that retires objects. The
provisioned hosts test the readings.

Ports were cross-built `CGO_ENABLED=0 GOOS=linux GOARCH=amd64`, static, and
**shipped rather than built in place** — the comparator must measure what would
deploy, and a build hidden inside a measurement is how a stale binary gets
measured twice. Checksums were compared on both ends before the run.

**`system` is absent from all three.** It has no Python adapter, so there is no
reference to disagree with — already named in
`test_differential.PORTED_WITHOUT_A_REFERENCE`. 18 compared, 19 ported, 20
collectors.

## Clean: seventeen collectors, 1,895 objects

| Collector | Objects | What it read |
|---|---|---|
| `packages` | 942 | a real dpkg database |
| `units` | 558 | a real systemd bus |
| `network` | 136 | a real ruleset, **including rules carrying `OpaqueReason: xt`** |
| `logs` | 100 | a real journal |
| `resources` | 70 | a real cgroup tree, 11 container scopes included |
| `docker` | 29 | eleven containers, volumes and networks |
| `hardware` | 20 | a real sysfs walk |
| `protection` | 16 | a manifest and 12 receipts on disk |
| `servarr` | 8 | **two** instances, radarr and sonarr, API v3 |
| `traefik` | 6 | a live dashboard over the docker provider |
| `kea` | 3 | a control socket, with the lease hook loaded |
| `downloaders` | 2 | transmission RPC and sabnzbd |
| `bazarr`, `paperless`, `plex`, `unbound`, `storage` | 1 each | see below |

Everything above also passed **both clocks and the port-stream check**, and the
nine newly provisioned venues were re-run with `--twice`: reference and port
stamps both advanced, so none of them is serving a frozen reading.

Three of these deserve naming, because they are shapes the residual ledger had
been waiting on.

**`storage` was compared against a pool with a spare in it.** That is the
configuration where the reference has lost three times, and where the group-vdev
blindness was found after four layers agreed it was fine. Both sides agreed.

**`network` was compared against a ruleset carrying `xt` statements.** The
`network/nft-rules-opaque` residual names its venue as *"a capture from a host
running iptables-nft compatibility (Docker, libvirt)"* and records that no lab
guest ran that layer. This one does — docker, libvirt and traefik between them
now drive 136 rows. **The `xt` spelling is visited.** The bare-string spelling
still is not, so that residual narrows rather than closes.

**`plex` was compared against an unclaimed server.** No claim token was passed,
`PLEX_CLAIM` is unset, and `Preferences.xml` carries no `PlexOnlineToken`,
`PlexOnlineUsername` or `PlexOnlineMail` — checked, on a file with 370 bytes of
real content in it. The server is linked to no Plex account and cannot adopt or
displace one. `ALLOWED_NETWORKS` is what makes the API answer, so
`SE_PLEX_TOKEN` is a placeholder the server never validates rather than a
credential. The receipt is only written after `/library/sections` is confirmed
to answer 200, because a receipt pointing at a server that 401s everything makes
both sides fail identically, and identical failure reads as agreement.

## The one that is not clean — `vms`

```
reference:  begin, commit 1, end     — it read libvirt
port:       begin, decline 1, end    — it declined
```

The open queue item says `se-collect-vms` *"declines `unsupported` on any host
where libvirt is listening"*. That was written from reasoning about the port's
construction; it is now a measurement. The ruling owed — whether a replay-only
port counts as ported, and whether the mechanism is cgo, a hand-written RPC
client, or Python past the cut — is unchanged.

## Closed since the last report

**Class 2 is closed.** `bazarr` and `downloaders` used to diverge the other way:
the reference emitted a real object — bazarr's `instance` row carrying
`ConfigMissing`, downloaders' two commits — where the port declined. Given real
receipts both sides now agree, on the row and on the count. The disagreement was
never about the reading; it was the two implementations taking different
branches when a key was absent, and that branch is class 1's question.

**Class 4 stays closed.** `resources` no longer reports live counters as
differences: `temperament` is already a closed vocabulary carrying `counter` and
`gauge`, so no new table was invented, and the **committed** declaration is read
rather than `declare` at run time — a port asked at run time what to exempt
could exempt everything. Value is excused; presence and type are not.

## Class 1 — the reference raises where the port declines

Every collector that used to sit here now has a receipt and compares clean, so
the **symptom** is gone from this host. The **ruling is still owed**, and the
run sharpened it rather than settling it.

The asymmetry is deliberate: bridging arbitrary exceptions into decline reasons
inside the live reference would make the two agree *by construction* and destroy
the comparator's independence on exactly the cases it exists to adjudicate.

What needs deciding is what the ports decline. All of them decline **`absent`**
— and `absent` commits zero and **retires**. The trigger is usually a missing
**receipt**, not a missing interface: before this run unbound was installed and
running on this host and the adapter still raised, because `SE_UNBOUND_SOCKET`
was unset. "This process was not told where to look" and "the thing is not here"
are different statements, and only one of them should retire a row.

Nothing is harmed today, because a host that never had the receipts never
published the objects. The shape that bites is a host that **loses** its
configuration: yesterday's rows retired on the strength of an unset variable,
under a decline record that reads as though the interface went away.

**`kea` showed the deeper version of this, and here the port wins outright.**
`lease4-get-all` lives in the `lease_cmds` hook, which Ubuntu ships but does not
load. Against that server:

```
reference:  exit 2 — RuntimeError: 'lease4-get-all' command not supported
port:       begin, object 3, commit 3, decline 1 (leases: unsupported), end
```

A kea with no hooks loaded is an ordinary kea, not a broken one. The reference
lost **all four collections** over one optional command; the port declined the
one collection that command serves, with the correct reason, and published the
other three. The reference has no decline vocabulary at all, so every unexpected
interface state costs it the whole collection — which is the same defect class
as class 1 and is not fixed by giving this lab a hook. The hook is loaded now so
the readings could be compared; the unhooked case is recorded here and not
repaired.

## What this run found in the reference — a silent, non-deterministic fact loss

The most important result is not a column of ticks. Running `units` unprivileged
produced 162 differing rows, all of the same shape: the port emitted
`Slice: system.slice` and the reference emitted nothing.

It was not privilege, and it was not the port. `units.py` read the `Slice`
property for every service and scope through **one unbounded `asyncio.gather`**.
`dbus_fast`'s write callback calls `send()` on a non-blocking socket and lets
`EAGAIN` escape as `BlockingIOError`; enough concurrent reads on one connection
and the calls fail for reasons that have nothing to do with any unit. `_slice_of`
caught that with a bare `except Exception` annotated *"unit may vanish
mid-walk"*, and returned `None` — which is exactly how "this unit accounts to no
slice" is spelled. A transport failure was published as a **positive claim about
the machine**.

Measured on this 558-unit host, twenty runs each side of the fix:

| | degraded runs | worst run |
|---|---|---|
| before | **6 / 20** | 39 of 219 `Slice` facts survived |
| after | **0 / 20** | — |

Every degraded run exited 0 and emitted the full 549-line stream. Nothing
downstream could tell.

Fixed by bounding the fan-out to `SLICE_PROBE_PARALLELISM = 8` — the same bound
the port already had. The port's own comment claimed the reference did not need
one because it shares a single bus connection; that comment has been corrected,
because sharing the connection is precisely why the reference needed it.

**What is not fixed, and is a ruling owed.** `_slice_of` still renders a failed
read and a genuine "no slice" identically. DESIGN 19 says could-not-read is the
`unobservable` record and has-no-such-property is the absent list — but `units`
emits no structural `unobservable` records at all on either side
(`collect.go` declares as much), and carries its other could-not-read case as a
*fact*, `MissingReferenceUnobservable`. Routing `Slice` to the channel is a
contract change touching both declarations, the corpus and both
implementations. Queued, not guessed.

## A note on the venue, because one of them proves less than the others

`protection` is the only venue here whose bytes are authored. Its manifest,
status document and twelve receipts are the committed corpus's own `authored`
payloads, installed at their real paths. **It is not a shape nobody captured and
is not claimed as one.** What it adds over replay is the path replay cannot
reach: a real `open()` at a real path with real permissions, the receipts
directory walked rather than enumerated by the seam, and the manifest-to-receipt
join run against a filesystem. Every other venue in this report is a live
service.

That staging also produced the run's one false finding, which is worth recording
because the failure mode is this repository's favourite. Two corpus payloads are
JSON `null` — the capture recording that the job never wrote that receipt. The
staging wrote them out as files containing `null`, creating a file that exists
and holds nothing, and the port correctly reported `ReceiptsUnobservable` on
both jobs while the reference said nothing. **A venue that misrepresents the
corpus produces a diff that looks exactly like a port defect.** The staging now
skips a null payload, and the two sides agree on all 16 objects.

## What gate 3 still needs

1. **The `vms` ruling** — the only collector not clean, and the measurement is
   in hand.
2. **A ruling on class 1** — whether a missing *receipt* may decline `absent`,
   given that `absent` retires. The symptom is provisioned away on this host;
   the question is not.
3. **A ruling on the reference's missing decline vocabulary**, which `kea` made
   concrete: one unsupported optional command costs the reference four
   collections where the port loses one.
4. **A ruling on `units`' could-not-read channel** — see above.

Item 4 of the previous report, *"receipts for the app collectors"*, is **done**:
`traefik`, `paperless`, `plex`, `servarr` and `bazarr` all compare on readings
now, and `downloaders`, `kea`, `unbound` and `protection` came with them.

Reproduce with `harness/bin/se-provision-lab <host> --ssh-config <path>`, then
`se-compare` with `/tmp/se-lab/receipts.env` sourced. Note that the receipts must
be sourced **inside** the privileged shell: `sudo -E` does not carry them past
`env_reset`, and the app collectors then decline for want of a receipt while
looking exactly like a host that has no apps.

Parity is **established for seventeen collectors, owed a ruling on one, and
unavailable for one**.
