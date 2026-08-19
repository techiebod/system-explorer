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
| `kea` | 3 | a control socket, with the lease hook loaded and four leases in the table |
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

## The receipt-withheld sweep, and the check that caught what parity could not

Provisioning the venues made a second run possible that the report had never
had: each app collector re-run with its **key withheld and its URL kept**, which
is the branch a key rotation actually takes. Five collectors, and the results
split three ways.

| Collector | Result |
|---|---|
| `servarr` | **clean** — 5 objects, 4 commits, both clocks. `ConfigMissing` on one instance of a two-instance fleet |
| `downloaders` | **clean** — 2 objects |
| `bazarr` | facts clean, **clock wrong** — see below |
| `plex` | **clock wrong, and a shape disagreement** — see below |
| `paperless` | the reference raises; the port declines. Class 1 |

**The `at: 0` defect, in two ports, and the parity check could not see it.** The
`ConfigMissing` row is built from the process environment and returns *before*
any document is fetched — and the fetch is what takes the clock reading. So a
row that rests on no read never got a stamp, and both ports published it with
`at: 0`, which the contract refuses outright (`0 < at <= 1e9`).

The facts were **identical on both sides**, so a comparator that only diffed
facts would have called both collectors clean. It was the clock check — the one
with no replay analogue, since under a pinned clock identical stamps are correct
— that failed them. Replay cannot reach this branch at all: the seam pins the
receipts precisely so a replaying host's own environment cannot decide a
committed row.

Fixed in both. `bazarr` takes the clock after the URL check and before the
receipt checks, which keeps the no-URL *decline* answerable on a host with no
`CLOCK_BOOTTIME` — a decline emits no object and owes no stamp, a row does.
`plex` gained `ready()` on its source interface, called on the one path that
publishes without reading. Both re-run: clean on all four checks.

**`plex` also disagrees about shape, and the reference is the dangerous half.**
With the token withheld, the shipping adapter commits `libraries` and `sessions`
with **zero objects each**. An empty commit is authoritative-empty, so every
library and every session the estate has published is **retired because a
variable was unset** — under a server row whose only content is a note that a
token is missing. The port declines both `unavailable`, naming the 401, and
retires nothing.

That is the second instance of the queue's *"commits zero with no decline"*
item, after `packages`, and this one needs no staging to reach: it is what an
ordinary key rotation does. Recorded, not repaired — the ruling is general now
rather than about one collector.

**And one venue reported exactly what it promised.** The
`servarr/instance-config-and-failure` residual predicted that stopping an app
would produce a disagreement about failure TEXT that neither implementation
could resolve, because the reference's value is its rendering of an httpx
exception. Sonarr's container was stopped:

```
reference:  StatusUnobservable = "ConnectError: All connection attempts failed"
port:        StatusUnobservable = "sonarr did not answer /system/status"
```

Everything else agreed — five objects, four commits, both clocks. Both sentences
are true and neither can produce the other, which is what the residual said it
would be rather than a defect in either.

## A disclosure the comparator found, which parity would have called a wording difference

`paperless` was run against an instance whose token belongs to a **non-superuser**
— `/api/status/` answers 403 — which is the venue its residual named. One fact
differs, and the difference is not wording:

```
reference:  HTTPStatusError: Client error '403 Forbidden' for url
            'http://…:8000/api/status/' For more information check: <MDN link>
port:       the paperless API answered GET /api/status/ with HTTP 403
```

The reference publishes the instance's **host and port inside a fact**.
`StatusUnobservable` is not a log line — it is a committed fact that travels to
a hub and out over MCP. `env.reason` strips userinfo and query strings and does
not strip the host, so the address rides along. On this guest the URL is
loopback and discloses nothing; on the estate it is the real one.

Neither side is defective and both statements are true, which is exactly why
this is an adjudication rather than a bug — but a corpus pair would have to
enshrine one of the two, and the safer one is not the reference's.

**And the leak is narrower than the house pattern, which matters for how you
look for it.** Stopping bazarr's container gives the same shape of disagreement
with no URL in it at all:

```
reference:  ConnectError: All connection attempts failed
port:       the bazarr API did not answer GET /api/system/status
```

httpx renders the two exceptions differently. `ConnectError` — nothing
listening — stringifies without the URL. `HTTPStatusError` — something
answered, with a status — stringifies **with** the request URL. So whether a
collector's failure text discloses an address depends on which exception fires,
and reading one collector's dark-app output and concluding the family is safe
would be exactly wrong.

The same run reached two facts nobody had reached. Stopping `paperless-redis`
made the app report `Error connecting to redis, check logs for more detail.`
and the matching celery sentence — **paperless's own words**, which is the
thing the residual said could not be invented, since an operator can rewrite a
status word but not the error string an app writes about its own failure. Both
sides agreed on both. `DatabaseError` and `IndexError` remain unreached: this
deployment is sqlite and there is no clean way to break either component
without breaking the app that reports on it.

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

5. **A ruling on the empty commit**, which `plex` turned from a `packages`
   curiosity into what a key rotation does.

Item 4 of the previous report, *"receipts for the app collectors"*, is **done**:
`traefik`, `paperless`, `plex`, `servarr` and `bazarr` all compare on readings
now, and `downloaders`, `kea`, `unbound` and `protection` came with them.

Two entries left the residual ledger on the strength of these runs, and one
closed outright. `kea/leases` is **closed**: its stated venue was "a capture
from a guest with the hook loaded", it ended "the tool exists, the guest does
not", and `corpus/kea/leases` is that capture — four leases carrying all three
`State` words, an infinite lifetime rendering `ExpiresAt` as `never`, and a
lease with no `Hostname`. `bazarr/config-missing` and
`servarr/instance-config-and-failure` both had their venues **run**; they stay
in the ledger because the facts are still reached by no committed stream, which
is what the ledger speaks for, but neither is owed a run any more.

Reproduce with `harness/bin/se-provision-lab <host> --ssh-config <path>`, then
`se-compare` with `/tmp/se-lab/receipts.env` sourced. Note that the receipts must
be sourced **inside** the privileged shell: `sudo -E` does not carry them past
`env_reset`, and the app collectors then decline for want of a receipt while
looking exactly like a host that has no apps.

Parity is **established for seventeen collectors, owed a ruling on one, and
unavailable for one**.
