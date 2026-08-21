"""Loading and validating corpus variants.

A variant is a pair — the native payloads a collector read, and the stream it
emitted from them (corpus/README.md). This module is the only thing that knows
the on-disk layout, so the replay driver, the capture tool and the tests all
agree about what a variant is without three copies of the shape.

Validation here is deliberately strict about the things that make a corpus
worth having: a variant that declares no payloads, or whose expected stream is
empty, is rejected rather than replayed, because a pair proving nothing is the
subset-guard shape wearing a test's clothes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
CORPUS = REPO / "corpus"
CONTRACT = REPO / "contract"

# os_version is required because coverage() reads it unconditionally — the
# version dimension is the one interface drift actually lives on, and a meta
# that omits it used to load fine and then KeyError in the coverage report.
# anchors are required because a variant with no hand-asserted truth proves
# determinism only, never correctness — DESIGN 20's second trap.
REQUIRED_META = (
    "collector",
    "variant",
    "os",
    "os_version",
    "source_version",
    "regenerable",
    "anchors",
)

# The closed set of variant kinds. A set that is consulted, unlike the tuple
# it replaces, which sat here asserting nothing while any spelling loaded: a
# new kind of variant is a decision about what the corpus covers, so it is
# added here, not minted ad hoc in a meta.json.
#
# The three ruleset kinds were added together, in one decision, when the lab
# staged the shapes a chain-reachability walk gets wrong. Each names the
# structure that makes it a distinct kind of coverage rather than another
# healthy ruleset, and each was a live defect in some collector:
#   goto        — a chain reached only by `goto`. A walk that counts `jump`
#                 alone reports it unreachable, and unreachable is the one
#                 answer here somebody acts on.
#   asymmetric  — one chain name in two families, jumped to in one of them.
#                 A walk keyed on the name alone answers for both at once.
#   named-map   — a chain reached only through `vmap @name`, whose verdicts
#                 live in the map OBJECT, in no rule's expression at all.
#
# The two time kinds were added together at R3b, when system/time landed as
# the first collection whose facts come through two bus interfaces that can
# go dark independently:
#   time-synced   — both interfaces answer: the full fact set, the poll
#                   bounds, and the server the host is actually using.
#   timesync-dark — timedate1 answers while timesync1 has nobody behind it
#                   (the chrony shape, captured from life): four facts come
#                   back unobservable, the collection still commits, and
#                   the time-sync rule must NOT fire — the clock IS
#                   synchronised, whoever synchronised it.
VALID_VARIANTS = frozenset(
    {
        "healthy",
        "degraded",
        "absent",
        "empty-ruleset",
        "time-synced",
        "timesync-dark",
        # bare-guest, added with storage's R3b collections: a machine with
        # no ZFS at all, whose capture stages the util-linux documents
        # alone. The shape a plain host actually is, and the one the old
        # UI opened on — block devices and mounts with no pool anywhere,
        # which the pools-bearing variants can never show.
        "bare-guest",
        # resolved, added with the resolver's R3b port: the resolve1 shape
        # — the walkable bus resolver — where bare-guest carries the file
        # shape as a documented plant, because both lab guests bus-activate
        # resolved and the dhcpcd host the founding correction names cannot
        # be captured from them.
        "resolved",
        # enslaved, added with links — the last of the bare-guest nine: a
        # topology staged on the guest's real kernel (bridge + enslaved
        # veth + empty bridge + down-but-addressed dummy), because the
        # shapes the link rules judge and the tree derives from do not
        # occur on a plain guest, and the fdb's learned-MAC join is only
        # honest when a real bridge actually learned it.
        "enslaved",
        # staged-disks, added with hardware's R3c retrofit: a guest given a
        # virtio-scsi disk and an NVMe controller in its domain definition,
        # each with a serial and a wwn. The default guest has virtio-blk,
        # which appears in NEITHER hardware walk — so the only hardware
        # capture in the corpus held two ata_piix hosts and nothing behind
        # them, and the identity chain a disk exists to demonstrate (by-id
        # spelling, kernel name, WWN, one object) was reachable by nothing.
        "staged-disks",
        "canary",
        "goto",
        "asymmetric",
        "named-map",
    }
)

# The anchor forms of DESIGN 20, as exact key sets — exact, because an anchor
# with a misspelt or extra key would otherwise be silently reshaped into
# whichever form its surviving keys resemble. The count form has two
# spellings: a committed size, or a decline with a stated reason.
#
# The relation form asserts one directed edge and what discriminates it. A
# variant staging a spare, a jump or a mount is staging an EDGE, and until
# this form existed the only anchorable half of that truth was a fact on a
# row — so "the pool is backed by this device twice, once inside spare-3 and
# once under spares" was a thing the corpus could regenerate and nobody could
# assert. `assertion_facts` is the whole fact dict, not a subset, so an
# anchor cannot pass by naming the discriminator and ignoring a wrong value
# beside it; {} asserts a type that carries none.
_ANCHOR_FORMS = (
    frozenset({"collection", "object", "fact", "value"}),
    frozenset({"collection", "object", "absent_fact"}),
    frozenset({"collection", "commit_objects"}),
    frozenset({"collection", "decline_reason"}),
    frozenset({"collection", "object", "relation", "target", "assertion_facts"}),
    # The identity chain, WHOLE: a disk reachable from its by-id spelling, its
    # kernel name and its WWN is one object with every name on it, and the
    # five forms above could pin a fact, an edge or a count but not that. Whole
    # for assertion_facts' reason — an anchor that named one family and ignored
    # a wrong value in the next would certify half a join.
    frozenset({"collection", "object", "names"}),
)


# Wrongness the corpus and the differential guard together cannot see, named
# rather than left to imply absence (DESIGN 20: "the product names its net… it
# never implies absence of holes"). Each entry is a collector defect that no
# committed capture makes false and no mutation operator mints — so its truth
# is owned by the venue named, not by the replay tier. These are the *unclaimed*
# gaps: a gap inside a class an operator declares it closes (an nftables family,
# a ZFS vdev group) is a guard defect and is closed by construction in
# differential.py, not parked here.
#
# A venue that does not exist yet is stated as owed, not as owned. Naming the
# net is worth nothing if the net is a promise, and for a while this list had
# one unbuilt tool holding up five separate deferrals — "Venue: the live
# comparator" reads to any reader as "there is a place this gets caught".
#
# The comparator was built on 2026-08-18 (harness/bin/se-compare) and run
# beside a real degraded pool, so the entries below now say what is true of a
# tool that exists. An entry whose venue is still unbuilt keeps saying so.
NAMED_RESIDUALS = {
    # R3c: the object verb's density facts — LoadError, UnitFileState,
    # FragmentPath, ActiveEnterTimestamp, MainPID, NRestarts, Result,
    # TasksCurrent, ExecMainStartTimestamp, NextElapse, LastTrigger — ride a
    # channel this harness does not run: collect never emits them, and replay
    # here replays collect. Not unstageable in principle, and therefore owned
    # rather than owed: the collector's own verb tests
    # (go/cmd/se-collect-units/verbs_test.go) serve them from staged lab
    # captures and pin the values. When the collator's on-demand path gives
    # this harness a verb channel, these facts move from named to observed and
    # this entry is deleted.
    "units/object-density": (
        "the eleven density facts (LoadError, UnitFileState, FragmentPath, "
        "ActiveEnterTimestamp, MainPID, NRestarts, Result, TasksCurrent, "
        "ExecMainStartTimestamp, NextElapse, LastTrigger) are served by the "
        "object verb only, which no replayed stream exercises. Venue: "
        "go/cmd/se-collect-units/verbs_test.go, staged from lab captures."
    ),
    # Kept, and narrowed, rather than deleted. The comparator now exercises
    # this join on every run — a five-wide raidz1 on virtio disks resolved
    # every by-id member to its kernel name, and the REMOVED member resolved
    # to nothing, which is the honest answer and the other half of the shape.
    # What replay still cannot do is judge it: no committed pool carries real
    # disks with an alias tree and no operator mints one, so the corpus would
    # pass a port that had lost the join entirely. The truth is now OWNED, by
    # a venue that runs; it is simply owned somewhere other than here.
    "storage/device-resolution": (
        "the by-id-path → kernel-name join (Device fact, names.ephemeral.kernel) "
        "fires only for a disk leaf whose path is in a readable devlinks tree; no "
        "committed pool carries real disks with an alias tree, and no operator "
        "mints one. Venue: the live comparator (harness/bin/se-compare), which "
        "exists and is run beside a real pool — so this truth is owned, and "
        "owned OUTSIDE the replay tier rather than owed."
    ),
    # Closed 2026-08-18 by corpus/network/rules, the first committed pair to
    # open two collections: "network/nft-rules — served by the reference but
    # captured by no committed variant". What replaces it is narrower and
    # true, and it is a shape rather than a collection.
    "network/nft-rules-opaque": (
        "every rule in every committed ruleset renders full or partial; no "
        "capture stages an `xt` statement or a bare-string statement, so the "
        "opaque comprehension path and both OpaqueReason spellings are "
        "exercised by no replayed stream, and no mutation operator mints one. "
        "Venue: a capture from a host running iptables-nft compatibility "
        "(Docker, libvirt); the live comparator now exists and would surface a "
        "disagreement on such a host, but no lab guest runs that compatibility "
        "layer yet — so the tool is real and the SHAPE is still unvisited, and "
        "this truth stays owed.\n\n"
        "VENUE REPORTED 2026-08-19 (docs/PARITY-REPORT.md), and this entry "
        "NARROWS rather than closes. A lab guest now runs that compatibility "
        "layer — docker and libvirt between them create 43 chains across 7 "
        "tables — and the live comparator read 97 network objects there, 13 "
        "of them carrying OpaqueReason `xt`. Both implementations agreed on "
        "every one, so the opaque comprehension path is exercised and the two "
        "ports of it do not disagree. What is still unvisited is the OTHER "
        "spelling: no rule anywhere has produced a bare-string statement, so "
        "one of the two OpaqueReason values is reached by nothing. The corpus "
        "also still holds no such ruleset, so this remains owned OUTSIDE the "
        "replay tier rather than by it."
    ),
    # The four servarr apps facts that are about the OBSERVER rather than about
    # any app: two of them state a fault in this process's own configuration,
    # and two carry the text of a failure only the reference can spell.
    "servarr/instance-config-and-failure": (
        "ConfigMissing and ConfigDuplicate are read from SE_SERVARR_INSTANCES "
        "and the per-instance receipts beside it, and StatusUnobservable and "
        "QueueUnobservable carry the failure text of an app that stopped "
        "answering. No committed capture reaches any of them — both instances "
        "were configured and both answered — and no mutation operator mints "
        "one, for two different reasons, each stated rather than shrugged at. "
        "The two Config facts would be minted by editing the fleet RECEIPT, "
        "which is this process's configuration and not the machine it "
        "observes: every operator in this module rewrites what an interface "
        "SAID, and a receipt is what the observer was told, so minting one "
        "would be the guard mutating itself. The two Unobservable facts cannot "
        "be minted at all, because their VALUE is the reference's own "
        "rendering of an httpx exception — the exception class name and "
        "httpx's message, with the request URL in it — which no independent "
        "implementation can reproduce and no corpus should enshrine; the "
        "replay seam therefore replays 404 and no other status, since 404 is "
        "the one code whose effect on a row is independent of that text. "
        "Venue: the live comparator (harness/bin/se-compare), run with an "
        "instance named and its receipts withheld, and again with an app "
        "stopped — where the two implementations' disagreement about the "
        "failure text is the finding rather than a defect in either.\n\nVENUE REPORTED 2026-08-19 (docs/PARITY-REPORT.md): run with no instance configured at all, which is the receipts-withheld case this entry describes. The reference RAISES — RuntimeError, no reading — and the port declines `absent`, which commits zero and retires. Neither side produced the ConfigMissing row this entry is about, so the fact stays unreached; what the run did establish is that the two implementations disagree about the SHAPE of an unconfigured fleet, not merely about a failure sentence.\n\nVENUE OWNED 2026-08-19, both halves, on a two-instance fleet. Receipts withheld: SE_SERVARR_INSTANCES named radarr and sonarr and radarr's key was removed, so the fleet stayed configured and one instance was short a receipt — the case the paragraph above could not reach by unconfiguring everything. Five objects, four commits, both clocks, CLEAN. ConfigMissing is therefore reproduced by the port and no longer an asymmetry; ConfigDuplicate still is, since no run has named one instance twice. App stopped: sonarr's container was stopped and the fleet re-read. Everything agreed except the one value this entry predicted would not — StatusUnobservable, where the reference renders httpx as `ConnectError: All connection attempts failed` and the port says `sonarr did not answer /system/status`. Both are true, neither can produce the other, and that is the finding this entry said it would be rather than a defect in either. QueueUnobservable stays unreached: the queue request is not made once /system/status has already gone dark."
    ),
    # The two readings a stalling slice takes when its stall is NOT accounted
    # for. Named rather than minted, and the reason is the guard's own rule
    # rather than a shrug about what could be staged.
    "resources/stall-not-accounted-for": (
        "StallUnexplained and StallAttributionUnobservable are what a slice "
        "states when every member was read and none accounts for its stall, "
        "and when a member could not be read at all. The only committed "
        "capture is of a machine at rest: three slices report an I/O stall and "
        "all three are explained by a member, so neither branch is reached and "
        "the pair of facts is published by no replayed stream. An operator "
        "COULD raise a slice above every member and mint the first — which is "
        "exactly why it is not minted here, because test_differential's "
        "no-dead-weight rule requires every operator to have a committed wrong "
        "fixture that dies to it, and no port has been written that is blind "
        "to these two while agreeing about everything else. So the REPLAY tier "
        "does not own them. StallUnexplained is now owned elsewhere: the live "
        "comparator (harness/bin/se-compare) was run on the lab guest on "
        "2026-08-19 with the root slice reading 0.07% while all 67 of its "
        "members read 0.0, and the reference and the port produced the "
        "identical sentence — so that half is owned, and owned OUTSIDE this "
        "tier. StallAttributionUnobservable is reached by nothing yet: it "
        "wants a host where a member's pressure file will not read, or a "
        "cgroup tree deeper than the walk's bound, and no lab guest stages "
        "either. Venue: the same live comparator, on a host that has one — the "
        "tool exists, the shape has not been met, and that half stays owed."
    ),
    # The units collection's one declared fact that no capture reaches and no
    # operator can mint — and the second half of that sentence is the reason it
    # is here rather than in the mutation guard, where MachineName and
    # MissingRequirements both went.
    "units/missing-reference-unobservable": (
        "MissingReferenceUnobservable stands for a backwards probe that did "
        "not happen: a GetAll on an absent unit that failed, a unit that went "
        "away between the listing and the probe, or a listing carrying more "
        "not-found units than one collection will probe. No committed capture "
        "holds one — every probe answered and 41 is far below the 200-unit cap "
        "— and no mutation operator can mint one either, which is a property "
        "of the harness rather than a gap in imagination: making a probe fail "
        "means removing a reply the listing names, and the replay seam fails "
        "the RUN on an uncaptured request rather than letting the adapter "
        "swallow it, so the reference half of any such mutation exits 2 and "
        "the guard's own control test refuses the operator. Venue: the live "
        "comparator (harness/bin/se-compare), where the race is real — a "
        "daemon-reload between the listing and the probe collects the Unit "
        "object and the path 404s — and where a host carrying more than 200 "
        "unloadable units would exercise the cap. The tool exists and no such "
        "run has caught one, so this truth stays owed rather than owned."
    ),
    # The packages collector reads three interfaces and the corpus captures
    # one. A second variant would close this outright — which is why the entry
    # says so rather than dressing a gap as a boundary.
    # `kea/leases` stood here until 2026-08-19 and is CLOSED, not moved: the
    # residual's own stated venue was "a capture from a guest with the hook
    # loaded, which is a staging change to the lab and not a code change", and
    # it ended "the tool exists, the guest does not". The guest now exists —
    # harness/remote/provision-estate.sh loads libdhcp_lease_cmds and plants
    # four leases through kea's own lease4-add — and corpus/kea/leases opens
    # the collection with all three State words, an infinite lifetime rendering
    # ExpiresAt as `never`, and a lease with no Hostname. The entry is deleted
    # rather than reworded because a residual describing a gap that has been
    # filled sends the next reader around an obstacle that is not there.
    # The hardware collector reads five trees and the only guest available to
    # capture it has devices in three of them. These four entries are what
    # that costs, named fact by fact rather than as "some disk facts" — the
    # contract check reads them, so a name missing from the prose is a promise
    # nothing tests and the guard says so.
    # Closed on 2026-08-21 by corpus/hardware/staged-disks, which is the
    # capture the lab work of 2026-08-19 was for: the guests were given a
    # virtio-SCSI disk and an emulated NVMe controller, each with a serial and
    # a WWN, and until this variant landed the READING lived only in the live
    # comparator. It now lives in the corpus, so the whole of what this entry
    # used to hold — the nvme collection committing zero objects, and every
    # scsi fact belonging to a disk rather than a controller — is exercised by
    # committed records. What is left is three shapes an emulated device
    # cannot present, kept here because the honest fix for each is hardware
    # and not a plant.
    "hardware/no-emulated-link-or-slot": (
        "three link shapes no emulated device can present. A virtio-scsi disk "
        "has no ata_link class, so the SATA link pair LinkSpeed and "
        "LinkSpeedMax never arrive on a scsi row and LinkSpeedStatus, which is "
        "derived from them, is never minted there — those want a guest with an "
        "emulated AHCI controller, which wants a q35 machine type. And an "
        "emulated NVMe controller sits in no PCI slot that publishes a slot "
        "capability, so SlotLinkSpeedMax and SlotLinkWidthMax are read back "
        "empty: the bridge above it publishes no maximum. That absence is the "
        "reason the link rules split the way they do — a link below the "
        "device's own maximum is a fault only where the slot could do better — "
        "so the `capped-by-slot` reading is the one this corpus cannot show, "
        "and the guard says so rather than a variant implying it never "
        "happens. Venue: the live comparator on a host with a real "
        "add-in-card NVMe drive, or a SATA disk on a real AHCI port."
    ),
    # WWNUnobservable is the absence of a fact rather than a fact, and the
    # guest's controller has exactly one namespace.
    "hardware/one-namespace-per-controller": (
        "WWNUnobservable is published only where a controller exposes SEVERAL "
        "namespaces, because a wwid belongs to a namespace and no single one "
        "then identifies the controller. The lab's emulated controller has "
        "one, so the fact that states the ambiguity is reached by nothing "
        "here. No operator mints it either: the shape is a second namespace, "
        "which is a device the capture never saw rather than a value in a "
        "document. Venue: the live comparator against a controller carrying "
        "more than one namespace."
    ),
    "hardware/udisks2-smart": (
        "no committed variant carries a udisks2 document at all, so every fact "
        "that arrives over D-Bus is exercised by no replayed stream: Firmware, "
        "Vendor, SmartFailing, SmartBadSectors, SmartSelftestStatus, "
        "SmartCriticalWarning, and the SmartTemperatureC and SmartPowerOnHours "
        "readings that come from the daemon rather than from smartctl. Two "
        "reasons, and the second is the harder one. The guest runs udisks2 and "
        "answers, but its drives are virtio-blk and appear in neither walk, so "
        "the reply joins to nothing and would contribute no fact. And the "
        "reply CANNOT be committed as it stands: the scrub manifest addresses "
        "payload leaves by dotted path, and a GetManagedObjects document is "
        "keyed by D-Bus INTERFACE NAMES which contain dots — so "
        "org.freedesktop.UDisks2.Drive.Serial cannot be told from "
        "org.freedesktop.UDisks2.Block.Device by any pattern the manifest "
        "grammar can write, and the only classification it admits is one "
        "wildcard over every property of every interface at once. That is the "
        "coarse-classification failure DESIGN 21 exists to prevent. Venue: the "
        "live comparator on a host with an ATA or NVMe drive udisks2 manages; "
        "the manifest gap is reported as an adjudication item, because "
        "classifying a D-Bus document is a decision about the scrubber's "
        "grammar and not a manifest's to make."
    ),
    "hardware/smartctl-depth": (
        "the deepest SMART depth runs only where the deployment granted raw "
        "device access, and the lab guest has no /run/system-explorer-smart "
        "and no block device in either walk to run it against — so "
        "SmartSnapshotAt, SmartSnapshotAgeSeconds, SmartSnapshotReason, "
        "SmartOverallPassed, SmartPercentUsed, SmartAvailableSparePct, "
        "SmartSpareThresholdPct, SmartSpareBelowThreshold (derived from the pair), SmartSnapshotAsleep (derived from the reason), SmartMediaErrors, SmartPowerOnHours, "
        "SmartTemperatureC and the SmartUnobservable statement that stands in "
        "for all of them are reached by no committed record. The three smart "
        "payloads are captured EMPTY rather than omitted, which is what makes "
        "the absence visible in the corpus rather than merely true. Venue: the "
        "live comparator on a host running the module's grantDiskAccess timer, "
        "where the snapshots exist and their age is derived against a real "
        "clock — which replay cannot authenticate in any case (DESIGN 19)."
    ),
    "hardware/no-hba-no-enclosure": (
        "the guest has no host bus adapter and no SES enclosure, and both are "
        "hardware nothing in a lab can conjure. The adapter's own identity is "
        "therefore unexercised — FirmwareVersion, BiosVersion and BoardName "
        "are published by mpt3sas-family drivers and read back null under all "
        "six attribute spellings here — as is the SAS topology beneath one: "
        "Level and SASAddress on an expander, and the enclosure facts a shelf "
        "supplies, Enclosure, EnclosureSlot, SlotStatus and Slots. platform's "
        "BoardName is the same shape one layer up: DMI leaves it empty on this "
        "i440FX guest and on most virtual machines. Venue: the live comparator "
        "on a host with a SAS HBA and a populated shelf. Not mintable by an "
        "operator for the same reason the disk facts are not — the sysfs "
        "subtree an enclosure publishes is a document nobody here has observed."
    ),
    "packages/nix-store-path": (
        "StorePath is published only by the nix branch, and no committed "
        "variant captures a NixOS host: a variant stages exactly the one "
        "payload its detected packaging interface produces, and every "
        "committed packages payload is dpkg's. No mutation operator mints it "
        "either, and that is a ruling rather than an oversight — an operator "
        "ADDS a shape to the machine its seed captured, where staging a Nix "
        "store swaps the machine outright and the guard's reference half would "
        "be answering about a host nobody observed. Venue: the live comparator "
        "(harness/bin/se-compare), run on a NixOS host, where the "
        "/run/current-system/sw link farm is walked for real and every "
        "StorePath it yields is compared. The tool exists and no such run has "
        "been taken, so this truth stays owed rather than owned."
    ),
    # Two facts of the bazarr instance row that no PAYLOAD can reach, which is
    # what makes them residuals rather than an operator's job: one is decided
    # by the deployment's environment before any document is fetched, and the
    # other by whether the network answered. A mutation operator rewrites the
    # documents a capture holds and can mint neither.
    "bazarr/config-missing": (
        "ConfigMissing is published where SE_BAZARR_URL names an instance and "
        "SE_BAZARR_API_KEY is absent or unfit to send in a header. It is read "
        "off the process environment BEFORE either document is fetched, so no "
        "captured payload reaches it and no mutation operator mints it — the "
        "replay seam pins the receipts precisely so a replaying workstation's "
        "own environment cannot decide a committed row. Venue: the live "
        "comparator (harness/bin/se-compare), run against a host with the URL "
        "configured and the key withheld, where the reference and the port "
        "build the row from the same environment. "
        "VENUE OWNED 2026-08-19: that run was taken, and it caught a defect no "
        "other tier could. The facts agreed on the first attempt — one object, "
        "one commit, the same ConfigMissing list — and the CLOCK did not: the "
        "port published the row with `at: 0`, which the contract refuses "
        "(0 < at <= 1e9). The row is built from the environment and returns "
        "before any fetch, and the fetch is what took the clock reading, so a "
        "row that rests on no read never got one. Replay cannot see it — the "
        "seam pins the receipts exactly so a replaying host cannot reach this "
        "branch — and the facts being identical is why a parity-only check "
        "would have called it clean. Fixed by taking the clock after the URL "
        "check and before the receipt checks, which keeps the no-URL decline "
        "answerable on a host with no CLOCK_BOOTTIME; re-run, clean on all "
        "four checks. The same shape was found and fixed in the plex port by "
        "the same sweep. This entry stays because the fact is still reached by "
        "no committed stream, and the corpus is what it speaks for."
    ),
    "bazarr/status-unobservable": (
        "StatusUnobservable is published where the configured instance did not "
        "answer, which is a property of the network and the daemon rather than "
        "of any document — so no captured payload reaches it and no mutation "
        "operator mints it. It carries a further asymmetry the venue must "
        "adjudicate rather than merely observe: the reference's value is "
        "`f\"{type(exc).__name__}: {exc}\"` over a Python exception, which no "
        "port in another language can reproduce, and the Go collector states "
        "the request and the HTTP status instead. Venue: the live comparator, "
        "run against a host whose bazarr is stopped, where the two readings sit "
        "beside each other and the difference is a finding rather than a "
        "verdict (DESIGN 20). "
        "VENUE REPORTED 2026-08-19: bazarr's container was stopped and the two "
        "readings are\n"
        "  reference: ConnectError: All connection attempts failed\n"
        "  port:      the bazarr API did not answer GET /api/system/status\n"
        "Everything else on the row agreed. Both are true, neither can produce "
        "the other, and that is the finding this entry said it would be.\n"
        "One thing the run added that the entry did not predict, and it is the "
        "reason the paperless disagreement is a DISCLOSURE and this one is "
        "not: httpx renders these two exceptions differently. A ConnectError "
        "— nothing listening — stringifies without the URL, so the reference's "
        "value here names no host. An HTTPStatusError — something answered, "
        "with a status — stringifies WITH the request URL, which is how "
        "paperless's 403 puts the instance's host and port into a committed "
        "fact. So the leak is not a property of this house pattern in general; "
        "it is a property of which httpx exception fires, which means reading "
        "one collector's failure text and concluding the family is safe would "
        "be wrong."
    ),
    # A traefik SERVICE error, distinct from the router error beside it, which
    # the dynamic-provider operator does mint. The distinction is what makes
    # this a residual rather than laziness: the ROUTER half was staged on a live
    # proxy and is covered, and this half could not be.
    "traefik/rejected-service": (
        "the services collection's Error fact is published only where Traefik "
        "rejects a SERVICE, and no committed capture carries one. It is not "
        "minted either, and that is a measurement rather than an omission: on a "
        "live Traefik 3.1.7 (2026-08-19) the file provider accepts a weighted "
        "service naming a service that does not exist, accepts a mirroring one "
        "the same way and accepts a load balancer with no servers — all three "
        "load `enabled` with no error member — and the docker provider skips a "
        "container with no port rather than publishing a service that carries "
        "the reason. An operator that minted the member anyway would be staging "
        "a document nobody has seen this interface produce, which is the "
        "failure the spares-and-logs placement already cost once. Venue: a "
        "capture from a Traefik whose provider does reject a service — the "
        "kubernetes and consul providers do — or the live comparator "
        "(harness/bin/se-compare) run beside one. The tool exists and no such "
        "proxy is in the lab, so this truth stays owed rather than owned."
    ),
    # The downloaders collector's two configuration-fault facts. Neither is a
    # shape a payload can carry, which is why this is a residual rather than a
    # capture nobody has taken yet.
    "downloaders/unconfigured-client": (
        "ConfigMissing and StatusUnobservable are the two facts a client row "
        "carries INSTEAD of a reading — a sabnzbd URL with no key, and a "
        "configured client whose API did not answer — and both are decided by "
        "the adapter's configuration gates rather than by any document. The "
        "replay seam pins those gates to a both-clients-present constant "
        "(harness/bin/se-reference-collector, the downloaders instance block), "
        "so no committed variant can stage either and no mutation operator can "
        "mint one: an operator ADDS a shape to a payload, and these are decided "
        "before a payload is read. Venue: the live comparator "
        "(harness/bin/se-compare), which was run on 2026-08-19 against a guest "
        "with one client's receipts withheld and then with one client stopped. "
        "So this truth is OWNED, and owned outside the replay tier — and the "
        "run found what a residual is worth having for: the two "
        "implementations agree exactly on ConfigMissing and disagree on "
        "StatusUnobservable, where the reference writes the transport "
        "exception's own text and the port writes a constant phrase, because "
        "that text is a channel carrying the client URL and sabnzbd's key.\n\nVENUE REPORTED 2026-08-19 (docs/PARITY-REPORT.md): the comparator was run against a guest with NEITHER client configured, and the finding is larger than the facts this entry names. The reference publishes two commits — real rows saying what it was not told — and the port DECLINES both. So the divergence is not a fact's spelling, it is whether an incompletely configured client produces a row at all, and a row that says \"I was not given the API key\" is a finding an operator can act on where a decline is not. The port does not reproduce it."
    ),
    # logs has a seam entry, a built Go port and no committed pair. That was
    # invisible until 2026-08-19, because the coverage guard skipped any
    # collector the corpus did not carry AT ALL — so the one collector in that
    # state was the one it could not see. The guard now denies by default and
    # this entry is what it found.
    # Replaced 2026-08-19 when the corpus gained its first journal pair. The
    # entry that stood here said "no committed variant" and named the two
    # publish-gate blockers; both were ruled, the capture landed, and a residual
    # that outlives its reason is worse than none — this is what is actually
    # still unreached.
    # The one fact vms declares that a shutoff domain cannot reach, and the
    # corpus holds exactly one shutoff domain.
    "vms/address-unobservable": (
        "IPAddressesUnobservable is what a RUNNING guest's row says when no "
        "address source could answer for it, and the committed variant stages "
        "a domain that is shut off — where an address does not apply at all, "
        "so the fact is correctly absent and the branch is unreached. No "
        "mutation operator mints it either: flipping the staged state word to "
        "`running` would produce a guest that is running with no interfaces "
        "and no lease, which is a machine nobody observed rather than a "
        "perturbation of one that was. "
        "The shape is not exotic — adapters/vms.py calls it the ORDINARY case "
        "for a guest on a bridge this host manages no lease file for, because "
        "libvirt refuses the guest agent outright on the read-only connection "
        "this collector opens and ARP entries expire when a guest goes idle. "
        "Venue: the live comparator (harness/bin/se-compare) on a host with a "
        "running domain, which is where it was in fact first reached — on "
        "2026-08-19, the first running guest either implementation had ever "
        "been asked about, and the two disagreed. That run is what settled "
        "which CHANNEL it travels on: the port emitted an unobservable record "
        "and the reference a fact, and the fact won, because rules/vms.py "
        "reads it to decide whether a blank address column is a gap or an "
        "answer and rules are computed from facts. So this entry speaks for a "
        "fact whose channel a live run chose, and which no replayed stream "
        "carries."
    ),
    "logs/severity-and-truncation": (
        "Two shapes the committed page does not hold, both of them properties "
        "of a QUIET machine rather than of the collector. Every one of the 100 "
        "entries is priority 5 or 6, so the whole severity ladder above notice "
        "is evaluated by nothing: no err, crit, alert or emerg row exists in "
        "any replayed stream, and the opinions rules/logs.py forms above notice "
        "are therefore formed by nothing either. And all 100 entries fit one "
        "page, so the bounding this collection exists to do never actually "
        "bounds: no cursor is issued, no truncation is reported, and MAX_LIMIT "
        "is not approached. A mutation operator could raise a PRIORITY member, "
        "and deliberately does not: the severity ladder's readings are rules "
        "output rather than facts, and the collector stream carries facts, so "
        "an operator would perturb a number the differential can see while "
        "leaving the judgement it feeds untested — which is the appearance of "
        "coverage rather than coverage. Venue: a capture from a host that has "
        "actually failed at something, and a second variant whose page exceeds "
        "the limit; the live comparator (harness/bin/se-compare) reads a real "
        "journal today and would surface a disagreement on either. The tool "
        "exists, the machine state has not been staged. "
        "STAGED 2026-08-19 for the SEVERITY half: `corpus/logs/severity` is a "
        "page carrying every rung — emerg, alert, crit, err (three), warning, "
        "notice, info — from a guest where a oneshot unit exited 7, so systemd "
        "wrote the err entry and its structured members (UNIT_RESULT, "
        "EXIT_CODE, EXIT_STATUS) rather than a logger line impersonating them. "
        "The live comparator agreed on that page as well. So the facts above "
        "notice are now reached by a replayed stream; what is NOT reached, and "
        "this entry keeps, is the OPINIONS half — a collector stream carries "
        "facts and the judgements rules/logs.py forms live in the agent's own "
        "tier, so no corpus variant of this collector can exercise them. "
        "The reason nobody had staged it is worth keeping: the page is the "
        "newest 100 entries, and on a guest running eleven containers the "
        "newest 100 span TWENTY-EIGHT SECONDS, so a failure staged and "
        "captured three minutes apart has already scrolled off and reads as a "
        "machine that never fails. "
        "The TRUNCATION half is RESTATED rather than owed, because it was "
        "asking this tier for something this tier does not have. That guest's "
        "journal holds 7,277 entries against a page of 100, so the bound "
        "engages and both implementations agree on which hundred — but the "
        "collector declares no cursor fact and no truncation fact. The journal "
        "cursor IS the object's name, and the bound is silent here by design. "
        "`no cursor is issued, no truncation is reported` describes the "
        "agent's HTTP paging, where DEFAULT_LIMIT and MAX_LIMIT live, and no "
        "capture of this collector can speak to it."
    ),
    # paperless's five fault facts. The archive answered, so none is reached —
    # and one of them could not be corpus-owned even if it were.
    "paperless/instance-faults": (
        "DatabaseError, RedisError, CeleryError and IndexError carry what a "
        "component check said WHEN IT FAILED, and StatusUnobservable carries "
        "why /api/status/ could not be read at all. The committed capture is "
        "of an archive whose four components all answered OK, so no replayed "
        "stream publishes any of them. Two different reasons they are named "
        "here rather than minted. The four errors would need a paperless with "
        "a broken component — an operator CAN rewrite a status word, but the "
        "matching error string is written by the app about its own failure and "
        "inventing one would enshrine a sentence paperless never said.\n\n"
        "StatusUnobservable is the one that cannot be owned by this tier at "
        "all, and the reason is worth stating because it is a DISCLOSURE "
        "difference rather than a wording one. The reference's value is "
        "httpx's HTTPStatusError rendering, and env.reason strips userinfo and "
        "query strings but not the HOST — so the reference's fact carries the "
        "instance URL. The Go port emits a URL-free sentence naming the path "
        "instead. A corpus pair would have to enshrine one of those two, and "
        "the safer one is not the reference's. Venue: the live comparator "
        "(harness/bin/se-compare), run against an instance with a "
        "non-superuser token, where the two implementations' disagreement is "
        "the finding rather than a defect in either — the same shape as "
        "servarr/instance-config-and-failure. "
        "VENUE RUN 2026-08-19, and it narrows this entry from five facts to "
        "two. RedisError and CeleryError are now OWNED, outside this tier: "
        "paperless-redis was stopped and the app said, in its own words, "
        "`Error connecting to redis, check logs for more detail.` and the "
        "matching celery sentence — which is exactly the string this entry "
        "said could not be invented — with reference and port agreeing on "
        "both. DatabaseError and IndexError stay unreached: this deployment is "
        "sqlite and there is no clean way to break either component without "
        "breaking the app that reports on it. "
        "StatusUnobservable is REPORTED rather than owned, and the "
        "disagreement is the disclosure difference this entry predicted, now "
        "measured rather than reasoned. With a non-superuser token "
        "`/api/status/` answers 403 and the two render it:\n"
        "  reference: HTTPStatusError: Client error '403 Forbidden' for url "
        "'http://…:8000/api/status/' For more information check: <an MDN link>\n"
        "  port:      the paperless API answered GET /api/status/ with HTTP 403\n"
        "So the reference publishes the instance's HOST and port inside a "
        "fact that travels to a hub and out over MCP, and the port publishes "
        "the path alone. On a lab guest the URL is loopback and discloses "
        "nothing; on the estate it is the real address. A corpus pair would "
        "have to enshrine one of the two and the safer one is still not the "
        "reference's."
    ),
    # plex's nine unreached facts, and they split cleanly into two groups with
    # two quite different reasons.
    "plex/failure-statements-and-sessions": (
        "Three of the nine are failure statements the capture never reaches: "
        "server/ConfigMissing (the receipts were incomplete), "
        "server/StatusUnobservable (the server went dark mid-sweep) and "
        "libraries/ItemCountUnobservable (one section's count would not read "
        "while the rest of its row stood). The captured server answered "
        "everything, and the last of the three is the interesting one — it is "
        "a PER-ROW narrowing, so a port that let one section's failure sink "
        "the whole collection would still replay this variant correctly.\n\n"
        "The other six — sessions/Title, Type, User, Player, State and "
        "VideoDecision — are unreached for a reason that is not going to "
        "change. They exist only in a session document describing something "
        "actually playing, which names a PERSON and what they were watching. "
        "harness/scrub/plex.json deliberately classifies none of it, so such a "
        "capture is refused leaf by leaf rather than scrubbed, and that is the "
        "correct outcome for a document of that kind. No mutation operator "
        "mints one either: an operator rewrites what an interface SAID, and "
        "inventing a viewer and a title would be composing the reading rather "
        "than perturbing it. Venue: the live comparator, run against a server "
        "while something is playing — it publishes nothing, which is exactly "
        "why it is the venue that can own this and the corpus cannot.\n\n"
        "VENUE REPORTED 2026-08-19, on the ConfigMissing third of this entry. "
        "Run against an unclaimed lab server with SE_PLEX_URL set and "
        "SE_PLEX_TOKEN withheld, the fact itself agreed — both sides publish "
        "the server row naming the variable — and TWO other things did not. "
        "The port stamped the row `at: 0`, because it rests on no document and "
        "the read path is what takes the clock; fixed, and the identical shape "
        "was found in bazarr by the same sweep. And the two disagree about the "
        "other two collections: the reference COMMITS `libraries` and "
        "`sessions` with zero objects, which is authoritative-empty and "
        "therefore retires every library and every session on the strength of "
        "an unset variable, while the port declines both `unavailable` naming "
        "the 401 and retires nothing. That is the second instance of the "
        "commits-zero-with-no-decline family the DESIGN queue already carries "
        "for packages, it is in the retiring direction, and it is recorded "
        "there rather than repaired here. The sessions facts stay unreached: "
        "nothing was playing, and nothing on this server can be."
    ),
    # protection carries an AUTHORED variant, so all three of its collections
    # are covered and none is orphaned. What is not covered is anything a
    # written document cannot be evidence of, and that is one thing rather
    # than three.
    "protection/never-captured": (
        "The committed variant is authored, not captured: every shape in it "
        "was read off a real capture taken on 2026-08-19, and every value was "
        "written. So the corpus is evidence about the COLLECTOR and is no "
        "evidence at all about the estate's documents — if the manifest, the "
        "verdict or the receipt schema moves, this variant keeps replaying "
        "happily against a shape nothing produces any more, and the "
        "source_version it claims (protection-manifest-schema 1) would go on "
        "saying 1 forever because it too was written here. No mutation "
        "operator can close that: an operator rewrites what an interface "
        "SAID, and the question is whether any interface still says it. The "
        "real capture is not committed because the manifest's 191 leaves "
        "describe what a private estate protects, where copies land and who "
        "may delete, and scrubbing substitutes the names while leaving the "
        "shape — harness/scrub/protection.json is written for that capture "
        "anyway, and was proven against a scratch copy of the authored "
        "payloads to classify every leaf and to substitute host names "
        "consistently, including inside the `<host>:<job>` references. Venue: "
        "the live comparator (harness/bin/se-compare) on a host that "
        "publishes the three documents, which reads the real ones and "
        "publishes none of them; it is the only thing that can notice the "
        "shape has moved. The tool exists and no such run has been made, so "
        "this truth stays owed rather than owned.\n\n"
        "One thing here is owed by nobody, which is different from unowned: "
        "a target's protection spans HOSTS by design — the source captures, "
        "another host pushes the off-site copy — so no host adapter can state "
        "the weakest link in a chain it cannot see, and the collector "
        "deliberately does not try. That belongs to the hub, and the hub does "
        "not exist yet."
    ),
}


class CorpusError(Exception):
    """A corpus entry that cannot be trusted to prove anything."""


def typed_equal(a: object, b: object) -> bool:
    """Recursive equality under a typed reader's eyes.

    Python's == thinks True == 1 and 20 == 20.0. A consumer in a typed
    language does not, so a corpus judged with == would pass a port that
    turned a bool into an int or an int into a float — a wrong value on the
    wire that no diff would ever show. bool is tested before anything else
    because bool IS int to isinstance, and applied recursively because the
    values that drift live inside facts dicts and name lists, not at the top.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(typed_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(
            typed_equal(x, y) for x, y in zip(a, b, strict=True)
        )
    if type(a) is not type(b):
        return False
    return a == b


@dataclass(frozen=True)
class Variant:
    """One collect invocation, captured."""

    path: Path
    meta: dict
    payloads: dict[str, object]
    expected: list[dict]

    @property
    def name(self) -> str:
        # the directory, not the declared variant: two variants may share a
        # variant name across OSes, and an id has to locate the one that failed
        return f"{self.meta['collector']}/{self.path.name}"

    @property
    def canaries(self) -> list[str]:
        return list(self.meta.get("canaries", []))

    @property
    def regenerable(self) -> bool:
        return bool(self.meta["regenerable"])

    @property
    def payload_suffixes(self) -> dict[str, str]:
        """The on-disk suffix each payload stem was committed under.

        load_variant decodes `.json` and keeps everything else as raw text,
        and that is a one-way trip: the string "dpkg" in a payloads dict could
        have come from a JSON document holding one string or from a text file
        holding one word, and the two are different files. Anything that
        writes a payload set back out — the mutation guard does, on every run
        — has to know which, or it hands a collector a directory its own
        replay seam cannot read and the verdict is about the harness.
        """
        return {
            p.stem: p.suffix
            for p in sorted((self.path / "payloads").iterdir())
            if p.is_file() and not p.name.startswith(".")
        }

    def collections(self) -> set[str]:
        return {
            record["collection"] for record in self.expected if "collection" in record
        }


def _read_stream(path: Path) -> list[dict]:
    """Decode a stream file.

    Records may be pretty-printed across lines — the wire is one object per
    line, but a corpus file is read by people, so decode by object rather than
    by line and let both shapes work.
    """
    text = path.read_text()
    decoder = json.JSONDecoder()
    records, index = [], 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        record, index = decoder.raw_decode(text, index)
        records.append(record)
    return records


def _anchor_shape_problem(anchor: object) -> str | None:
    """Why this anchor matches none of the declared forms, or None."""
    if not isinstance(anchor, dict):
        return "an anchor is an object, not a bare value"
    keys = frozenset(anchor)
    if keys not in _ANCHOR_FORMS:
        return (
            f"keys {sorted(keys)} match no anchor form — the forms are exact "
            "key sets, so an extra or misspelt key is rejected rather than "
            "reshaped into whichever form the rest resembles"
        )
    for key in ("collection", "object", "fact", "absent_fact", "decline_reason",
                "relation"):
        if key in anchor and (not isinstance(anchor[key], str) or not anchor[key]):
            return f"{key} must be a non-empty string, not {anchor[key]!r}"
    if "target" in anchor:
        target = anchor["target"]
        if not isinstance(target, dict) or frozenset(target) != frozenset(
            {"kind", "name"}
        ):
            return (
                f"target must be exactly {{kind, name}}, not {target!r} — a "
                "target carries a name and never an id, because resolution is "
                "a property that changes (DESIGN 13)"
            )
        for key in ("kind", "name"):
            if not isinstance(target[key], str) or not target[key]:
                return f"target.{key} must be a non-empty string, not {target[key]!r}"
    if "names" in anchor:
        names = anchor["names"]
        if not isinstance(names, dict) or not names:
            return (f"names must be a non-empty object of name families, not "
                    f"{names!r}")
        if not frozenset(names) <= frozenset({"stable", "ephemeral"}):
            return (f"names carries {sorted(frozenset(names) - {'stable', 'ephemeral'})}"
                    " — the classes are exactly stable and ephemeral (DESIGN 16)")
    if "assertion_facts" in anchor and not isinstance(anchor["assertion_facts"], dict):
        return (
            f"assertion_facts must be an object, not {anchor['assertion_facts']!r} "
            "— {} asserts a relation type that carries no facts"
        )
    if "commit_objects" in anchor and (
        isinstance(anchor["commit_objects"], bool)
        or not isinstance(anchor["commit_objects"], int)
        or anchor["commit_objects"] < 0
    ):
        return f"commit_objects must be a non-negative int, not {anchor['commit_objects']!r}"
    if "value" in anchor and anchor["value"] is None:
        return (
            "a fact value is never null (DESIGN 19), so an anchor asserting "
            "null asserts the unassertable"
        )
    return None


def load_variant(path: Path) -> Variant:
    """Load one variant directory, or say precisely why it cannot be used."""
    meta_path = path / "meta.json"
    if not meta_path.exists():
        raise CorpusError(f"{path}: no meta.json — a variant must say what it is")
    meta = json.loads(meta_path.read_text())

    missing = [key for key in REQUIRED_META if key not in meta]
    if missing:
        raise CorpusError(f"{path}: meta.json lacks {missing}")

    if meta["variant"] not in VALID_VARIANTS:
        raise CorpusError(
            f"{path}: variant {meta['variant']!r} is not one of "
            f"{sorted(VALID_VARIANTS)} — a new kind of variant is a decision "
            "about what the corpus covers, made in VALID_VARIANTS, not minted "
            "in a meta.json"
        )

    anchors = meta["anchors"]
    if not isinstance(anchors, list) or not anchors:
        raise CorpusError(
            f"{path}: anchors is {anchors!r} — every variant carries at least "
            "one truth hand-asserted at staging time, because a pair whose "
            "expected half came from the reference proves determinism, never "
            "correctness (DESIGN 20)"
        )
    for anchor in anchors:
        problem = _anchor_shape_problem(anchor)
        if problem:
            raise CorpusError(f"{path}: anchor {anchor!r}: {problem}")

    # Missing, not merely empty: git does not track empty directories, so an
    # absent-interface variant still commits a keep file under payloads/ and
    # a directory that is not there at all is a broken checkout — replaying a
    # populated variant against it would judge the collector over nothing.
    payload_dir = path / "payloads"
    if not payload_dir.is_dir():
        raise CorpusError(
            f"{path}: payloads/ directory is missing — a broken checkout is "
            "not an absent interface; even a variant with nothing to replay "
            "commits the empty directory"
        )
    # Every file under payloads/ IS a payload: the native format is the
    # payload (DESIGN 20), and for some interfaces that format is text —
    # os-release, the kernel hostname — so a loader that only spoke JSON
    # would silently drop a text capture and then reject the variant as
    # payload-less. .json parses; anything else is the raw text, keyed by
    # stem exactly as the replay seam names it. Dotfiles are git plumbing
    # (the .gitkeep that makes an absent-interface payloads/ committable),
    # never captures.
    payloads: dict[str, object] = {}
    for p in sorted(payload_dir.iterdir()):
        if not p.is_file() or p.name.startswith("."):
            continue
        if p.stem in payloads:
            raise CorpusError(
                f"{path}: two payload files share the stem {p.stem!r} — the "
                "replay seam addresses payloads by stem, so one of them "
                "would silently shadow the other"
            )
        payloads[p.stem] = (
            json.loads(p.read_text()) if p.suffix == ".json" else p.read_text()
        )
    expected_path = path / "expected.jsonl"
    if not expected_path.exists():
        raise CorpusError(f"{path}: no expected.jsonl — half a pair is not a pair")
    expected = _read_stream(expected_path)
    if not expected:
        raise CorpusError(f"{path}: expected.jsonl is empty")

    # A variant with no payloads is legitimate in exactly one case: the
    # interface was absent on the machine captured, and the expected stream
    # says so. Anything else is a variant that would replay against nothing
    # and agree with itself.
    if not payloads:
        declines = [r for r in expected if r.get("record") == "decline"]
        if not declines:
            raise CorpusError(
                f"{path}: no payloads and no decline — a variant with nothing "
                "to replay against proves nothing, and would pass vacuously"
            )
        if any(r["reason"] != "absent" for r in declines):
            raise CorpusError(
                f"{path}: a payload-less variant may only expect an absent "
                "decline; unauthorised, unavailable and unsupported all mean "
                "something was there and could not be read"
            )

    return Variant(path=path, meta=meta, payloads=payloads, expected=expected)


def validate_anchors(variant: Variant, records: list[dict]) -> list[str]:
    """Hold a stream to the variant's planted truths (DESIGN 20).

    The expected half of a pair is generated by running the reference over
    the payloads, so the two halves agreeing proves determinism and nothing
    more — wherever the reference is wrong, the corpus enshrines the wrong
    answer and fails the collector that gets it right. Anchors are written at
    staging time, the one moment ground truth is known independently of any
    implementation, which is what makes them an authority the generated half
    is not. Both halves are validated against them, so a reference that
    drifts from what was staged fails its own corpus.
    """
    problems: list[str] = []
    for anchor in variant.meta.get("anchors", []):
        collection = anchor.get("collection")
        if "relation" in anchor:
            # Every copy, and the facts compared WHOLE. A relation is keyed on
            # source, type, target name and the declared discriminator, so two
            # assertions differing only in a fact value are two edges — which
            # is exactly the engaged-spare shape — and an anchor that matched
            # on the first three would certify either of them.
            matches = [
                r
                for r in records
                if r.get("record") == "relation_assertion"
                and r.get("collection") == collection
                and r.get("name") == anchor["object"]
                and r.get("type") == anchor["relation"]
                and r.get("target") == anchor["target"]
                and typed_equal(r.get("facts", {}), anchor["assertion_facts"])
            ]
            if not matches:
                problems.append(
                    f"anchor {anchor!r}: no {anchor['relation']!r} assertion "
                    f"from {anchor['object']!r} to {anchor['target']!r} with "
                    f"those facts in {collection!r}"
                )
            continue
        if "object" in anchor:
            # every copy, not the first: a corrupted duplicate hiding behind
            # a good one is the exact shape diff() was once blind to
            matches = [
                r
                for r in records
                if r.get("record") == "object"
                and r.get("collection") == collection
                and r.get("name") == anchor["object"]
            ]
            if not matches:
                problems.append(
                    f"anchor {anchor!r}: no object named {anchor['object']!r} "
                    f"in {collection!r}"
                )
            for record in matches:
                facts = record.get("facts") or {}
                if "names" in anchor:
                    if not typed_equal(record.get("names"), anchor["names"]):
                        problems.append(
                            f"anchor {anchor!r}: stream carries names "
                            f"{record.get('names')!r}, staging asserted "
                            f"{anchor['names']!r}"
                        )
                elif "fact" in anchor:
                    if anchor["fact"] not in facts:
                        problems.append(
                            f"anchor {anchor!r}: {anchor['fact']!r} is not "
                            "among the object's facts"
                        )
                    elif not typed_equal(facts[anchor["fact"]], anchor["value"]):
                        problems.append(
                            f"anchor {anchor!r}: stream carries "
                            f"{facts[anchor['fact']]!r}, staging asserted "
                            f"{anchor['value']!r}"
                        )
                elif anchor["absent_fact"] in facts:
                    problems.append(
                        f"anchor {anchor!r}: {anchor['absent_fact']!r} was "
                        "asserted absent at staging, and the stream carries it"
                    )
        elif "commit_objects" in anchor:
            commits = [
                r
                for r in records
                if r.get("record") == "commit" and r.get("collection") == collection
            ]
            if not commits:
                problems.append(f"anchor {anchor!r}: no commit for {collection!r}")
            for commit in commits:
                if not typed_equal(commit.get("objects"), anchor["commit_objects"]):
                    problems.append(
                        f"anchor {anchor!r}: commit carries "
                        f"objects={commit.get('objects')!r}, staging asserted "
                        f"{anchor['commit_objects']!r}"
                    )
        else:
            declines = [
                r
                for r in records
                if r.get("record") == "decline" and r.get("collection") == collection
            ]
            if not any(d.get("reason") == anchor["decline_reason"] for d in declines):
                problems.append(
                    f"anchor {anchor!r}: no decline with reason "
                    f"{anchor['decline_reason']!r} for {collection!r}"
                )
    return problems


def all_variants(root: Path | None = None) -> list[Variant]:
    """Every variant in the corpus, in a stable order."""
    root = root or CORPUS
    if not root.exists():
        return []
    found = []
    for meta_path in sorted(root.rglob("meta.json")):
        found.append(load_variant(meta_path.parent))
    return found


def coverage(variants: list[Variant]) -> dict:
    """What the corpus covers, as a statement rather than an implication.

    The corpus must state its own coverage (DESIGN 20), so this is the shape a
    reader gets: which collectors, which variants, which interface versions,
    which entries the lab cannot re-stage — the set a drift diff misses — and
    what the re-stageable ones need in order to be re-staged at all.

    That last dimension is not a nicety. `regenerable` is a boolean and the
    truth is not: storage/degraded IS re-stageable, but only on a guest
    carrying OpenZFS >= 2.3, because `zpool status -j` does not exist before
    it — the lab's own Ubuntu 24.04 image ships 2.2.2 and can produce no
    storage payload at all. A drift run on that guest regenerates the network
    variants, silently skips the storage one and presents a clean diff over a
    partial set, which is DESIGN 20's stated failure. So a variant may
    declare `regenerable_on`, and the report carries it beside the
    unregenerable list rather than leaving it to a note nothing reads.
    """
    collectors: dict[str, set[str]] = {}
    versions: dict[str, set[str]] = {}
    opened: dict[str, set[str]] = {}
    systems: set[str] = set()
    unregenerable: list[str] = []
    requires: dict[str, str] = {}
    for variant in variants:
        collector = variant.meta["collector"]
        collectors.setdefault(collector, set()).add(variant.meta["variant"])
        versions.setdefault(collector, set()).add(variant.meta["source_version"])
        opened.setdefault(collector, set()).update(variant.collections())
        systems.add(f"{variant.meta['os']} {variant.meta['os_version']}")
        if not variant.regenerable:
            unregenerable.append(variant.name)
        elif variant.meta.get("regenerable_on"):
            requires[variant.name] = variant.meta["regenerable_on"]
    return {
        "collectors": {k: sorted(v) for k, v in sorted(collectors.items())},
        "source_versions": {k: sorted(v) for k, v in sorted(versions.items())},
        # The dimension whose absence hid a whole collection. Until this line
        # existed the report named collectors, variant kinds, operating
        # systems and interface versions — every dimension except the one a
        # collection can go missing on — so nft-rules was served by the
        # reference, captured by nothing, and visible only to a person who
        # already knew to look. A collection is what a collector is FOR, and
        # a coverage report that cannot say which ones were exercised is
        # reporting success about what it never reached.
        "collections": {k: sorted(v) for k, v in sorted(opened.items())},
        # The dimension interface drift actually lives on: a corpus on one OS
        # cannot show a field that a different distribution's build removed.
        "operating_systems": sorted(systems),
        "unregenerable": sorted(unregenerable),
        # Regenerable, but not everywhere: the guest a re-stage needs.
        "regeneration_requires": dict(sorted(requires.items())),
        # The net named, so absence of a hole is never implied (DESIGN 20). A
        # shape here is wrong-detectable by neither a committed capture nor a
        # mutation operator — it is owned by the venue named, not by this tier.
        "named_residuals": dict(sorted(NAMED_RESIDUALS.items())),
        "variants": len(variants),
    }
