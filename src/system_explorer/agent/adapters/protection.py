"""protection subsystem: what the estate promises to keep, whether the
promise is built, whether it ran, and whether anything has ever been
restored from it.

Host-scoped and credential-free by construction. Three documents the
host already publishes for exactly this purpose — a rendered
declaration under /etc, receipts written by the jobs themselves, and an
hourly staleness verdict — are read as files and nothing else. The
repositories those jobs write to are deliberately NOT reached: reading
the off-site one needs the delete-capable credential that lives with
the maintenance identity, and an observer holding it would break the
estate's own invariant that a source cannot prune its own history. The
receipt and the proof record are the honest proxies.

Three collections, each owning one admin question:

- `targets` — Answers: what does the estate promise to protect, is each
  promise actually built, and has anything ever been restored from it.
  One row per declared target, carrying its class, its destinations,
  which hops are implemented and by which job, and the rungs of the
  recovery ladder a restore has been performed from — passing or not.
- `jobs` — Answers: did the protection actually run, and when did it
  last SUCCEED. One row per registered job: the staleness verdict, when
  that verdict was computed, the age it rests on, and the last run's
  result — "it ran and failed" and "it has not run" are different rows,
  never one silence.
- `destinations` — Answers: where do copies land, who may delete them,
  and what protects history from a compromised source. Facts only: the
  immutability statement is security prose written by a person and is
  carried verbatim, because paraphrasing it here would be inventing a
  security claim.

FIVE STATES, NOT TWO. Declared, implemented, running-green, proven by
restore, and TRIED-AND-FAILED are different things, and a job can be
green for months while its artifact is unusable — the estate calls this
invariant 5. So an unproven rung is a stated fact on the row, never an
absence: "last proven: never" beside a green job is the only honest
thing to say about most of them, and a green tick there would be this
product's own absence-as-health failure wearing a backup's clothes. A
restore somebody attempted and could not read back is the fifth state
and the worst of them; it is stated separately, because folding it into
"never tried" renders the alarming case as the ordinary one.

ONE ROW, ONE VINTAGE. The staleness verdict is recomputed hourly and
persists in /var/lib between runs, while the receipts are written by the
runs themselves. Mixing them silently — a checker's hour-old "it
succeeded" beside the exit status of the failure that has happened since
— makes a row contradict itself, so the receipt is the authority for
what the last run did and the verdict carries its own as-of stamp.

WHY SEVERITY IS SCOPED TO THE OWNER: the declaration is estate-wide and
identical on every host, so a coverage gap read locally would mint the
same finding once per host — one condition reported five times. The
facts therefore ride on every host that can read the manifest, while
the opinions fire only where the target's ownerHost matches this one.
The chain a target's protection actually forms (source captures,
receiver clones, off-site push) spans hosts by design and belongs to
the hub, which can see every hop at once; no host adapter can state a
weakest link it cannot see.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from .. import envelope as env
from ..rules.protection import job_opinions, target_opinions

MANIFEST = "/etc/homelab/protection-manifest.json"
STATUS = "/var/lib/homelab/protection/status.json"
RECEIPTS = "/var/lib/homelab/protection/receipts"

REFERENCE = [
    "cat /etc/homelab/protection-manifest.json",
    "cat /var/lib/homelab/protection/status.json",
    "ls -l /var/lib/homelab/protection/receipts",
    "cat /var/lib/homelab/protection/receipts/<job>.last.json",
    "cat /var/lib/homelab/protection/receipts/<job>.last-success.json",
    "systemctl status homelab-protection-staleness.service",
]

# What losing the data would mean, ordered. Where one job carries hops for
# more than one target, the job is graded by the WORST consequence it is
# responsible for: a join may sharpen a verdict, never soften one.
_CLASS_RANK = {"recreate": 0, "replicate": 1, "backup": 2}

_TARGET_GLOSSARY = {
    "Class": "What losing this data would mean, in the estate's own three words: backup is irreplaceable, replicate is replaceable at a cost in time, recreate is rebuilt from the estate's own definitions.",
    "Kind": "How the artifact is produced (a ZFS send, a file mirror, the application's own exporter) — orthogonal to the class, which is about the loss, not the method.",
    "OwnerHost": "The host that owns the authority and therefore runs the job; execution lives with the data, never on an admin machine.",
    "Source": "The dataset, path, container or domain the protected artifact is captured from.",
    "Retention": "The named retention policy, resolved by whoever administers the destination — a source cannot state how long its copies are kept.",
    "Cadence": "The frequency this target's capture is promised at, as a calendar expression. It is the contract a window is derived from and never the window itself: stating one is what makes a target expected at all, while the threshold a run is actually measured against is the job's separately registered MaxAgeSeconds, set from this promise plus deliberate grace.",
    "Destinations": "The logical destinations this target's copies are declared to reach, by name.",
    "IndependentDestinations": "Which of those destinations share no failure domain with this host or either site — the ones that decide whether the data survives losing the site, rather than merely surviving a disk.",
    "ImplementedHops": "Which of those destinations actually have a job behind them, estate-wide — the declaration's own account of what is built.",
    "HopImplementedBy": "Which job builds each implemented hop, and on which host — execution splits by verb, so the host holding the data is often not the host that pushes its off-site copy, and a hop claimed built with no job named is a claim with nothing to go and look at.",
    "UnimplementedHops": "Destinations this target declares and nothing implements: a promise with no job behind it, which is worse than an admitted gap because the target's other hops can look green while it holds.",
    "ProvenRungs": "The rungs of the recovery ladder a restore has actually been performed from and matched against an independent copy. It may name a rung that is not a destination at all — the source host's own snapshot history is the rung an operator reaches for first — so it is not the complement of UnprovenRungs.",
    "UnprovenRungs": "Declared destinations with no passing restore behind them — an attempt somebody made and could not match leaves its rung unproven too, so FailedProofRungs says which of these were actually tried.",
    "LastProvenAt": "When each rung was last proven, stated per rung and deliberately never collapsed into one date: the newest proof belongs to exactly one rung and says nothing about the others, and the rung reached for first survives neither the disk nor the site.",
    "FailedProofRungs": "Rungs where a restore was attempted, compared, and did not come back correct, with no passing proof since — tried and failed, which is a different and worse answer than never having tried.",
    "LastFailedProofAt": "The date of the newest failed attempt no later pass has answered; the record named by ProofRecord is where what went wrong is written down.",
    "ProofScope": "What each passing restore actually recovered, in the declaration's own words — a sampled restore is worth having and worth not reading as broader than it was, so the caveat travels beside the date rather than behind a link.",
    "ProofComparedAgainst": "The independent copy each passing restore was checked against; a restore compared against nothing is a download rather than a proof.",
    "ProofRecord": "Where the evidence for those attempts is written down — the commands, hashes and caveats behind each recorded proof, passing or failed.",
}

_JOB_GLOSSARY = {
    "Job": "The registered protection job this row describes, keyed by the target it protects where one exists and by the hop it carries where the two differ.",
    "Unit": "The systemd unit whose completion writes this job's receipt.",
    "State": "The staleness verdict in the checker's own words, as of the moment it last ran: ok means a success receipt was inside the job's declared window then, stale means it was not.",
    "Basis": "What the verdict was measured from — the last success receipt, or the job's registration when it has never succeeded at all.",
    "AgeSeconds": "How old the basis was when the checker last ran, in seconds; against MaxAgeSeconds this is the staleness arithmetic itself, and against CheckedAgeSeconds it is how long ago that arithmetic was done.",
    "MaxAgeSeconds": "The oldest a success may be before this job counts as stale, set from the protection contract rather than from the job's own timer.",
    "CheckedAt": "When the staleness checker last completed and rewrote its verdict; the state, basis and age beside it are what it saw at that moment rather than what is true now.",
    "CheckedAgeSeconds": "How long ago that was, measured now. A large value means the checker itself stopped writing rather than that nothing has changed — the document keeps its last verdict either way, which is how a dead timer renders as a green board.",
    "LastResult": "How the most recent run ended, in systemd's own vocabulary, taken from the receipt that run wrote — the checker's copy of the same answer can be an hour older, and a run that failed inside the window still leaves an unstale job.",
    "LastFinishedAt": "When the most recent run finished, successful or not, from the receipt it wrote.",
    "LastSuccessAt": "When this job most recently SUCCEEDED — kept in its own receipt so a later failure cannot overwrite the evidence of the last good run.",
    "ExitStatus": "The exit status the last run reported, as the receipt recorded it.",
    "ReceiptsUnobservable": "Why a receipt this job has already written could not be read, when one exists and will not open — the last run's facts are missing for that reason, and not because no run happened.",
    "TargetClass": "The class of the data this job protects, joined from the declaration — a job that has never succeeded matters differently for irreplaceable data than for derived state.",
    "TargetClassUnjoined": "Why this row carries no class: nothing in the declaration ties this job to a target, neither by name nor as the implementation of any hop on this host, so what losing its artifact would mean is unknown here rather than known to be small.",
    "ImplementsHops": "The declared hops this job is the stated implementation of, target by destination — the join that makes the class above credible, and the reason a job named for its hop rather than its target is not a job about nothing.",
}

_DESTINATION_GLOSSARY = {
    "Kind": "How artifacts reach this destination — a ZFS receive, or a restic repository over REST or S3.",
    "Independent": "Whether this destination shares no failure domain with any estate host or site; it is declared rather than inferred, because it is a fact about the world.",
    "Immutability": "How history here is protected from a compromised source, in the operator's own words — carried verbatim, because a paraphrase of a security property is a new claim.",
    "PruneAuthority": "Which identity may delete here; never a source host, or a source that malfunctions becomes a mirror of its own mistakes.",
}


def _load(path: str) -> tuple[object, str | None]:
    """(document, why-not). Absence and malformation are different
    answers: a host with no protection layer has no file, while a file
    that will not parse is a fault to state — collapsing them would let
    a half-written manifest read as "nothing is declared here"."""
    try:
        return json.loads(Path(path).read_text()), None
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError) as exc:
        return None, env.reason(f"{type(exc).__name__}: {exc}")


def _epoch_iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def job_joins(manifest: dict, hostname: str | None) -> tuple[dict, dict]:
    """(job key -> class, job key -> the hops it implements).

    A job is keyed by its target's name only WHERE ONE FITS. Where the
    hop's owner is not the target's owner — the source captures, another
    host pushes the copy off-site — the estate names the job for the HOP,
    and implementedBy ({destination -> "<host>:<job>"}) is where the
    declaration says so. Joining on name equality alone drops the class
    on exactly those jobs, and a dropped class silently grades a
    never-succeeded irreplaceable push as if its data were derived.

    The union of both routes, because neither covers the other: a target
    with an empty implementedBy still registers a job under its own name.
    Host-filtered, because a job key is only unique within a host —
    `sanoid` runs on more than one — so an unfiltered reverse map would
    import another host's class onto a local job of the same name.
    """
    classes: dict = {}
    hops: dict = {}
    for name, raw in sorted((manifest.get("targets") or {}).items()):
        if not isinstance(raw, dict):
            continue
        klass = raw.get("class")
        keys = [name]
        for destination, ref in sorted((raw.get("implementedBy") or {}).items()):
            host, _sep, job = str(ref).partition(":")
            if job and host == hostname:
                keys.append(job)
                hops.setdefault(job, []).append(f"{name} -> {destination}")
        for key in keys:
            held = classes.get(key)
            if _CLASS_RANK.get(str(klass), -1) > _CLASS_RANK.get(str(held), -1):
                classes[key] = klass
    return classes, hops


def target_facts(name: str, raw: dict, destinations: dict) -> dict:
    """One target's row from the manifest's own members. The hop split
    comes from the declaration itself (destinations minus the ones
    implementedBy names), which is the same computation the estate's
    checker publishes and does not need the checker to have run."""
    facts: dict = {}
    for fact, member in (("Class", "class"), ("Kind", "kind"),
                         ("OwnerHost", "ownerHost"), ("Source", "source"),
                         ("Retention", "retention"), ("Cadence", "cadence")):
        if raw.get(member):
            facts[fact] = raw[member]
    declared = [d for d in raw.get("destinations") or [] if isinstance(d, str)]
    if declared:
        facts["Destinations"] = declared
    # Independence is declared on the destination, not the target, and it
    # is what separates "a second copy" from "a copy that survives the
    # site" — the distinction the estate's own backup-class assertion
    # rests on, so the row states which of its hops carry it.
    independent = [d for d in declared
                   if (destinations.get(d) or {}).get("independent")]
    if independent:
        facts["IndependentDestinations"] = independent
    implemented = raw.get("implementedBy") or {}
    covered = [d for d in declared if d in implemented]
    if covered:
        facts["ImplementedHops"] = covered
        # The declaration names WHICH job builds each hop and on which
        # host, because the estate splits execution by verb. Keeping only
        # the key leaves a row asserting a hop is built with nothing to go
        # and look at, and leaves the job's own row unable to say what it
        # is for.
        facts["HopImplementedBy"] = [f"{d} -> {implemented[d]}" for d in covered]
    missing = [d for d in declared if d not in implemented]
    if missing:
        facts["UnimplementedHops"] = missing

    # Proofs are per RUNG: proving one says nothing about the others, and
    # a single date would hide exactly that — so the dates stay per rung
    # here too. Only the rungs the declaration names are expected: local
    # snapshot history is a rung a proof can cite but the manifest never
    # declares, so it counts when proven and is not invented as a gap when
    # it is not.
    proven = raw.get("lastProvenAt") or {}
    if not isinstance(proven, dict):
        proven = {}
    if proven:
        facts["ProvenRungs"] = sorted(proven)
        facts["LastProvenAt"] = [f"{rung}: {proven[rung]}"
                                 for rung in sorted(proven)]
    unproven = [d for d in declared if d not in proven]
    if unproven:
        facts["UnprovenRungs"] = unproven

    proofs = [proof for proof in raw.get("proofs") or []
              if isinstance(proof, dict)]
    # A restore ATTEMPTED and not matched is a third answer, never a
    # silence: the declaration records failed attempts deliberately and
    # only passes reach lastProvenAt, so reading proofs for their record
    # alone publishes the most alarming fact this inventory can hold as
    # the ordinary absence of one. A LATER pass on the same rung answers a
    # failure; an earlier one does not.
    failed: dict = {}
    for proof in proofs:
        if proof.get("result") != "fail":
            continue
        rung, at = str(proof.get("rung") or ""), str(proof.get("at") or "")
        if rung and at > str(proven.get(rung) or ""):
            failed[rung] = max(at, failed.get(rung, ""))
    if failed:
        facts["FailedProofRungs"] = sorted(failed)
        facts["LastFailedProofAt"] = max(failed.values())
    # The caveats travel with the date, verbatim and never parsed into a
    # verdict — the same treatment Immutability gets. Without them a
    # three-file sample of a multi-terabyte snapshot reads exactly like a
    # full restore, which is the over-reading the declaration's own
    # `scope` member exists to prevent.
    passed = [proof for proof in proofs if proof.get("result") == "pass"]
    scopes = sorted(f"{proof.get('rung')} {proof.get('at')}: {proof['scope']}"
                    for proof in passed if proof.get("scope"))
    if scopes:
        facts["ProofScope"] = scopes
    compared = sorted(
        f"{proof.get('rung')} {proof.get('at')}: {proof['comparedAgainst']}"
        for proof in passed if proof.get("comparedAgainst"))
    if compared:
        facts["ProofComparedAgainst"] = compared
    records = sorted({str(proof["record"]) for proof in proofs
                      if proof.get("record")})
    if records:
        facts["ProofRecord"] = records if len(records) > 1 else records[0]
    return facts


def job_facts(row: dict, receipts: dict, target_class: str | None,
              receipt_faults: dict | None = None,
              checked_at: object = None,
              hops: list | None = None) -> dict:
    """One job's row: the checker's verdict and when it was computed,
    plus what the job's own receipts say about its last run and its last
    SUCCESS — two files deliberately, so "it ran and failed" cannot
    overwrite the evidence that it once worked."""
    facts: dict = {"Job": row.get("job")}
    last = receipts.get("last") or {}
    success = receipts.get("last-success") or {}
    for fact, member in (("State", "state"), ("Basis", "basis"),
                         ("AgeSeconds", "ageSeconds"),
                         ("MaxAgeSeconds", "maxAgeSeconds")):
        value = row.get(member)
        if value is not None and value != "none":
            facts[fact] = value
    # The verdict's own age. status.json changes only when the checker
    # COMPLETES — its script is `set -uo pipefail` with no -e, so a failed
    # mktemp or write leaves the last good verdict in place while the unit
    # still exits 0, as does a masked timer — so the three facts above are
    # what the checker saw at this stamp, never what is true now. Computed
    # here so the rule stays clock-free (the SMART snapshot precedent).
    if isinstance(checked_at, (int, float)) and not isinstance(checked_at, bool):
        facts["CheckedAt"] = _epoch_iso(checked_at)
        facts["CheckedAgeSeconds"] = max(0, int(time.time() - checked_at))
    if last.get("unit"):
        facts["Unit"] = last["unit"]
    # One run, one vintage. The run writes its own result; the checker's
    # lastResult is a copy of this same member read up to an hour earlier
    # (hourly, plus five minutes of jitter), so a run that failed since
    # the last check would otherwise read "success" beside the finish time
    # and exit status of the failure — a row contradicting itself, with
    # the warn the two-receipt design exists to produce suppressed. The
    # receipt is the authority; the status row is the fallback for a
    # receipt this host cannot open. "unknown" mirrors the ExitStatus
    # filter below: it is the receipt writer's filler, not an outcome.
    result = last.get("result")
    if result in (None, "unknown"):
        result = row.get("lastResult")
    if result not in (None, "none", "unknown"):
        facts["LastResult"] = result
    if last.get("finishedAt"):
        facts["LastFinishedAt"] = last["finishedAt"]
    if last.get("exitStatus") not in (None, "unknown"):
        facts["ExitStatus"] = last["exitStatus"]
    if success.get("finishedAt"):
        facts["LastSuccessAt"] = success["finishedAt"]
    if receipt_faults:
        # The run happened and left a record this host cannot read.
        # Silence here publishes the row of a job that never ran.
        facts["ReceiptsUnobservable"] = "; ".join(
            f"{name}: {why}" for name, why in sorted(receipt_faults.items()))
    if target_class:
        facts["TargetClass"] = target_class
    else:
        # No class is UNJOINED, not "no class": silence here grades the
        # job as if the declaration had called its data replaceable.
        facts["TargetClassUnjoined"] = (
            "no declared target names this job — not by name, and not in any"
            " implementedBy hop on this host — so what losing its artifact"
            " would mean is unknown, and the verdict below is graded as if it"
            " were not irreplaceable")
    if hops:
        facts["ImplementsHops"] = list(hops)
    return facts


def destination_facts(raw: dict) -> dict:
    facts: dict = {}
    for fact, member in (("Kind", "kind"), ("PruneAuthority", "pruneAuthority")):
        if raw.get(member):
            facts[fact] = raw[member]
    if raw.get("independent") is not None:
        facts["Independent"] = bool(raw["independent"])
    if raw.get("immutability"):
        # Verbatim, never summarised: this sentence is a security claim
        # a person wrote and corrected, and a paraphrase would be SE
        # making a security claim of its own.
        facts["Immutability"] = raw["immutability"]
    return facts


class Adapter:
    subsystem = "protection"

    def collections(self) -> list[str]:
        return ["targets", "jobs", "destinations"]

    async def capability(self) -> dict:
        manifest, problem = _load(MANIFEST)
        if problem:
            return {"available": False, "reason": (
                f"{MANIFEST} could not be read: {problem}")}
        if not isinstance(manifest, dict):
            return {"available": False, "reason": (
                f"no protection manifest at {MANIFEST} — this host declares"
                " no protection inventory (the NixOS module renders it from"
                " homelab.protection.targets)")}
        unavailable: dict = {}
        status, status_problem = _load(STATUS)
        if status_problem:
            unavailable["jobs"] = f"{STATUS} could not be read: {status_problem}"
        elif not isinstance(status, dict):
            # NOT "nothing is protected here". The same NixOS conditional
            # renders the manifest and installs the checker, so a manifest
            # this readable proves the checker is installed: a missing
            # verdict is one nobody has written yet (a fresh deploy, a
            # wiped /var/lib) or one that is not running. Unobservable,
            # never absent — and the two discriminators are stated rather
            # than inferred, because what this host owes is in the
            # document already in hand.
            owed = sorted(
                name for name, raw in (manifest.get("targets") or {}).items()
                if isinstance(raw, dict) and raw.get("cadence")
                and raw.get("ownerHost") == env.HOST.get("hostname"))
            seen = registered_jobs()
            unavailable["jobs"] = (
                f"no staleness verdict at {STATUS}: nothing has written one"
                " here, so whether this host's protection ran is unobservable,"
                " not absent — the declaration that renders the manifest also"
                " installs the checker."
                f" Targets this host owns with a cadence:"
                f" {env.reason(', '.join(owed) or 'none', 200)}."
                f" Jobs that have ever written a receipt here:"
                f" {env.reason(', '.join(seen) or 'none', 200)}."
                " Check systemctl status homelab-protection-staleness.service")
        out: dict = {"available": True,
                     "collections": [c for c in self.collections()
                                     if c not in unavailable]}
        if unavailable:
            out["unavailable_collections"] = unavailable
        return out

    def fact_glossary(self, collection: str) -> dict:
        return {"targets": _TARGET_GLOSSARY, "jobs": _JOB_GLOSSARY,
                "destinations": _DESTINATION_GLOSSARY}.get(collection, {})

    def _source(self, collection: str, unjudged_owner: str | None = None) -> dict:
        method = {"targets": f"read {MANIFEST}",
                  "jobs": f"read {STATUS} + {RECEIPTS}",
                  "destinations": f"read {MANIFEST}"}[collection]
        notes = None
        if collection == "targets":
            notes = ["Opinions are stated only where this host is the"
                     " target's ownerHost: the declaration is identical on"
                     " every host, so an estate-wide gap judged locally"
                     " would be one condition reported once per host."]
            if unjudged_owner:
                # An object carrying no opinions because none were
                # EVALUATED renders exactly like one judged and found
                # clean. The rows keep that distinction (opinions=None
                # makes no severity claim); without this note the opened
                # object throws it away and a reader has to diff OwnerHost
                # against the envelope's own hostname to recover it.
                notes.append(
                    f"NOT JUDGED HERE: this target is owned by"
                    f" {unjudged_owner}, so no verdict was formed on this"
                    f" host. An object carrying no opinions because none"
                    f" were evaluated is not an object judged healthy.")
        return env.source("homelab-protection", "homelab protection surfaces",
                          REFERENCE, method=method, notes=notes)

    def _receipts_for(self, job: str) -> tuple[dict, dict]:
        """(documents, why-not per receipt). A receipt that exists and
        will not open is not a receipt that was never written: dropping
        the reason here would let a corrupt or unreadable last-success
        render byte-identically to a job that has never succeeded, which
        is the one distinction this collection exists to keep."""
        out: dict = {}
        faults: dict = {}
        for suffix in ("last", "last-success"):
            name = f"{job}.{suffix}.json"
            document, problem = _load(f"{RECEIPTS}/{name}")
            if isinstance(document, dict):
                out[suffix] = document
            elif problem is not None:
                faults[name] = problem
            elif document is not None:
                faults[name] = env.reason(
                    f"the receipt parsed as {type(document).__name__},"
                    " not an object")
        return out, faults

    def _manifest(self) -> dict:
        document, problem = _load(MANIFEST)
        if problem is not None:
            raise RuntimeError(f"{MANIFEST}: {problem}")
        if not isinstance(document, dict):
            raise RuntimeError(f"no protection manifest at {MANIFEST}")
        return document

    def _status(self) -> dict:
        document, problem = _load(STATUS)
        if problem is not None:
            raise RuntimeError(f"{STATUS}: {problem}")
        if not isinstance(document, dict):
            raise RuntimeError(f"no staleness verdict at {STATUS}")
        return document

    @staticmethod
    def _owned_opinions(facts: dict) -> list[dict]:
        """Verdicts only where this host owns the target — see the module
        docstring: the declaration is identical estate-wide, so judging it
        locally would mint one finding per host for one condition."""
        if facts.get("OwnerHost") != env.HOST.get("hostname"):
            return []
        return target_opinions(facts)

    def _target_items(self) -> list[dict]:
        manifest = self._manifest()
        items = []
        destinations = manifest.get("destinations") or {}
        for name, raw in sorted((manifest.get("targets") or {}).items()):
            if not isinstance(raw, dict):
                continue
            facts = target_facts(name, raw, destinations)
            owned = facts.get("OwnerHost") == env.HOST.get("hostname")
            items.append(env.item_summary(
                f"target:{name}", "protection-target", name, facts,
                opinions=self._owned_opinions(facts) if owned else None,
                healthy="ok"))
        return items

    def _job_items(self) -> list[dict]:
        status = self._status()
        checked_at = status.get("checkedAt")
        classes, hops = job_joins(self._manifest(), env.HOST.get("hostname"))
        items = []
        for row in status.get("jobs") or []:
            if not isinstance(row, dict) or not row.get("job"):
                continue
            name = str(row["job"])
            documents, faults = self._receipts_for(name)
            facts = job_facts(row, documents, classes.get(name),
                              receipt_faults=faults, checked_at=checked_at,
                              hops=hops.get(name))
            items.append(env.item_summary(
                f"job:{name}", "protection-job", name, facts,
                opinions=job_opinions(facts)))
        return items

    def _destination_items(self) -> list[dict]:
        manifest = self._manifest()
        items = []
        for name, raw in sorted((manifest.get("destinations") or {}).items()):
            if not isinstance(raw, dict):
                continue
            # No opinions, deliberately: whether a destination's posture
            # is adequate is a judgement about prose this adapter cannot
            # parse, and the estate's own assertions already refuse a
            # backup target with no independent destination.
            items.append(env.item_summary(
                f"destination:{name}", "protection-destination", name,
                destination_facts(raw), opinions=[], healthy=None))
        return items

    @env.single_flight
    async def acquire(self, collection: str) -> list[dict]:
        if collection == "targets":
            return self._target_items()
        if collection == "jobs":
            return self._job_items()
        if collection == "destinations":
            return self._destination_items()
        raise env.UnknownCollection(collection)

    async def collect(self, collection: str, query: dict, limit: int | None,
                      cursor: str | None) -> dict:
        fetched = await self.acquire(collection)
        items = env.apply_fact_filters(fetched, query)
        page, applied, next_cursor, total = env.paginate(items, limit, cursor)
        return env.collection_page(self.subsystem, collection,
                                   self._source(collection),
                                   page, applied, next_cursor,
                                   requested_limit=limit, total=total,
                                   filters=query or None)

    async def get_object(self, collection: str, object_id: str) -> dict:
        matches = [item for item in await self.acquire(collection)
                   if item["id"] == object_id]
        if not matches:
            raise env.UnknownObject(object_id)
        item = matches[0]
        # The opened object carries every verdict this host is entitled to
        # state — including the info-level ones a row deliberately leaves
        # out (rule 14) — and where it is entitled to none, its source
        # says so rather than reading clean.
        owner = item["facts"].get("OwnerHost")
        unjudged = ((owner or "a host this manifest does not name")
                    if collection == "targets"
                    and owner != env.HOST.get("hostname") else None)
        opinions = (self._owned_opinions(item["facts"])
                    if collection == "targets" else
                    job_opinions(item["facts"]) if collection == "jobs"
                    else [])
        return env.observation(
            self.subsystem,
            env.obj_ref(item["id"], item["type"], item["native_id"]),
            self._source(collection, unjudged), item["facts"],
            opinions=opinions or None,
            evidence_ref=env.evidence_ref(self.subsystem, collection,
                                          item["id"]))

    async def get_evidence(self, collection: str, object_id: str) -> dict:
        """The documents the row was folded from, membership checked in
        those same documents — a job's evidence carries both receipts,
        because the pair IS the distinction between a run that failed
        and a job that has never run."""
        if collection not in self.collections():
            raise env.UnknownCollection(collection)
        manifest = self._manifest()
        payload: object
        if collection == "jobs":
            status = self._status()
            name = object_id.partition(":")[2]
            known = {str(row.get("job")) for row in status.get("jobs") or []
                     if isinstance(row, dict) and row.get("job")}
            if name not in known:
                raise env.UnknownObject(object_id)
            documents, faults = self._receipts_for(name)
            payload = {STATUS: status, RECEIPTS: documents}
            if faults:
                # Evidence must be able to show its object: a receipt that
                # would not open is shown as itself, never as a gap in the
                # pair the row rests on.
                payload[f"{RECEIPTS} (unreadable)"] = faults
        else:
            # The same predicate the collection is built from: an entry
            # that is not an object is no object at all, and evidence that
            # vouches for an id get_object refuses cannot show its object.
            section = manifest.get(
                "targets" if collection == "targets" else "destinations")
            name = object_id.partition(":")[2]
            if not isinstance(section, dict) \
                    or not isinstance(section.get(name), dict):
                raise env.UnknownObject(object_id)
            payload = {MANIFEST: manifest}
        return {"object_id": object_id, "captured_at": env.utc_now(),
                "interface": "homelab protection surfaces", "payload": payload}


def registered_jobs() -> list[str]:
    """Receipt file stems on this host: what has ever written one. The
    directory listing is the only place a job that vanished from the
    declaration still leaves a trace, and it is what lets a missing
    staleness verdict be stated as unwritten rather than as nothing owed."""
    try:
        names = os.listdir(RECEIPTS)
    except OSError:
        return []
    return sorted({name.split(".")[0] for name in names
                   if name.endswith(".json")})
