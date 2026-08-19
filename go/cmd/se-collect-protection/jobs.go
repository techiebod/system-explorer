package main

import (
	"math"
	"strconv"
)

// TargetClassUnjoined's text, verbatim from the reference. It is a FACT VALUE
// that travels the wire, so a port that reworded it would disagree with the
// reference on a row no committed capture stages — and the sentence is the
// whole point of the fact: silence here would grade the job as if the
// declaration had called its data replaceable.
const targetClassUnjoined = "no declared target names this job — not by name, and not in any" +
	" implementedBy hop on this host — so what losing its artifact" +
	" would mean is unknown, and the verdict below is graded as if it" +
	" were not irreplaceable"

// jobRows answers: did the protection actually run, and when did it last
// SUCCEED. One row per REGISTERED job — enumerated from the verdict's own job
// list and never from a directory walk, so a receipt left behind by a job the
// declaration has dropped does not mint a row.
//
// ONE ROW, ONE VINTAGE. The staleness verdict is recomputed hourly and
// persists between runs, while the receipts are written by the runs
// themselves. Mixing them silently — a checker's hour-old "it succeeded"
// beside the exit status of the failure that has happened since — makes a row
// contradict itself, so the receipt is the authority for what the last run did
// and the verdict carries its own as-of stamp.
func jobRows(src source) ([]row, error) {
	// The manifest first, because the absence of the whole interface is a
	// reading and the host pin is not: a host with no protection layer must
	// decline rather than report a capture as broken.
	manifest, err := readManifest(src)
	if err != nil {
		return nil, err
	}
	// The host identity is required HERE and by neither of the other two
	// collections, because this is where it changes an answer: which
	// implementedBy hops count as local decides a job's TargetClass and its
	// ImplementsHops. targets and destinations are pure declaration and read
	// identically on every host, so a capture that staged no hostname still
	// serves them — the reference needs it for all three only because its
	// opinions are scoped by it, and no opinion travels this stream.
	hostname, err := src.hostname()
	if err != nil {
		return nil, err
	}
	status, err := readStatus(src, manifest, hostname)
	if err != nil {
		return nil, err
	}
	classes, hops := jobJoins(manifest, hostname)
	targets := manifest.get("targets")

	checkedAt := status.get("checkedAt")
	var rows []row
	for _, entry := range arrayItems(status.get("jobs")) {
		if !entry.isObject() || !entry.get("job").truthy() {
			continue
		}
		name := entry.get("job").pyStr()
		documents, faults, err := receipts(src, name)
		if err != nil {
			return nil, err
		}
		// The job's own declared subject outranks the inference: it is stated
		// beside the job, where jobJoins' name-equality and implementedBy
		// routes are this collector guessing from the other end. Only fall
		// back where nothing is declared.
		declared := entry.get("target")
		var joined *value
		if declared.isString() && declared.truthy() {
			joined = targets.get(declared.text).get("class")
		}
		if !joined.truthy() {
			joined = classes[name]
		}
		rows = append(rows, row{
			name:  name,
			facts: jobFacts(src, entry, documents, faults, joined, checkedAt, hops[name]),
		})
	}
	return rows, nil
}

// hop is one declared hop a job is the stated implementation of: the target
// whose data it moves and the destination it moves it to.
type hop struct{ target, destination string }

// What losing the data would mean, ordered. Where one job carries hops for
// more than one target, the job is graded by the WORST consequence it is
// responsible for: a join may sharpen a verdict, never soften one.
var classRank = map[string]int{"recreate": 0, "replicate": 1, "backup": 2}

func rankOf(v *value) int {
	if v == nil {
		// `_CLASS_RANK.get(str(None), -1)`: an unheld class ranks below every
		// declared one, so the first class to arrive always wins.
		return -1
	}
	rank, ok := classRank[v.pyStr()]
	if !ok {
		return -1
	}
	return rank
}

// jobJoins answers (job key -> class, job key -> the hops it implements).
//
// A job is keyed by its target's name only WHERE ONE FITS. Where the hop's
// owner is not the target's owner — the source captures, another host pushes
// the copy off-site — the estate names the job for the HOP, and implementedBy
// ({destination -> "<host>:<job>"}) is where the declaration says so. Joining
// on name equality alone drops the class on exactly those jobs, and a dropped
// class silently grades a never-succeeded irreplaceable push as if its data
// were derived.
//
// The union of both routes, because neither covers the other: a target with an
// empty implementedBy still registers a job under its own name. Host-filtered,
// because a job key is only unique within a host — a sweep job runs on more
// than one — so an unfiltered reverse map would import another host's class
// onto a local job of the same name.
func jobJoins(manifest *value, hostname string) (map[string]*value, map[string][]hop) {
	classes := map[string]*value{}
	hops := map[string][]hop{}
	targets := manifest.get("targets")
	for _, name := range targets.sortedKeys() {
		raw := targets.get(name)
		if !raw.isObject() {
			continue
		}
		class := raw.get("class")
		keys := []string{name}
		implemented := raw.get("implementedBy")
		for _, destination := range implemented.sortedKeys() {
			host, job := splitRef(implemented.get(destination))
			if job != "" && host == hostname {
				keys = append(keys, job)
				hops[job] = append(hops[job], hop{target: name, destination: destination})
			}
		}
		for _, key := range keys {
			if rankOf(class) > rankOf(classes[key]) {
				classes[key] = class
			}
		}
	}
	return classes, hops
}

// jobFacts is one job's row: the checker's verdict and when it was computed,
// plus what the job's own receipts say about its last run and its last
// SUCCESS.
func jobFacts(src source, entry *value, documents map[string]*value, faults map[string]string,
	targetClass, checkedAt *value, implements []hop) *value {
	facts := newObject()
	facts.set("Job", entry.get("job"))

	last := documents["last"]
	success := documents["last-success"]

	// The checker's verdict, in its own words and at its own vintage. "none"
	// is the checker's filler for a member it has no answer for, not a
	// reading, so it is omitted rather than published as a value.
	for _, pair := range [...][2]string{
		{"State", "state"}, {"Basis", "basis"},
		{"AgeSeconds", "ageSeconds"}, {"MaxAgeSeconds", "maxAgeSeconds"},
	} {
		member := entry.get(pair[1])
		if member.stated() && !member.isText("none") {
			facts.set(pair[0], member)
		}
	}

	// The verdict's own age. status.json changes only when the checker
	// COMPLETES — its script is `set -uo pipefail` with no -e, so a failed
	// mktemp or write leaves the last good verdict in place while the unit
	// still exits 0, as does a masked timer — so the three facts above are
	// what the checker saw at this stamp, never what is true now. A large
	// CheckedAgeSeconds means the checker itself stopped writing rather than
	// that nothing has changed, which is how a dead timer renders as a green
	// board.
	if checkedAt != nil && checkedAt.kind == jsonNumber {
		if seconds, ok := numberSeconds(checkedAt); ok {
			facts.set("CheckedAt", stringValue(epochISO(seconds)))
			age := int64(src.now() - seconds) // int(): truncated toward zero, as Python's is
			if age < 0 {
				age = 0
			}
			facts.set("CheckedAgeSeconds", intValue(age))
		}
	}

	if unit := last.get("unit"); unit.truthy() {
		facts.set("Unit", unit)
	}

	// ONE RUN, ONE VINTAGE. The run writes its own result; the checker's
	// lastResult is a copy of the same member read up to an hour earlier
	// (hourly, plus five minutes of jitter), so a run that failed since the
	// last check would otherwise read "success" beside the finish time and
	// exit status of the failure — a row contradicting itself, with the warn
	// the two-receipt design exists to produce suppressed. The receipt is the
	// authority; the status row is the fallback for a receipt this host cannot
	// open. "unknown" mirrors the ExitStatus filter below: it is the receipt
	// writer's filler, not an outcome.
	result := last.get("result")
	if !result.stated() || result.isText("unknown") {
		result = entry.get("lastResult")
	}
	if result.stated() && !result.isText("none") && !result.isText("unknown") {
		facts.set("LastResult", result)
	}
	if finished := last.get("finishedAt"); finished.truthy() {
		facts.set("LastFinishedAt", finished)
	}
	if exit := last.get("exitStatus"); exit.stated() && !exit.isText("unknown") {
		facts.set("ExitStatus", exit)
	}
	// Its own receipt, so a later failure cannot overwrite the evidence of the
	// last good run.
	if finished := success.get("finishedAt"); finished.truthy() {
		facts.set("LastSuccessAt", finished)
	}
	if text := receiptsUnobservable(faults); text != "" {
		// The run happened and left a record this host cannot read. Silence
		// here publishes the row of a job that never ran.
		facts.set("ReceiptsUnobservable", stringValue(text))
	}

	// THREE answers, not two. The checker states `target` per job: a name is
	// the job's own subject (authoritative — it is declared beside the job,
	// where the joins above are inference); an explicit null is the
	// declaration SAYING there is no single subject (a scrub is pool-scoped,
	// and no target's class applies to it); and the member being absent
	// entirely is a host that predates the field, where the inference is all
	// there is. Folding the middle case into the last would report a stated
	// answer as a failed join, which is the same lie in the other direction.
	declaredTarget := entry.get("target")
	statedNoSubject := entry.has("target") && !declaredTarget.stated()
	if declaredTarget.isString() && declaredTarget.truthy() {
		facts.set("Target", declaredTarget)
	}
	switch {
	case targetClass.truthy():
		facts.set("TargetClass", targetClass)
	case statedNoSubject:
		facts.set("TargetNotScoped", boolValue(true))
	default:
		// No class is UNJOINED, not "no class": silence here grades the job as
		// if the declaration had called its data replaceable.
		facts.set("TargetClassUnjoined", stringValue(targetClassUnjoined))
	}

	if len(implements) > 0 {
		// The join that makes the class above credible, and the reason a job
		// named for its hop rather than its target is not a job about nothing.
		items := make([]*value, 0, len(implements))
		for _, one := range implements {
			carried := newObject()
			carried.set("Target", stringValue(one.target))
			carried.set("Destination", stringValue(one.destination))
			items = append(items, carried)
		}
		facts.set("ImplementsHops", newArray(items))
	}
	return facts
}

// numberSeconds parses a unix time the checker wrote. The token is kept
// everywhere a number is PASSED THROUGH; this is the one place a number is
// consumed as arithmetic, and the result reaches only a formatted timestamp
// and a computed age — never the wire as itself.
func numberSeconds(v *value) (float64, bool) {
	seconds, err := strconv.ParseFloat(v.text, 64)
	if err != nil {
		return 0, false
	}
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return 0, false
	}
	return seconds, true
}
