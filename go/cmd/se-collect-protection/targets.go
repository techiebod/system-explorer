package main

import (
	"sort"
	"strings"
)

// targetRows answers: what does the estate promise to protect, is each promise
// actually built, and has anything ever been restored from it. One row per
// declared target, from the manifest's own members and arithmetic on them —
// the hop split is destinations minus the ones implementedBy names, which is
// the same computation the estate's checker publishes and does not need the
// checker to have run.
func targetRows(src source) ([]row, error) {
	manifest, err := readManifest(src)
	if err != nil {
		return nil, err
	}
	destinations := manifest.get("destinations")
	targets := manifest.get("targets")
	var rows []row
	for _, name := range targets.sortedKeys() {
		raw := targets.get(name)
		if !raw.isObject() {
			// An entry that is not an object is no target at all — the same
			// predicate the evidence document is checked against, so an id
			// this collection publishes is one the object verb can open.
			continue
		}
		rows = append(rows, row{name: name, facts: targetFacts(raw, destinations)})
	}
	return rows, nil
}

// splitRef reads `"<host>:<job>"` as its two parts; an unqualified name comes
// back with no host.
//
// The manifest qualifies a hop's implementation by host because execution
// splits by verb — the host holding the data is routinely not the host that
// pushes its off-site copy. An unqualified reference names NO host, which is a
// different thing from naming this one: it is left unattributed rather than
// assumed local, because assuming would let one host claim to implement
// another's hop.
func splitRef(ref *value) (host, job string) {
	text := ref.pyStr()
	before, after, found := strings.Cut(text, ":")
	if found && after != "" {
		return before, after
	}
	return "", text
}

// targetFacts is one target's row.
func targetFacts(raw, destinations *value) *value {
	facts := newObject()
	for _, pair := range [...][2]string{
		{"Class", "class"}, {"Kind", "kind"}, {"OwnerHost", "ownerHost"},
		{"Source", "source"}, {"Retention", "retention"}, {"Cadence", "cadence"},
	} {
		if member := raw.get(pair[1]); member.truthy() {
			facts.set(pair[0], member)
		}
	}

	// The declared destinations, string members only: a hop this collector
	// cannot name is a hop it cannot go and look at.
	var declared []string
	for _, item := range arrayItems(raw.get("destinations")) {
		if item.isString() {
			declared = append(declared, item.text)
		}
	}
	if len(declared) > 0 {
		facts.set("Destinations", stringArray(declared))
	}

	// Independence is declared on the DESTINATION, not the target, and it is
	// what separates "a second copy" from "a copy that survives the site" —
	// the distinction the estate's own backup-class assertion rests on, so the
	// row states which of its hops carry it.
	var independent []string
	for _, name := range declared {
		if destinations.get(name).get("independent").truthy() {
			independent = append(independent, name)
		}
	}
	if len(independent) > 0 {
		facts.set("IndependentDestinations", stringArray(independent))
	}

	implemented := raw.get("implementedBy")
	var covered, missing []string
	for _, name := range declared {
		if implemented.has(name) {
			covered = append(covered, name)
		} else {
			missing = append(missing, name)
		}
	}
	if len(covered) > 0 {
		facts.set("ImplementedHops", stringArray(covered))
		// The declaration names WHICH job builds each hop and on which host,
		// because the estate splits execution by verb. Keeping only the key
		// leaves a row asserting a hop is built with nothing to go and look
		// at, and leaves the job's own row unable to say what it is for. The
		// host is stated separately from the job because a job name is unique
		// only within a host.
		hops := make([]*value, 0, len(covered))
		for _, name := range covered {
			host, job := splitRef(implemented.get(name))
			hop := newObject()
			hop.set("Destination", stringValue(name))
			if host != "" {
				hop.set("Host", stringValue(host))
			}
			hop.set("Job", stringValue(job))
			hops = append(hops, hop)
		}
		facts.set("HopImplementedBy", newArray(hops))
	}
	if len(missing) > 0 {
		// A promise with no job behind it, which is worse than an admitted
		// gap because the target's other hops can look green while it holds.
		facts.set("UnimplementedHops", stringArray(missing))
	}

	// Proofs are per RUNG: proving one says nothing about the others, and a
	// single date would hide exactly that — so the dates stay per rung here
	// too. Only the rungs the declaration names are expected: local snapshot
	// history is a rung a proof can cite but the manifest never declares, so
	// it counts when proven and is not invented as a gap when it is not.
	proven := raw.get("lastProvenAt")
	if !proven.isObject() {
		proven = nil
	}
	provenRungs := proven.sortedKeys()
	if len(provenRungs) > 0 {
		facts.set("ProvenRungs", stringArray(provenRungs))
		dated := make([]string, 0, len(provenRungs))
		for _, rung := range provenRungs {
			dated = append(dated, rung+": "+proven.get(rung).pyStr())
		}
		facts.set("LastProvenAt", stringArray(dated))
	}
	var unproven []string
	for _, name := range declared {
		if !proven.has(name) {
			unproven = append(unproven, name)
		}
	}
	if len(unproven) > 0 {
		facts.set("UnprovenRungs", stringArray(unproven))
	}

	var proofs []*value
	for _, item := range arrayItems(raw.get("proofs")) {
		if item.isObject() {
			proofs = append(proofs, item)
		}
	}

	// A restore ATTEMPTED and not matched is a third answer, never a silence:
	// the declaration records failed attempts deliberately and only passes
	// reach lastProvenAt, so reading proofs for their record alone publishes
	// the most alarming fact this inventory can hold as the ordinary absence
	// of one. A LATER pass on the same rung answers a failure; an earlier one
	// does not.
	failed := map[string]string{}
	for _, proof := range proofs {
		if !proof.get("result").isText("fail") {
			continue
		}
		rung, at := orEmpty(proof.get("rung")), orEmpty(proof.get("at"))
		if rung != "" && at > orEmpty(proven.get(rung)) {
			if at > failed[rung] {
				failed[rung] = at
			}
		}
	}
	if len(failed) > 0 {
		rungs := make([]string, 0, len(failed))
		newest := ""
		for rung, at := range failed {
			rungs = append(rungs, rung)
			if at > newest {
				newest = at
			}
		}
		sort.Strings(rungs)
		facts.set("FailedProofRungs", stringArray(rungs))
		facts.set("LastFailedProofAt", stringValue(newest))
	}

	// The caveats travel with the date, verbatim and never parsed into a
	// verdict — the same treatment Immutability gets. Without them a
	// three-file sample of a multi-terabyte snapshot reads exactly like a full
	// restore, which is the over-reading the declaration's own `scope` member
	// exists to prevent.
	var scopes, compared []string
	records := map[string]bool{}
	for _, proof := range proofs {
		if proof.get("result").isText("pass") {
			prefix := proof.get("rung").pyStr() + " " + proof.get("at").pyStr() + ": "
			if scope := proof.get("scope"); scope.truthy() {
				scopes = append(scopes, prefix+scope.pyStr())
			}
			if against := proof.get("comparedAgainst"); against.truthy() {
				compared = append(compared, prefix+against.pyStr())
			}
		}
		// The record is where the evidence is written down for EVERY attempt,
		// passing or failed — the failed one is the attempt somebody most
		// needs to go and read.
		if record := proof.get("record"); record.truthy() {
			records[record.pyStr()] = true
		}
	}
	sort.Strings(scopes)
	sort.Strings(compared)
	if len(scopes) > 0 {
		facts.set("ProofScope", stringArray(scopes))
	}
	if len(compared) > 0 {
		facts.set("ProofComparedAgainst", stringArray(compared))
	}
	if len(records) > 0 {
		names := make([]string, 0, len(records))
		for name := range records {
			names = append(names, name)
		}
		sort.Strings(names)
		if len(names) == 1 {
			facts.set("ProofRecord", stringValue(names[0]))
		} else {
			facts.set("ProofRecord", stringArray(names))
		}
	}
	return facts
}

// arrayItems is `raw.get(member) or []`: a member that is not an array
// contributes nothing, which is the iteration the reference performs.
func arrayItems(v *value) []*value {
	if v == nil || v.kind != jsonArray {
		return nil
	}
	return v.items
}

// orEmpty is `str(value or "")`: the guard the failed-proof comparison uses
// before it compares two dates as text.
func orEmpty(v *value) string {
	if !v.truthy() {
		return ""
	}
	return v.pyStr()
}
