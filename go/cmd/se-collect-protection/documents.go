package main

import (
	"fmt"
	"sort"
)

// The two documents every collection rests on, read through the one seam and
// turned into the three answers a caller can act on: the document, a decline,
// or an inability to run.

// readManifest is the rendered declaration — what the estate promises to
// protect. Both collections that are pure declaration (targets, destinations)
// and the join that grades a job's class come from it.
func readManifest(src source) (*value, error) {
	if src.interfaceAbsent() {
		reason := declineNoManifest
		return nil, &reason
	}
	document, whyNot, err := src.load(manifestPath)
	if err != nil {
		return nil, err
	}
	if whyNot != "" {
		// The file is there and will not open. Unavailable rather than
		// absent, and the difference is the whole point: absent commits and
		// retires, and a half-written render must never retire an estate's
		// declared targets. The reason itself stays on stderr — it is a
		// library's phrasing of a parse failure over an estate's own
		// document, and the decline detail travels to a hub.
		reason := declineManifestUnreadable
		return nil, fmt.Errorf("%s: %s: %w", manifestPath, whyNot, &reason)
	}
	if !document.isObject() {
		// No document, or one that is not a mapping: this host declares no
		// protection inventory, which is the same reading as no file at all —
		// the reference's own capability() puts both in this branch. Absent,
		// so it commits and can retire.
		reason := declineNoManifest
		return nil, &reason
	}
	return document, nil
}

// readStatus is the hourly staleness verdict, and it belongs to the jobs
// collection alone. A missing one is NOT "nothing is protected here": the same
// declaration that renders the manifest installs the checker, so a manifest
// this readable proves the checker is installed and a missing verdict is one
// nobody has written yet or one that is not running. Unobservable, never
// absent — which is why every branch below declines `unavailable` and commits
// nothing, leaving the job rows standing rather than retiring them over a
// checker that stopped.
func readStatus(src source, manifest *value, hostname string) (*value, error) {
	document, whyNot, err := src.load(statusPath)
	if err != nil {
		return nil, err
	}
	if whyNot != "" {
		reason := declineNoVerdict
		return nil, fmt.Errorf("%s: %s: %w", statusPath, whyNot, &reason)
	}
	if !document.isObject() {
		reason := declineNoVerdict
		// The two discriminators the reference states, on stderr rather than
		// in the decline: what this host OWES and what has ever run here are
		// both estate content, and this is the channel a person debugging
		// reads. They are what tells a fresh deploy from a dead timer.
		return nil, fmt.Errorf("%s: no verdict written; targets this host owns with a cadence: %v; check systemctl status homelab-protection-staleness.service: %w",
			statusPath, ownedWithCadence(manifest, hostname), &reason)
	}
	return document, nil
}

// ownedWithCadence names the targets this host is on the hook for, which is
// half of what separates "nobody has written a verdict yet" from "the checker
// stopped". Stated from the document already in hand rather than inferred.
func ownedWithCadence(manifest *value, hostname string) []string {
	var owed []string
	targets := manifest.get("targets")
	for _, name := range targets.sortedKeys() {
		raw := targets.get(name)
		if !raw.isObject() {
			continue
		}
		if raw.get("cadence").truthy() && raw.get("ownerHost").isText(hostname) {
			owed = append(owed, name)
		}
	}
	return owed
}

// receiptSuffixes are the two receipts a job writes, and the pair IS the
// distinction this collection exists to keep: a later failure cannot overwrite
// the evidence of the last good run, because the two live in different files.
var receiptSuffixes = [...]string{"last", "last-success"}

// receipts is one job's documents and the why-not for each receipt that would
// not open. A receipt that exists and will not open is NOT a receipt that was
// never written: dropping the reason here would let a corrupt last-success
// render byte-identically to a job that has never succeeded, which is the one
// distinction this collection exists to keep.
func receipts(src source, job string) (map[string]*value, map[string]string, error) {
	documents := map[string]*value{}
	faults := map[string]string{}
	for _, suffix := range receiptSuffixes {
		path := receiptPath(job, suffix)
		document, whyNot, err := src.load(path)
		if err != nil {
			return nil, nil, err
		}
		name := job + "." + suffix + ".json"
		switch {
		case document.isObject():
			documents[suffix] = document
		case whyNot != "":
			// The run happened and left a record this host cannot read.
			faults[name] = whyNot
		case document != nil:
			// It opened, it parsed, and it is not a receipt. Still a fault in
			// the evidence rather than evidence that no run happened.
			faults[name] = fmt.Sprintf("the receipt parsed as %s, not an object", document.pythonTypeName())
		}
		// The remaining case is the file not being there at all, and it is
		// deliberately NOT a fault: a job that has never succeeded has no
		// last-success receipt, and reporting one would alarm on every job
		// that has not got there yet.
	}
	return documents, faults, nil
}

// receiptsUnobservable folds the faults into the fact's text, sorted by file
// name so two runs of one payload agree.
func receiptsUnobservable(faults map[string]string) string {
	if len(faults) == 0 {
		return ""
	}
	names := make([]string, 0, len(faults))
	for name := range faults {
		names = append(names, name)
	}
	sort.Strings(names)
	out := ""
	for i, name := range names {
		if i > 0 {
			out += "; "
		}
		out += name + ": " + faults[name]
	}
	return out
}
