package main

import (
	"errors"
	"fmt"
	"io"
)

// The one collection, and the row's native name. One process fronts one
// bazarr, so the name is a constant rather than anything read out of a
// document: the collator mints `instance:bazarr` from the declared prefix and
// this name, which is the id the shipping adapter mints too.
const (
	collectionInstance = "instance"
	instanceName       = "bazarr"
)

// The facts this collection can publish, spelled once. Six, and only two of
// them are ever present together on a healthy instance — the other four each
// say a different thing went differently, which is why the derivation below
// reads as a sequence of arms rather than as one build.
const (
	factVersion            = "Version"
	factSonarrVersion      = "SonarrVersion"
	factRadarrVersion      = "RadarrVersion"
	factHealthIssues       = "HealthIssues"
	factConfigMissing      = "ConfigMissing"
	factStatusUnobservable = "StatusUnobservable"
)

// The status members this collection lifts, and the fact each becomes, in the
// REFERENCE'S order — status_facts walks this pairing and the row keeps the
// order it was built in.
//
// A member is lifted only when it is TRUTHY, which is the load-bearing half: a
// bazarr wired to no sonarr answers `"sonarr_version": ""`, and the member is
// present and empty rather than missing. Publishing a fact whenever the key
// exists would put an empty string on the row, which says the manager answered
// and reported no version — the opposite of what the document means.
var statusMembers = [...]struct{ fact, member string }{
	{factVersion, "bazarr_version"},
	{factSonarrVersion, "sonarr_version"},
	{factRadarrVersion, "radarr_version"},
}

// statusFacts folds the status document onto the row, and reports whether the
// document had a shape it could be folded from. False is the reference's
// AttributeError arm: `raw.get("data")` on a document that is not an object,
// or `data.get(member)` on a `data` that is truthy and not an object. Nothing
// is written in that case, because status_facts builds its dict locally and
// raises before returning it.
func statusFacts(doc jsonValue, facts *factRow) bool {
	if !doc.isObject() {
		return false
	}
	data := doc.get("data")
	if !data.truthy() {
		// `raw.get("data") or {}` — a missing, null or empty `data` is an
		// empty mapping and yields no facts, which is a reading and not a
		// failure.
		return true
	}
	if !data.isObject() {
		return false
	}
	for _, pair := range statusMembers {
		if value := data.get(pair.member); value.truthy() {
			facts.setValue(pair.fact, value)
		}
	}
	return true
}

// healthIssues folds bazarr's health document — {data: [{object, issue}]} — to
// the app's own sentences, bounded, one per issue. bazarr does not grade them,
// so nothing here does either: the list is mirrored whole and the count is all
// the estate adds.
//
// The second return is the reference's TypeError arm. `for entry in data`
// iterates an array over its elements, an object over its KEYS and a string
// over its characters — none of the last two is a dict, so both yield an empty
// list — while a number or a boolean is not iterable at all, and that is the
// only shape here that is a failure rather than a reading.
func healthIssues(doc jsonValue) ([]string, bool) {
	if !doc.isObject() {
		return nil, false
	}
	issues := []string{}
	data := doc.get("data")
	if !data.truthy() {
		return issues, true
	}
	switch data.kind {
	case jsonArray:
	case jsonObject, jsonString:
		// Iterable, and its members are not dicts: every entry is skipped and
		// the list is empty. Spelled out rather than folded into the default,
		// because "empty" and "could not be read" are different answers.
		return issues, true
	default:
		return nil, false
	}
	for _, entry := range data.array {
		if !entry.isObject() {
			continue
		}
		subject, issue := entry.get("object"), entry.get("issue")
		var line string
		switch {
		case subject.truthy() && issue.truthy():
			line = pythonStr(subject) + ": " + pythonStr(issue)
		case issue.truthy():
			// `issue or subject` hands back the VALUE, and the row keeps it
			// only if it is truthy — so an entry naming neither half is
			// dropped rather than published as an empty sentence.
			line = pythonStr(issue)
		case subject.truthy():
			line = pythonStr(subject)
		default:
			continue
		}
		issues = append(issues, reasonText(line))
	}
	return issues, true
}

// instanceRow is the whole derivation: what this collector could establish
// about the instance, as one row.
//
// The order of the arms is the reference's and it matters twice. The receipts
// are checked BEFORE anything is fetched, so an incomplete receipt publishes
// only what is missing and never a half-read instance. And the status document
// is folded onto the row BEFORE the health request is made, so an instance
// whose health endpoint went dark keeps its version facts and loses only its
// issue list — the row says both things at once, which is what the estate
// needs to see.
func instanceRow(got reading) *factRow {
	facts := newFactRow()
	if len(got.configMissing) > 0 {
		facts.setStrings(factConfigMissing, got.configMissing)
		return facts
	}

	unobservable := got.unobservable
	// Folded whenever the document was READ, not only when nothing failed: a
	// health endpoint that went dark leaves `unobservable` set beside a status
	// document that came back perfectly well, and the reference keeps what it
	// had already folded.
	if got.statusRead && !statusFacts(got.status, facts) {
		// The status document could not be folded at all, so the reference
		// never reached the health request and this reading replaces whatever
		// stood before it.
		unobservable = detailUnreadable(pathStatus)
	}
	if unobservable == "" && got.healthRead {
		issues, ok := healthIssues(got.health)
		if !ok {
			unobservable = detailUnreadable(pathHealth)
		} else {
			facts.setStrings(factHealthIssues, issues)
		}
	}
	if unobservable != "" {
		facts.setString(factStatusUnobservable, unobservable)
	}
	return facts
}

// collectInstance serves the one collection this collector answers for.
func collectInstance(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	got, err := src.instance()
	var refused *declined
	if errors.As(err, &refused) {
		if err.Error() != refused.Error() {
			// The record carries the constant, because decline detail travels
			// to a hub and out over MCP — and this collector's URL is
			// deployment configuration that may carry userinfo. Whatever the
			// seam wrapped around it stays here on stderr, where a person
			// debugging can read it and no redaction path has to be reviewed
			// for it. Printed only when there IS something wrapped, so an
			// ordinary absence does not restate itself into the journal on
			// every sweep.
			fmt.Fprintln(stderr, "instance:", err)
		}
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     refused.reason,
			Detail:     refused.detail,
		})
		// absent is authoritative-empty: it must be able to retire the instance
		// a previous batch published, so it declines AND commits zero. No other
		// reason commits — nothing was established, so prior state stands and
		// the collator marks it stale.
		if refused.reason == "absent" {
			out.emit(commitRecord{Record: "commit", Collection: collection, Generation: generation})
		}
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	out.emit(objectRecord{
		Record:     "object",
		Collection: collection,
		Name:       instanceName,
		Facts:      instanceRow(got).encode(),
		At:         src.stamp(*objects),
	})
	*objects++
	// One row, no relations, and no unobservable RECORD — StatusUnobservable is
	// a fact the reference publishes on the row, not a per-fact could-not-read
	// statement, and turning it into one here would be a second implementation
	// rather than the port of this one. The two zeroes below are therefore the
	// statement rather than a placeholder.
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    1,
	})
	return exitOK
}
