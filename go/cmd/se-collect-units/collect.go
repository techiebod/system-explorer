package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// writer is the one edge every derivation below writes diagnostics to. Named
// so a function's signature says it takes the diagnostic channel and not some
// second output — stderr goes to the journal and never carries payload
// content (DESIGN 19).
type writer = io.Writer

// Stream records as Go structs, every member the contract names and no other:
// the schemas are closed precisely because an open object is how a struct's
// exported field names once shipped as {"Stable":…} without a test going red
// (se.stream.1.json), so the json tags here ARE the wire and a missing one is
// a wire bug.
type beginRecord struct {
	Record      string            `json:"record"`
	Request     string            `json:"request"`
	Batch       string            `json:"batch"`
	Declaration string            `json:"declaration"`
	BootID      string            `json:"boot_id"`
	Timens      int64             `json:"timens"`
	Instance    *string           `json:"instance"` // no omitempty: null means host-native and only null means it
	Generations map[string]uint64 `json:"generations"`
}

// Facts are raw because the row carries strings, a boolean and lists of
// strings and nothing else: a map[string]any here would route every value
// through the encoder's own escaping and re-render text the payload spelled
// exactly.
//
// There is no `absent` member and no `names` member, and both are absences by
// construction rather than by omitempty. A property this collection could not
// read is not a property the unit was asked about and denied, and the row
// publishes no name family, because the reference's summary carries none and
// inventing one here would key the collator on a name no other implementation
// publishes.
type relationAssertionRecord struct {
	Record     string          `json:"record"`
	Collection string          `json:"collection"`
	Name       string          `json:"name"`
	Type       string          `json:"type"`
	Vantage    string          `json:"vantage"`
	Target     assertionTarget `json:"target"`
}

type assertionTarget struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type objectRecord struct {
	Record     string `json:"record"`
	Collection string `json:"collection"`
	Name       string `json:"name"`
	// The unit's kind — service, slice, device, mount — which this
	// collector has always computed for its ordering and never emitted.
	// On the wire since the 2026-08-21 ruling: it is what a facet bar
	// offers and what a hide rule may match, and half a busy host's rows
	// are the device wall that rule exists for.
	Type  string          `json:"type,omitempty"`
	Facts json.RawMessage `json:"facts"`
	// Declared facts this object genuinely lacks — the verb responses'
	// channel; the collect path states its gaps per fact instead, on the
	// unobservable records the listing can attribute.
	Absent []string `json:"absent,omitempty"`
	At     float64  `json:"at"`
}

// unobservableRecord is DESIGN 19's could-not-read channel: a fact this
// collector tried to read and could not, named per object, distinct from a
// fact the object does not have. Added 2026-08-19 with the Slice ruling; the
// comment below used to say this collector emitted none.
type unobservableRecord struct {
	Record     string `json:"record"`
	Collection string `json:"collection"`
	Name       string `json:"name"`
	Fact       string `json:"fact"`
	Reason     string `json:"reason"`
	Detail     string `json:"detail"`
}

type declineRecord struct {
	Record     string `json:"record"`
	Collection string `json:"collection"`
	Reason     string `json:"reason"`
	Detail     string `json:"detail"`
}

type commitRecord struct {
	Record     string `json:"record"`
	Collection string `json:"collection"`
	Generation uint64 `json:"generation"`
	// All three counts, always, zero when zero: they are required members
	// precisely so a subject cannot disable the truncation check by omitting
	// the count (DESIGN 19).
	Objects      int `json:"objects"`
	Assertions   int `json:"assertions"`
	Unobservable int `json:"unobservable"`
}

type endRecord struct {
	Record  string  `json:"record"`
	Request string  `json:"request"`
	Batch   string  `json:"batch"`
	CPUMS   float64 `json:"cpu_ms"`
	WallMS  float64 `json:"wall_ms"`
}

// emitter serialises records as NDJSON and keeps the first write error: once
// stdout is gone the stream is truncated no matter what else runs, so the
// batch reports "I could not run" rather than pretending the missing tail was
// intentional — the commit counts make truncation detectable at the far end,
// and the exit status makes it loud at this one.
type emitter struct {
	encoder *json.Encoder
	err     error
}

func newEmitter(w io.Writer) *emitter {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return &emitter{encoder: encoder}
}

func (e *emitter) emit(record any) {
	if e.err == nil {
		e.err = e.encoder.Encode(record)
	}
}

const collectionUnits = "units"

// isUncaptured says whether a failure is a payload the variant did not stage.
// It exists so a broken capture can be told from an interface that answered
// and refused, which are different things to tell an operator and different
// things for a batch to do.
func isUncaptured(err error) bool { return errors.Is(err, errUncaptured) }

// collect runs one batch: begin, each requested collection under its issued
// generation, end. The collection order is the request line's, and `at`
// advances in emission order across the whole batch, matching the replay pin
// (1.0 + 0.001*i).
func collect(stdout, stderr io.Writer, src source, order []string, generations map[string]uint64) int {
	bootID, err := src.bootID()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	batch, err := src.batch()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	out := newEmitter(stdout)
	out.emit(beginRecord{
		Record:      "begin",
		Request:     batch, // request := batch by ruling (appendix C); the collator correlates by the connection it dialled
		Batch:       batch,
		Declaration: src.declaration(),
		BootID:      bootID,
		Timens:      src.timens(),
		Instance:    nil, // host-native: this collector fronts no fleet-named instance
		Generations: generations,
	})

	objects := 0
	for _, collection := range order {
		if collection != collectionUnits {
			// A name this collector never published is declined, not
			// sanitised and not crashed on (DESIGN 18). unsupported — the
			// reason that reaches whoever maintains the request — and no
			// commit, so prior state stands rather than being retired by a
			// batch that never looked.
			out.emit(declineRecord{
				Record:     "decline",
				Collection: collection,
				Reason:     "unsupported",
				Detail:     "this collector serves units only",
			})
			continue
		}
		if code := collectUnits(out, stderr, src, collection, generations[collection], &objects); code != exitOK {
			return code
		}
	}

	cpu, wall := src.costs()
	out.emit(endRecord{Record: "end", Request: batch, Batch: batch, CPUMS: cpu, WallMS: wall})

	if out.err != nil {
		fmt.Fprintln(stderr, "writing the stream:", out.err)
		return exitRuntime
	}
	return exitOK
}

func collectUnits(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	rows, err := buildRows(src, stderr)
	var refused *declined
	if errors.As(err, &refused) {
		if err.Error() != refused.Error() {
			// The record carries the constant, because decline detail travels
			// to a hub and out over MCP. Whatever the seam wrapped around it —
			// busctl's own words, the errno — stays here on stderr, where a
			// person debugging can read it and no redaction path has to be
			// reviewed for it. Printed only when there IS something wrapped,
			// so an ordinary absence does not restate itself into the journal
			// on every sweep.
			fmt.Fprintln(stderr, "units:", err)
		}
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     refused.reason,
			Detail:     refused.detail,
		})
		// absent is authoritative-empty: it must be able to retire the units a
		// previous batch published, so it declines AND commits zero. No other
		// reason commits — nothing was established, so prior state stands and
		// the collator marks it stale.
		if refused.reason == "absent" {
			out.emit(commitRecord{Record: "commit", Collection: collection, Generation: generation})
		}
		return exitOK
	}
	if err != nil {
		// A capture missing a document the listing named, or a reply whose
		// signature moved: "I could not run", never a decline, which would
		// state something about a machine nobody observed.
		fmt.Fprintln(stderr, "units:", err)
		return exitRuntime
	}

	unobservables, assertions := 0, 0
	for _, item := range rows {
		out.emit(objectRecord{
			Record:     "object",
			Collection: collection,
			Name:       item.name,
			Type:       item.kind,
			Facts:      item.facts.encode(),
			At:         src.stamp(*objects),
		})
		*objects++
		// The slice hierarchy as edges (the R1 ruling): the collator
		// derives the tree from these, and the set is exactly the children
		// map the applied order walked.
		if item.parent != "" {
			out.emit(relationAssertionRecord{
				Record:     "relation_assertion",
				Collection: collection,
				Name:       item.name,
				Vantage:    collection,
				Type:       "member-of",
				Target:     assertionTarget{Kind: "unit", Name: item.parent},
			})
			assertions++
		}
		// After the object, because a record about a fact must follow the row
		// that fact belongs to.
		for _, missing := range item.unobservable {
			out.emit(unobservableRecord{
				Record:     "unobservable",
				Collection: collection,
				Name:       item.name,
				Fact:       missing.fact,
				Reason:     missing.reason,
				Detail:     missing.detail,
			})
			unobservables++
		}
	}
	// The member-of edges above are the listing's own knowledge; the
	// dependency edges (requires, wants, after) still need the per-unit
	// forward properties and ride the object verb, where the properties
	// are already in hand.
	out.emit(commitRecord{
		Record:       "commit",
		Collection:   collection,
		Generation:   generation,
		Objects:      len(rows),
		Assertions:   assertions,
		Unobservable: unobservables,
	})
	return exitOK
}
