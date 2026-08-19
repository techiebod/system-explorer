package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

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

// Facts are raw because their member order and their number TOKENS are decided
// upstream, by the document model: a map[string]any here would randomise the
// row's order and route every counter through a float64, re-rendering figures
// the payload spelled exactly.
//
// There is no `absent` member and no `names` member, and both are absences by
// construction rather than by omitempty. A fact this collector does not carry
// is inapplicable rather than genuinely missing — a transmission transfer has
// no SizeMB because transmission counts in bytes, and rule 7 omits those — and
// the row publishes no name family, because the reference's summary carries
// none and inventing one here would key the collator on a name no other
// implementation publishes.
type objectRecord struct {
	Record     string          `json:"record"`
	Collection string          `json:"collection"`
	Name       string          `json:"name"`
	Facts      json.RawMessage `json:"facts"`
	At         float64         `json:"at"`
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
// stdout is gone the stream is truncated no matter what else runs, so the batch
// reports "I could not run" rather than pretending the missing tail was
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

// The two collections this collector serves, each bound to the function that
// builds its rows. One table rather than a switch, because the SAME set has to
// be the decline test, the request-order walk and the declaration's collection
// list — and a switch is where those three drift apart.
const (
	collectionClients   = "clients"
	collectionTransfers = "transfers"
)

var served = map[string]func(source, io.Writer) ([]row, error){
	collectionClients:   clientRows,
	collectionTransfers: transferRows,
}

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
	// Before the first collection and before begin: `at` must precede the
	// earliest native read that contributes to any row, and a row can rest on
	// the configuration alone rather than on a document.
	if err := src.openBatch(); err != nil {
		fmt.Fprintln(stderr, "reading the boot clock:", err)
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
		build, serves := served[collection]
		if !serves {
			// A name this collector never published is declined, not sanitised
			// and not crashed on (DESIGN 18). unsupported — the reason that
			// reaches whoever maintains the request — and no commit, so prior
			// state stands rather than being retired by a batch that never
			// looked.
			out.emit(declineRecord{
				Record:     "decline",
				Collection: collection,
				Reason:     "unsupported",
				Detail:     "this collector serves clients and transfers only",
			})
			continue
		}
		if code := collectOne(out, stderr, src, collection, build,
			generations[collection], &objects); code != exitOK {
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

// collectOne serves one collection: build its rows, emit them, commit.
//
// The absence question is asked ONCE, of the configuration, before any document
// is read — a process holding neither client's receipts observes no download
// client, and that is the same reading on both collections and on both sides of
// the seam.
func collectOne(out *emitter, stderr io.Writer, src source, collection string,
	build func(source, io.Writer) ([]row, error), generation uint64, objects *int) int {
	if !src.clients().any() {
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     declineNoClient.reason,
			Detail:     declineNoClient.detail,
		})
		// No commit. A process holding neither client's receipts has not
		// established that this host runs no download client — only that it was
		// not told where to look — and RULED 2026-08-19 a configuration gap may
		// never retire an object. Prior state stands and the collator marks it
		// stale. `absent` remains the one reason that commits, and this is not
		// it.
		return exitOK
	}

	built, err := build(src, stderr)
	var refused *declined
	if errors.As(err, &refused) {
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     refused.reason,
			Detail:     refused.detail,
		})
		// Keyed on the REASON `absent` and not on which constant was raised.
		// It used to compare against declineNoClient.reason, which meant the
		// commit followed that constant wherever its reason went — and when the
		// ruling moved it to `unavailable`, every unavailable decline in this
		// collector would have started retiring rows. The rule is about the
		// reason, so the test is about the reason.
		if refused.reason == "absent" {
			out.emit(commitRecord{Record: "commit", Collection: collection, Generation: generation})
		}
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, collection+":", err)
		return exitRuntime
	}
	for _, one := range built {
		out.emit(objectRecord{
			Record:     "object",
			Collection: collection,
			Name:       one.name,
			Facts:      one.facts.encode(),
			At:         src.stamp(*objects),
		})
		*objects++
	}
	// This collection carries no health and no relations on the acquisition
	// path: no assertion, no unobservable. The two zeroes are the statement,
	// not a placeholder — the `tracks` and `dispatches-to` edges that reach
	// these ids are emitted by the servarr collector, which is the side whose
	// API stated the key.
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    len(built),
	})
	return exitOK
}
