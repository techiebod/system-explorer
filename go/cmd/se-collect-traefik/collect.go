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

// Facts are raw because their member order and their number tokens are decided
// upstream, by the document model: a map[string]any here would randomise the
// row's order and re-render a figure the payload spelled — including the
// priority two below 2^63 that the committed capture anchors.
//
// There is no `absent` member and no `names` member, and both are absences by
// construction rather than by omitempty. This collector never says a route
// genuinely lacks a property: a fact it does not carry is one the API document
// did not state, which rule 7 omits — Traefik's own internal services carry no
// `type` at all. And the row publishes no name family, because the reference's
// summary carries none and inventing one here would key the collator on a name
// no other implementation publishes.
type objectRecord struct {
	Record     string          `json:"record"`
	Collection string          `json:"collection"`
	Name       string          `json:"name"`
	Type       string          `json:"type,omitempty"`
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

// collectionTypes is each collection's structural kind, on the wire
// since the 2026-08-21 ruling. Constant per collection here because
// these collections are homogeneous; the heterogeneous collectors
// (units, hardware, resources) carry it per row instead.
var collectionTypes = map[string]string{
	"overview": "traefik-overview",
	"routers":  "traefik-router",
	"services": "traefik-service",
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

// row is one object as the collection publishes it: the name the collator keys
// on, and the facts, already free of anything the document did not state.
type row struct {
	name  string
	facts *value
}

// The three collections this collector serves, each bound to the function that
// acquires its documents and turns them into rows. One table rather than a
// switch, because the SAME set has to be the decline test, the request-order
// walk and the declaration's collection list — and a switch is where those
// three drift apart.
//
// The acquisition lives behind the row builder rather than beside it because
// the collections do not agree on how many documents they take: `overview` is
// three (the counts, the version and the entrypoints), and the other two are
// one apiece.
var served = map[string]func(source) ([]row, error){
	"overview": overviewRows,
	"routers":  routerRows,
	"services": serviceRows,
}

// The prose the unsupported decline carries, spelled once so it cannot drift
// from the table above.
const servedNames = "this collector serves overview, routers and services only"

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
				Detail:     servedNames,
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

// collectOne serves one collection: acquire it, row it, commit it.
func collectOne(out *emitter, stderr io.Writer, src source, collection string,
	build func(source) ([]row, error), generation uint64, objects *int) int {
	// One clock reading per collection, taken before its first request: the
	// overview row rests on three documents that arrive together, and a stamp
	// per document would report it fresher than its oldest contributing byte.
	src.mark()
	built, err := build(src)
	var refused *declined
	if errors.As(err, &refused) {
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     refused.reason,
			Detail:     refused.detail,
		})
		// absent is authoritative-empty: it must be able to retire the objects
		// a previous batch published, so it declines AND commits zero. No other
		// reason commits — nothing was established, so prior state stands and
		// the collator marks it stale.
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
			Type:       collectionTypes[collection],
			Collection: collection,
			Name:       one.name,
			Facts:      one.facts.encode(),
			At:         src.stamp(*objects),
		})
		*objects++
	}
	// These collections carry no health and no relations on the acquisition
	// path: no assertion, no unobservable. The two zeroes are the statement,
	// not a placeholder — the service-to-router `routes-via` edges belong to
	// the opened object, which this collector does not serve.
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    len(built),
	})
	return exitOK
}
