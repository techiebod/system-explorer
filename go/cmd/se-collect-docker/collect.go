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
// row's order and re-render a figure the payload spelled.
//
// There is no `absent` member and no `names` member, and both are absences by
// construction rather than by omitempty. This collector never says a container
// genuinely lacks a property — a fact it does not carry is inapplicable (an
// exited container has no scope because systemd deleted it) and rule 7 omits
// those. And the row publishes no name family at all: the reference's summary
// carries none, and inventing one here would key the collator on a name no
// other implementation publishes.
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

// The three collections this collector serves, each bound to the Engine API
// path that answers it and the function that turns that document into rows.
// One table rather than a switch, because the SAME set has to be the decline
// test, the request-order walk and the declaration's collection list — and a
// switch is where those three drift apart.
var served = map[string]struct {
	path string
	rows func(*value) ([]row, error)
}{
	"containers": {pathContainers, containerRows},
	"volumes":    {pathVolumes, volumeRows},
	"networks":   {pathNetworks, networkRows},
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
		spec, serves := served[collection]
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
				Detail:     "this collector serves containers, volumes and networks only",
			})
			continue
		}
		if code := collectOne(out, stderr, src, collection, spec.path, spec.rows,
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

// collectOne serves one collection: fetch its document, row it, commit it.
func collectOne(out *emitter, stderr io.Writer, src source, collection, path string,
	rows func(*value) ([]row, error), generation uint64, objects *int) int {
	document, err := src.document(path)
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
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	built, err := rows(document)
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
	// not a placeholder — the container-to-scope and container-to-volume edges
	// belong to the opened object, which this collector does not serve.
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    len(built),
	})
	return exitOK
}
