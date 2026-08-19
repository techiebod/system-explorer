package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Stream records as Go structs, every member the contract names and no
// other: the schemas are closed precisely because an open object is how a
// struct's exported field names once shipped as {"Stable":…} without a test
// going red (se.stream.1.json), so the json tags here ARE the wire and a
// missing one is a wire bug.
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

// Every fact this collection publishes is a single string, so the facts map is
// typed rather than raw: there is no ordered document to preserve and no
// 64-bit number to round on the way out.
type objectRecord struct {
	Record     string            `json:"record"`
	Collection string            `json:"collection"`
	Name       string            `json:"name"`
	Facts      map[string]string `json:"facts"`
	// Present only when a declared fact genuinely is not: we looked, and
	// the document has no such property — distinct from unobservable,
	// each on its own channel, never a null (DESIGN 19).
	Absent []string `json:"absent,omitempty"`
	At     float64  `json:"at"`
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
	// precisely so a subject cannot disable the truncation check by
	// omitting the count (DESIGN 19).
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

// emitter serialises records as NDJSON and keeps the first write error:
// once stdout is gone the stream is truncated no matter what else runs, so
// the batch reports "I could not run" rather than pretending the missing
// tail was intentional — the commit counts make truncation detectable at
// the far end, and the exit status makes it loud at this one.
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

// collect runs one batch: begin, each requested collection under its issued
// generation, end. The collection order is the request line's, and `at`
// advances in emission order across the whole batch, matching the replay
// pin (1.0 + 0.001*i).
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
		Record:  "begin",
		Request: batch, // request := batch by ruling (appendix C); the collator correlates by the connection it dialled
		Batch:   batch,
		// The hash of the exact bytes declare emits, so an unknown hash
		// triggers a refetch, not a guess (DESIGN 19).
		Declaration: src.declaration(),
		BootID:      bootID,
		Timens:      src.timens(),
		Instance:    nil, // host-native: this collector fronts no fleet-named instance
		Generations: generations,
	})

	objects := 0
	for _, collection := range order {
		if collection != "packages" {
			// A name this collector never published is declined, not
			// sanitised and not crashed on (DESIGN 18). unsupported —
			// the reason that reaches whoever maintains the request —
			// and no commit, so prior state stands.
			out.emit(declineRecord{
				Record:     "decline",
				Collection: collection,
				Reason:     "unsupported",
				Detail:     "this collector serves packages only",
			})
			continue
		}
		if code := collectPackages(out, stderr, src, collection, generations[collection], &objects); code != exitOK {
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

// collectPackages serves the one collection this collector answers for.
func collectPackages(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	got, err := src.packages()
	var refused *declined
	if errors.As(err, &refused) {
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     refused.reason,
			Detail:     refused.detail,
		})
		// absent is authoritative-empty: it must be able to retire objects a
		// previous batch published, so it declines AND commits zero. No
		// other reason commits — nothing was established, so prior state
		// stands and the collator marks it stale.
		if refused.reason == "absent" {
			out.emit(commitRecord{Record: "commit", Collection: collection, Generation: generation})
		}
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	emitted := 0
	for _, row := range inventory(got) {
		out.emit(objectRecord{
			Record:     "object",
			Collection: collection,
			Name:       row.native,
			Facts:      row.facts,
			Absent:     row.absent,
			At:         src.stamp(*objects),
		})
		*objects++
		emitted++
	}
	// An inventory carries no health and no relations: no opinion, no
	// severity, no assertion, no unobservable. The two zeroes below are the
	// statement, not a placeholder — the roll-up declines an opinion on this
	// subsystem for exactly that reason.
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    emitted,
	})
	return exitOK
}
