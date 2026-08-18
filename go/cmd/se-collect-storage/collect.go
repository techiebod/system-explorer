package main

import (
	"encoding/json"
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

// Facts and Names are raw because their member order and their number tokens
// are decided upstream, by the ordered document model: a map[string]any here
// would randomise vdev order and round a 64-bit guid on the way out.
type objectRecord struct {
	Record     string          `json:"record"`
	Collection string          `json:"collection"`
	Name       string          `json:"name"`
	Facts      json.RawMessage `json:"facts"`
	Names      json.RawMessage `json:"names,omitempty"`
	// Present only when a declared fact genuinely is not: we looked, and
	// the document has no such property — distinct from unobservable,
	// each on its own channel, never a null (DESIGN 19).
	Absent []string `json:"absent,omitempty"`
	At     float64  `json:"at"`
}

// relationAssertionRecord is one vantage's directed claim about an edge.
// Two members the contract refuses are absent by construction rather than
// by omitempty: there is no observability field, because whether the far end
// was seen is a fact about another collector's output that only the collator
// holds; and the target carries a name, never an id, because resolution is a
// property that changes and a key that changed with it would reset the
// relation's lifecycle every time the estate learned something (DESIGN 13).
type relationAssertionRecord struct {
	Record     string          `json:"record"`
	Collection string          `json:"collection"`
	Name       string          `json:"name"`
	Type       string          `json:"type"`
	Vantage    string          `json:"vantage"`
	Target     assertionTarget `json:"target"`
	// Omitted entirely for a type declaring carries_facts false: an empty
	// object would be a fact channel opened for a relation that has none.
	Facts json.RawMessage `json:"facts,omitempty"`
}

type assertionTarget struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

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
		if collection != "pools" {
			// A name this collector never published is declined, not
			// sanitised and not crashed on (DESIGN 18). unsupported —
			// the reason that reaches whoever maintains the request —
			// and no commit, so prior state stands.
			out.emit(declineRecord{
				Record:     "decline",
				Collection: collection,
				Reason:     "unsupported",
				Detail:     "this collector serves pools only",
			})
			continue
		}
		if code := collectPools(out, stderr, src, collection, generations[collection], &objects); code != exitOK {
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
