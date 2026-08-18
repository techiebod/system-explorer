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

// Facts here cannot be map[string]string as the identity collector's are: a
// chain row carries a boolean, a counted integer, a sorted array of caller
// names, and five members copied out of the document with their JSON type
// intact. `any` holds all four, and every pass-through is a jsonValue so the
// digits it emits are the digits it read.
type objectRecord struct {
	Record     string         `json:"record"`
	Collection string         `json:"collection"`
	Name       string         `json:"name"`
	Facts      map[string]any `json:"facts"`
	At         float64        `json:"at"`
}

// relationAssertionRecord is one vantage's directed claim about an edge.
// Two members the contract refuses are absent by construction rather than by
// omitempty: there is no observability field, because whether the far end was
// seen is a fact about another collector's output that only the collator
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
	Facts map[string]any `json:"facts,omitempty"`
}

type assertionTarget struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
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
// intentional.
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

const (
	collectionChains = "nft-chains"
	collectionRules  = "nft-rules"
)

// collect runs one batch: begin, each requested collection under its issued
// generation, end. The collection order is the request line's, and `at`
// advances in emission order across the whole batch — one counter, not one
// per collection, which is what the two-collection pair pins.
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

	// One document, both collections, acquired once. The reference
	// re-acquires per collection because each adapter method calls the
	// acquisition itself; reading once is the same answer under replay and a
	// stronger one live, where two `nft -j list ruleset` runs could straddle a
	// ruleset reload and publish chains and rules from different firewalls.
	// Nothing is read at all for a request naming no collection this serves.
	var doc jsonValue
	var acqErr error
	for _, collection := range order {
		if collection == collectionChains || collection == collectionRules {
			doc, acqErr = src.nftRuleset()
			break
		}
	}
	if acqErr != nil && !isDeclinable(acqErr) {
		// Not a statement about any machine: a staged payload this side could
		// not read is a broken capture, and a live failure with no decline
		// shape is "I could not run".
		fmt.Fprintln(stderr, "nft:", acqErr)
		return exitRuntime
	}

	objects := 0
	for _, collection := range order {
		switch collection {
		case collectionChains, collectionRules:
			if acqErr != nil {
				declineAcquisition(out, collection, generations[collection], acqErr)
				continue
			}
			var rows, edges int
			if collection == collectionChains {
				rows, edges = emitChains(out, src, collection, doc, &objects)
			} else {
				rows, edges = emitRules(out, src, collection, doc, &objects)
			}
			out.emit(commitRecord{
				Record:     "commit",
				Collection: collection,
				Generation: generations[collection],
				Objects:    rows,
				Assertions: edges,
			})
		default:
			// A name this collector never published is declined, not
			// sanitised and not crashed on. unsupported — the reason that
			// reaches whoever maintains the request — and no commit, so prior
			// state stands rather than being retired by a batch that never
			// looked.
			out.emit(declineRecord{
				Record:     "decline",
				Collection: collection,
				Reason:     "unsupported",
				Detail:     "this collector serves nft-chains and nft-rules only",
			})
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

func emitChains(out *emitter, src source, collection string, doc jsonValue, objects *int) (int, int) {
	rows := nftChains(doc)
	edges := 0
	for _, row := range rows {
		name := row.key.streamName()
		out.emit(objectRecord{
			Record:     "object",
			Collection: collection,
			// The chain's own three-part native name, spaces between: the
			// same chain name in ip and ip6 is two chains, and a rule
			// admitting a port in one says nothing about the other.
			Name:  name,
			Facts: row.facts,
			At:    src.stamp(*objects),
		})
		*objects++
		edges += emitAssertions(out, collection, name, row.edges)
	}
	return len(rows), edges
}

func emitRules(out *emitter, src source, collection string, doc jsonValue, objects *int) (int, int) {
	rows := nftRules(doc)
	edges := 0
	for _, row := range rows {
		out.emit(objectRecord{
			Record:     "object",
			Collection: collection,
			// Keyed by the kernel's own handle, which is the right join key
			// WITHIN a snapshot and not durable across a flush-and-restore.
			Name:  row.name,
			Facts: row.facts,
			At:    src.stamp(*objects),
		})
		*objects++
		edges += emitAssertions(out, collection, row.name, row.edges)
	}
	return len(rows), edges
}

// emitAssertions completes each edge with the three members a row cannot
// supply and puts it on the wire. The source NAME is the one the object
// record was published under and nothing else: a relation's key derives from
// the source object's id and the target's name as published (DESIGN 13), so
// an assertion naming its source any other way keys against an object that
// does not exist. The vantage is the collection this reading came from, which
// is what makes the assertion directed.
func emitAssertions(out *emitter, collection, name string, edges []relationAssertionRecord) int {
	for _, edge := range edges {
		edge.Record = "relation_assertion"
		edge.Collection = collection
		edge.Name = name
		edge.Vantage = collection
		out.emit(edge)
	}
	return len(edges)
}

// declineAcquisition maps an acquisition failure onto the decline vocabulary.
// Only `absent` commits: an absent decline is authoritative-empty and must be
// able to retire chains a previous batch published, while the other three say
// nothing was established and leave prior state standing, marked stale by the
// collator.
func declineAcquisition(out *emitter, collection string, generation uint64, err error) {
	reason, detail := declineFor(err)
	out.emit(declineRecord{
		Record:     "decline",
		Collection: collection,
		Reason:     reason,
		Detail:     detail,
	})
	if reason == "absent" {
		out.emit(commitRecord{
			Record:     "commit",
			Collection: collection,
			Generation: generation,
		})
	}
}

func isDeclinable(err error) bool {
	reason, _ := declineFor(err)
	return reason != ""
}

// The detail strings are constants. Decline detail travels to a hub and out
// over MCP, so the underlying error text goes to stderr alone — a payload byte
// echoed into a detail reaches a channel no redaction path covers.
func declineFor(err error) (reason, detail string) {
	switch {
	case errors.Is(err, errNftAbsent):
		// Byte for byte what the reference emits, and the corpus holds it.
		return "absent", "no nft on this host"
	case errors.Is(err, errNftRefused):
		return "unauthorised", "nft could not read the ruleset"
	case errors.Is(err, errNftSilent):
		return "unavailable", "nft did not answer"
	case errors.Is(err, errNftUnreadable):
		return "unsupported", "nft answered in a form this collector cannot read"
	}
	return "", ""
}
