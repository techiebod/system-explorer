package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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

type objectRecord struct {
	Record     string            `json:"record"`
	Collection string            `json:"collection"`
	Name       string            `json:"name"`
	Type       string            `json:"type,omitempty"`
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
		Declaration: declarationDigest,
		BootID:      bootID,
		Timens:      src.timens(),
		Instance:    nil, // host-native: this collector fronts no fleet-named instance
		Generations: generations,
	})

	objects := 0
	for _, collection := range order {
		if collection != "identity" {
			// A name this collector never published is declined, not
			// sanitised and not crashed on (DESIGN 18). unsupported —
			// the reason that reaches whoever maintains the request —
			// and no commit, so prior state stands.
			out.emit(declineRecord{
				Record:     "decline",
				Collection: collection,
				Reason:     "unsupported",
				Detail:     "this collector serves identity only",
			})
			continue
		}
		if code := collectIdentity(out, stderr, src, collection, generations[collection], &objects); code != exitOK {
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

// The identity facts in declared order, each with the os-release key it is
// extracted from — the same paths the declaration's `from` members state,
// held beside each other so the two cannot drift silently.
var identityFacts = [...]struct{ fact, key string }{
	{"OsId", "ID"},
	{"OsVersionId", "VERSION_ID"},
	{"OsPrettyName", "PRETTY_NAME"},
}

func collectIdentity(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	// `at` before the earliest native read that contributes to the object,
	// so the tie breaks toward older: an acquisition stamped at completion
	// would report itself fresher than its oldest contributing byte
	// (DESIGN 19).
	at, err := src.stamp(*objects)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	raw, err := src.osRelease()
	if errors.Is(err, fs.ErrNotExist) {
		// Authoritative-empty: a machine without os-release answered
		// truthfully, so absent declines AND commits zero — the pair of
		// records is the statement, and the commit is what lets it retire
		// an identity a previous batch published (DESIGN 19).
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     "absent",
			Detail:     "no os-release on this host",
		})
		out.emit(commitRecord{Record: "commit", Collection: collection, Generation: generation})
		return exitOK
	}
	if err != nil {
		// Present but not answering: nothing was established, so no
		// commit — prior state stands, marked stale by the collator. The
		// error's own text goes to stderr only; decline detail travels to
		// a hub and out over MCP, so it stays a constant (DESIGN 19).
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     "unavailable",
			Detail:     "os-release exists but could not be read",
		})
		fmt.Fprintln(stderr, "os-release:", err)
		return exitOK
	}

	host, err := src.hostname()
	if err != nil {
		if errors.Is(err, errUncaptured) {
			// A replay variant staging os-release but no hostname is a
			// broken capture, not a statement about any machine: "I
			// could not run", never a decline that would lie about the
			// host the payloads came from.
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     "unavailable",
			Detail:     "the kernel hostname did not answer",
		})
		fmt.Fprintln(stderr, "hostname:", err)
		return exitOK
	}

	doc := parseOsRelease(raw)
	facts := map[string]string{"Hostname": host}
	var absent []string
	for _, f := range identityFacts {
		// A key present with an empty value states nothing a reader can
		// use, so it joins the genuinely-missing on the absent list
		// rather than shipping "" as a fact — and the os-release spec's
		// synthetic defaults (ID falls back to "linux") are deliberately
		// not applied: every emitted value must be checkable against the
		// evidence document at its declared `from` path, and a
		// manufactured value is at no path.
		if value := doc[f.key]; value != "" {
			facts[f.fact] = value
		} else {
			absent = append(absent, f.fact)
		}
	}

	// The one object's native name IS the hostname — law 1, the name
	// observed: this collector does not know what id any collator minted.
	out.emit(objectRecord{
		Record:     "object",
		Type:       "identity",
		Collection: collection,
		Name:       host,
		Facts:      facts,
		Absent:     absent,
		At:         at,
	})
	*objects++
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    1,
	})
	return exitOK
}
