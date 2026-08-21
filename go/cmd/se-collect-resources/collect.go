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

// Facts are raw because their number TOKENS are decided where the kernel file
// was parsed: a map[string]any here would route every counter through a
// float64 and lose the last digits of a u64 the kernel spelled exactly.
//
// There is no `absent` member, no `names` member and no assertions, and all
// three are absences by construction rather than by omitempty. A cgroup file
// the kernel does not keep is a fact this collection does not serve for that
// row — the reference omits it and says so nowhere else — the row publishes no
// name family because a cgroup's name IS systemd's unit name and inventing a
// second one would key the collator on a name no other implementation
// publishes, and the parent link is a FACT rather than a relation because both
// projections of a unit are the same object under identity (adapters/
// resources.py's opening note), so there is no edge to assert.
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

const collectionWorkloads = "workloads"

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
		if collection != collectionWorkloads {
			// A name this collector never published is declined, not
			// sanitised and not crashed on (DESIGN 18). unsupported — the
			// reason that reaches whoever maintains the request — and no
			// commit, so prior state stands rather than being retired by a
			// batch that never looked.
			out.emit(declineRecord{
				Record:     "decline",
				Collection: collection,
				Reason:     "unsupported",
				Detail:     "this collector serves workloads only",
			})
			continue
		}
		if code := collectWorkloads(out, stderr, src, collection, generations[collection], &objects); code != exitOK {
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

// collectWorkloads serves the one collection this collector answers for.
func collectWorkloads(out *emitter, stderr io.Writer, src source, collection string,
	generation uint64, objects *int) int {
	found, err := readTree(src)
	var refused *declined
	if errors.As(err, &refused) {
		if err.Error() != refused.Error() {
			// The record carries the constant, because decline detail travels
			// to a hub and out over MCP. Whatever the seam wrapped around it —
			// the errno, the path, the kernel's refusal — stays here on
			// stderr, where a person debugging can read it and no redaction
			// path has to be reviewed for it.
			fmt.Fprintln(stderr, "workloads:", err)
		}
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     refused.reason,
			Detail:     refused.detail,
		})
		// absent is authoritative-empty: it must be able to retire the rows a
		// previous batch published, so it declines AND commits zero. No other
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

	// The whole derivation, in the reference's own order: the attribution walk
	// over the tree, then the host denominator, then the rows. /proc/stat is
	// read AFTER the tree, deliberately — both sides are monotonic counters,
	// so a total sampled later than its parts can only be larger, and reading
	// in this order is what stops a negative remainder being manufactured out
	// of the sampling gap.
	attribution := stallAttribution(found)
	remainder, err := unattributedCPU(src, found)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	rows := found.rows(remainder, attribution)
	for _, row := range rows {
		out.emit(objectRecord{
			Record:     "object",
			Collection: collection,
			Type:       unitKind(row.name),
			Name:       row.name,
			Facts:      row.facts.encode(),
			At:         src.stamp(*objects),
		})
		*objects++
	}
	// No relations and no unobservable records, and the zeroes are the
	// statement rather than a placeholder: every reading here either produced
	// a fact or produced nothing, and a cgroup file the kernel does not keep
	// is a fact this collection does not serve on that row (adapters/
	// resources.py's `_read_int`: absent, never zero).
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    len(rows),
	})
	return exitOK
}
