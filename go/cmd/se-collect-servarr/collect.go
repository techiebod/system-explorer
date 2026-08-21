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
// row's order and re-render a figure the app spelled.
//
// There is no `absent` member and no `names` member, and both are absences by
// construction rather than by omitempty. This collector never says an app
// genuinely lacks a property — a fact it does not carry is inapplicable (a
// prowlarr row has no QueueTotal because prowlarr has no queue) and rule 7
// omits those. And the row publishes no name family at all: the reference's
// summary carries none, and inventing one here would key the collator on a
// name no other implementation publishes.
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
	"apps":    "servarr-app",
	"health":  "servarr-health-item",
	"history": "servarr-history-event",
	"queue":   "servarr-queue-item",
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

// The four collections this collector serves. `apps` is the one that walks the
// WHOLE fleet, including the instances that cannot be observed; the other three
// fan out over the instances that can. One table rather than a switch, because
// the SAME set has to be the decline test, the request-order walk and the
// declaration's collection list — and a switch is where those three drift
// apart.
var served = map[string]struct {
	fanout bool
	rows   func(source, instance) ([]row, error)
}{
	"apps":    {fanout: false},
	"health":  {fanout: true, rows: healthRows},
	"queue":   {fanout: true, rows: queueRows},
	"history": {fanout: true, rows: historyRows},
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
		// Host-native, and deliberately so on the one collector that fronts a
		// fleet. DESIGN 19's `instance` scopes a collector that is one of
		// several processes fronting one application; this is ONE process
		// fronting several instances, and it keeps them apart by namespacing
		// every row's name with the instance handle instead. A value here
		// would claim the whole batch belonged to one of them.
		Instance:    nil,
		Generations: generations,
	})

	apps, err := src.fleet()
	var refused *declined
	if err == nil && len(apps) == 0 {
		// A fleet of nothing is the absence, whichever side answered: live it
		// is SE_SERVARR_INSTANCES naming nobody, and under replay it is a
		// capture whose receipt is an empty list. One decision point, so the
		// two paths cannot spell one reading two ways — the defect the storage
		// collector carried for as long as it existed.
		reason := declineNoInstances
		refused = &reason
	}
	switch {
	case refused != nil, errors.As(err, &refused):
		// `absent` is authoritative-empty and commits zero for every requested
		// collection, or the ones it skipped are never retired. Every OTHER
		// reason commits nothing: nothing was established, so prior state
		// stands and the collator marks it stale.
		//
		// Keyed on the reason and not on which constant was raised. This used
		// to commit unconditionally, which was correct only while
		// declineNoInstances was `absent` — the moment the configuration-gap
		// ruling moved it to `unavailable` (2026-08-19) this block began
		// committing after a decline that establishes nothing, and the stream
		// law caught it: "a 'unavailable' decline must not commit". The same
		// latent coupling was in downloaders.
		for _, collection := range order {
			if _, serves := served[collection]; !serves {
				out.emit(unsupportedFor(collection))
				continue
			}
			out.emit(declineRecord{
				Record:     "decline",
				Collection: collection,
				Reason:     refused.reason,
				Detail:     refused.detail,
			})
			if refused.reason == "absent" {
				out.emit(commitRecord{Record: "commit", Collection: collection,
					Generation: generations[collection]})
			}
		}
		return finish(out, stderr, src, batch)
	case err != nil:
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	objects := 0
	for _, collection := range order {
		spec, serves := served[collection]
		if !serves {
			// A name this collector never published is declined, not sanitised
			// and not crashed on (DESIGN 18). unsupported — the reason that
			// reaches whoever maintains the request — and no commit, so prior
			// state stands rather than being retired by a batch that never
			// looked.
			out.emit(unsupportedFor(collection))
			continue
		}
		if err := src.beginCollection(); err != nil {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		var built []row
		var err error
		if spec.fanout {
			built, err = fanout(src, apps, spec.rows)
		} else {
			built, err = appRows(src, apps)
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
				At:         src.stamp(objects),
			})
			objects++
		}
		// No assertion and no unobservable on the acquisition path. The queue's
		// `tracks` edge and the app's `dispatches-to` edges belong to the
		// opened object, which this collector does not serve, and every fact
		// these rows publish is either read or absent — never unreadable in a
		// way that leaves the row standing.
		out.emit(commitRecord{
			Record:     "commit",
			Collection: collection,
			Generation: generations[collection],
			Objects:    len(built),
		})
	}
	return finish(out, stderr, src, batch)
}

func unsupportedFor(collection string) declineRecord {
	return declineRecord{
		Record:     "decline",
		Collection: collection,
		Reason:     "unsupported",
		Detail:     "this collector serves apps, health, queue and history only",
	}
}

func finish(out *emitter, stderr io.Writer, src source, batch string) int {
	cpu, wall := src.costs()
	out.emit(endRecord{Record: "end", Request: batch, Batch: batch, CPUMS: cpu, WallMS: wall})
	if out.err != nil {
		fmt.Fprintln(stderr, "writing the stream:", out.err)
		return exitRuntime
	}
	return exitOK
}

// fanout is adapters/servarr.py `_fanout()`: rows from every instance that
// answers, in configuration order. An instance that fails NARROWS the
// collection — its rows are missing and its apps row carries the reason — and
// only ALL of them failing is an inability to run.
//
// A dark instance must not cost the fleet its other rows, and it must not be
// silent either: which instance dropped out is stated on the apps collection,
// which is the row an operator reads. That split is why this returns the rows
// it has rather than the first error it met.
func fanout(src source, apps []instance, rows func(source, instance) ([]row, error)) ([]row, error) {
	var out []row
	ready, failures := 0, 0
	var last error
	for _, app := range apps {
		if !app.ready() {
			continue
		}
		ready++
		built, err := rows(src, app)
		if err != nil {
			if _, narrowed := narrowing(err); !narrowed {
				// A broken capture or an unreadable payload is not a dark app:
				// it says nothing about any machine, so it ends the batch
				// rather than quietly removing an instance from the answer.
				return nil, err
			}
			failures++
			last = err
			continue
		}
		out = append(out, built...)
	}
	if ready == 0 {
		// Every configured instance is missing its receipts. The apps
		// collection says which and why; this one establishes nothing at all,
		// and a commit of zero here would retire whatever a previous batch
		// published on the strength of a configuration fault.
		return nil, errors.New(
			"no configured instance has complete receipts — see the apps " +
				"collection for what is missing")
	}
	if failures == ready {
		return nil, fmt.Errorf("no instance answered: %v", last)
	}
	return out, nil
}
