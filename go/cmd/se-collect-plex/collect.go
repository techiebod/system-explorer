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
// (se.stream.1.json), so the json tags here ARE the wire and a missing one is a
// wire bug.
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
// row's order and re-render a figure the payload spelled — including the item
// counts the committed capture anchors as integers.
//
// There is no `absent` member and no `names` member, and both are absences by
// construction rather than by omitempty. This collector never says a row
// genuinely lacks a property — a member the API document did not state is one
// rule 7 omits — and the rows publish no name family at all: the reference's
// summary carries none, and inventing one here would key the collator on a name
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
	// precisely so a subject cannot disable the truncation check by omitting the
	// count (DESIGN 19).
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
// intentional — the commit counts make truncation detectable at the far end, and
// the exit status makes it loud at this one.
type emitter struct {
	encoder *json.Encoder
	err     error
}

// collectionTypes is each collection's structural kind, on the wire
// since the 2026-08-21 ruling. Constant per collection here because
// these collections are homogeneous; the heterogeneous collectors
// (units, hardware, resources) carry it per row instead.
var collectionTypes = map[string]string{
	"libraries": "plex-library",
	"server":    "plex-server",
	"sessions":  "plex-session",
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

// The server row's native name. One process fronts one Plex, so the name is a
// constant rather than anything read out of a document: the collator mints
// `server:plex` from the declared prefix and this name, which is the id the
// shipping adapter mints too. The friendly name is a FACT on that row and never
// its identity — a server renamed in its own settings is the same server.
const serverName = "plex"

// The three collections this collector serves, each bound to the function that
// acquires its documents and turns them into rows. One table rather than a
// switch, because the SAME set has to be the decline test, the request-order walk
// and the declaration's collection list — and a switch is where those three drift
// apart.
//
// `requests` is not here, and its absence is a ruling rather than an omission. It
// is seerr's collection, not Plex's: it is read from a different application over
// a different credential, seerr's first-run setup authenticates against a Plex
// ACCOUNT, and no corpus variant can stage one — so the replay seam does not
// serve it, the live reference does not compare it, and a port that answered it
// would be answering for an interface nothing here has ever read.
var served = map[string]func(source) ([]row, error){
	"server":    serverRows,
	"libraries": libraryRows,
	"sessions":  sessionRows,
}

// The prose the unsupported decline carries, spelled once so it cannot drift from
// the table above.
const servedNames = "this collector serves server, libraries and sessions only"

// collect runs one batch: begin, each requested collection under its issued
// generation, end. The collection order is the request line's, and `at` advances
// in emission order across the whole batch, matching the replay pin
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
	// One clock reading per collection, taken before its first request: a library
	// row rests on two documents fetched one after the other, and a stamp per
	// document would report the row fresher than its oldest contributing byte.
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
		// absent is authoritative-empty: it must be able to retire the objects a
		// previous batch published, so it declines AND commits zero. No other
		// reason commits — nothing was established, so prior state stands and the
		// collator marks it stale.
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
	// These collections carry no relations and no per-fact could-not-read
	// statements: StatusUnobservable and ItemCountUnobservable are FACTS the
	// reference publishes on the row, not `unobservable` records, and turning
	// them into records here would be a second implementation rather than a port
	// of this one. The two zeroes are therefore the statement, not a placeholder.
	//
	// A commit of ZERO OBJECTS is the important case rather than the empty one.
	// The sessions document carries no `Metadata` member when nothing is playing,
	// and that is an authoritative emptiness: committing zero RETIRES every
	// session a previous batch published, where declining would leave stale
	// sessions standing forever.
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    len(built),
	})
	return exitOK
}

// gate is the reading every collection takes before it asks the API anything: is
// a Plex addressed here at all, and can this deployment open it. The two answers
// are different verdicts, and the third argument is what a collection does with
// the receipts gap — `server` publishes a row that names it, the other two
// decline, because guessing at a token would only manufacture 401s.
func gate(src source) (deployment, error) {
	got := src.deployment()
	if got.absent {
		reason := declineNoServer
		return got, &reason
	}
	return got, nil
}

// serverRows answers: is the thing every stream depends on up, and which release
// answers.
//
// The order of the arms is the reference's and it matters twice. The receipts are
// checked BEFORE anything is fetched, so an incomplete receipt publishes only
// what is missing and never a half-read server. And the root document is folded
// onto the row BEFORE the sessions request is made, so a server whose session
// list alone went dark keeps its identity and version facts and loses only the
// count — the row says both things at once, which is what the estate needs to see.
func serverRows(src source) ([]row, error) {
	deploy, err := gate(src)
	if err != nil {
		return nil, err
	}
	facts := newObject()
	if len(deploy.missing) > 0 {
		// This row rests on no document, so nothing else takes the clock for
		// it — and a published object with `at: 0` is refused by the contract.
		if err := src.ready(); err != nil {
			return nil, err
		}
		facts.set(factConfigMissing, stringList(deploy.missing))
		return []row{{name: serverName, facts: facts}}, nil
	}

	root, err := src.document(pathRoot)
	if err != nil {
		return nil, err
	}
	if root.detail != "" {
		// The row STAYS, and this is the one collection where a dark API is a
		// fact rather than a decline: every stream in the house depends on this
		// server answering, and a row that vanished would say nothing at all
		// about why.
		facts.set(factStatusUnobservable, stringValue(root.detail))
		return []row{{name: serverName, facts: facts}}, nil
	}
	serverFacts(root.doc, facts)

	sessions, err := src.document(pathSessions)
	if err != nil {
		return nil, err
	}
	if sessions.detail != "" {
		facts.set(factStatusUnobservable, stringValue(sessions.detail))
		return []row{{name: serverName, facts: facts}}, nil
	}
	sessionCount(sessions.doc, facts)
	return []row{{name: serverName, facts: facts}}, nil
}

// libraryRows answers: does each section still hold what it held.
//
// The fan-out is the shape a port gets wrong. `/library/sections` names the
// sections, and each section then costs ONE MORE REQUEST to
// `/library/sections/<key>/all` with a zero-size container window — so the number
// of documents this collection reads is not fixed by the collector, it is one per
// section. Each row therefore draws on two documents, and a section whose count
// could not be read keeps the rest of its row and says so.
func libraryRows(src source) ([]row, error) {
	deploy, err := gate(src)
	if err != nil {
		return nil, err
	}
	if len(deploy.missing) > 0 {
		reason := declineNoReceipts
		return nil, &reason
	}
	sections, err := src.document(pathSections)
	if err != nil {
		return nil, err
	}
	if sections.detail != "" {
		reason := declineServerSilent
		return nil, &reason
	}

	rows := []row{}
	for _, section := range sections.doc.get("MediaContainer").get("Directory").elements() {
		// The section KEY names the row, and it is the section's own identifier
		// rather than its position in this listing: a library created, deleted
		// and recreated leaves the keys non-consecutive, and a port that walked
		// by index would name one section after another and ask the wrong
		// section for its count.
		key := section.get("key")
		if !key.stated() {
			continue
		}
		name := pythonStr(key)

		facts := newObject()
		libraryFacts(section, facts)
		page, err := src.window(sectionWindowPath(name))
		if err != nil {
			return nil, err
		}
		if page.detail != "" {
			// The count narrows and says so. An unreadable count is NOT an empty
			// library, and the emptied-library shape cannot be ruled out without
			// it — which is why this is its own statement rather than a zero.
			facts.set(factItemCountUnobservable, stringValue(page.detail))
		} else {
			itemCount(page.doc, facts)
		}
		rows = append(rows, row{name: name, facts: facts})
	}
	return rows, nil
}

// sessionRows answers: what is playing right now, by whom, and is it transcoding.
//
// It reads the SAME document the server row read its count from — one request
// path, two collections — and it commits whatever it finds, including nothing. A
// server with nothing playing answers `{"MediaContainer": {"size": 0}}` with no
// `Metadata` member at all: zero rows, committed, which retires every session a
// previous batch published. A port that declined on the missing member would
// leave stale sessions standing forever, and one that crashed on it would never
// commit at all.
func sessionRows(src source) ([]row, error) {
	deploy, err := gate(src)
	if err != nil {
		return nil, err
	}
	if len(deploy.missing) > 0 {
		reason := declineNoReceipts
		return nil, &reason
	}
	sessions, err := src.document(pathSessions)
	if err != nil {
		return nil, err
	}
	if sessions.detail != "" {
		reason := declineServerSilent
		return nil, &reason
	}

	rows := []row{}
	for _, session := range sessions.doc.get("MediaContainer").get("Metadata").elements() {
		name, named := sessionName(session)
		if !named {
			continue
		}
		facts := newObject()
		sessionFacts(session, facts)
		rows = append(rows, row{name: name, facts: facts})
	}
	return rows, nil
}
