package main

// The object and evidence verbs (DESIGN 18, landed at R3c under the
// re-baseline's register rows 1–2). A collector is addressed by the native
// name it published — it does not know what id the collator minted — and
// every request token is data: never a path fragment, never an option,
// never part of a command string.
//
// The object verb serves the density the row deliberately does not carry:
// the acquisition-cost ruling stands — fetching NRestarts for every unit
// would turn one bus call into hundreds — so the detail facts live here,
// where one unit's properties are already in hand. The dependency edges
// ride the same response for the same reason: the row's reverse probe
// cannot afford a property read per unit, and here the forward directives
// are already read. The collator overlays this density on the row it
// holds; this response is one unit's properties, never a restatement of
// the listing.
//
// The evidence verb serves the raw documents those facts were read from —
// the only thing in this product that is not our interpretation — with
// the three environment members withheld as the declaration's redactions
// state: an Environment= line is where a credential lives, and evidence
// is the last place a reader may be shown one.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"
)

type verbEndRecord struct {
	Record    string `json:"record"`
	Verb      string `json:"verb"`
	Truncated bool   `json:"truncated"`
}

type evidenceDocumentRecord struct {
	Record    string `json:"record"`
	MediaType string `json:"media_type"`
	Digest    string `json:"digest"`
	Canon     string `json:"canon,omitempty"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
}

// The declared bounds, pinned against declaration.json by test: a bound
// only in the declaration is a promise, one only here is undeclared
// authority.
const (
	objectVerbBytes   = 262144
	evidenceVerbBytes = 1048576
)

// typedIfaces is the old TYPED_IFACES: the type-specific interfaces worth
// a second GetAll. The Service spelling is the test package's existing
// constant; the timer's arrives with the verb that reads it.
const detailTimerIface = "org.freedesktop.systemd1.Timer"

var typedIfaces = map[string]string{
	"service": "org.freedesktop.systemd1.Service",
	"timer":   detailTimerIface,
}

// The dependency directives the object verb asserts as edges — forward
// directions only: the reverse rows (RequiredBy, WantedBy) are the other
// unit's forward edge, and the collator's inverse machinery is the proper
// home for confirming them.
var dependencyEdges = [...]struct{ property, relType string }{
	{"Requires", "requires"},
	{"Wants", "wants"},
	{"PartOf", "member-of"},
	{"After", "after"},
}

// unsetU64 is systemd's not-set sentinel for usec properties.
const unsetU64 = "18446744073709551615"

// usecISO renders a usec-realtime token at seconds precision, UTC — the
// reference's own rendering. ("", false) for zero and the unset sentinel:
// a moment nobody scheduled is absent, never 1970.
func usecISO(token string) (string, bool) {
	if token == "" || token == "0" || token == unsetU64 {
		return "", false
	}
	usec, err := strconv.ParseUint(token, 10, 64)
	if err != nil {
		return "", false
	}
	return time.Unix(int64(usec/1e6), 0).UTC().Format("2006-01-02T15:04:05Z"), true
}

// propertyMap decodes one GetAll reply into its variants.
func propertyMap(raw []byte) (map[string]variant, error) {
	argument, err := singleArgument(raw, sigProperties)
	if err != nil {
		return nil, err
	}
	var properties map[string]variant
	if err := json.Unmarshal(argument, &properties); err != nil {
		return nil, fmt.Errorf("the argument is not a property map: %v", err)
	}
	return properties, nil
}

func propText(props map[string]variant, name string) string {
	v, ok := props[name]
	if !ok || v.Type != sigString {
		return ""
	}
	var s string
	if json.Unmarshal(v.Data, &s) != nil {
		return ""
	}
	return s
}

// propToken is the raw number token for a numeric property, "" where the
// property is missing or not numeric — pass-through, because the wire's
// type is the answer's type (§19: 12 and 12.0 are different answers).
func propToken(props map[string]variant, name string) string {
	v, ok := props[name]
	if !ok {
		return ""
	}
	switch v.Type {
	case "u", "t", "i", "x", "q", "n", "y":
		return string(v.Data)
	}
	return ""
}

// ── the shared acquisition ──────────────────────────────────────────────

type unitDetailReading struct {
	unitDoc    []byte
	typedDoc   []byte
	typedIface string
	declineRsn string
	declineTxt string
	runtime    error
}

// unitDetail resolves one published name to its documents. systemd keeps
// a Unit object for every name anything references, which is what lets
// the verbs answer for a not-found unit too.
func unitDetail(src source, name string) unitDetailReading {
	path, err := src.loadUnit(name)
	if err != nil {
		var refused *declined
		if errors.As(err, &refused) {
			return unitDetailReading{declineRsn: refused.reason, declineTxt: refused.detail}
		}
		if errors.Is(err, errUncaptured) {
			return unitDetailReading{runtime: err}
		}
		return unitDetailReading{declineRsn: "unavailable",
			declineTxt: "systemd would not resolve this unit name on the system bus"}
	}
	unitDoc, err := src.unitProperties(path)
	if err != nil {
		if errors.Is(err, errUncaptured) {
			return unitDetailReading{runtime: err}
		}
		return unitDetailReading{declineRsn: "unavailable",
			declineTxt: "the unit's properties did not answer on the system bus"}
	}
	props, err := propertyMap(unitDoc)
	if err != nil {
		return unitDetailReading{runtime: fmt.Errorf("unit properties: %v", err)}
	}
	reading := unitDetailReading{unitDoc: unitDoc}
	// The typed interface answers GetAll for a not-found name with several
	// hundred DEFAULTS — Result "success", NRestarts 0 on a unit with no
	// file — every one a property of nothing, so it is not fetched.
	if propText(props, "LoadState") != "not-found" {
		if iface := typedIfaces[unitType(name)]; iface != "" {
			if doc, err := src.typedProperties(path, iface); err == nil {
				reading.typedDoc, reading.typedIface = doc, iface
			}
			// Not staged, or a live bus refusing one interface: the unit
			// half serves alone either way — the same degradation.
		}
	}
	return reading
}

// ── object ──────────────────────────────────────────────────────────────

func serveObject(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if collection != "units" {
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: "unsupported", Detail: "this collector does not serve this collection"})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
		return verbExit(out, stderr)
	}
	reading := unitDetail(src, name)
	if reading.runtime != nil {
		fmt.Fprintln(stderr, reading.runtime)
		return exitRuntime
	}
	if reading.declineRsn != "" {
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: reading.declineRsn, Detail: reading.declineTxt})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
		return verbExit(out, stderr)
	}
	props, err := propertyMap(reading.unitDoc)
	if err != nil {
		fmt.Fprintln(stderr, "unit properties:", err)
		return exitRuntime
	}
	lists, err := decodeStringListProperties(reading.unitDoc)
	if err != nil {
		fmt.Fprintln(stderr, "unit properties:", err)
		return exitRuntime
	}

	facts := newFactRow()
	var absent []string
	keep := func(fact string) {
		if value := propText(props, fact); value != "" {
			facts.setString(fact, value)
		} else {
			absent = append(absent, fact)
		}
	}
	for _, fact := range [...]string{"LoadState", "ActiveState", "SubState",
		"Description"} {
		keep(fact)
	}
	notFound := propText(props, "LoadState") == "not-found"
	// systemd's own account of why a unit did not load, present only when
	// there is one — it separates ordinary absence from a fragment that
	// exists and is broken, which reads identically otherwise.
	if loadError := lists["LoadError"]; len(loadError) > 0 &&
		(loadError[len(loadError)-1] != "" || loadError[0] != "") {
		message := loadError[len(loadError)-1]
		if message == "" {
			message = loadError[0]
		}
		facts.setString("LoadError", message)
	}
	if !notFound {
		// Everything below describes a unit systemd loaded: a file it came
		// from, a state that file is installed in, a moment it started. A
		// name with no file has none of them, and systemd answers with ""
		// and 0 anyway — absent facts, because omission reads as
		// does-not-apply where an empty string reads as measured emptiness.
		keep("UnitFileState")
		keep("FragmentPath")
		if iso, ok := usecISO(propToken(props, "ActiveEnterTimestamp")); ok {
			facts.setString("ActiveEnterTimestamp", iso)
		} else {
			absent = append(absent, "ActiveEnterTimestamp")
		}
		if reading.typedIface == typedIfaces["service"] && reading.typedDoc != nil {
			typed, terr := propertyMap(reading.typedDoc)
			if terr == nil {
				for _, fact := range [...]string{"MainPID", "NRestarts", "TasksCurrent"} {
					if token := propToken(typed, fact); token != "" && token != unsetU64 {
						facts.set(fact, token)
					} else {
						absent = append(absent, fact)
					}
				}
				if result := propText(typed, "Result"); result != "" {
					facts.setString("Result", result)
				} else {
					absent = append(absent, "Result")
				}
				if iso, ok := usecISO(propToken(typed, "ExecMainStartTimestamp")); ok {
					facts.setString("ExecMainStartTimestamp", iso)
				} else {
					absent = append(absent, "ExecMainStartTimestamp")
				}
			}
		}
		if reading.typedIface == detailTimerIface && reading.typedDoc != nil {
			typed, terr := propertyMap(reading.typedDoc)
			if terr == nil {
				for property, fact := range map[string]string{
					"NextElapseUSecRealtime": "NextElapse",
					"LastTriggerUSec":        "LastTrigger"} {
					if iso, ok := usecISO(propToken(typed, property)); ok {
						facts.setString(fact, iso)
					} else {
						absent = append(absent, fact)
					}
				}
			}
		}
	}

	sort.Strings(absent)
	out.emit(objectRecord{
		Record:     "object",
		Collection: collection,
		Name:       name,
		Type:       unitType(name),
		Facts:      facts.encode(),
		Absent:     absent,
		At:         src.stamp(0),
	})
	for _, edge := range dependencyEdges {
		for _, target := range lists[edge.property] {
			if target == "" {
				continue
			}
			out.emit(relationAssertionRecord{
				Record:     "relation_assertion",
				Collection: collection,
				Name:       name,
				Vantage:    collection,
				Type:       edge.relType,
				Target:     assertionTarget{Kind: "unit", Name: target},
			})
		}
	}
	// The object response is one unit's properties and sits far inside the
	// declared bound by construction; the bound genuinely bites on
	// evidence, where it is enforced on the payload.
	out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
	return verbExit(out, stderr)
}

// ── evidence ────────────────────────────────────────────────────────────

// redactedProperties strips the three declared environment members from a
// GetAll document — withheld entirely, exactly as the declaration's
// redactions state.
var withheldProperties = [...]string{"Environment", "UnsetEnvironment", "PassEnvironment"}

func redactedProperties(raw []byte) (json.RawMessage, error) {
	var doc struct {
		Type string            `json:"type"`
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if len(doc.Data) != 1 {
		return nil, fmt.Errorf("expected one argument, got %d", len(doc.Data))
	}
	var properties map[string]json.RawMessage
	if err := json.Unmarshal(doc.Data[0], &properties); err != nil {
		return nil, err
	}
	for _, name := range withheldProperties {
		delete(properties, name)
	}
	rebuilt, err := json.Marshal(map[string]any{
		"type": doc.Type, "data": []any{properties}})
	if err != nil {
		return nil, err
	}
	return rebuilt, nil
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if collection != "units" {
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: "unsupported", Detail: "this collector does not serve this collection"})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "evidence"})
		return verbExit(out, stderr)
	}
	reading := unitDetail(src, name)
	if reading.runtime != nil {
		fmt.Fprintln(stderr, reading.runtime)
		return exitRuntime
	}
	if reading.declineRsn != "" {
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: reading.declineRsn, Detail: reading.declineTxt})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "evidence"})
		return verbExit(out, stderr)
	}

	payload := map[string]json.RawMessage{}
	document, err := redactedProperties(reading.unitDoc)
	if err != nil {
		fmt.Fprintln(stderr, "evidence payload:", err)
		return exitRuntime
	}
	payload[unitIface] = document
	if reading.typedDoc != nil {
		document, err := redactedProperties(reading.typedDoc)
		if err != nil {
			fmt.Fprintln(stderr, "evidence payload:", err)
			return exitRuntime
		}
		payload[reading.typedIface] = document
	}
	// Go marshals map keys sorted, which is the canon the digest names:
	// re-reading and re-digesting is a meaningful comparison, not a coin
	// toss over key ordering (DESIGN 19).
	canonical, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintln(stderr, "evidence payload:", err)
		return exitRuntime
	}
	truncated := false
	if len(canonical) > evidenceVerbBytes {
		// A truncated document marked truncated is still evidence; an
		// unmarked one is a lie about the system (DESIGN 19). The digest
		// is over the bytes AS SERVED, so it stays checkable.
		canonical = canonical[:evidenceVerbBytes]
		truncated = true
	}
	sum := sha256.Sum256(canonical)
	out.emit(evidenceDocumentRecord{
		Record:    "evidence_document",
		MediaType: "application/json",
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		Canon:     "jcs/1",
		Bytes:     len(canonical),
		Truncated: truncated,
	})
	if out.err == nil {
		if _, err := stdout.Write(append(canonical, '\n')); err != nil {
			out.err = err
		}
	}
	out.emit(verbEndRecord{Record: "verb_end", Verb: "evidence",
		Truncated: truncated})
	return verbExit(out, stderr)
}

func verbExit(out *emitter, stderr io.Writer) int {
	if out.err != nil {
		fmt.Fprintln(stderr, "writing the response:", out.err)
		return exitRuntime
	}
	return exitOK
}
