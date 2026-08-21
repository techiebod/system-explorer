// Package wire is the collator's side of the collect stream (DESIGN §18–19).
//
// The collator is the validating party: it issued the generations and it
// holds the declaration, so it is the tier that can check what varies
// across streams. Everything here is judged before anything is applied —
// a violation rejects the whole batch with a recorded reason, because an
// invalid stream is authoritative for nothing and applying half of one
// would put a partial read where a committed collection belongs.
package wire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// Violation is a structural defect in a received stream. It carries a
// short machine-stable reason (recorded verbatim in the store) so a
// rejection can be audited later without re-reading the stream.
type Violation struct {
	Reason string
	Detail string
}

func (v *Violation) Error() string {
	if v.Detail == "" {
		return v.Reason
	}
	return v.Reason + ": " + v.Detail
}

func violation(reason, format string, args ...any) *Violation {
	return &Violation{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

// collectionName mirrors the contract's collection-name pattern: the
// stream may only speak under a name a declaration could have declared.
var collectionName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// uuidShaped is the 8-4-4-4-12 hex shape for boot_id. The dashless
// 32-hex spelling is machine-id's — stable across boots — and refusing
// it is the point (contract se.stream/1).
var uuidShaped = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

const nilUUID = "00000000-0000-0000-0000-000000000000"

// Begin opens a batch. Instance is a pointer because null and absent are
// different claims and "" is a third scope nobody declared — the schema
// refuses it and so do we.
type Begin struct {
	Request     string
	Batch       string
	Declaration string
	BootID      string
	Timens      int64
	Instance    *string
	Generations map[string]uint64
}

// Object is one emitted thing. Facts, Names, Absent and Evidence are kept
// as canonical re-marshalled bytes (sorted keys, source number lexemes via
// json.Number) so that hashing the applied set is deterministic without
// trusting the sender's key order.
type Object struct {
	Collection string
	Name       string
	// Type is the object's structural kind, "" when the record carried
	// none (ruled 2026-08-21): scsi-host vs disk, service vs slice. It
	// decides which health statement a row is entitled to, so it is
	// carried verbatim rather than inferred anywhere downstream.
	Type       string
	Facts      json.RawMessage
	Names      json.RawMessage // nil when the record carried none
	Absent     []string
	Evidence   json.RawMessage // nil when the record carried none
	At         float64
}

// Relation is a relation_assertion as received. The collator core stores
// nothing from it yet (joins are a later phase) but the counts must
// reconcile, so it is parsed and counted rather than skipped.
type Relation struct {
	Collection string
	Name       string
	Type       string
	Vantage    string
	TargetKind string
	TargetName string
	Facts      json.RawMessage
}

// Unobservable is a per-fact could-not-read. Counted against the commit.
type Unobservable struct {
	Collection string
	Name       string
	Fact       string
	Reason     string
	Detail     string
}

// Decline is a collection-level statement. absent is authoritative-empty
// and commits; the other three never do (DESIGN §19).
type Decline struct {
	Collection string
	Reason     string
	Detail     string
}

// Commit closes a collection. All three counts are required, never
// optional: a subject that can disable the truncation check by omitting
// a count has defeated it.
type Commit struct {
	Collection   string
	Generation   uint64
	Objects      int64
	Assertions   int64
	Unobservable int64
	// The collector's own account of what this collection cost, advisory
	// by construction (DESIGN 19): bounded here — finite, non-negative —
	// and never authenticated, because a replayed collector cannot measure
	// real cost and a live one could misreport it. Negative when the
	// commit carried none, so "not reported" and "cost zero" stay
	// distinguishable readings.
	CPUMs float64
}

// End closes the batch and the request that begin opened.
type End struct {
	Request string
	Batch   string
	CPUMs   float64
	WallMs  float64
}

// CollectionStream is everything one collection said in one batch.
type CollectionStream struct {
	Objects       []Object
	Assertions    []Relation
	Unobservables []Unobservable
	Decline       *Decline
	Commit        *Commit
}

// Batch is a fully validated stream. Only a value of this type reaches
// the store: construction is the proof of structural validity.
// ContentHash commits to the exact bytes received — the identity a
// transport retry preserves (same bytes, same id, DESIGN §19), which is
// what lets the ack table tell a retry from a batch id someone reused.
type Batch struct {
	Begin       Begin
	Collections map[string]*CollectionStream
	End         End
	ContentHash string
}

// ParseBatch validates NDJSON bytes against the issued generations and
// returns the batch, or the first *Violation found. The rules here are
// exactly the run-varying-member rules DESIGN §19 assigns to the collator:
// echoes, counts, order, and the closed shapes of the contract schemas.
func ParseBatch(raw []byte, issued map[string]uint64) (*Batch, error) {
	lines := splitLines(raw)
	if len(lines) == 0 {
		return nil, violation("empty-stream", "no records received")
	}

	b := &Batch{Collections: map[string]*CollectionStream{}, ContentHash: ContentHash(raw)}
	seenBegin := false
	seenEnd := false
	// lastAt enforces at non-decreasing per collection, in emission order.
	lastAt := map[string]float64{}
	// seenNames refuses a native name emitted twice in one collection:
	// both emissions would mint the same id (law 1), and applying them
	// would be a silent last-writer-wins the contract never granted.
	seenNames := map[string]map[string]bool{}

	for i, line := range lines {
		rec, err := decodeRecord(line)
		if err != nil {
			return nil, violation("unparseable-record", "line %d: %v", i+1, err)
		}
		kind, ok := rec["record"].(string)
		if !ok {
			return nil, violation("missing-record-discriminator", "line %d", i+1)
		}
		if seenEnd {
			return nil, violation("record-after-end", "line %d: %s after end", i+1, kind)
		}
		if !seenBegin && kind != "begin" {
			return nil, violation("begin-not-first", "line %d: %s before begin", i+1, kind)
		}

		switch kind {
		case "begin":
			if seenBegin {
				return nil, violation("duplicate-begin", "line %d", i+1)
			}
			seenBegin = true
			begin, verr := parseBegin(rec, issued)
			if verr != nil {
				return nil, verr
			}
			b.Begin = *begin
		case "object":
			obj, verr := parseObject(rec, issued)
			if verr != nil {
				return nil, verr
			}
			cs, verr := b.openEmitting(obj.Collection, kind)
			if verr != nil {
				return nil, verr
			}
			if last, seen := lastAt[obj.Collection]; seen && obj.At < last {
				return nil, violation("at-decreasing",
					"collection %s: at %v after %v", obj.Collection, obj.At, last)
			}
			lastAt[obj.Collection] = obj.At
			if seenNames[obj.Collection] == nil {
				seenNames[obj.Collection] = map[string]bool{}
			}
			if seenNames[obj.Collection][obj.Name] {
				return nil, violation("duplicate-object-name",
					"collection %s: %q emitted twice", obj.Collection, obj.Name)
			}
			seenNames[obj.Collection][obj.Name] = true
			cs.Objects = append(cs.Objects, *obj)
		case "relation_assertion":
			rel, verr := parseRelation(rec, issued)
			if verr != nil {
				return nil, verr
			}
			cs, verr := b.openEmitting(rel.Collection, kind)
			if verr != nil {
				return nil, verr
			}
			cs.Assertions = append(cs.Assertions, *rel)
		case "unobservable":
			u, verr := parseUnobservable(rec, issued)
			if verr != nil {
				return nil, verr
			}
			cs, verr := b.openEmitting(u.Collection, kind)
			if verr != nil {
				return nil, verr
			}
			cs.Unobservables = append(cs.Unobservables, *u)
		case "decline":
			d, verr := parseDecline(rec, issued)
			if verr != nil {
				return nil, verr
			}
			cs, verr := b.open(d.Collection)
			if verr != nil {
				return nil, verr
			}
			// A decline is a statement about the whole collection; a
			// collection that already emitted anything cannot also decline.
			if d2 := cs.Decline; d2 != nil {
				return nil, violation("duplicate-decline", "collection %s", d.Collection)
			}
			if len(cs.Objects) > 0 || len(cs.Assertions) > 0 || len(cs.Unobservables) > 0 {
				return nil, violation("decline-after-records", "collection %s", d.Collection)
			}
			cs.Decline = d
		case "commit":
			c, verr := parseCommit(rec, issued)
			if verr != nil {
				return nil, verr
			}
			cs, verr := b.open(c.Collection)
			if verr != nil {
				return nil, verr
			}
			if cs.Commit != nil {
				return nil, violation("duplicate-commit", "collection %s", c.Collection)
			}
			cs.Commit = c
		case "end":
			seenEnd = true
			end, verr := parseEnd(rec)
			if verr != nil {
				return nil, verr
			}
			b.End = *end
		default:
			return nil, violation("unknown-record", "line %d: %q", i+1, kind)
		}
	}
	if !seenEnd {
		return nil, violation("missing-end", "stream closed without an end record")
	}
	if verr := b.check(issued); verr != nil {
		return nil, verr
	}
	return b, nil
}

// open returns the collection's stream, refusing any record for a
// collection whose commit has already closed it — a committed collection
// is authoritative, so nothing may trail in behind its counts.
func (b *Batch) open(collection string) (*CollectionStream, *Violation) {
	cs := b.Collections[collection]
	if cs == nil {
		cs = &CollectionStream{}
		b.Collections[collection] = cs
	}
	if cs.Commit != nil {
		return nil, violation("record-after-commit", "collection %s", collection)
	}
	return cs, nil
}

// openEmitting is open for the emitting records — object,
// relation_assertion, unobservable. A decline is a statement about the
// whole collection, so it closes the collection to everything except
// absent's zero commit: an emission after it is the mirror of
// decline-after-records, and accepting it would drop the record silently
// where the collection's verdict already stands.
func (b *Batch) openEmitting(collection, kind string) (*CollectionStream, *Violation) {
	cs, verr := b.open(collection)
	if verr != nil {
		return nil, verr
	}
	if cs.Decline != nil {
		return nil, violation("record-after-decline",
			"collection %s: %s after its decline", collection, kind)
	}
	return cs, nil
}

// check runs the whole-batch rules that only hold once the stream is
// complete: echoes, counts, decline/commit pairing, and wall_ms.
func (b *Batch) check(issued map[string]uint64) *Violation {
	// end closes the batch and request that begin opened (DESIGN §19).
	if b.End.Request != b.Begin.Request || b.End.Batch != b.Begin.Batch {
		return violation("end-echo-mismatch",
			"end %s/%s does not echo begin %s/%s",
			b.End.Request, b.End.Batch, b.Begin.Request, b.Begin.Batch)
	}
	anyObjects := false
	for name, cs := range b.Collections {
		if cs.Decline != nil {
			if cs.Decline.Reason == "absent" {
				// absent is a successful reading, so it commits — the
				// decline and its zero commit are one statement, and the
				// commit is the ZERO commit: an absent collection has no
				// objects to count, relate or fail to read.
				if cs.Commit == nil {
					return violation("absent-without-commit", "collection %s", name)
				}
				if cs.Commit.Objects != 0 || cs.Commit.Assertions != 0 || cs.Commit.Unobservable != 0 {
					return violation("absent-with-objects",
						"collection %s committed counts %d/%d/%d under an absent decline; absent commits empty",
						name, cs.Commit.Objects, cs.Commit.Assertions, cs.Commit.Unobservable)
				}
			} else if cs.Commit != nil {
				// unauthorised/unavailable/unsupported established nothing,
				// so nothing may commit under them.
				return violation("decline-with-commit",
					"collection %s declined %s and also committed", name, cs.Decline.Reason)
			}
		}
		if cs.Commit != nil {
			// The commit's counts let the collator check it received what
			// was sent; a mismatch is truncation or invention, either way
			// the stream is not what the collector claims it sent.
			if int64(len(cs.Objects)) != cs.Commit.Objects ||
				int64(len(cs.Assertions)) != cs.Commit.Assertions ||
				int64(len(cs.Unobservables)) != cs.Commit.Unobservable {
				return violation("commit-count-mismatch",
					"collection %s: commit says %d/%d/%d, stream carried %d/%d/%d",
					name, cs.Commit.Objects, cs.Commit.Assertions, cs.Commit.Unobservable,
					len(cs.Objects), len(cs.Assertions), len(cs.Unobservables))
			}
		}
		if len(cs.Objects) > 0 {
			anyObjects = true
		}
	}
	// A batch that emitted objects reports a positive wall_ms — the zero
	// is the stub's signature, not a fast machine's.
	if anyObjects && !(b.End.WallMs > 0) {
		return violation("wall-ms-not-positive", "objects were emitted with wall_ms %v", b.End.WallMs)
	}
	_ = issued
	return nil
}

// Uncommitted lists issued collections that neither committed nor
// declined. They are not violations — the stream may be structurally
// legal around them — but they are held and never applied: a partial
// read must not be allowed to delete anything (DESIGN §19).
func (b *Batch) Uncommitted() []string {
	var out []string
	for name := range b.Begin.Generations {
		cs := b.Collections[name]
		if cs == nil || (cs.Commit == nil && cs.Decline == nil) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// ── record parsers ──────────────────────────────────────────────────────

// decodeRecord parses one line with UseNumber so number lexemes survive
// verbatim into the canonical re-marshal — 61.2 stays 61.2, and a
// content hash over two identical streams is the same hash.
func decodeRecord(line []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var rec map[string]any
	if err := dec.Decode(&rec); err != nil {
		return nil, err
	}
	// Trailing content after the JSON value would mean two records on one
	// line — one of them invisible to a line-based reader.
	if dec.More() {
		return nil, fmt.Errorf("trailing content after record")
	}
	return rec, nil
}

// fields enforces the contract's closed-object rule: a member the
// contract does not name is a claim the judge cannot see, which is how
// exported Go field names once shipped as {"Stable":…} unnoticed.
func fields(rec map[string]any, kind string, required []string, optional []string) *Violation {
	allowed := map[string]bool{"record": true}
	for _, f := range required {
		allowed[f] = true
		if _, ok := rec[f]; !ok {
			return violation("missing-member", "%s record lacks %q", kind, f)
		}
	}
	for _, f := range optional {
		allowed[f] = true
	}
	for f := range rec {
		if !allowed[f] {
			return violation("undeclared-member", "%s record carries %q", kind, f)
		}
	}
	return nil
}

func identity(rec map[string]any, kind, member string) (string, *Violation) {
	s, ok := rec[member].(string)
	if !ok || s == "" {
		return "", violation("bad-identity", "%s.%s must be a non-empty string", kind, member)
	}
	return s, nil
}

func knownCollection(rec map[string]any, kind string, issued map[string]uint64) (string, *Violation) {
	name, verr := identity(rec, kind, "collection")
	if verr != nil {
		return "", verr
	}
	if !collectionName.MatchString(name) {
		return "", violation("bad-collection-name", "%s: %q", kind, name)
	}
	// The collator issued the request, so it knows which collections it
	// asked for; a record for anything else was never requested.
	if _, ok := issued[name]; !ok {
		return "", violation("unissued-collection", "%s record for %q, which was not requested", kind, name)
	}
	return name, nil
}

func parseBegin(rec map[string]any, issued map[string]uint64) (*Begin, *Violation) {
	if verr := fields(rec, "begin",
		[]string{"request", "batch", "declaration", "boot_id", "timens", "instance", "generations"},
		nil); verr != nil {
		return nil, verr
	}
	b := &Begin{Generations: map[string]uint64{}}
	var verr *Violation
	if b.Request, verr = identity(rec, "begin", "request"); verr != nil {
		return nil, verr
	}
	if b.Batch, verr = identity(rec, "begin", "batch"); verr != nil {
		return nil, verr
	}
	if b.Declaration, verr = identity(rec, "begin", "declaration"); verr != nil {
		return nil, verr
	}
	if b.BootID, verr = identity(rec, "begin", "boot_id"); verr != nil {
		return nil, verr
	}
	// UUID-shaped and never nil: the shape catches the stub and the nil
	// placeholder, which is all a single stream can authenticate — a
	// constant-but-plausible id is the cross-boot live check's to catch.
	if !uuidShaped.MatchString(b.BootID) || strings.EqualFold(b.BootID, nilUUID) {
		return nil, violation("bad-boot-id", "%q", b.BootID)
	}
	timens, ok := rec["timens"].(json.Number)
	if !ok {
		return nil, violation("bad-timens", "timens must be an integer")
	}
	n, err := timens.Int64()
	if err != nil {
		return nil, violation("bad-timens", "timens %v is not an integer", timens)
	}
	b.Timens = n
	switch inst := rec["instance"].(type) {
	case nil:
		b.Instance = nil // host-native; only null means it
	case string:
		if inst == "" {
			// "" would mint a third scope nobody declared (contract).
			return nil, violation("bad-instance", "instance may not be empty")
		}
		b.Instance = &inst
	default:
		return nil, violation("bad-instance", "instance must be a string or null")
	}
	gens, ok := rec["generations"].(map[string]any)
	if !ok {
		return nil, violation("bad-generations", "generations must be an object")
	}
	for name, v := range gens {
		if !collectionName.MatchString(name) {
			return nil, violation("bad-generations", "collection name %q", name)
		}
		num, ok := v.(json.Number)
		if !ok {
			return nil, violation("bad-generations", "%s: generation must be an integer", name)
		}
		g, err := num.Int64()
		if err != nil || g < 0 {
			return nil, violation("bad-generations", "%s: generation %v", name, num)
		}
		b.Generations[name] = uint64(g)
	}
	// The echo rule: begin.generations equals what was issued, exactly.
	// A missing collection is a request the collector silently dropped; an
	// extra one was never issued; a changed number is somebody else's
	// generation — all three void the batch's claim to its generations.
	if len(b.Generations) != len(issued) {
		return nil, violation("generations-echo-mismatch",
			"issued %d collections, begin echoes %d", len(issued), len(b.Generations))
	}
	for name, g := range issued {
		if got, ok := b.Generations[name]; !ok || got != g {
			return nil, violation("generations-echo-mismatch",
				"collection %s: issued %d, begin echoes %v", name, g, b.Generations[name])
		}
	}
	return b, nil
}

func parseObject(rec map[string]any, issued map[string]uint64) (*Object, *Violation) {
	if verr := fields(rec, "object",
		[]string{"collection", "name", "facts", "at"},
		[]string{"type", "names", "absent", "evidence"}); verr != nil {
		return nil, verr
	}
	o := &Object{}
	var verr *Violation
	if o.Collection, verr = knownCollection(rec, "object", issued); verr != nil {
		return nil, verr
	}
	if o.Name, verr = identity(rec, "object", "name"); verr != nil {
		return nil, verr
	}
	if raw, present := rec["type"]; present {
		s, ok := raw.(string)
		if !ok || !collectionName.MatchString(s) {
			return nil, violation("bad-type",
				"object %s: type must be a lowercase name, got %v", o.Name, raw)
		}
		o.Type = s
	}
	facts, ok := rec["facts"].(map[string]any)
	if !ok {
		return nil, violation("bad-facts", "object %s: facts must be an object", o.Name)
	}
	// A fact's value is never null, at any depth: could-not-read is the
	// unobservable record and has-no-such-property is the absent list,
	// each on its own channel, and a null names neither. The recursive
	// walk exists because the flat rule this replaces passed the same
	// null one level down, inside a nested row.
	if path := findNull(facts, "facts"); path != "" {
		return nil, violation("null-fact", "object %s: %s", o.Name, path)
	}
	o.Facts = canonical(facts)
	if names, present := rec["names"]; present {
		verr := checkNames(names, o.Name)
		if verr != nil {
			return nil, verr
		}
		o.Names = canonical(names)
	}
	if absent, present := rec["absent"]; present {
		list, ok := absent.([]any)
		if !ok {
			return nil, violation("bad-absent", "object %s: absent must be an array", o.Name)
		}
		for _, item := range list {
			s, ok := item.(string)
			if !ok || s == "" {
				return nil, violation("bad-absent", "object %s: absent entries must be non-empty strings", o.Name)
			}
			o.Absent = append(o.Absent, s)
		}
	}
	if ev, present := rec["evidence"]; present {
		verr := checkEvidence(ev, o.Name)
		if verr != nil {
			return nil, verr
		}
		o.Evidence = canonical(ev)
	}
	at, ok := rec["at"].(json.Number)
	if !ok {
		return nil, violation("bad-at", "object %s: at must be a number", o.Name)
	}
	f, err := at.Float64()
	if err != nil {
		return nil, violation("bad-at", "object %s: at %v", o.Name, at)
	}
	// Boot-scale by construction: zero and below is a reading nobody
	// took; past 1e9 (~31 years of uptime) it is a wall clock smuggled
	// onto the wrong axis (contract se.stream/1).
	if !(f > 0) || f > 1e9 {
		return nil, violation("at-out-of-range", "object %s: at %v", o.Name, f)
	}
	o.At = f
	return o, nil
}

func checkNames(names any, objName string) *Violation {
	m, ok := names.(map[string]any)
	if !ok {
		return violation("bad-names", "object %s: names must be an object", objName)
	}
	for class, families := range m {
		// Closed to exactly two classes: the marshalling bug this catches
		// emitted {"Stable":…} and every name silently left the join.
		if class != "stable" && class != "ephemeral" {
			return violation("bad-names", "object %s: unknown stability class %q", objName, class)
		}
		fm, ok := families.(map[string]any)
		if !ok {
			return violation("bad-names", "object %s: %s must be an object", objName, class)
		}
		for family, v := range fm {
			switch val := v.(type) {
			case string:
				if val == "" {
					return violation("bad-names", "object %s: %s.%s is empty", objName, class, family)
				}
			case json.Number:
			case []any:
				for _, item := range val {
					switch s := item.(type) {
					case string:
						if s == "" {
							return violation("bad-names", "object %s: %s.%s has an empty name", objName, class, family)
						}
					case json.Number:
					default:
						return violation("bad-names", "object %s: %s.%s has a non-scalar name", objName, class, family)
					}
				}
			default:
				return violation("bad-names", "object %s: %s.%s must be a scalar or a list of scalars", objName, class, family)
			}
		}
	}
	return nil
}

func checkEvidence(ev any, objName string) *Violation {
	m, ok := ev.(map[string]any)
	if !ok {
		return violation("bad-evidence", "object %s: evidence must be an object", objName)
	}
	for member := range m {
		if member != "digest" && member != "media_type" && member != "canon" {
			return violation("bad-evidence", "object %s: evidence carries %q", objName, member)
		}
	}
	digest, ok := m["digest"].(string)
	if !ok || digest == "" {
		return violation("bad-evidence", "object %s: digest must be a non-empty string", objName)
	}
	mediaType, ok := m["media_type"].(string)
	if !ok || mediaType == "" {
		return violation("bad-evidence", "object %s: media_type must be a non-empty string", objName)
	}
	_, hasCanon := m["canon"]
	// JSON digests under a named canonicalisation or the digest is a coin
	// toss over key ordering; any other media type digests exact bytes, so
	// a canon there would claim a rule that was never applied.
	if mediaType == "application/json" && !hasCanon {
		return violation("bad-evidence", "object %s: application/json evidence requires canon", objName)
	}
	if mediaType != "application/json" && hasCanon {
		return violation("bad-evidence", "object %s: canon on non-JSON media type %q", objName, mediaType)
	}
	if hasCanon {
		if s, ok := m["canon"].(string); !ok || s == "" {
			return violation("bad-evidence", "object %s: canon must be a non-empty string", objName)
		}
	}
	return nil
}

func parseRelation(rec map[string]any, issued map[string]uint64) (*Relation, *Violation) {
	if verr := fields(rec, "relation_assertion",
		[]string{"collection", "name", "type", "vantage", "target"},
		[]string{"facts"}); verr != nil {
		return nil, verr
	}
	r := &Relation{}
	var verr *Violation
	if r.Collection, verr = knownCollection(rec, "relation_assertion", issued); verr != nil {
		return nil, verr
	}
	if r.Name, verr = identity(rec, "relation_assertion", "name"); verr != nil {
		return nil, verr
	}
	if r.Type, verr = identity(rec, "relation_assertion", "type"); verr != nil {
		return nil, verr
	}
	if r.Vantage, verr = identity(rec, "relation_assertion", "vantage"); verr != nil {
		return nil, verr
	}
	target, ok := rec["target"].(map[string]any)
	if !ok {
		return nil, violation("bad-target", "relation from %s: target must be an object", r.Name)
	}
	// A target carries a name and a kind, never an id and never an
	// observability — whether the far end was seen is a fact about
	// another collector's output, which only the collator holds. The
	// closed member set refuses both.
	for member := range target {
		if member != "kind" && member != "name" {
			return nil, violation("bad-target", "relation from %s: target carries %q", r.Name, member)
		}
	}
	if r.TargetKind, verr = identity(target, "target", "kind"); verr != nil {
		return nil, verr
	}
	if r.TargetName, verr = identity(target, "target", "name"); verr != nil {
		return nil, verr
	}
	if facts, present := rec["facts"]; present {
		fm, ok := facts.(map[string]any)
		if !ok {
			return nil, violation("bad-facts", "relation from %s: facts must be an object", r.Name)
		}
		if path := findNull(fm, "facts"); path != "" {
			return nil, violation("null-fact", "relation from %s: %s", r.Name, path)
		}
		r.Facts = canonical(fm)
	}
	return r, nil
}

func parseUnobservable(rec map[string]any, issued map[string]uint64) (*Unobservable, *Violation) {
	if verr := fields(rec, "unobservable",
		[]string{"collection", "name", "fact", "reason"},
		[]string{"detail"}); verr != nil {
		return nil, verr
	}
	u := &Unobservable{}
	var verr *Violation
	if u.Collection, verr = knownCollection(rec, "unobservable", issued); verr != nil {
		return nil, verr
	}
	if u.Name, verr = identity(rec, "unobservable", "name"); verr != nil {
		return nil, verr
	}
	if u.Fact, verr = identity(rec, "unobservable", "fact"); verr != nil {
		return nil, verr
	}
	reason, ok := rec["reason"].(string)
	if !ok {
		return nil, violation("bad-unobservable-reason", "%s.%s: reason must be a string", u.Name, u.Fact)
	}
	// The decline vocabulary minus absent: could-not-read-because-it-is-
	// not-there is the absent list's statement, on its own channel.
	switch reason {
	case "unauthorised", "unavailable", "unsupported":
		u.Reason = reason
	default:
		return nil, violation("bad-unobservable-reason", "%s.%s: %q", u.Name, u.Fact, reason)
	}
	if detail, present := rec["detail"]; present {
		s, ok := detail.(string)
		if !ok {
			return nil, violation("bad-detail", "unobservable %s.%s", u.Name, u.Fact)
		}
		u.Detail = s
	}
	return u, nil
}

func parseDecline(rec map[string]any, issued map[string]uint64) (*Decline, *Violation) {
	if verr := fields(rec, "decline",
		[]string{"collection", "reason"},
		[]string{"detail"}); verr != nil {
		return nil, verr
	}
	d := &Decline{}
	var verr *Violation
	if d.Collection, verr = knownCollection(rec, "decline", issued); verr != nil {
		return nil, verr
	}
	reason, ok := rec["reason"].(string)
	if !ok {
		return nil, violation("bad-decline-reason", "collection %s: reason must be a string", d.Collection)
	}
	// The closed vocabulary. A reason outside it is not a new kind of
	// decline, it is a stream the contract does not describe.
	switch reason {
	case "absent", "unauthorised", "unavailable", "unsupported":
		d.Reason = reason
	default:
		return nil, violation("bad-decline-reason", "collection %s: %q", d.Collection, reason)
	}
	if detail, present := rec["detail"]; present {
		s, ok := detail.(string)
		if !ok {
			return nil, violation("bad-detail", "decline %s", d.Collection)
		}
		d.Detail = s
	}
	return d, nil
}

func parseCommit(rec map[string]any, issued map[string]uint64) (*Commit, *Violation) {
	if verr := fields(rec, "commit",
		[]string{"collection", "generation", "objects", "assertions", "unobservable"},
		[]string{"cpu_ms"}); verr != nil {
		return nil, verr
	}
	c := &Commit{}
	var verr *Violation
	if c.Collection, verr = knownCollection(rec, "commit", issued); verr != nil {
		return nil, verr
	}
	gen, verr := count(rec, "commit", "generation")
	if verr != nil {
		return nil, verr
	}
	c.Generation = uint64(gen)
	// A commit echoes the generation the request line issued. Anything
	// else is a generation somebody minted — and only the collator mints.
	if issuedGen := issued[c.Collection]; c.Generation != issuedGen {
		return nil, violation("generation-echo-mismatch",
			"collection %s: issued %d, commit echoes %d", c.Collection, issuedGen, c.Generation)
	}
	if c.Objects, verr = count(rec, "commit", "objects"); verr != nil {
		return nil, verr
	}
	if c.Assertions, verr = count(rec, "commit", "assertions"); verr != nil {
		return nil, verr
	}
	if c.Unobservable, verr = count(rec, "commit", "unobservable"); verr != nil {
		return nil, verr
	}
	// Bounded before it is kept (the measured-cost rule): the value is
	// advisory, the shape is not. -1 when the commit carried none, so
	// "not reported" and "cost zero" stay distinguishable readings.
	c.CPUMs = -1
	if cpu, present := rec["cpu_ms"]; present {
		num, ok := cpu.(json.Number)
		if !ok {
			return nil, violation("bad-cpu-ms", "collection %s", c.Collection)
		}
		if verr := checkMeasured(num, "bad-cpu-ms", "commit "+c.Collection); verr != nil {
			return nil, verr
		}
		f, _ := num.Float64()
		c.CPUMs = f
	}
	return c, nil
}

func parseEnd(rec map[string]any) (*End, *Violation) {
	if verr := fields(rec, "end",
		[]string{"request", "batch"},
		[]string{"cpu_ms", "wall_ms"}); verr != nil {
		return nil, verr
	}
	e := &End{}
	var verr *Violation
	if e.Request, verr = identity(rec, "end", "request"); verr != nil {
		return nil, verr
	}
	if e.Batch, verr = identity(rec, "end", "batch"); verr != nil {
		return nil, verr
	}
	for member, dst := range map[string]*float64{"cpu_ms": &e.CPUMs, "wall_ms": &e.WallMs} {
		if v, present := rec[member]; present {
			num, ok := v.(json.Number)
			if !ok {
				return nil, violation("bad-"+strings.ReplaceAll(member, "_", "-"), "must be a number")
			}
			reason := "bad-" + strings.ReplaceAll(member, "_", "-")
			if verr := checkMeasured(num, reason, "end"); verr != nil {
				return nil, verr
			}
			f, _ := num.Float64()
			*dst = f
		}
	}
	return e, nil
}

// checkMeasured holds cpu_ms and wall_ms to what a clock can read:
// finite and non-negative. Cost is advisory, never authenticated
// (DESIGN §19) — but bounded, the same bound the contract schema and
// the replay judge apply, so the three artifacts agree at -0.001.
func checkMeasured(num json.Number, reason, where string) *Violation {
	f, err := num.Float64()
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
		return violation(reason,
			"%s: measured cost must be a finite non-negative number, got %v", where, num)
	}
	return nil
}

func count(rec map[string]any, kind, member string) (int64, *Violation) {
	num, ok := rec[member].(json.Number)
	if !ok {
		return 0, violation("bad-count", "%s.%s must be an integer", kind, member)
	}
	n, err := num.Int64()
	if err != nil || n < 0 {
		return 0, violation("bad-count", "%s.%s: %v", kind, member, num)
	}
	return n, nil
}

// findNull walks a decoded value and returns the path of the first null,
// or "" when there is none. json.Decoder gives null as untyped nil at
// every depth, which is exactly what a nil struct member marshals to.
func findNull(v any, path string) string {
	switch val := v.(type) {
	case nil:
		return path
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if p := findNull(val[k], path+"."+k); p != "" {
				return p
			}
		}
	case []any:
		for i, item := range val {
			if p := findNull(item, fmt.Sprintf("%s[%d]", path, i)); p != "" {
				return p
			}
		}
	}
	return ""
}

// canonical re-marshals a decoded value. encoding/json sorts map keys and
// json.Number keeps the source lexeme, so two streams with the same
// content produce the same bytes here regardless of their key order —
// which is what makes the store's content hash a statement about content.
func canonical(v any) json.RawMessage {
	out, err := json.Marshal(v)
	if err != nil {
		// Unreachable for values produced by json decoding; a panic here
		// means the input was not from decodeRecord.
		panic(fmt.Sprintf("canonical re-marshal failed: %v", err))
	}
	return out
}

func splitLines(raw []byte) [][]byte {
	var lines [][]byte
	for _, line := range bytes.Split(raw, []byte("\n")) {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) > 0 {
			lines = append(lines, trimmed)
		}
	}
	return lines
}
