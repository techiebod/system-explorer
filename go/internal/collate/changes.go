// What changed (register row 17), at the tier DESIGN 06 puts the record:
// the collator keeps the snapshot store and the diff, because it is the
// tier that already holds both samples.
//
// **A fact whose temperament is counter or gauge does not participate.**
// The rule is DESIGN 12's and it was measured before it was written: 57
// of 222 nft-rules rows changed hourly in the reference and every one of
// them differed only in CounterPackets and CounterBytes — 96 times a day
// for thirty days; every SMART row changed on every 24-hour diff because
// SmartSnapshotAgeSeconds is computed at acquisition, a permanent false
// positive that would HIDE a Serial or EnclosureSlot actually changing;
// 17 of 18 datasets churned on AvailBytes alone.
//
// The exclusion is DERIVED from each collection's declaration rather than
// listed here, which is the difference between this and the reference:
// the reference had no declared temperament to read, so it could only
// have carried a hand-maintained table — a fourth copy of what the
// producer knows, and one that a plugin's counter would never be in.
//
// **And the record has a horizon, which the answer states.** Ruled
// 2026-08-23 with the cut: change tracking begins at the cut, nothing is
// translated forward from the old store, and a question reaching before
// the record begins is answered with a stated gap rather than from an
// empty baseline. Diffing against a baseline that is missing rather than
// empty would report every object in the collection as added, which is a
// confident answer to a question the record cannot reach.
package collate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/techiebod/system-explorer/go/internal/store"
)

// MeasureFacts is the set of fact names a collection declares as counter
// or gauge — the ones a diff must not read.
//
// A collection whose declaration this store does not hold yields an empty
// set AND says so through `known`. That distinction is the point: an
// unknown declaration means every fact would be diffed, including the
// counters, so a caller must be able to refuse rather than quietly
// produce the churn this whole mechanism exists to prevent.
func MeasureFacts(declarationBytes []byte, collection string) (measures map[string]bool, known bool) {
	var document declaredDocument
	if err := json.Unmarshal(declarationBytes, &document); err != nil {
		return nil, false
	}
	for _, declared := range document.Collections {
		if declared.Name != collection {
			continue
		}
		measures = map[string]bool{}
		for name, raw := range declared.Facts {
			var axes struct {
				Temperament string `json:"temperament"`
			}
			if err := json.Unmarshal(raw, &axes); err != nil {
				continue
			}
			if axes.Temperament == "counter" || axes.Temperament == "gauge" {
				measures[name] = true
			}
		}
		return measures, true
	}
	return nil, false
}

// DiffableObject is one object stripped to what the record compares.
// COVERAGE: the absent list is NOT carried. store.ObjectRow does not
// serve one — the column exists but no reader returns it — so a fact
// moving between value and absent is invisible to this diff, which is
// the change most worth reporting because absence is the state this
// product exists to stop rendering as health. Stated here rather than
// omitted silently; closing it is a reader on ObjectRow, not a change
// to the comparison.
type DiffableObject struct {
	ID    string         `json:"id"`
	Name  string         `json:"name"`
	Type  string         `json:"type,omitempty"`
	Facts map[string]any `json:"facts"`
}

// Diffable strips the measures out of one collection's objects, producing
// what a snapshot stores and what a diff reads.
//
// Sorted by id, and the facts are a map that marshals with sorted keys,
// so the digest over the result is stable across two runs that emitted
// the same objects in a different order — which is what makes "did the
// diffable content change" answerable by comparing two strings.
func Diffable(objects []store.ObjectRow, measures map[string]bool) ([]DiffableObject, error) {
	out := make([]DiffableObject, 0, len(objects))
	for _, object := range objects {
		facts := map[string]any{}
		if len(object.Facts) > 0 {
			if err := json.Unmarshal(object.Facts, &facts); err != nil {
				return nil, fmt.Errorf("object %s: %w", object.ID, err)
			}
		}
		for name := range facts {
			if measures[name] {
				delete(facts, name)
			}
		}
		out = append(out, DiffableObject{
			ID: object.ID, Name: object.Name, Type: object.Type, Facts: facts,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ChangedObject names one object and the paths that differ.
type ChangedObject struct {
	ID    string   `json:"id"`
	Paths []string `json:"paths"`
}

// CollectionChanges is one collection's answer.
type CollectionChanges struct {
	Collection string          `json:"collection"`
	Added      []string        `json:"added,omitempty"`
	Removed    []string        `json:"removed,omitempty"`
	Changed    []ChangedObject `json:"changed,omitempty"`
	// The moment the baseline was taken. A caller comparing two answers
	// needs to know they rest on the same reading.
	Since string `json:"since"`
	// Set where the question reached before this collection's record
	// begins. The answer is then the gap, and `added` is deliberately
	// EMPTY rather than every object: an unreachable baseline is not an
	// empty one.
	Gap *RecordGap `json:"gap,omitempty"`
}

// RecordGap says where the record's horizon is and why the question
// could not be answered inside it.
type RecordGap struct {
	AskedAbout string `json:"asked_about"`
	Begins     string `json:"begins,omitempty"`
	Reason     string `json:"reason"`
	Detail     string `json:"detail"`
}

// Compare diffs two diffable readings by object id.
//
// Object ids are stable for unchanged objects (law 1), so identity
// carries the diff: ids only in `after` are added, ids only in `before`
// are removed, and objects in both are compared field by field.
func Compare(before, after []DiffableObject) CollectionChanges {
	beforeByID := map[string]DiffableObject{}
	for _, object := range before {
		beforeByID[object.ID] = object
	}
	afterByID := map[string]DiffableObject{}
	for _, object := range after {
		afterByID[object.ID] = object
	}
	var changes CollectionChanges
	for id := range afterByID {
		if _, held := beforeByID[id]; !held {
			changes.Added = append(changes.Added, id)
		}
	}
	for id := range beforeByID {
		if _, held := afterByID[id]; !held {
			changes.Removed = append(changes.Removed, id)
		}
	}
	for id, was := range beforeByID {
		now, held := afterByID[id]
		if !held {
			continue
		}
		if paths := changedPaths(was, now); len(paths) > 0 {
			changes.Changed = append(changes.Changed, ChangedObject{ID: id, Paths: paths})
		}
	}
	sort.Strings(changes.Added)
	sort.Strings(changes.Removed)
	sort.Slice(changes.Changed, func(i, j int) bool {
		return changes.Changed[i].ID < changes.Changed[j].ID
	})
	return changes
}

// changedPaths names every field that differs between two readings of one
// object, as dotted paths a reader can follow to the fact.
func changedPaths(was, now DiffableObject) []string {
	var paths []string
	if was.Name != now.Name {
		paths = append(paths, "name")
	}
	if was.Type != now.Type {
		paths = append(paths, "type")
	}
	seen := map[string]bool{}
	for name := range was.Facts {
		seen[name] = true
	}
	for name := range now.Facts {
		seen[name] = true
	}
	for name := range seen {
		wasValue, hadBefore := was.Facts[name]
		nowValue, hasNow := now.Facts[name]
		if hadBefore != hasNow || !sameValue(wasValue, nowValue) {
			paths = append(paths, "facts."+name)
		}
	}
	sort.Strings(paths)
	return paths
}

// sameValue compares two decoded JSON values structurally. Re-encoding
// rather than reflecting: both sides came out of json.Unmarshal, so their
// shapes are already normalised, and marshalling a map sorts its keys.
func sameValue(a, b any) bool {
	left, errLeft := json.Marshal(a)
	right, errRight := json.Marshal(b)
	if errLeft != nil || errRight != nil {
		return false
	}
	return string(left) == string(right)
}

// ChangesSince answers "what changed" for one collection, against the
// live applied set.
//
// The declaration is required, not optional: without it the measures
// cannot be identified, and diffing a collection whose counters are still
// in it produces the continuous churn DESIGN 12 measured. So an unknown
// declaration is a stated refusal rather than a diff nobody should trust.
func ChangesSince(s *store.Store, collection, scope, since string) (CollectionChanges, error) {
	answer := CollectionChanges{Collection: collection, Since: since}

	declaration, err := s.DeclarationFor(collection)
	if err != nil {
		return answer, err
	}
	measures, known := MeasureFacts([]byte(declaration), collection)
	if !known {
		answer.Gap = &RecordGap{
			AskedAbout: since,
			Reason:     "undeclared",
			Detail: "this collection's declaration is not held, so the facts whose " +
				"temperament is counter or gauge cannot be identified — and a diff " +
				"that included them would report change continuously and say nothing",
		}
		return answer, nil
	}

	begins, err := s.RecordBegins(collection, scope)
	if err != nil {
		return answer, err
	}
	baseline, err := s.SnapshotAtOrBefore(collection, scope, since)
	if err != nil {
		return answer, err
	}
	if baseline == nil {
		detail := "the record does not reach that far back"
		reason := "before-record"
		if begins == "" {
			detail = "this collection has no stored reading yet, so there is nothing " +
				"to compare against — which is a record that has not begun, never a " +
				"collection in which nothing changed"
			reason = "no-record"
		}
		answer.Gap = &RecordGap{
			AskedAbout: since, Begins: begins, Reason: reason, Detail: detail,
		}
		return answer, nil
	}

	var before []DiffableObject
	if err := json.Unmarshal([]byte(baseline.Objects), &before); err != nil {
		return answer, fmt.Errorf("baseline for %s: %w", collection, err)
	}
	live, err := s.Objects(collection)
	if err != nil {
		return answer, err
	}
	after, err := Diffable(live, measures)
	if err != nil {
		return answer, err
	}
	changes := Compare(before, after)
	changes.Collection = collection
	changes.Since = baseline.TakenAt
	return changes, nil
}

// nowStamp is the default baseline moment: the newest stored reading at
// or before now, which is every reading there is. Same rendering as the
// snapshots carry, so the lexicographic comparison in SQL stays
// chronological.
func nowStamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// digestOf is the snapshot's identity: sha256 over exactly the bytes
// stored, so "did the diffable content change" is a string comparison.
func digestOf(encoded []byte) string {
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SnapshotFor builds the snapshot to store for one collection's applied
// set: the diffable objects and the digest over exactly those bytes.
func SnapshotFor(s *store.Store, collection, scope, takenAt string, generation uint64) (store.Snapshot, bool, error) {
	declaration, err := s.DeclarationFor(collection)
	if err != nil {
		return store.Snapshot{}, false, err
	}
	measures, known := MeasureFacts([]byte(declaration), collection)
	if !known {
		// Nothing is stored for a collection whose declaration is not
		// held: a snapshot taken with the measures still in it would be a
		// baseline that reports churn for as long as it survives, and a
		// wrong baseline outlives the moment that produced it.
		return store.Snapshot{}, false, nil
	}
	objects, err := s.Objects(collection)
	if err != nil {
		return store.Snapshot{}, false, err
	}
	diffable, err := Diffable(objects, measures)
	if err != nil {
		return store.Snapshot{}, false, err
	}
	encoded, err := json.Marshal(diffable)
	if err != nil {
		return store.Snapshot{}, false, err
	}
	return store.Snapshot{
		Collection: collection, Scope: scope, TakenAt: takenAt,
		Generation: generation, Digest: digestOf(encoded),
		Objects: string(encoded),
	}, true, nil
}
