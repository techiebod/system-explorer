// What changed, and the two things that make it different from the
// reference implementation it replaces: the measures are excluded by
// DECLARATION rather than by a table, and a question the record cannot
// reach is answered with a stated gap rather than from an empty baseline.
//
// The exclusion cases are DESIGN 12's own measurements, reproduced as
// fixtures: nft-rules churning on CounterPackets and CounterBytes, a
// SMART row churning on SmartSnapshotAgeSeconds while a Serial change
// hides behind it, a dataset churning on AvailBytes.
package collate

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
	"github.com/techiebod/system-explorer/go/internal/wire"
)

const nftDeclaration = `{"collections":[{"name":"nft-rules","question":"q","prefix":"rule",
 "facts":{
   "Expression":{"type":"string","temperament":"configuration","kind":"observed","discloses":"nothing","sentence":"."},
   "Handle":{"type":"integer","temperament":"configuration","kind":"observed","discloses":"nothing","sentence":"."},
   "CounterPackets":{"type":"integer","unit":"count","temperament":"counter","kind":"observed","discloses":"nothing","sentence":"."},
   "CounterBytes":{"type":"integer","unit":"bytes","temperament":"counter","kind":"observed","discloses":"nothing","sentence":"."},
   "AvailBytes":{"type":"integer","unit":"bytes","temperament":"gauge","kind":"observed","discloses":"nothing","sentence":"."}}}]}`

func recordStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestMeasuresAreReadFromTheDeclarationNotAList(t *testing.T) {
	measures, known := MeasureFacts([]byte(nftDeclaration), "nft-rules")
	if !known {
		t.Fatal("the collection is declared")
	}
	// Counters AND gauges: a gauge reads meaningfully on its own but it
	// still moves on every sample, which is what the diff cannot carry.
	for _, name := range []string{"CounterPackets", "CounterBytes", "AvailBytes"} {
		if !measures[name] {
			t.Errorf("%s is a measure and must not reach the diff", name)
		}
	}
	for _, name := range []string{"Expression", "Handle"} {
		if measures[name] {
			t.Errorf("%s is configuration and IS the thing worth diffing", name)
		}
	}
}

func TestAnUndeclaredCollectionIsRefusedNotDiffedAnyway(t *testing.T) {
	// The distinction that matters: with no declaration the counters
	// cannot be identified, so a diff would carry them and churn. Silence
	// would be a diff nobody should trust, reported as an answer.
	if _, known := MeasureFacts([]byte(nftDeclaration), "no-such"); known {
		t.Fatal("a collection this declaration does not describe is not known")
	}
	if _, known := MeasureFacts([]byte("{"), "nft-rules"); known {
		t.Fatal("an unparseable declaration is not a declaration")
	}
}

func recordRows(t *testing.T, objects ...store.ObjectRow) []store.ObjectRow {
	t.Helper()
	return objects
}

func recordObject(id, name string, facts map[string]any) store.ObjectRow {
	raw, _ := json.Marshal(facts)
	return store.ObjectRow{ID: id, Name: name, Facts: raw, Scope: store.HostNative}
}

func TestACounterAdvancingIsNotAChange(t *testing.T) {
	// DESIGN 12's measurement: 57 of 222 nft-rules rows changed hourly and
	// every one differed only in CounterPackets and CounterBytes — 96
	// times a day for thirty days.
	measures, _ := MeasureFacts([]byte(nftDeclaration), "nft-rules")
	before, err := Diffable(recordRows(t, recordObject("rule:4", "accept-ssh", map[string]any{
		"Expression": "tcp dport 22 accept", "Handle": 4,
		"CounterPackets": 1200, "CounterBytes": 91000})), measures)
	if err != nil {
		t.Fatal(err)
	}
	after, err := Diffable(recordRows(t, recordObject("rule:4", "accept-ssh", map[string]any{
		"Expression": "tcp dport 22 accept", "Handle": 4,
		"CounterPackets": 88213, "CounterBytes": 7712004})), measures)
	if err != nil {
		t.Fatal(err)
	}
	changes := Compare(before, after)
	if len(changes.Changed) != 0 || len(changes.Added) != 0 || len(changes.Removed) != 0 {
		t.Fatalf("a counter advancing is what a counter does: %+v", changes)
	}
}

func TestAMeasureDoesNotHideARealChangeBehindIt(t *testing.T) {
	// The SMART case, and the reason the rule is not merely about noise:
	// SmartSnapshotAgeSeconds is computed at acquisition, so it differs on
	// every 24-hour diff — a permanent false positive that would HIDE a
	// Serial or EnclosureSlot actually changing, because the row is
	// already reported as changed and nobody reads which path.
	measures, _ := MeasureFacts([]byte(nftDeclaration), "nft-rules")
	before, _ := Diffable(recordRows(t, recordObject("rule:4", "r", map[string]any{
		"Expression": "old", "AvailBytes": 100})), measures)
	after, _ := Diffable(recordRows(t, recordObject("rule:4", "r", map[string]any{
		"Expression": "new", "AvailBytes": 200})), measures)
	changes := Compare(before, after)
	if len(changes.Changed) != 1 {
		t.Fatalf("%+v", changes)
	}
	// Exactly the real path, and not the measure beside it.
	if got := changes.Changed[0].Paths; len(got) != 1 || got[0] != "facts.Expression" {
		t.Fatalf("the real change alone: %v", got)
	}
}

func TestAddedRemovedAndRenamed(t *testing.T) {
	measures, _ := MeasureFacts([]byte(nftDeclaration), "nft-rules")
	before, _ := Diffable(recordRows(t,
		recordObject("rule:1", "a", map[string]any{"Handle": 1}),
		recordObject("rule:2", "b", map[string]any{"Handle": 2})), measures)
	after, _ := Diffable(recordRows(t,
		recordObject("rule:2", "b-renamed", map[string]any{"Handle": 2}),
		recordObject("rule:3", "c", map[string]any{"Handle": 3})), measures)
	changes := Compare(before, after)
	if len(changes.Added) != 1 || changes.Added[0] != "rule:3" {
		t.Errorf("added: %v", changes.Added)
	}
	if len(changes.Removed) != 1 || changes.Removed[0] != "rule:1" {
		t.Errorf("removed: %v", changes.Removed)
	}
	if len(changes.Changed) != 1 || changes.Changed[0].Paths[0] != "name" {
		t.Errorf("changed: %+v", changes.Changed)
	}
}

func TestAFactAppearingOrLeavingIsAChange(t *testing.T) {
	measures, _ := MeasureFacts([]byte(nftDeclaration), "nft-rules")
	before, _ := Diffable(recordRows(t, recordObject("rule:1", "a",
		map[string]any{"Handle": 1})), measures)
	after, _ := Diffable(recordRows(t, recordObject("rule:1", "a",
		map[string]any{"Handle": 1, "Expression": "drop"})), measures)
	changes := Compare(before, after)
	if len(changes.Changed) != 1 || changes.Changed[0].Paths[0] != "facts.Expression" {
		t.Fatalf("%+v", changes)
	}
}

// --- the record's horizon --------------------------------------------

func seedRecord(t *testing.T, st *store.Store, collection string, gen uint64,
	objects []store.Object) {
	t.Helper()
	if _, err := st.IssueGenerations([]string{collection}, "sha256:d"); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeclaration("sha256:d", nftDeclaration); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyCommit(collection, store.HostNative, gen, "b", "boot",
		objects); err != nil {
		t.Fatal(err)
	}
}

// keep drives the record explicitly with a stamp the test chose.
//
// These tests do NOT go through collate.applyCollection, which is where
// production keeps the record — so they set their own stamps and never
// read a wall clock, and the wiring gets its own test rather than being
// assumed here. A test whose baseline moment depends on when it runs
// passes or fails by the hour.
func reapply(t *testing.T, st *store.Store, collection string, objects []store.Object) uint64 {
	t.Helper()
	issued, err := st.IssueGenerations([]string{collection}, "sha256:d")
	if err != nil {
		t.Fatal(err)
	}
	gen := issued[collection]
	outcome, err := st.ApplyCommit(collection, store.HostNative, gen, "b", "boot", objects)
	if err != nil {
		t.Fatal(err)
	}
	// Asserted rather than assumed: re-using a generation is a protocol
	// error the store refuses, and a test that ignored the outcome would
	// diff a collection nothing had changed and call the silence a pass.
	if outcome != store.OutcomeApplied {
		t.Fatalf("the second reading must apply, got %q", outcome)
	}
	return gen
}

func keep(t *testing.T, st *store.Store, collection, at string, gen uint64) bool {
	t.Helper()
	snapshot, ok, err := SnapshotFor(st, collection, store.HostNative, at, gen)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("the declaration is held, so a snapshot is takeable")
	}
	written, err := st.RecordSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return written
}

func TestAQuestionBeforeTheRecordBeginsIsAStatedGap(t *testing.T) {
	// The cut ruling, at the surface: diffing against a baseline that is
	// MISSING rather than empty would report every object as added, which
	// is a confident answer to a question the record cannot reach.
	st := recordStore(t)
	seedRecord(t, st, "nft-rules", 1, []store.Object{
		{ID: "rule:1", Name: "a", Facts: json.RawMessage(`{"Handle":1}`)}})
	keep(t, st, "nft-rules", "2026-08-23T10:00:00Z", 1)

	changes, err := ChangesSince(st, "nft-rules", store.HostNative, "2020-01-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if changes.Gap == nil {
		t.Fatal("a question the record cannot reach is a gap, never an answer")
	}
	if len(changes.Added) != 0 {
		t.Fatalf("an unreachable baseline is not an empty one: %v", changes.Added)
	}
	if changes.Gap.Begins == "" {
		t.Error("the gap names where the record does begin, so a caller can re-ask")
	}
}

func TestAnUnstartedRecordIsNotACollectionInWhichNothingChanged(t *testing.T) {
	st := recordStore(t)
	if _, err := st.IssueGenerations([]string{"nft-rules"}, "sha256:d"); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeclaration("sha256:d", nftDeclaration); err != nil {
		t.Fatal(err)
	}
	changes, err := ChangesSince(st, "nft-rules", store.HostNative, "2026-08-23T10:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if changes.Gap == nil || changes.Gap.Reason != "no-record" {
		t.Fatalf("%+v", changes.Gap)
	}
}

func TestASnapshotIsWrittenOnlyWhenTheDiffableContentChanged(t *testing.T) {
	// Which is what keeps the store small: a collection whose counters
	// advance every sweep writes one row, not one per sweep.
	st := recordStore(t)
	seedRecord(t, st, "nft-rules", 1, []store.Object{
		{ID: "rule:1", Name: "a",
			Facts: json.RawMessage(`{"Handle":1,"CounterPackets":10}`)}})

	first, ok, err := SnapshotFor(st, "nft-rules", store.HostNative, "2026-08-23T10:00:00Z", 1)
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if !keep(t, st, "nft-rules", "2026-08-23T10:00:00Z", 1) {
		t.Fatal("the first reading is always written")
	}
	// The same objects with the counter advanced: identical diffable
	// content, so nothing is stored.
	gen := reapply(t, st, "nft-rules", []store.Object{{ID: "rule:1", Name: "a",
		Facts: json.RawMessage(`{"Handle":1,"CounterPackets":99999}`)}})
	again, _, err := SnapshotFor(st, "nft-rules", store.HostNative, "2026-08-23T11:00:00Z", gen)
	if err != nil {
		t.Fatal(err)
	}
	if again.Digest != first.Digest {
		t.Fatal("a counter advancing must not move the diffable digest")
	}
	if written, err := st.RecordSnapshot(again); err != nil || written {
		t.Fatalf("unchanged diffable content writes nothing: %v %v", written, err)
	}
}

func TestTheDiffAnswersAgainstTheStoredBaseline(t *testing.T) {
	st := recordStore(t)
	seedRecord(t, st, "nft-rules", 1, []store.Object{
		{ID: "rule:1", Name: "a", Facts: json.RawMessage(`{"Expression":"old"}`)}})
	keep(t, st, "nft-rules", "2026-08-23T10:00:00Z", 1)
	reapply(t, st, "nft-rules", []store.Object{
		{ID: "rule:1", Name: "a", Facts: json.RawMessage(`{"Expression":"new"}`)},
		{ID: "rule:2", Name: "b", Facts: json.RawMessage(`{"Expression":"fresh"}`)}})
	changes, err := ChangesSince(st, "nft-rules", store.HostNative, "2026-08-23T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if changes.Gap != nil {
		t.Fatalf("the record reaches this question: %+v", changes.Gap)
	}
	if len(changes.Added) != 1 || changes.Added[0] != "rule:2" {
		t.Errorf("added: %v", changes.Added)
	}
	if len(changes.Changed) != 1 || changes.Changed[0].ID != "rule:1" {
		t.Errorf("changed: %+v", changes.Changed)
	}
	// The answer says which reading it rests on, not which moment was asked
	// about: two answers are comparable only if they share a baseline.
	if changes.Since != "2026-08-23T10:00:00Z" {
		t.Errorf("since: %q", changes.Since)
	}
}

func TestPruningKeepsTheOldestSurvivingBaseline(t *testing.T) {
	// A collection whose last change predates the horizon is the ordinary
	// case for configuration, and pruning it to nothing would move the
	// record's horizon forward — turning "unchanged for a year" into "we
	// cannot say".
	st := recordStore(t)
	for _, at := range []string{"2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z"} {
		if _, err := st.RecordSnapshot(store.Snapshot{
			Collection: "nft-rules", Scope: store.HostNative, TakenAt: at,
			Generation: 1, Digest: "sha256:" + at, Objects: "[]"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.PruneSnapshots("2026-08-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	begins, err := st.RecordBegins("nft-rules", store.HostNative)
	if err != nil {
		t.Fatal(err)
	}
	if begins == "" {
		t.Fatal("pruning must never leave a collection with no baseline at all")
	}
	if begins != "2026-02-01T00:00:00Z" {
		t.Fatalf("the newest survives as the baseline: %q", begins)
	}
}

func TestAFlappingConditionKeepsEveryFlip(t *testing.T) {
	// De-duplicating against the whole history rather than the newest
	// reading would collapse a flapping condition into one entry, which
	// is the shape a record exists to show.
	st := recordStore(t)
	for i, digest := range []string{"a", "b", "a"} {
		written, err := st.RecordSnapshot(store.Snapshot{
			Collection: "units", Scope: store.HostNative,
			TakenAt: []string{"2026-08-23T10:00:00Z", "2026-08-23T11:00:00Z",
				"2026-08-23T12:00:00Z"}[i],
			Generation: uint64(i + 1), Digest: "sha256:" + digest, Objects: "[]"})
		if err != nil || !written {
			t.Fatalf("flip %d: %v %v", i, written, err)
		}
	}
}

// --- the wiring ------------------------------------------------------

func TestTheApplyPathKeepsTheRecord(t *testing.T) {
	// The tests above drive the record explicitly so their stamps are
	// their own. This one proves the production path keeps it at all —
	// without it, every assertion above would hold over a mechanism
	// nothing ever calls, which is a guard describing a feature that is
	// not wired up.
	st := recordStore(t)
	issued, err := st.IssueGenerations([]string{"nft-rules"}, "sha256:d")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeclaration("sha256:d", nftDeclaration); err != nil {
		t.Fatal(err)
	}
	batch := &wire.Batch{
		Begin: wire.Begin{
			Batch: "b1", BootID: "boot", Generations: issued,
		},
		Collections: map[string]*wire.CollectionStream{
			"nft-rules": {
				Objects: []wire.Object{{
					Name:  "accept-ssh",
					Facts: json.RawMessage(`{"Expression":"tcp dport 22 accept"}`),
				}},
				Commit: &wire.Commit{},
			},
		},
	}
	if err := applyCollection(st, "nft-rules", store.HostNative, batch); err != nil {
		t.Fatal(err)
	}
	begins, err := st.RecordBegins("nft-rules", store.HostNative)
	if err != nil {
		t.Fatal(err)
	}
	if begins == "" {
		t.Fatal("an applied collection is a reading the record keeps")
	}
	// And a failure to keep it is RECORDED rather than swallowed: the
	// record is a product feature over already-durable state, so it must
	// not fail the apply, but a record that has stopped keeping itself
	// must be visible rather than inferred from a diff that answers "no
	// change" for ever.
	if rejections, err := st.Rejections(); err != nil || len(rejections) != 0 {
		t.Fatalf("a clean apply records no refusal: %v %v", rejections, err)
	}
}
