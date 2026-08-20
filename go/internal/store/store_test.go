// The batch authority's rules, each proven against the store the daemon
// actually runs on — acceptance items 1, 2, 4 and 5 at unit scale.
package store

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "collate.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st, path
}

// The boot id every test apply stamps: which clock domain the at
// readings belong to (DESIGN §09).
const testBootID = "5e000000-0000-4000-8000-000000000001"

func obj(name, facts string, at float64) Object {
	return Object{
		ID:    MintID("identity", name),
		Name:  name,
		Facts: json.RawMessage(facts),
		At:    at,
	}
}

func issue(t *testing.T, st *Store, names ...string) map[string]uint64 {
	t.Helper()
	issued, err := st.IssueGenerations(names, "sha256:test")
	if err != nil {
		t.Fatal(err)
	}
	return issued
}

func mustApply(t *testing.T, st *Store, gen uint64, batch string, objects ...Object) {
	t.Helper()
	outcome, err := st.ApplyCommit("identity", HostNative, gen, batch, testBootID, objects)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != OutcomeApplied {
		t.Fatalf("expected applied, got %s", outcome)
	}
}

func state(t *testing.T, st *Store) CollectionState {
	t.Helper()
	all, err := st.Collections()
	if err != nil {
		t.Fatal(err)
	}
	for _, cs := range all {
		if cs.Name == "identity" {
			return cs
		}
	}
	t.Fatal("collection identity not found")
	return CollectionState{}
}

func TestIssuedGenerationsAreMonotonicAndPersisted(t *testing.T) {
	st, path := open(t)
	if got := issue(t, st, "identity")["identity"]; got != 1 {
		t.Fatalf("first issue: %d", got)
	}
	if got := issue(t, st, "identity")["identity"]; got != 2 {
		t.Fatalf("second issue: %d", got)
	}
	// Reopen: the counter must survive the process, or a restarted
	// collator would reissue a generation an in-flight batch already
	// carries — the reuse the monotonic rule exists to make impossible.
	st.Close()
	st2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	issued, err := st2.IssueGenerations([]string{"identity"}, "sha256:test")
	if err != nil {
		t.Fatal(err)
	}
	if issued["identity"] != 3 {
		t.Fatalf("after reopen: %d", issued["identity"])
	}
}

func TestApplyReplacesTheWholeCollection(t *testing.T) {
	st, _ := open(t)
	issue(t, st, "identity")
	issue(t, st, "identity")
	mustApply(t, st, 1, "b1", obj("a", `{"F":1}`, 10), obj("b", `{"F":2}`, 11))
	// Everything a committed collection did not emit is gone: b changes,
	// c appears, a was not emitted and must be retired.
	mustApply(t, st, 2, "b2", obj("b", `{"F":3}`, 12), obj("c", `{"F":4}`, 13))
	rows, err := st.Objects("identity")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].ID != "identity:b" || rows[1].ID != "identity:c" {
		t.Fatalf("committed set is the whole collection: %+v", rows)
	}
	if string(rows[0].Facts) != `{"F":3}` {
		t.Fatalf("newest committed facts serve: %s", rows[0].Facts)
	}
}

func TestAbsentAppliesEmptyAndIsNotStale(t *testing.T) {
	st, _ := open(t)
	issue(t, st, "identity")
	issue(t, st, "identity")
	mustApply(t, st, 1, "b1", obj("a", `{"F":1}`, 10))
	// Acceptance item 2: absent (with its zero commit) APPLIES EMPTY —
	// prior objects retired, collection not stale.
	mustApply(t, st, 2, "b2")
	cs := state(t, st)
	if cs.ObjectCount != 0 || cs.Stale || cs.Generation != 2 {
		t.Fatalf("authoritative emptiness: %+v", cs)
	}
	if cs.OldestAt != nil {
		t.Fatal("an empty collection has no oldest read")
	}
}

func TestNonAbsentDeclineLeavesObjectsMarkedStale(t *testing.T) {
	st, _ := open(t)
	issue(t, st, "identity")
	mustApply(t, st, 1, "b1", obj("a", `{"F":1}`, 10))
	// Acceptance item 2: unauthorised/unavailable/unsupported apply
	// nothing; prior objects stand and are served marked stale.
	if err := st.MarkStale("identity", "unavailable"); err != nil {
		t.Fatal(err)
	}
	cs := state(t, st)
	if cs.ObjectCount != 1 || !cs.Stale || cs.StaleReason == nil || *cs.StaleReason != "unavailable" {
		t.Fatalf("prior state must stand, marked: %+v", cs)
	}
	if cs.Generation != 1 {
		t.Fatalf("nothing was established; the generation may not move: %d", cs.Generation)
	}
	// The next successful apply clears the marking.
	issue(t, st, "identity")
	mustApply(t, st, 2, "b2", obj("a", `{"F":2}`, 11))
	cs = state(t, st)
	if cs.Stale || cs.StaleReason != nil {
		t.Fatalf("a committed reading un-marks the collection: %+v", cs)
	}
}

func TestCommitBelowAppliedIsRefusedAndRecorded(t *testing.T) {
	st, _ := open(t)
	issue(t, st, "identity") // 1 — the batch that will arrive late
	issue(t, st, "identity") // 2
	mustApply(t, st, 2, "b2", obj("a", `{"F":2}`, 12))
	// The watch/schedule hazard: generation 1 finishes last. Refused.
	outcome, err := st.ApplyCommit("identity", HostNative, 1, "b1", testBootID,
		[]Object{obj("a", `{"F":1}`, 10)})
	if err != nil {
		t.Fatal(err)
	}
	if outcome != OutcomeRefusedBelow {
		t.Fatalf("older may never replace newer: %s", outcome)
	}
	rows, _ := st.Objects("identity")
	if len(rows) != 1 || string(rows[0].Facts) != `{"F":2}` {
		t.Fatalf("newer state must stand: %+v", rows)
	}
	rejections, err := st.Rejections()
	if err != nil {
		t.Fatal(err)
	}
	if len(rejections) != 1 || rejections[0].Reason != string(OutcomeRefusedBelow) {
		t.Fatalf("a refusal is recorded, not silent: %+v", rejections)
	}
}

func TestEqualGenerationIdenticalContentIsANoop(t *testing.T) {
	st, _ := open(t)
	issue(t, st, "identity")
	objects := []Object{obj("a", `{"F":1}`, 10)}
	mustApply(t, st, 1, "b1", objects...)
	// The re-delivered batch: same generation, same content. Safe.
	outcome, err := st.ApplyCommit("identity", HostNative, 1, "b1", testBootID, objects)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != OutcomeNoop {
		t.Fatalf("retransmission must be a no-op: %s", outcome)
	}
	if rejections, _ := st.Rejections(); len(rejections) != 0 {
		t.Fatalf("a safe retry is not an incident: %+v", rejections)
	}
}

func TestEqualGenerationDifferentContentIsAProtocolError(t *testing.T) {
	st, _ := open(t)
	issue(t, st, "identity")
	mustApply(t, st, 1, "b1", obj("a", `{"F":1}`, 10))
	// Two different readings claiming one generation: somebody reused it.
	outcome, err := st.ApplyCommit("identity", HostNative, 1, "b1x", testBootID,
		[]Object{obj("a", `{"F":99}`, 10)})
	if err != nil {
		t.Fatal(err)
	}
	if outcome != OutcomeProtocolError {
		t.Fatalf("expected protocol error, got %s", outcome)
	}
	rows, _ := st.Objects("identity")
	if string(rows[0].Facts) != `{"F":1}` {
		t.Fatalf("never merged, never applied: %s", rows[0].Facts)
	}
	rejections, _ := st.Rejections()
	if len(rejections) != 1 || rejections[0].Reason != string(OutcomeProtocolError) {
		t.Fatalf("recorded: %+v", rejections)
	}
}

func TestNeverIssuedGenerationIsAnError(t *testing.T) {
	st, _ := open(t)
	issue(t, st, "identity")
	// Deny-by-default on the high side: 99 was never issued, however
	// fresh it claims to be.
	if _, err := st.ApplyCommit("identity", HostNative, 99, "b", testBootID, nil); err == nil {
		t.Fatal("a generation this authority never issued must not apply")
	}
}

func TestApplyRequiresABootID(t *testing.T) {
	st, _ := open(t)
	issue(t, st, "identity")
	// An apply whose clock domain is unknown would serve uninterpretable
	// ages; the authority refuses it rather than trusting the caller.
	if _, err := st.ApplyCommit("identity", HostNative, 1, "b1", "", nil); err == nil {
		t.Fatal("an apply without a boot id must be refused")
	}
}

func TestOldestAtGovernsFreshness(t *testing.T) {
	st, _ := open(t)
	issue(t, st, "identity")
	// Acceptance item 5: a six-second acquisition must never report
	// itself fresher than its oldest contributing read.
	mustApply(t, st, 1, "b1", obj("slow", `{"F":1}`, 10.0), obj("fast", `{"F":2}`, 16.0))
	cs := state(t, st)
	if cs.OldestAt == nil {
		t.Fatal("no oldest read reported")
	}
	if *cs.OldestAt != 10.0 {
		t.Fatalf("freshness derives from the OLDEST at: got %v", *cs.OldestAt)
	}
	rows, _ := st.Objects("identity")
	for _, r := range rows {
		if r.At != 10.0 && r.At != 16.0 {
			t.Fatalf("at is stored verbatim: %v", r.At)
		}
	}
}

func TestTwoInstancesWithIdenticalNamesNeverMerge(t *testing.T) {
	st, _ := open(t)
	issue(t, st, "identity")
	issue(t, st, "identity")
	// Acceptance item 1: same native name, two instances. The minted id
	// string is identical; the scope keeps them apart.
	mustApply(t, st, 1, "b1", obj("indexer:3", `{"Port":1}`, 10))
	outcome, err := st.ApplyCommit("identity", "radarr", 2, "b2", testBootID,
		[]Object{obj("indexer:3", `{"Port":2}`, 11)})
	if err != nil || outcome != OutcomeApplied {
		t.Fatalf("%v %s", err, outcome)
	}
	rows, _ := st.Objects("identity")
	if len(rows) != 2 {
		t.Fatalf("two instances, two objects, no merge: %+v", rows)
	}
	// And an instance's re-commit retires only its own scope.
	issued := issue(t, st, "identity")
	outcome, err = st.ApplyCommit("identity", "radarr", issued["identity"], "b3", testBootID, nil)
	if err != nil || outcome != OutcomeApplied {
		t.Fatalf("%v %s", err, outcome)
	}
	rows, _ = st.Objects("identity")
	if len(rows) != 1 || string(rows[0].Facts) != `{"Port":1}` {
		t.Fatalf("host-native scope must be untouched: %+v", rows)
	}
}

func TestHashIsContentNotOrder(t *testing.T) {
	a := obj("a", `{"F":1}`, 10)
	b := obj("b", `{"F":2}`, 11)
	if HashObjects([]Object{a, b}) != HashObjects([]Object{b, a}) {
		t.Fatal("emission order is not content")
	}
	b2 := obj("b", `{"F":3}`, 11)
	if HashObjects([]Object{a, b}) == HashObjects([]Object{a, b2}) {
		t.Fatal("a changed fact is different content")
	}
	bLater := obj("b", `{"F":2}`, 12)
	// A re-read is a different observation even when the values agree:
	// the at stamp is part of what was applied.
	if HashObjects([]Object{a, b}) == HashObjects([]Object{a, bLater}) {
		t.Fatal("a changed at is different content")
	}
}

func TestAckIdempotency(t *testing.T) {
	st, _ := open(t)
	gens := map[string]uint64{"identity": 1}
	if acked, _ := st.Acked("batch-1"); acked {
		t.Fatal("nothing acked yet")
	}
	if err := st.RecordAck("batch-1", gens, "sha256:aa"); err != nil {
		t.Fatal(err)
	}
	if acked, _ := st.Acked("batch-1"); !acked {
		t.Fatal("ack lost")
	}
	// Acking twice must not error: the crash-shaped duplicate.
	if err := st.RecordAck("batch-1", gens, "sha256:aa"); err != nil {
		t.Fatal(err)
	}
}

func TestJudgeAckedDiscriminates(t *testing.T) {
	st, _ := open(t)
	gens := map[string]uint64{"identity": 1}
	// Never seen: the generation rules govern it.
	if outcome, err := st.JudgeAcked("batch-1", gens, "sha256:aa"); err != nil || outcome != AckNew {
		t.Fatalf("unseen id: %s %v", outcome, err)
	}
	if err := st.RecordAck("batch-1", gens, "sha256:aa"); err != nil {
		t.Fatal(err)
	}
	// Same id, same generations, same bytes: the transport retry, and
	// safe is silent — a true retry is not an incident.
	if outcome, err := st.JudgeAcked("batch-1", gens, "sha256:aa"); err != nil || outcome != AckRetry {
		t.Fatalf("true retry: %s %v", outcome, err)
	}
	if rejections, _ := st.Rejections(); len(rejections) != 0 {
		t.Fatalf("a safe retry is not an incident: %+v", rejections)
	}
	// Same id, different generations: a fresh acquisition wearing an old
	// id. Recorded protocol error — visible, never a silent skip.
	if outcome, err := st.JudgeAcked("batch-1", map[string]uint64{"identity": 2}, "sha256:bb"); err != nil || outcome != AckReused {
		t.Fatalf("reused id with fresh generations: %s %v", outcome, err)
	}
	// Same id, same generations, different bytes: equal, with different
	// content, is a protocol error (DESIGN §19).
	if outcome, err := st.JudgeAcked("batch-1", gens, "sha256:cc"); err != nil || outcome != AckReused {
		t.Fatalf("reused id with different content: %s %v", outcome, err)
	}
	rejections, _ := st.Rejections()
	if len(rejections) != 2 {
		t.Fatalf("each reuse is recorded: %+v", rejections)
	}
	for _, r := range rejections {
		if r.Reason != string(AckReused) || r.Batch != "batch-1" {
			t.Fatalf("recorded against the reused id, by name: %+v", r)
		}
	}
}
