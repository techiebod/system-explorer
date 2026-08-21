// The acquisition pipeline end to end, in process, against the scripted
// collector: what applies, what marks stale, what is held, and what a
// violation is allowed to touch (nothing).
package collate

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
	"github.com/techiebod/system-explorer/go/internal/wire"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "collate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func identityState(t *testing.T, st *store.Store) store.CollectionState {
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
	t.Fatal("identity not known to the store")
	return store.CollectionState{}
}

func acquire(t *testing.T, st *store.Store, f *fake) error {
	t.Helper()
	return AcquireOnce(context.Background(), st, &wire.Client{Socket: f.Socket})
}

func TestAcquisitionAppliesTheCommittedCollection(t *testing.T) {
	f := newFake(t)
	st := openStore(t)
	if err := acquire(t, st, f); err != nil {
		t.Fatal(err)
	}
	cs := identityState(t, st)
	if cs.Generation != 1 || cs.ObjectCount != 1 || cs.Stale {
		t.Fatalf("first acquisition: %+v", cs)
	}
	rows, _ := st.Objects("identity")
	if rows[0].ID != "identity:host1" {
		t.Fatalf("the minted id is <collection>:<native-name>: %s", rows[0].ID)
	}
	// The commit's own cost account survives to the state (register row
	// 16): the fake's commit says 0.5, and "never reported" would be nil.
	if cs.CostCPUMs == nil || *cs.CostCPUMs != 0.5 {
		t.Fatalf("the commit's advisory cost must be recorded: %+v", cs.CostCPUMs)
	}
	if string(rows[0].Facts) != `{"Gen":1}` {
		t.Fatalf("facts: %s", rows[0].Facts)
	}
	if acked, _ := st.Acked("batch-1"); !acked {
		t.Fatal("an applied batch is acknowledged")
	}
	// A second acquisition takes a fresh generation and replaces state.
	if err := acquire(t, st, f); err != nil {
		t.Fatal(err)
	}
	cs = identityState(t, st)
	rows, _ = st.Objects("identity")
	if cs.Generation != 2 || string(rows[0].Facts) != `{"Gen":2}` {
		t.Fatalf("second acquisition: %+v %s", cs, rows[0].Facts)
	}
}

func TestAbsentDeclineRetiresPriorObjects(t *testing.T) {
	f := newFake(t)
	st := openStore(t)
	if err := acquire(t, st, f); err != nil {
		t.Fatal(err)
	}
	f.set(func(f *fake) { f.declineReason = "absent" })
	if err := acquire(t, st, f); err != nil {
		t.Fatal(err)
	}
	cs := identityState(t, st)
	// Item 2: applies empty — prior objects retired, not stale.
	if cs.ObjectCount != 0 || cs.Stale || cs.Generation != 2 {
		t.Fatalf("absent must retire and advance: %+v", cs)
	}
}

func TestOtherDeclinesMarkStaleAndApplyNothing(t *testing.T) {
	for _, reason := range []string{"unauthorised", "unavailable", "unsupported"} {
		t.Run(reason, func(t *testing.T) {
			f := newFake(t)
			st := openStore(t)
			if err := acquire(t, st, f); err != nil {
				t.Fatal(err)
			}
			f.set(func(f *fake) { f.declineReason = reason })
			if err := acquire(t, st, f); err != nil {
				t.Fatal(err)
			}
			cs := identityState(t, st)
			// Item 2: prior objects stand, marked stale with the reason;
			// the generation does not advance because nothing committed.
			if cs.ObjectCount != 1 || !cs.Stale || cs.StaleReason == nil || *cs.StaleReason != reason {
				t.Fatalf("declined %s: %+v", reason, cs)
			}
			if cs.Generation != 1 {
				t.Fatalf("nothing was established at generation 2: %+v", cs)
			}
			rows, _ := st.Objects("identity")
			if string(rows[0].Facts) != `{"Gen":1}` {
				t.Fatalf("prior objects serve: %s", rows[0].Facts)
			}
		})
	}
}

func TestAViolationAppliesNothingOverPriorState(t *testing.T) {
	f := newFake(t)
	st := openStore(t)
	if err := acquire(t, st, f); err != nil {
		t.Fatal(err)
	}
	// From here the end record closes a batch begin never opened.
	f.set(func(f *fake) {
		f.tamper = func(lines []string) []string {
			lines[len(lines)-1] = `{"record":"end","request":"someone-else","batch":"someone-else","wall_ms":1.0}`
			return lines
		}
	})
	if err := acquire(t, st, f); err == nil {
		t.Fatal("end must echo the batch and request begin opened")
	}
	cs := identityState(t, st)
	if cs.Generation != 1 || cs.ObjectCount != 1 {
		t.Fatalf("an invalid stream applies NOTHING: %+v", cs)
	}
	rows, _ := st.Objects("identity")
	if string(rows[0].Facts) != `{"Gen":1}` {
		t.Fatalf("prior state must stand: %s", rows[0].Facts)
	}
	rejections, _ := st.Rejections()
	if len(rejections) != 1 || rejections[0].Reason != "end-echo-mismatch" {
		t.Fatalf("rejected with a recorded reason: %+v", rejections)
	}
}

func TestCountMismatchRejectsTheWholeBatch(t *testing.T) {
	f := newFake(t)
	st := openStore(t)
	f.set(func(f *fake) {
		f.tamper = func(lines []string) []string {
			// The object vanishes; the commit still claims it. This is
			// the truncation the three counts exist to catch.
			out := make([]string, 0, len(lines))
			for _, l := range lines {
				if len(l) > 20 && l[11:17] == "object" {
					continue
				}
				out = append(out, l)
			}
			return out
		}
	})
	if err := acquire(t, st, f); err == nil {
		t.Fatal("commit counts must reconcile with the stream")
	}
	rejections, _ := st.Rejections()
	if len(rejections) != 1 || rejections[0].Reason != "commit-count-mismatch" {
		t.Fatalf("the rejection and its reason are recorded: %+v", rejections)
	}
	if cs := identityState(t, st); cs.ObjectCount != 0 || cs.Generation != 0 {
		t.Fatalf("nothing applied: %+v", cs)
	}
}

func TestUncommittedCollectionIsHeldAndRecorded(t *testing.T) {
	f := newFake(t)
	st := openStore(t)
	if err := acquire(t, st, f); err != nil {
		t.Fatal(err)
	}
	f.set(func(f *fake) {
		f.tamper = func(lines []string) []string {
			// Strip the object AND its commit: a legal stream in which
			// identity simply never answers. Held, never applied.
			return []string{lines[0], lines[len(lines)-1]}
		}
	})
	if err := acquire(t, st, f); err != nil {
		t.Fatal(err)
	}
	cs := identityState(t, st)
	if cs.Generation != 1 || cs.ObjectCount != 1 {
		t.Fatalf("a partial read must not delete anything: %+v", cs)
	}
	rejections, _ := st.Rejections()
	if len(rejections) != 1 || rejections[0].Reason != "uncommitted-collection" {
		t.Fatalf("held is not silent: %+v", rejections)
	}
}

// The blast-radius half of DESIGN §19's judge-vs-collator note: the
// live collator holds ONLY the offending collection and applies the
// rest, because one bad collection must not cost the host its other
// facts — where replay, judging a pinned corpus, refuses whole streams.
func TestAnUncommittedCollectionIsHeldWhileTheRestApplies(t *testing.T) {
	decl := []byte(`{"schema":"se.declaration/1","collector":"system",` +
		`"collections":[{"name":"identity","freshness":"1h"},{"name":"pools","freshness":"1h"}]}`)
	f := newScriptedFake(t, decl, func(issued map[string]uint64) []string {
		// identity answers and commits; pools — issued in the same
		// request — never commits and never declines: a partial read.
		batch := "batch-mixed"
		begin := fmt.Sprintf(`{"record":"begin","request":%q,"batch":%q,"declaration":%q,`+
			`"boot_id":%q,"timens":0,"instance":null,"generations":{"identity":%d,"pools":%d}}`,
			batch, batch, wire.DeclarationHash(decl), fakeBootID, issued["identity"], issued["pools"])
		return []string{
			begin,
			`{"record":"object","collection":"identity","name":"host1","facts":{"OsId":"nixos"},"at":10.5}`,
			fmt.Sprintf(`{"record":"commit","collection":"identity","generation":%d,`+
				`"objects":1,"assertions":0,"unobservable":0,"cpu_ms":0.5}`, issued["identity"]),
			fmt.Sprintf(`{"record":"end","request":%q,"batch":%q,"cpu_ms":0.5,"wall_ms":1.0}`, batch, batch),
		}
	})
	st := openStore(t)
	if err := AcquireOnce(context.Background(), st, &wire.Client{Socket: f.Socket}); err != nil {
		t.Fatal(err)
	}
	states, err := st.Collections()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]store.CollectionState{}
	for _, cs := range states {
		byName[cs.Name] = cs
	}
	if cs := byName["identity"]; cs.Generation != 1 || cs.ObjectCount != 1 {
		t.Fatalf("the rest of the batch applies: %+v", cs)
	}
	if cs := byName["pools"]; cs.Generation != 0 || cs.ObjectCount != 0 {
		t.Fatalf("the held collection stays unapplied: %+v", cs)
	}
	rejections, _ := st.Rejections()
	if len(rejections) != 1 || rejections[0].Collection != "pools" ||
		rejections[0].Reason != "uncommitted-collection" {
		t.Fatalf("held is recorded, once, against the collection: %+v", rejections)
	}
	// The message cites its own scope — the reader of a rejection log
	// must learn the radius from the record, not from the design doc.
	if !strings.Contains(rejections[0].Detail, "the rest of the batch applies") {
		t.Fatalf("the detail names the per-collection radius: %q", rejections[0].Detail)
	}
	if acked, _ := st.Acked("batch-mixed"); !acked {
		t.Fatal("a batch whose only defect is a held collection still acknowledges")
	}
}

func TestUnknownDeclarationHashHoldsTheBatch(t *testing.T) {
	f := newFake(t)
	st := openStore(t)
	f.set(func(f *fake) { f.beginDeclaration = "sha256:beef" })
	if err := acquire(t, st, f); err == nil {
		t.Fatal("a batch under an unknown declaration is held, not applied")
	}
	if cs := identityState(t, st); cs.ObjectCount != 0 {
		t.Fatalf("held means applied nothing: %+v", cs)
	}
	rejections, _ := st.Rejections()
	if len(rejections) != 1 || rejections[0].Reason != "declaration-unknown" {
		t.Fatalf("%+v", rejections)
	}
}

func TestAFreshBatchReusingAnAckedIdIsAProtocolError(t *testing.T) {
	f := newFake(t)
	st := openStore(t)
	f.set(func(f *fake) { f.fixedBatchID = "batch-fixed" })
	if err := acquire(t, st, f); err != nil {
		t.Fatal(err)
	}
	// The next acquisition issues generation 2; the collector answers it
	// correctly — fresh content, fresh echo — under the id it already
	// spent. A transport retry is same-bytes-same-id; this is a second
	// look at the system, so it is refused and RECORDED, never silently
	// skipped: an ack check that only asked "seen?" disabled every
	// future acquisition from this collector.
	if err := acquire(t, st, f); err == nil {
		t.Fatal("a fresh batch under an acked id must be refused")
	}
	cs := identityState(t, st)
	if cs.Generation != 1 {
		t.Fatalf("nothing under a reused id may apply: %+v", cs)
	}
	rows, _ := st.Objects("identity")
	if string(rows[0].Facts) != `{"Gen":1}` {
		t.Fatalf("prior state must stand: %s", rows[0].Facts)
	}
	rejections, _ := st.Rejections()
	if len(rejections) != 1 || rejections[0].Reason != string(store.AckReused) ||
		rejections[0].Batch != "batch-fixed" {
		t.Fatalf("visible, never silent, against the id by name: %+v", rejections)
	}
}

func TestNextIntervalFollowsTheDeclaredFreshness(t *testing.T) {
	f := newFake(t)
	// The scripted declaration says 1h; the schedule must say what the
	// declaration says, not a constant someone liked.
	if got := nextInterval(&wire.Client{Socket: f.Socket}); got.String() != "1h0m0s" {
		t.Fatalf("declared freshness sets the pace: %v", got)
	}
	// No declaration to schedule by: the fixed retry stands in.
	dead := &wire.Client{Socket: filepath.Join(t.TempDir(), "nothing.sock")}
	if got := nextInterval(dead); got != retryInterval {
		t.Fatalf("an unreachable collector retries at %v, got %v", retryInterval, got)
	}
}

func TestCollectorsEnvParsing(t *testing.T) {
	got, err := parseCollectors(" system=/run/a.sock , storage=/run/b.sock ")
	if err != nil || len(got) != 2 || got[0].name != "storage" || got[1].socket != "/run/a.sock" {
		t.Fatalf("%+v %v", got, err)
	}
	if empty, err := parseCollectors("  "); err != nil || len(empty) != 0 {
		t.Fatalf("an empty fleet is a valid daemon: %+v %v", empty, err)
	}
	for _, bad := range []string{"system", "=path", "system=", "a=/x,a=/y"} {
		if _, err := parseCollectors(bad); err == nil {
			t.Errorf("parseCollectors(%q) accepted; half a fleet list observes half a fleet", bad)
		}
	}
}

func TestTheAdvisoryCostReachesTheReadSurfaceLabelled(t *testing.T) {
	// End to end (register row 16): the collector's commit says 0.5 ms,
	// and the read surface serves it under a name that SAYS advisory —
	// a reader must not take a collector's self-report for the
	// collator's own accounting (DESIGN 19).
	f := newFake(t)
	st := openStore(t)
	if err := acquire(t, st, f); err != nil {
		t.Fatal(err)
	}
	rr := get(t, NewHandler(st, func() float64 { return 26.0 }, fakeBootID),
		"/v1/collections")
	body := rr.Body.String()
	if !strings.Contains(body, `"advisory_cost_cpu_ms":0.5`) {
		t.Fatalf("the advisory cost must be served, labelled: %s", body)
	}
}
