// Acceptance item 3 for the collator's three boundaries: kill the
// process at every commit/transaction boundary and prove state is
// all-or-nothing, never partial. The subject is this package's own Main
// — the test binary re-execs itself into it — dying against a real
// socket, a real store, and a real SIGKILL-shaped exit, because a crash
// simulated inside one process proves recovery of nothing.
//
// The boundary ids and their expectations come verbatim from
// harness/crash/boundaries.json; a drifted expectation fails here before
// it misleads anyone.
package collate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
	"github.com/techiebod/system-explorer/go/internal/wire"
)

// TestMain re-execs into the daemon when the crash tests ask it to. The
// helper is the real Main: same acquisition path, same store, same
// crashpoints — the only difference from production is who built the env.
func TestMain(m *testing.M) {
	if os.Getenv("SE_COLLATE_HELPER") == "1" {
		os.Exit(Main())
	}
	os.Exit(m.Run())
}

type boundary struct {
	ID     string `json:"id"`
	Kill   string `json:"kill"`
	Expect string `json:"expect"`
}

// loadBoundaries reads the protocol's own crash enumeration and pins the
// three expectations these tests were written against. If the harness
// file moves, the assertions must be re-derived, not silently kept.
func loadBoundaries(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "harness", "crash", "boundaries.json"))
	if err != nil {
		t.Fatalf("boundaries.json is the crash contract: %v", err)
	}
	var doc struct {
		Boundaries []boundary `json:"boundaries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	expects := map[string]string{}
	for _, b := range doc.Boundaries {
		expects[b.ID] = b.Expect
	}
	pinned := map[string]string{
		"post-commit-pre-apply": "on restart the collection is at its previous generation; the batch is re-run",
		"mid-apply":             "all of it or none of it; a generation may never advance over unapplied objects",
		"post-apply-pre-ack":    "applied and durable; a re-sent identical batch at the same generation is a no-op",
	}
	for id, want := range pinned {
		if got, ok := expects[id]; !ok || got != want {
			t.Fatalf("boundary %s: expect drifted from what these tests assert.\n harness: %q\n  pinned: %q", id, got, want)
		}
	}
	return pinned
}

// runCollate spawns the daemon in oneshot mode against the fake's socket
// and returns its exit code.
func runCollate(t *testing.T, stateDir, socket, crashAt string) int {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		"SE_COLLATE_HELPER=1",
		"SE_ONESHOT=1",
		"SE_STATE_DIR="+stateDir,
		"SE_COLLECTORS=system="+socket,
		"SE_CRASH_AT="+crashAt,
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("spawn failed: %v (output %q)", err, out)
	}
	return exit.ExitCode()
}

func openStateStore(t *testing.T, stateDir string) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(stateDir, "collate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func assertIdentity(t *testing.T, st *store.Store, expect string, wantGen uint64, wantFacts string) {
	t.Helper()
	all, err := st.Collections()
	if err != nil {
		t.Fatal(err)
	}
	var cs *store.CollectionState
	for i := range all {
		if all[i].Name == "identity" {
			cs = &all[i]
		}
	}
	if cs == nil {
		t.Fatalf("[%s] the store lost the collection", expect)
	}
	if cs.Generation != wantGen {
		t.Fatalf("[%s] generation %d, want %d", expect, cs.Generation, wantGen)
	}
	rows, err := st.Objects("identity")
	if err != nil {
		t.Fatal(err)
	}
	if wantFacts == "" {
		if len(rows) != 0 {
			t.Fatalf("[%s] expected no objects, found %+v", expect, rows)
		}
		return
	}
	if len(rows) != 1 || string(rows[0].Facts) != wantFacts {
		t.Fatalf("[%s] objects %+v, want facts %s", expect, rows, wantFacts)
	}
}

// The shared choreography: run 1 applies generation 1 cleanly, run 2 is
// killed at the boundary while applying generation 2, and the asserts
// take the store's word for what survived.
func crashAtBoundary(t *testing.T, crashAt string) (f *fake, stateDir string) {
	t.Helper()
	f = newFake(t)
	stateDir = t.TempDir()
	if code := runCollate(t, stateDir, f.Socket, ""); code != 0 {
		t.Fatalf("clean run exited %d", code)
	}
	if code := runCollate(t, stateDir, f.Socket, crashAt); code != 137 {
		t.Fatalf("the process must die AT the boundary: exit %d, want 137", code)
	}
	return f, stateDir
}

func TestCrashPostCommitPreApply(t *testing.T) {
	expect := loadBoundaries(t)["post-commit-pre-apply"]
	f, stateDir := crashAtBoundary(t, "post-commit-pre-apply")

	// After death: "on restart the collection is at its previous
	// generation" — generation 1 with generation 1's facts, the crashed
	// batch (generation 2) nowhere.
	st := openStateStore(t, stateDir)
	assertIdentity(t, st, expect, 1, `{"Gen":1}`)
	st.Close()

	// "the batch is re-run" — a restart re-acquires. Going back to the
	// interface is a fresh acquisition, so it takes a fresh generation
	// (3; the crashed 2 was issued durably and is never reused).
	if code := runCollate(t, stateDir, f.Socket, ""); code != 0 {
		t.Fatalf("restart exited %d", code)
	}
	st2 := openStateStore(t, stateDir)
	assertIdentity(t, st2, expect, 3, `{"Gen":3}`)
	t.Logf("post-commit-pre-apply: %s — held: gen 1 after death, gen 3 after re-run", expect)
}

func TestCrashMidApply(t *testing.T) {
	expect := loadBoundaries(t)["mid-apply"]
	f, stateDir := crashAtBoundary(t, "mid-apply")

	// After death inside the transaction — after every write, before
	// COMMIT: "all of it or none of it; a generation may never advance
	// over unapplied objects". SQLite must hand back generation 1 whole:
	// generation 2's already-written rows rolled away with its journal.
	st := openStateStore(t, stateDir)
	assertIdentity(t, st, expect, 1, `{"Gen":1}`)
	st.Close()

	if code := runCollate(t, stateDir, f.Socket, ""); code != 0 {
		t.Fatalf("restart exited %d", code)
	}
	st2 := openStateStore(t, stateDir)
	assertIdentity(t, st2, expect, 3, `{"Gen":3}`)
	t.Logf("mid-apply: %s — held: gen 1 whole after death, gen 3 after re-run", expect)
}

func TestCrashPostApplyPreAck(t *testing.T) {
	expect := loadBoundaries(t)["post-apply-pre-ack"]
	f, stateDir := crashAtBoundary(t, "post-apply-pre-ack")

	// After death: "applied and durable" — generation 2 committed with
	// generation 2's facts — and only the acknowledgement is missing.
	st := openStateStore(t, stateDir)
	assertIdentity(t, st, expect, 2, `{"Gen":2}`)
	if acked, err := st.Acked("batch-2"); err != nil || acked {
		t.Fatalf("[%s] the ack is exactly what the crash lost: acked=%v err=%v", expect, acked, err)
	}

	// "a re-sent identical batch at the same generation is a no-op" —
	// the recovery for the lost ack. The fake is deterministic per
	// generation, so re-requesting generation 2 re-delivers the batch
	// byte for byte; the authority must shrug.
	batch, err := (&wire.Client{Socket: f.Socket}).Collect(context.Background(), map[string]uint64{"identity": 2})
	if err != nil {
		t.Fatal(err)
	}
	objects := make([]store.Object, 0, 1)
	for _, o := range batch.Collections["identity"].Objects {
		objects = append(objects, store.Object{
			ID: store.MintID("identity", o.Name), Name: o.Name,
			Facts: o.Facts, Names: o.Names, Absent: o.Absent, At: o.At,
		})
	}
	outcome, err := st.ApplyCommit("identity", store.HostNative, 2, batch.Begin.Batch, batch.Begin.BootID, objects)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != store.OutcomeNoop {
		t.Fatalf("[%s] re-sent identical batch: outcome %s, want %s", expect, outcome, store.OutcomeNoop)
	}
	assertIdentity(t, st, expect, 2, `{"Gen":2}`)
	if rejections, _ := st.Rejections(); len(rejections) != 0 {
		t.Fatalf("[%s] a safe retry is not an incident: %+v", expect, rejections)
	}
	st.Close()

	// And the daemon carries on: the next real acquisition applies.
	if code := runCollate(t, stateDir, f.Socket, ""); code != 0 {
		t.Fatalf("restart exited %d", code)
	}
	st2 := openStateStore(t, stateDir)
	assertIdentity(t, st2, expect, 3, `{"Gen":3}`)
	t.Logf("post-apply-pre-ack: %s — held: gen 2 durable after death, identical re-send was a no-op, gen 3 after restart", expect)
}
