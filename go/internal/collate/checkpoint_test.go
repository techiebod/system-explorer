// What a checkpoint must say, asserted record by record. The schema in
// contract/ judges shape; these judge meaning — which collections appear,
// which send state, what the terminal counts, and what a stated gap is.
package collate

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
	_ "modernc.org/sqlite"
)

// stagePreMigrationStore opens a store whose path the test keeps, so it
// can reach the database directly and produce the one condition no API
// can: a collections row whose declaration is NULL, which is what a
// store written before 2026-08-20 carries. Staged rather than asserted
// from a fixture, because the migration means it cannot be created any
// other way once it has run.
func stagePreMigrationStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "collate.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st, path
}

func clearDeclaration(path, collection string) error {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(`UPDATE collections SET declaration = NULL WHERE name = ?`, collection)
	return err
}

// records decodes a written checkpoint into its lines, failing the test
// if anything is malformed — a checkpoint that will not parse is not a
// checkpoint whose meaning is worth asserting.
func records(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	for dec.More() {
		var m map[string]any
		if err := dec.Decode(&m); err != nil {
			t.Fatalf("decode: %v\n%s", err, buf.String())
		}
		out = append(out, m)
	}
	return out
}

func write(t *testing.T, st *store.Store, gap *HistoryGap) []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteCheckpoint(&buf, st, "cp-1", "storage-1", fakeBootID, gap); err != nil {
		t.Fatalf("write checkpoint: %v", err)
	}
	return records(t, &buf)
}

// seed applies one object into collection under gen, issuing first.
func seed(t *testing.T, st *store.Store, collection string, gen uint64, batch string, objects []store.Object) {
	t.Helper()
	for i := uint64(0); i < gen; i++ {
		if _, err := st.IssueGenerations([]string{collection}, "sha256:"+collection); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.ApplyCommit(collection, store.HostNative, gen, batch, fakeBootID, objects); err != nil {
		t.Fatal(err)
	}
}

func obj(id, name, facts string, at float64) store.Object {
	return store.Object{ID: id, Name: name, Facts: json.RawMessage(facts), At: at}
}

// The manifest names collections that send no state, which is the whole
// reason it exists: without it the hub cannot tell a collection that is
// missing from one that is empty, and completeness is unfalsifiable.
func TestManifestNamesNeverAppliedCollections(t *testing.T) {
	st := openStore(t)
	seed(t, st, "pools", 1, "b1", []store.Object{obj("pools:tank", "tank", `{"State":"ok"}`, 10)})
	// leases is declared and has never applied: a generation was issued
	// and no commit followed, which is a real state and the one a hub
	// must be able to tell from silence.
	if _, err := st.IssueGenerations([]string{"leases"}, "sha256:leases"); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkStale("leases", "unsupported"); err != nil {
		t.Fatal(err)
	}

	recs := write(t, st, nil)
	if recs[0]["record"] != "manifest" {
		t.Fatalf("a checkpoint opens with its manifest: %v", recs[0])
	}
	entries := recs[0]["collections"].([]any)
	if len(entries) != 2 {
		t.Fatalf("every declared collection, not only the ones with state: %v", entries)
	}
	byName := map[string]map[string]any{}
	for _, e := range entries {
		m := e.(map[string]any)
		byName[m["collection"].(string)] = m
	}
	leases := byName["leases"]
	if leases["generation"] != float64(0) || leases["freshness"] != "stale" ||
		leases["stale_reason"] != "unsupported" {
		t.Fatalf("never-applied is generation 0, stale, with its reason: %v", leases)
	}
	if byName["pools"]["freshness"] != "current" {
		t.Fatalf("an applied collection is current: %v", byName["pools"])
	}
	if _, ok := byName["pools"]["stale_reason"]; ok {
		t.Fatalf("a current collection carries no stale reason: %v", byName["pools"])
	}
	// One state record, for pools alone, and the terminal counts it.
	if len(recs) != 3 {
		t.Fatalf("manifest, one state, terminal: %d records", len(recs))
	}
	if recs[1]["collection"] != "pools" {
		t.Fatalf("only the applied collection sends state: %v", recs[1])
	}
	if recs[2]["record"] != "terminal" || recs[2]["collections"] != float64(1) {
		t.Fatalf("the terminal counts state records: %v", recs[2])
	}
}

// The terminal counts rather than merely arriving, so a checkpoint whose
// middle was lost is distinguishable from one that finished.
func TestTerminalCountsEveryStateRecord(t *testing.T) {
	st := openStore(t)
	seed(t, st, "pools", 1, "b1", []store.Object{obj("pools:tank", "tank", `{}`, 10)})
	seed(t, st, "units", 1, "b2", []store.Object{obj("units:ssh", "ssh", `{}`, 11)})
	recs := write(t, st, nil)
	last := recs[len(recs)-1]
	if last["collections"] != float64(2) {
		t.Fatalf("two collections sent state: %v", last)
	}
	sent := 0
	for _, r := range recs {
		if r["record"] == "collection_state" {
			sent++
		}
	}
	if sent != 2 {
		t.Fatalf("terminal count must equal records actually sent, got %d", sent)
	}
}

// Null is the first-connection reading and it is PRESENT, because a
// missing member and a stated absence of gap are different claims.
func TestHistoryGapIsStatedEitherWay(t *testing.T) {
	st := openStore(t)
	seed(t, st, "pools", 1, "b1", nil)

	recs := write(t, st, nil)
	term := recs[len(recs)-1]
	gap, ok := term["history_gap"]
	if !ok {
		t.Fatalf("history_gap is required, never omitted: %v", term)
	}
	if gap != nil {
		t.Fatalf("a first connection has nothing to have missed: %v", gap)
	}

	recs = write(t, st, &HistoryGap{From: 81422.5, To: 98301.0})
	stated := recs[len(recs)-1]["history_gap"].(map[string]any)
	if stated["from"] != 81422.5 || stated["to"] != 98301.0 {
		t.Fatalf("a stated gap carries its interval: %v", stated)
	}
}

// Acceptance item 1's precondition at the hub tier: two instances mint
// one id, so the checkpoint must carry what tells them apart or the hub
// merges what the collator kept separate.
func TestCheckpointDistinguishesTwoInstances(t *testing.T) {
	st := openStore(t)
	for range 2 {
		if _, err := st.IssueGenerations([]string{"identity"}, "sha256:identity"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.ApplyCommit("identity", store.HostNative, 1, "b1", fakeBootID,
		[]store.Object{obj("identity:indexer:3", "indexer:3", `{"Port":1}`, 10)}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyCommit("identity", "radarr", 2, "b2", fakeBootID,
		[]store.Object{obj("identity:indexer:3", "indexer:3", `{"Port":2}`, 11)}); err != nil {
		t.Fatal(err)
	}
	recs := write(t, st, nil)
	objects := recs[1]["objects"].([]any)
	if len(objects) != 2 {
		t.Fatalf("two instances, two objects: %v", objects)
	}
	a, b := objects[0].(map[string]any), objects[1].(map[string]any)
	if a["id"] != b["id"] {
		t.Fatalf("the minted id IS identical; that is the premise: %v %v", a, b)
	}
	for i, o := range []map[string]any{a, b} {
		if _, ok := o["instance"]; !ok {
			t.Fatalf("object %d carries no instance: %v", i, o)
		}
	}
	if a["instance"] != nil || b["instance"] != "radarr" {
		t.Fatalf("host-native is null and the named instance is itself: %v %v", a, b)
	}
}

// An applied collection holding nothing sends an EMPTY array, not null:
// it is the reading a decline of `absent` leaves, and null would be a
// different claim.
func TestAppliedAndEmptySendsAnEmptyArray(t *testing.T) {
	st := openStore(t)
	seed(t, st, "pools", 1, "b1", nil)
	var buf bytes.Buffer
	if err := WriteCheckpoint(&buf, st, "cp-1", "storage-1", fakeBootID, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"objects":[]`) {
		t.Fatalf("an empty applied collection sends []: %s", buf.String())
	}
}

// The refusals, each stated rather than papered over.
func TestCheckpointRefusals(t *testing.T) {
	t.Run("no collections at all", func(t *testing.T) {
		st := openStore(t)
		err := WriteCheckpoint(&bytes.Buffer{}, st, "cp-1", "storage-1", fakeBootID, nil)
		if !errors.Is(err, ErrNothingToCheckpoint) {
			t.Fatalf("an empty authority is a stated state, not a fault: %v", err)
		}
	})
	t.Run("nil boot id", func(t *testing.T) {
		st := openStore(t)
		seed(t, st, "pools", 1, "b1", nil)
		err := WriteCheckpoint(&bytes.Buffer{}, st, "cp-1", "storage-1", nilUUID, nil)
		if err == nil || !strings.Contains(err.Error(), "clock domain") {
			t.Fatalf("a nil boot id names no clock domain: %v", err)
		}
	})
	t.Run("collection with no declaration", func(t *testing.T) {
		st, path := stagePreMigrationStore(t)
		seed(t, st, "pools", 1, "b1", nil)
		// The pre-migration shape: a row whose declaration is NULL.
		if err := clearDeclaration(path, "pools"); err != nil {
			t.Fatal(err)
		}
		err := WriteCheckpoint(&bytes.Buffer{}, st, "cp-1", "storage-1", fakeBootID, nil)
		if err == nil || !strings.Contains(err.Error(), "names no declaration") {
			t.Fatalf("a hash the store cannot name is refused, never invented: %v", err)
		}
	})
	t.Run("empty host", func(t *testing.T) {
		st := openStore(t)
		seed(t, st, "pools", 1, "b1", nil)
		if err := WriteCheckpoint(&bytes.Buffer{}, st, "cp-1", "  ", fakeBootID, nil); err == nil {
			t.Fatal("an empty scope name merges everything it touches")
		}
	})
}

// Every record echoes the checkpoint id: a hub accumulating two
// interleaved checkpoints on one connection must be able to see it,
// because promoting a mixture promotes a state that existed at no moment.
func TestEveryRecordEchoesTheCheckpointID(t *testing.T) {
	st := openStore(t)
	seed(t, st, "pools", 1, "b1", []store.Object{obj("pools:tank", "tank", `{}`, 10)})
	for _, r := range write(t, st, nil) {
		if r["checkpoint"] != "cp-1" {
			t.Fatalf("record does not echo the checkpoint id: %v", r)
		}
	}
}

// TestEmitsConformanceSamples writes real checkpoints — produced by the
// same WriteCheckpoint the wire uses — for the Python conformance suite
// to judge against contract/se.checkpoint.1.json. It is skipped unless
// that suite asks for them.
//
// Generated rather than committed as fixtures, because a committed
// sample is a copy that drifts: it would keep validating after the
// emitter stopped agreeing with it, which is the fourth-copy defect
// wearing a test fixture. And judged in Python rather than here because
// the schema file itself must be the judge — a Go re-implementation of
// the shapes would be this package agreeing with itself.
func TestEmitsConformanceSamples(t *testing.T) {
	dir := os.Getenv("SE_CHECKPOINT_SAMPLES")
	if dir == "" {
		t.Skip("set SE_CHECKPOINT_SAMPLES to emit; conformance does")
	}
	samples := map[string]func(t *testing.T) *bytes.Buffer{
		// The document's own worked case: one applied collection, one
		// that never has, and a stated gap.
		"manifest-state-terminal": func(t *testing.T) *bytes.Buffer {
			st := openStore(t)
			seed(t, st, "pools", 1, "b1", []store.Object{
				obj("pools:tank", "tank", `{"State":"degraded"}`, 10),
				obj("pools:scratch", "scratch", `{"State":"ok"}`, 11),
			})
			if _, err := st.IssueGenerations([]string{"leases"}, "sha256:leases"); err != nil {
				t.Fatal(err)
			}
			if err := st.MarkStale("leases", "unsupported"); err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := WriteCheckpoint(&buf, st, "cp-8f21", "storage-1", fakeBootID,
				&HistoryGap{From: 81422.5, To: 98301.0}); err != nil {
				t.Fatal(err)
			}
			return &buf
		},
		// First connection: gap null, and an applied collection holding
		// nothing, which is the shape `absent` leaves behind.
		"first-connection-empty": func(t *testing.T) *bytes.Buffer {
			st := openStore(t)
			seed(t, st, "pools", 1, "b1", nil)
			var buf bytes.Buffer
			if err := WriteCheckpoint(&buf, st, "cp-first", "edge-1", fakeBootID, nil); err != nil {
				t.Fatal(err)
			}
			return &buf
		},
		// Two instances under one collection: the id repeats and the
		// instance is what separates them.
		"two-instances": func(t *testing.T) *bytes.Buffer {
			st := openStore(t)
			for range 2 {
				if _, err := st.IssueGenerations([]string{"identity"}, "sha256:identity"); err != nil {
					t.Fatal(err)
				}
			}
			for i, inst := range []string{store.HostNative, "radarr"} {
				if _, err := st.ApplyCommit("identity", inst, uint64(i+1), "b", fakeBootID,
					[]store.Object{obj("identity:indexer:3", "indexer:3", `{"Port":1}`, 10)}); err != nil {
					t.Fatal(err)
				}
			}
			var buf bytes.Buffer
			if err := WriteCheckpoint(&buf, st, "cp-inst", "storage-1", fakeBootID, nil); err != nil {
				t.Fatal(err)
			}
			return &buf
		},
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, build := range samples {
		buf := build(t)
		if err := os.WriteFile(filepath.Join(dir, name+".jsonl"), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
