package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"strings"
	"testing"
)

// fakeSource logs every acquisition call and hands out clock readings that
// advance on each call — so WHEN a value was taken is recoverable from the
// value itself, which is what lets the at-before-read test below fail if
// the stamp ever moves after the reads.
type fakeSource struct {
	calls    []string
	tick     float64
	osrel    []byte
	oserr    error
	host     string
	hosterr  error
	timedate []byte
	tderr    error
	timesync []byte
	tserr    error
	procs    map[string]string
	blocks   map[string]bool
	ncpu     int
	now      float64
	sysd     []byte
	sderr    error
	nixp     *nixPointers
	vars     map[string][]byte
	partmap  map[string]string
}

func (f *fakeSource) note(what string) float64 {
	f.calls = append(f.calls, what)
	f.tick++
	return f.tick
}

func (f *fakeSource) bootID() (string, error) {
	f.note("boot_id")
	return "4f2a1c8e-7b3d-4a91-9e2f-6c5d8a0b1e37", nil
}
func (f *fakeSource) timens() int64 { return 0 }
func (f *fakeSource) batch() (string, error) {
	f.note("batch")
	return "test-batch", nil
}
func (f *fakeSource) stamp(int) (float64, error) { return f.note("stamp"), nil }
func (f *fakeSource) osRelease() ([]byte, error) {
	f.note("os-release")
	return f.osrel, f.oserr
}
func (f *fakeSource) timedate1() ([]byte, error) {
	f.note("timedate1")
	if f.timedate == nil && f.tderr == nil {
		return nil, errCallFailed
	}
	return f.timedate, f.tderr
}
func (f *fakeSource) timesync1() ([]byte, error) {
	f.note("timesync1")
	if f.timesync == nil && f.tserr == nil {
		return nil, errCallFailed
	}
	return f.timesync, f.tserr
}
func (f *fakeSource) proc(name string) string {
	f.note("proc:" + name)
	return f.procs[name]
}
func (f *fakeSource) sysBlock() map[string]bool {
	if f.blocks == nil {
		return map[string]bool{}
	}
	return f.blocks
}
func (f *fakeSource) cpus() int        { return f.ncpu }
func (f *fakeSource) wallNow() float64 { return f.now }
func (f *fakeSource) systemd1() ([]byte, error) {
	f.note("systemd1")
	if f.sysd == nil && f.sderr == nil {
		return nil, errCallFailed
	}
	return f.sysd, f.sderr
}
func (f *fakeSource) nix() *nixPointers          { return f.nixp }
func (f *fakeSource) efivars() map[string][]byte { return f.vars }
func (f *fakeSource) partitionDevice(uuid string) string {
	return f.partmap[uuid]
}
func (f *fakeSource) hostname() (string, error) {
	f.note("hostname")
	if f.hosterr != nil {
		return "", f.hosterr
	}
	return f.host, nil
}
func (f *fakeSource) costs() (float64, float64) {
	f.note("costs")
	return 2.0, 3.0
}

func healthyFake() *fakeSource {
	return &fakeSource{
		osrel: []byte("ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"),
		host:  "corpus-host",
	}
}

func runCollect(t *testing.T, src source, order []string, generations map[string]uint64) (int, []map[string]any, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := collect(&stdout, &stderr, src, order, generations)
	return code, parseRecords(t, stdout.String()), stderr.String()
}

func parseRecords(t *testing.T, stream string) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(stream), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("stream line is not JSON: %v\n%s", err, line)
		}
		records = append(records, record)
	}
	return records
}

func ofKind(records []map[string]any, kind string) []map[string]any {
	var out []map[string]any
	for _, r := range records {
		if r["record"] == kind {
			out = append(out, r)
		}
	}
	return out
}

func TestAtIsStampedBeforeTheEarliestContributingRead(t *testing.T) {
	src := healthyFake()
	code, records, stderr := runCollect(t, src, []string{"identity"}, map[string]uint64{"identity": 7})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}

	// The stamp must precede both native reads in call order…
	order := strings.Join(src.calls, " ")
	stamp := strings.Index(order, "stamp")
	if stamp == -1 || stamp > strings.Index(order, "os-release") || stamp > strings.Index(order, "hostname") {
		t.Fatalf("`at` must be stamped before the earliest contributing read; calls were: %v", src.calls)
	}

	// …and the emitted `at` must carry the reading taken THEN — the fake's
	// clock advances on every call, so a stamp moved after the reads would
	// surface here as a larger value even if the call log were gamed.
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("expected one object, got %d", len(objects))
	}
	// boot_id(1) → batch(2) → stamp(3): the object may never claim a
	// reading taken after its reads (4, 5), because the tie must break
	// toward older (DESIGN 19).
	if at := objects[0]["at"].(float64); at != 3.0 {
		t.Errorf("object claims at=%v, but the pre-read stamp was 3.0 — the stamp moved after a read", at)
	}
}

// The other half of the `at` rule: non-decreasing within a collection. One
// batch of this collector emits one object, so the property lives in the
// generator — the replay formula must advance with emission order, and a
// live stamp is CLOCK_BOOTTIME, monotonic by the kernel's own contract.
func TestReplayStampAdvancesWithEmissionOrder(t *testing.T) {
	src := replaySource{}
	previous := -1.0
	for i := 0; i < 100; i++ {
		at, err := src.stamp(i)
		if err != nil {
			t.Fatal(err)
		}
		if at <= previous {
			t.Fatalf("stamp(%d) = %v does not advance past %v", i, at, previous)
		}
		if at <= 0 || at >= 1e9 {
			t.Fatalf("stamp(%d) = %v is not boot-scale", i, at)
		}
		previous = at
	}
}

func TestHealthyBatchEmitsTheDeclaredFactsAndCounts(t *testing.T) {
	code, records, stderr := runCollect(t, healthyFake(), []string{"identity"}, map[string]uint64{"identity": 41})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}

	object := ofKind(records, "object")[0]
	if object["name"] != "corpus-host" {
		t.Errorf("the object's native name IS the hostname (law 1); got %v", object["name"])
	}
	facts := object["facts"].(map[string]any)
	for fact, want := range map[string]string{
		"OsId":         "debian",
		"OsVersionId":  "12",
		"OsPrettyName": "Debian GNU/Linux 12 (bookworm)",
		"Hostname":     "corpus-host",
	} {
		if facts[fact] != want {
			t.Errorf("%s: got %v, want %q", fact, facts[fact], want)
		}
	}
	if _, ok := object["absent"]; ok {
		t.Error("nothing is missing here, so no absent list may appear")
	}

	commit := ofKind(records, "commit")[0]
	for member, want := range map[string]float64{"objects": 1, "assertions": 0, "unobservable": 0, "generation": 41} {
		if commit[member] != any(want) {
			t.Errorf("commit %s: got %v, want %v", member, commit[member], want)
		}
	}

	begin, end := ofKind(records, "begin")[0], ofKind(records, "end")[0]
	if begin["request"] != begin["batch"] {
		t.Error("request := batch by ruling (appendix C)")
	}
	if end["request"] != begin["request"] || end["batch"] != begin["batch"] {
		t.Error("end must echo the batch and request begin opened")
	}
}

func TestMissingVersionIDLandsOnTheAbsentList(t *testing.T) {
	src := healthyFake()
	src.osrel = []byte("ID=arch\nPRETTY_NAME=\"Arch Linux\"\n") // rolling: genuinely no VERSION_ID
	_, records, _ := runCollect(t, src, []string{"identity"}, map[string]uint64{"identity": 3})

	object := ofKind(records, "object")[0]
	absent, ok := object["absent"].([]any)
	if !ok || len(absent) != 1 || absent[0] != "OsVersionId" {
		t.Fatalf("a genuinely missing VERSION_ID is the absent list's statement, on its own channel; got %v", object["absent"])
	}
	if _, ok := object["facts"].(map[string]any)["OsVersionId"]; ok {
		t.Error("an absent fact must not also carry a value")
	}
}

func TestBothOsReleaseFilesMissingDeclinesAbsentAndCommitsZero(t *testing.T) {
	src := healthyFake()
	src.oserr = fs.ErrNotExist
	src.osrel = nil
	code, records, stderr := runCollect(t, src, []string{"identity"}, map[string]uint64{"identity": 9})
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d, stderr: %s", code, stderr)
	}

	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["reason"] != "absent" {
		t.Fatalf("expected one absent decline, got %v", declines)
	}
	commits := ofKind(records, "commit")
	if len(commits) != 1 {
		t.Fatalf("absent is authoritative-empty and MUST commit, so it can retire stale objects; got %d commits", len(commits))
	}
	for _, member := range []string{"objects", "assertions", "unobservable"} {
		if commits[0][member] != any(0.0) {
			t.Errorf("commit %s: got %v, want 0 — zero when zero, never omitted", member, commits[0][member])
		}
	}
	if len(ofKind(records, "object")) != 0 {
		t.Error("an absent collection emits no objects")
	}
}

func TestUnreadableOsReleaseDeclinesUnavailableWithoutCommitting(t *testing.T) {
	src := healthyFake()
	src.oserr = fs.ErrPermission
	src.osrel = nil
	code, records, _ := runCollect(t, src, []string{"identity"}, map[string]uint64{"identity": 5})
	if code != exitOK {
		t.Fatalf("a decline is data, never an error exit; got %d", code)
	}

	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["reason"] != "unavailable" {
		t.Fatalf("expected one unavailable decline, got %v", declines)
	}
	if commits := ofKind(records, "commit"); len(commits) != 0 {
		t.Fatalf("unavailable established nothing and must not commit — a commit here could delete real state; got %v", commits)
	}
	if len(ofKind(records, "end")) != 1 {
		t.Error("the batch still closes: end is about the batch, not the collection")
	}
}

func TestACollectionThisCollectorNeverDeclaredIsDeclinedUnsupported(t *testing.T) {
	code, records, _ := runCollect(t, healthyFake(), []string{"pools", "identity"},
		map[string]uint64{"pools": 8814, "identity": 41})
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var poolDecline map[string]any
	for _, d := range ofKind(records, "decline") {
		if d["collection"] == "pools" {
			poolDecline = d
		}
	}
	if poolDecline == nil || poolDecline["reason"] != "unsupported" {
		t.Fatalf("a name this collector did not publish is declined, not sanitised (DESIGN 18); got %v", poolDecline)
	}
	for _, c := range ofKind(records, "commit") {
		if c["collection"] == "pools" {
			t.Fatal("an unsupported decline must not commit")
		}
	}
	// The requested collection this collector does serve still answers.
	if len(ofKind(records, "object")) != 1 {
		t.Error("identity must still be served alongside the declined collection")
	}
}
