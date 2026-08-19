package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The two documents as the control socket answers them, trimmed to the records
// this collection reads plus enough of their neighbours to keep the shape
// honest: the per-thread block that precedes every total, and the clock records
// that follow them.
const healthyStatus = `version: 1.24.2
verbosity: 1
threads: 1
modules: 2 [ validator iterator ]
uptime: 3648 seconds
options: reuseport control(namedpipe)
unbound (pid 32742) is running...
`

const healthyStats = `thread0.num.queries=21
thread0.num.cachehits=13
thread0.num.cachemiss=8
thread0.num.prefetch=0
thread0.requestlist.current.all=0
thread0.recursion.time.avg=0.120223
total.num.queries=21
total.num.cachehits=13
total.num.cachemiss=8
total.num.prefetch=0
total.requestlist.current.all=0
total.recursion.time.avg=0.120223
time.now=1787128431.901711
time.up=3647.985167
`

// stage writes one replay directory. Each document is named by the COMMAND it
// answers, which is how the seam addresses it — the reference keys a dispatched
// acquisition on its argument, and the corpus commits the same names.
func stage(t *testing.T, documents map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range documents {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func stageDaemon(t *testing.T, status, stats string) string {
	t.Helper()
	return stage(t, map[string]string{"status.txt": status, "stats_noreset.txt": stats})
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

func TestReplayIsByteDeterministicAcrossTwoRuns(t *testing.T) {
	env := map[string]string{"SE_REPLAY_DIR": stageDaemon(t, healthyStatus, healthyStats)}
	code1, first, stderr := runWith(t, "collect daemon:824\n", env)
	code2, second, _ := runWith(t, "collect daemon:824\n", env)
	if code1 != exitOK || code2 != exitOK {
		t.Fatalf("exits %d/%d, stderr: %s", code1, code2, stderr)
	}
	if first != second {
		t.Fatalf("replay is not byte-deterministic:\n%s\nvs\n%s", first, second)
	}
}

func TestReplayPinsEveryRunVaryingMember(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect daemon:824\n",
		map[string]string{"SE_REPLAY_DIR": stageDaemon(t, healthyStatus, healthyStats)})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)

	begin := ofKind(records, "begin")[0]
	if begin["request"] != "replay" || begin["batch"] != "replay" {
		t.Errorf("replay pins batch and request to the constant \"replay\"; got %v/%v", begin["request"], begin["batch"])
	}
	if begin["boot_id"] != replayBootID {
		t.Errorf("a variant staging no boot_id gets the fixed v4-shaped id; got %v", begin["boot_id"])
	}
	if begin["timens"] != 0.0 {
		t.Errorf("no time namespace was observed at capture, so timens is 0; got %v", begin["timens"])
	}
	if begin["instance"] != nil {
		t.Errorf("host-native means instance null, and only null; got %v", begin["instance"])
	}
	// The declaration hash stays REAL under replay — the bytes it covers are
	// static, so determinism costs nothing and the collator's
	// refetch-on-mismatch contract keeps meaning something.
	declaration, _ := begin["declaration"].(string)
	if declaration != declarationDigest || !strings.HasPrefix(declaration, "sha256:") || len(declaration) != len("sha256:")+64 {
		t.Errorf("begin.declaration %q must be the sha256 of the exact declare bytes", declaration)
	}

	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("two documents describe ONE resolver; got %d objects", len(objects))
	}
	if objects[0]["at"] != 1.0 {
		t.Errorf("the first object carries the reference constant 1.0; got %v", objects[0]["at"])
	}
	if objects[0]["name"] != daemonName {
		t.Errorf("the row's native name is %q; got %v", daemonName, objects[0]["name"])
	}
	end := ofKind(records, "end")[0]
	if end["cpu_ms"] != 0.5 || end["wall_ms"] != 1.0 {
		t.Errorf("replay pins cpu_ms=0.5 wall_ms=1.0; got %v/%v", end["cpu_ms"], end["wall_ms"])
	}
}

func TestReplayBootIDIsTheStagedFileWhenAVariantHasOne(t *testing.T) {
	dir := stageDaemon(t, healthyStatus, healthyStats)
	if err := os.WriteFile(filepath.Join(dir, "boot_id"), []byte("8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stdout, _ := runWith(t, "collect daemon:1\n", map[string]string{"SE_REPLAY_DIR": dir})
	if got := ofKind(parseRecords(t, stdout), "begin")[0]["boot_id"]; got != "8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44" {
		t.Fatalf("boot_id must be the staged file, trimmed; got %v", got)
	}
}

func TestReplayNowIsIgnoredButNeverACrash(t *testing.T) {
	// Every fact here is a figure the daemon stated; nothing is derived
	// against a clock, so the pin has nothing to freeze. The contract is only
	// that setting it changes nothing and breaks nothing.
	dir := stageDaemon(t, healthyStatus, healthyStats)
	bare := map[string]string{"SE_REPLAY_DIR": dir}
	pinned := map[string]string{"SE_REPLAY_DIR": dir, "SE_REPLAY_NOW": "2026-08-19T08:33:51Z"}

	code1, first, _ := runWith(t, "collect daemon:2\n", bare)
	code2, second, _ := runWith(t, "collect daemon:2\n", pinned)
	if code1 != exitOK || code2 != exitOK || first != second {
		t.Fatalf("SE_REPLAY_NOW changed the outcome: exits %d/%d", code1, code2)
	}
}

// The seam's whole point: a machine with no resolver of its own replays this
// capture without ever dialling a socket. Asserted on the OUTPUT, because the
// development machine that runs it has no unbound at all — so a seam escape
// here would produce an absent decline, not an error.
func TestTheStagedDocumentsDecideRatherThanTheReplayingHost(t *testing.T) {
	env := map[string]string{
		"SE_REPLAY_DIR": stageDaemon(t, healthyStatus, healthyStats),
		// Deliberately pointing somewhere real-looking: under replay it must
		// never be consulted, and a port that fell back to it on a machine
		// that happened to have a socket would read the wrong resolver.
		socketVariable: "/run/unbound.ctl",
	}
	code, stdout, stderr := runWith(t, "collect daemon:9\n", env)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	facts, _ := ofKind(parseRecords(t, stdout), "object")[0]["facts"].(map[string]any)
	if facts["Version"] != "1.24.2" || facts["NumQueries"] != 21.0 {
		t.Fatalf("the row must come from the staged documents: %v", facts)
	}
}

func TestAnEmptyReplayDirectoryDeclinesUnavailableAndCommitsNothing(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect daemon:77\n",
		map[string]string{"SE_REPLAY_DIR": t.TempDir()})
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["reason"] != "unavailable" ||
		declines[0]["detail"] != declineNoSocket.detail {
		t.Fatalf("expected the shared unavailable decline, got %v", declines)
	}
	// RULED 2026-08-19: a configuration gap must never retire an object, so
	// this reading declines and commits NOTHING. It used to commit zero per
	// collection, which is authoritative-empty and retires — on a host where
	// the interface may be running perfectly and only the receipt is missing.
	// Prior state stands and the collator marks it stale, which is the honest
	// rendering of a reading that did not happen.
	if commits := ofKind(records, "commit"); len(commits) != 0 {
		t.Fatalf("no decline but `absent` commits, so nothing may be retired here; got %v", commits)
	}
}

// The absent reading is spelled ONCE. Storage answered this same question two
// opposite ways for as long as it existed — live `unsupported`, replay `absent`
// — because replay exercises only the replay half; this asserts the two paths
// reach the same VALUE, which is what makes the disagreement unspellable rather
// than merely currently-absent.
//
// At the source rather than through run(), because the live path's other half
// is a Linux clock: the whole batch cannot run on the machine this test is
// written on, and the reading under test is taken before that clock is read
// precisely so an absence answers truthfully on any platform.
func TestAnUnconfiguredSocketIsTheSameAbsentReadingAsAnEmptyCapture(t *testing.T) {
	empty := t.TempDir()
	sources := map[string]source{
		"no socket configured": newSource(func(string) string { return "" }),
		"an empty capture": newSource(func(key string) string {
			if key == "SE_REPLAY_DIR" {
				return empty
			}
			return ""
		}),
	}
	for label, src := range sources {
		_, err := src.daemon()
		var refused *declined
		if !errors.As(err, &refused) {
			t.Fatalf("%s: %v is not a decline at all", label, err)
		}
		if *refused != declineNoSocket {
			t.Fatalf("%s: reached %v, and the shared constant is %v", label, *refused, declineNoSocket)
		}
	}
}

// A capture staging one document and not the other is a broken capture, not a
// statement about a machine: the socket that answered `status` was there to
// answer `stats_noreset` too. "I could not run" — never a decline, which would
// state something about a machine nobody observed, and never a fall-back to the
// resolver of whichever host is replaying.
func TestAHalfStagedCaptureRefusesToRunRatherThanDeclining(t *testing.T) {
	cases := map[string]string{
		"the counters without the status document": stage(t, map[string]string{
			"stats_noreset.txt": healthyStats}),
		"the status document without the counters": stage(t, map[string]string{
			"status.txt": healthyStatus}),
	}
	for label, dir := range cases {
		code, stdout, stderr := runWith(t, "collect daemon:5\n", map[string]string{"SE_REPLAY_DIR": dir})
		if code != exitRuntime {
			t.Errorf("%s: exit %d, want %d", label, code, exitRuntime)
		}
		if stderr == "" {
			t.Errorf("%s: refusing without saying why tells nobody anything", label)
		}
		if len(ofKind(parseRecords(t, stdout), "decline")) != 0 {
			t.Errorf("%s: a broken capture must not become a statement about a machine", label)
		}
	}
}

func TestProbeAnswersWithAVerdictNotAnExitCode(t *testing.T) {
	code, stdout, _ := runWith(t, "probe\n",
		map[string]string{"SE_REPLAY_DIR": stageDaemon(t, healthyStatus, healthyStats)})
	if code != exitOK || !strings.Contains(stdout, `"verdict":"yes"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}

	// A no is still exit zero: the verdict is the answer, and a non-zero exit
	// would read as a crash (DESIGN 18).
	code, stdout, _ = runWith(t, "probe\n", map[string]string{"SE_REPLAY_DIR": t.TempDir()})
	if code != exitOK || !strings.Contains(stdout, `"verdict":"no"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	if record := parseRecords(t, stdout)[0]; record["reason"] == "" || record["reason"] == nil {
		t.Fatal("a verdict without its why is not actionable")
	}
}
