package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Three rows in the shape dpkg-query answers this collector's format string
// with: name, version, architecture, db status.
var healthyRows = [][]string{
	{"adduser", "3.153ubuntu1", "all", "installed"},
	{"dpkg", "1.23.7ubuntu1", "amd64", "installed"},
	{"zstd", "1.5.7+dfsg-3", "amd64", "installed"},
}

// stage writes one replay directory. Every payload is named by the stem the
// seam addresses it under, exactly as the corpus commits it.
func stage(t *testing.T, payloads map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	for stem, document := range payloads {
		raw, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, stem+".json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func stageDpkg(t *testing.T, rows [][]string) string {
	t.Helper()
	return stage(t, map[string]any{"manager": managerDpkg, "dpkg": rows})
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
	env := map[string]string{"SE_REPLAY_DIR": stageDpkg(t, healthyRows)}
	code1, first, stderr := runWith(t, "collect packages:658\n", env)
	code2, second, _ := runWith(t, "collect packages:658\n", env)
	if code1 != exitOK || code2 != exitOK {
		t.Fatalf("exits %d/%d, stderr: %s", code1, code2, stderr)
	}
	if first != second {
		t.Fatalf("replay is not byte-deterministic:\n%s\nvs\n%s", first, second)
	}
}

func TestReplayPinsEveryRunVaryingMember(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect packages:658\n",
		map[string]string{"SE_REPLAY_DIR": stageDpkg(t, healthyRows)})
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
	// The declaration hash stays REAL under replay — the bytes it covers
	// are static, so determinism costs nothing and the collator's
	// refetch-on-mismatch contract keeps meaning something.
	declaration, _ := begin["declaration"].(string)
	if declaration != declarationDigest || !strings.HasPrefix(declaration, "sha256:") || len(declaration) != len("sha256:")+64 {
		t.Errorf("begin.declaration %q must be the sha256 of the exact declare bytes", declaration)
	}

	objects := ofKind(records, "object")
	if len(objects) != len(healthyRows) {
		t.Fatalf("expected %d objects, got %d", len(healthyRows), len(objects))
	}
	// One counter across the batch, 1.0 + 0.001*i, rounded as the reference
	// rounds it: at a thousand rows the unrounded constant reads
	// 1.1260000000000001 in a file people compare by eye.
	for i, want := range []float64{1.0, 1.001, 1.002} {
		if objects[i]["at"] != want {
			t.Errorf("object %d carries at %v, want %v", i, objects[i]["at"], want)
		}
	}
	end := ofKind(records, "end")[0]
	if end["cpu_ms"] != 0.5 || end["wall_ms"] != 1.0 {
		t.Errorf("replay pins cpu_ms=0.5 wall_ms=1.0; got %v/%v", end["cpu_ms"], end["wall_ms"])
	}
}

func TestReplayBootIDIsTheStagedFileWhenAVariantHasOne(t *testing.T) {
	dir := stageDpkg(t, healthyRows)
	if err := os.WriteFile(filepath.Join(dir, "boot_id"), []byte("8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stdout, _ := runWith(t, "collect packages:1\n", map[string]string{"SE_REPLAY_DIR": dir})
	if got := ofKind(parseRecords(t, stdout), "begin")[0]["boot_id"]; got != "8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44" {
		t.Fatalf("boot_id must be the staged file, trimmed; got %v", got)
	}
}

func TestReplayNowIsIgnoredButNeverACrash(t *testing.T) {
	// An inventory is a set of strings the interface handed over; nothing
	// here is derived against a clock, so the pin has nothing to freeze. The
	// contract is only that setting it changes nothing and breaks nothing.
	dir := stageDpkg(t, healthyRows)
	bare := map[string]string{"SE_REPLAY_DIR": dir}
	pinned := map[string]string{"SE_REPLAY_DIR": dir, "SE_REPLAY_NOW": "2026-08-19T08:00:00Z"}

	code1, first, _ := runWith(t, "collect packages:2\n", bare)
	code2, second, _ := runWith(t, "collect packages:2\n", pinned)
	if code1 != exitOK || code2 != exitOK || first != second {
		t.Fatalf("SE_REPLAY_NOW changed the outcome: exits %d/%d", code1, code2)
	}
}

// The whole point of pinning _detect: a machine with no package manager of
// its own replays a dpkg capture without ever reading its own database. The
// test asserts the OUTPUT rather than the absence of a call, because the
// development machine that runs it has neither dpkg-query nor a Nix closure
// — so a seam escape here would produce an empty inventory, not an error.
func TestTheStagedManagerDecidesRatherThanTheReplayingHost(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect packages:9\n",
		map[string]string{"SE_REPLAY_DIR": stageDpkg(t, healthyRows)})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	for _, object := range ofKind(parseRecords(t, stdout), "object") {
		facts, _ := object["facts"].(map[string]any)
		if facts["Manager"] != managerDpkg {
			t.Fatalf("row %v names manager %v, and the capture says dpkg", object["name"], facts["Manager"])
		}
	}
}

func TestAnEmptyReplayDirectoryDeclinesAbsentAndCommitsZero(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect packages:77\n",
		map[string]string{"SE_REPLAY_DIR": t.TempDir()})
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["reason"] != "absent" ||
		declines[0]["detail"] != declineNoManager.detail {
		t.Fatalf("expected the shared absent decline, got %v", declines)
	}
	commits := ofKind(records, "commit")
	if len(commits) != 1 || commits[0]["objects"] != 0.0 || commits[0]["generation"] != 77.0 {
		t.Fatalf("absent is authoritative-empty and commits zero under the issued generation; got %v", commits)
	}
}

// Three broken captures, each of which must be "I could not run" and never a
// decline: a decline states something about a machine, and none of these
// observed one. The alternative in every case is worse than an error — a
// guess at which manager was speaking, an inventory retired on the strength
// of a missing file, or every package on the host retired because a word
// nobody understood was read as an empty listing.
func TestABrokenCaptureRefusesToRunRatherThanDeclining(t *testing.T) {
	cases := map[string]string{
		"rows with no manager beside them": stage(t, map[string]any{"dpkg": healthyRows}),
		"a manager whose rows are missing": stage(t, map[string]any{"manager": managerDpkg}),
		"a manager this collector cannot read": stage(t, map[string]any{
			"manager": "pacman", "dpkg": healthyRows}),
	}
	for label, dir := range cases {
		code, stdout, stderr := runWith(t, "collect packages:5\n", map[string]string{"SE_REPLAY_DIR": dir})
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
		map[string]string{"SE_REPLAY_DIR": stageDpkg(t, healthyRows)})
	if code != exitOK || !strings.Contains(stdout, `"verdict":"yes"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	if !strings.Contains(stdout, managerDpkg) {
		t.Fatalf("a yes must name which manager answered, because that is the Manager fact: %q", stdout)
	}

	// A no is still exit zero: the verdict is the answer, and a non-zero
	// exit would read as a crash (DESIGN 18).
	code, stdout, _ = runWith(t, "probe\n", map[string]string{"SE_REPLAY_DIR": t.TempDir()})
	if code != exitOK || !strings.Contains(stdout, `"verdict":"no"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	if record := parseRecords(t, stdout)[0]; record["reason"] == "" || record["reason"] == nil {
		t.Fatal("a verdict without its why is not actionable")
	}
}
