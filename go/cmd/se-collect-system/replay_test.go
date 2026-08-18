package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const healthyOsRelease = "ID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n"

// stageReplayDir lays out the documents the replay seam reads: os-release
// and hostname as raw text, boot_id optional (empty string stages none, so
// the fallback path is reachable).
func stageReplayDir(t *testing.T, osRelease, hostname, bootID string) string {
	t.Helper()
	dir := t.TempDir()
	stage := func(name, content string) {
		if content == "" {
			return
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stage("os-release", osRelease)
	stage("hostname", hostname)
	stage("boot_id", bootID)
	return dir
}

func TestReplayIsByteDeterministicAcrossTwoRuns(t *testing.T) {
	dir := stageReplayDir(t, healthyOsRelease, "corpus-host", "8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44\n")
	env := map[string]string{"SE_REPLAY_DIR": dir}

	code1, first, stderr := runWith(t, "collect identity:658\n", env)
	code2, second, _ := runWith(t, "collect identity:658\n", env)
	if code1 != exitOK || code2 != exitOK {
		t.Fatalf("exits %d/%d, stderr: %s", code1, code2, stderr)
	}
	if first != second {
		t.Fatalf("replay is not byte-deterministic:\n%s\nvs\n%s", first, second)
	}
}

func TestReplayPinsEveryRunVaryingMember(t *testing.T) {
	dir := stageReplayDir(t, healthyOsRelease, "corpus-host", "8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44\n")
	code, stdout, stderr := runWith(t, "collect identity:658\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)

	begin := ofKind(records, "begin")[0]
	if begin["request"] != "replay" || begin["batch"] != "replay" {
		t.Errorf("replay pins batch and request to the constant \"replay\"; got %v/%v", begin["request"], begin["batch"])
	}
	if begin["boot_id"] != "8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44" {
		t.Errorf("boot_id must be the staged file, trimmed; got %v", begin["boot_id"])
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

	if at := ofKind(records, "object")[0]["at"]; at != 1.0 {
		t.Errorf("the first replayed object carries at = 1.0 + 0.001*0; got %v", at)
	}
	end := ofKind(records, "end")[0]
	if end["cpu_ms"] != 0.5 || end["wall_ms"] != 1.0 {
		t.Errorf("replay pins cpu_ms=0.5 wall_ms=1.0; got %v/%v", end["cpu_ms"], end["wall_ms"])
	}
}

func TestReplayBootIDFallsBackToTheFixedID(t *testing.T) {
	dir := stageReplayDir(t, healthyOsRelease, "corpus-host", "")
	_, stdout, _ := runWith(t, "collect identity:1\n", map[string]string{"SE_REPLAY_DIR": dir})
	begin := ofKind(parseRecords(t, stdout), "begin")[0]
	if begin["boot_id"] != replayBootID {
		t.Fatalf("a variant staging no boot_id gets the fixed v4-shaped id %s; got %v", replayBootID, begin["boot_id"])
	}
}

func TestReplayNowIsIgnoredButNeverACrash(t *testing.T) {
	// This collector derives nothing from wall time, so SE_REPLAY_NOW has
	// nothing to pin — the contract is only that setting it changes
	// nothing and breaks nothing.
	dir := stageReplayDir(t, healthyOsRelease, "corpus-host", "")
	bare := map[string]string{"SE_REPLAY_DIR": dir}
	pinned := map[string]string{"SE_REPLAY_DIR": dir, "SE_REPLAY_NOW": "2026-08-14T12:00:00Z"}

	code1, first, _ := runWith(t, "collect identity:2\n", bare)
	code2, second, _ := runWith(t, "collect identity:2\n", pinned)
	if code1 != exitOK || code2 != exitOK || first != second {
		t.Fatalf("SE_REPLAY_NOW changed the outcome: exits %d/%d", code1, code2)
	}
}

func TestReplayWithoutOsReleaseDeclinesAbsentAndCommitsZero(t *testing.T) {
	dir := stageReplayDir(t, "", "corpus-host", "")
	code, stdout, stderr := runWith(t, "collect identity:77\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["reason"] != "absent" {
		t.Fatalf("expected the absent decline, got %v", declines)
	}
	commits := ofKind(records, "commit")
	if len(commits) != 1 || commits[0]["objects"] != 0.0 || commits[0]["generation"] != 77.0 {
		t.Fatalf("absent commits zero under the issued generation; got %v", commits)
	}
}

func TestReplayWithUnreadableOsReleaseDeclinesUnavailable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads through file modes, so the staged unreadability would not hold")
	}
	dir := stageReplayDir(t, healthyOsRelease, "corpus-host", "")
	if err := os.Chmod(filepath.Join(dir, "os-release"), 0o000); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := runWith(t, "collect identity:6\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("a decline is data, never an error exit; got %d", code)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["reason"] != "unavailable" {
		t.Fatalf("expected the unavailable decline, got %v", declines)
	}
	if len(ofKind(records, "commit")) != 0 {
		t.Fatal("unavailable established nothing and must not commit")
	}
}

func TestReplayWithUncapturedHostnameRefusesToRun(t *testing.T) {
	// os-release staged, hostname not: a broken capture, not a statement
	// about any machine — so "I could not run", never a decline that would
	// lie about the host the payloads came from.
	dir := stageReplayDir(t, healthyOsRelease, "", "")
	code, _, stderr := runWith(t, "collect identity:5\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitRuntime {
		t.Fatalf("exit %d, want %d", code, exitRuntime)
	}
	if !strings.Contains(stderr, "not captured") {
		t.Fatalf("stderr must name the missing capture: %q", stderr)
	}
}

func TestProbeAnswersWithAVerdictNotAnExitCode(t *testing.T) {
	ready := stageReplayDir(t, healthyOsRelease, "corpus-host", "")
	code, stdout, _ := runWith(t, "probe\n", map[string]string{"SE_REPLAY_DIR": ready})
	if code != exitOK || !strings.Contains(stdout, `"verdict":"yes"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}

	// A no is still exit zero: the verdict is the answer, and a non-zero
	// exit would read as a crash (DESIGN 18).
	bare := stageReplayDir(t, "", "", "")
	code, stdout, _ = runWith(t, "probe\n", map[string]string{"SE_REPLAY_DIR": bare})
	if code != exitOK || !strings.Contains(stdout, `"verdict":"no"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	record := parseRecords(t, stdout)[0]
	if record["reason"] == "" || record["reason"] == nil {
		t.Fatal("a verdict without its why is not actionable")
	}
}
