package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Four entries in the shape journalctl -o json answers with: every value a
// string, newest first, and a cursor on each. The third and fourth share a
// MESSAGE_ID and differ in their interpolated text, which is the repeat
// identity's whole reason for preferring the id.
var healthyEntries = []map[string]any{
	{
		"__CURSOR":             "s=aa;i=4;b=bb;m=1;t=1;x=1",
		"__REALTIME_TIMESTAMP": "1787125570280809",
		"MESSAGE":              "Accepted publickey for root",
		"PRIORITY":             "6",
		"SYSLOG_IDENTIFIER":    "sshd-session",
		"_TRANSPORT":           "syslog",
		"_SYSTEMD_UNIT":        "ssh.service",
		"_COMM":                "sshd-session",
		"_PID":                 "4321",
	},
	{
		"__CURSOR":             "s=aa;i=3;b=bb;m=2;t=2;x=2",
		"__REALTIME_TIMESTAMP": "1787125570000000",
		"MESSAGE":              "audit: apparmor=\"DENIED\" operation=\"open\"",
		"PRIORITY":             "4",
		"SYSLOG_IDENTIFIER":    "kernel",
		"_TRANSPORT":           "kernel",
	},
	{
		"__CURSOR":             "s=aa;i=2;b=bb;m=3;t=3;x=3",
		"__REALTIME_TIMESTAMP": "1787125569000000",
		"MESSAGE":              "Started session-9.scope.",
		"MESSAGE_ID":           "39f53479d3a045ac8e11786248231fbf",
		"PRIORITY":             "6",
		"SYSLOG_IDENTIFIER":    "systemd",
		"_TRANSPORT":           "journal",
		"_SYSTEMD_UNIT":        "init.scope",
		"_COMM":                "systemd",
		"_PID":                 "1",
	},
	{
		"__CURSOR":             "s=aa;i=1;b=bb;m=4;t=4;x=4",
		"__REALTIME_TIMESTAMP": "1787125568000000",
		"MESSAGE":              "Started session-8.scope.",
		"MESSAGE_ID":           "39f53479d3a045ac8e11786248231fbf",
		"PRIORITY":             "6",
		"SYSLOG_IDENTIFIER":    "systemd",
		"_TRANSPORT":           "journal",
		"_SYSTEMD_UNIT":        "init.scope",
		"_COMM":                "systemd",
		"_PID":                 "1",
	},
}

// stageEntries writes one replay directory. The payload is named by the stem
// the seam addresses it under — derived, never typed, so a test cannot
// accidentally agree with a name the collector no longer looks for.
func stageEntries(t *testing.T, entries []map[string]any) string {
	t.Helper()
	dir := t.TempDir()
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, replayPayload()), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
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

func factsOf(t *testing.T, record map[string]any) map[string]any {
	t.Helper()
	facts, ok := record["facts"].(map[string]any)
	if !ok {
		t.Fatalf("object record carries no facts object: %v", record)
	}
	return facts
}

func TestReplayIsByteDeterministicAcrossTwoRuns(t *testing.T) {
	env := map[string]string{"SE_REPLAY_DIR": stageEntries(t, healthyEntries)}
	code1, first, stderr := runWith(t, "collect journal:658\n", env)
	code2, second, _ := runWith(t, "collect journal:658\n", env)
	if code1 != exitOK || code2 != exitOK {
		t.Fatalf("exits %d/%d, stderr: %s", code1, code2, stderr)
	}
	if first != second {
		t.Fatalf("replay is not byte-deterministic:\n%s\nvs\n%s", first, second)
	}
}

func TestReplayPinsEveryRunVaryingMember(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect journal:658\n",
		map[string]string{"SE_REPLAY_DIR": stageEntries(t, healthyEntries)})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)

	begin := ofKind(records, "begin")[0]
	if begin["request"] != "replay" || begin["batch"] != "replay" {
		t.Errorf("replay pins batch and request to the constant \"replay\"; got %v/%v", begin["request"], begin["batch"])
	}
	if begin["boot_id"] != replayBootID {
		t.Errorf("replay boot_id is %v, want the published v4-shaped stand-in", begin["boot_id"])
	}
	if begin["timens"] != float64(0) {
		t.Errorf("replay timens is %v; a live reading here would smuggle the replaying machine in", begin["timens"])
	}
	// The reference constant, one counter across the whole batch. Asserted
	// because a hardcoded zero would satisfy "finite and boot-scale" while
	// exercising nothing the rule is for.
	for i, object := range ofKind(records, "object") {
		want := float64(int64((1.0+0.001*float64(i))*1000+0.5)) / 1000
		if object["at"] != want {
			t.Errorf("object %d carries at=%v, want the replay constant %v", i, object["at"], want)
		}
	}
	if commit := ofKind(records, "commit")[0]; commit["generation"] != float64(658) {
		t.Errorf("the commit echoes generation %v, and the request line issued 658", commit["generation"])
	}
}

// The counts a commit carries describe the stream it closes, and all three are
// required members: a subject that can disable the truncation check by omitting
// one has defeated it (DESIGN 19). A journal entry asserts no relation and
// reports no unobservable, so the two zeroes are the statement.
func TestTheCommitCountsTheStreamItCloses(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect journal:7\n",
		map[string]string{"SE_REPLAY_DIR": stageEntries(t, healthyEntries)})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	commit := ofKind(records, "commit")[0]
	if commit["objects"] != float64(len(healthyEntries)) {
		t.Errorf("commit says objects=%v, stream carries %d", commit["objects"], len(ofKind(records, "object")))
	}
	for _, member := range []string{"assertions", "unobservable"} {
		if commit[member] != float64(0) {
			t.Errorf("commit %s is %v; this collection publishes neither", member, commit[member])
		}
	}
}

// A journal entry is named by its cursor and by nothing else: the cursor is the
// only handle that reads the same entry again, and a row the collator cannot
// re-address is a row nobody can open.
func TestEveryRowIsNamedByItsCursor(t *testing.T) {
	code, stdout, _ := runWith(t, "collect journal:7\n",
		map[string]string{"SE_REPLAY_DIR": stageEntries(t, healthyEntries)})
	if code != exitOK {
		t.Fatal("collect failed")
	}
	objects := ofKind(parseRecords(t, stdout), "object")
	for i, object := range objects {
		if object["name"] != healthyEntries[i]["__CURSOR"] {
			t.Errorf("row %d is named %v, and its entry's cursor is %v", i, object["name"], healthyEntries[i]["__CURSOR"])
		}
	}
}

// The absent reading is ONE constant reached by both paths. This is the storage
// lesson executed rather than commented: that collector answered one condition
// `unsupported` live and `absent` under replay for as long as it existed, each
// under a confident comment arguing against the other, and nothing caught it
// because replay exercises only the replay half. So both halves are driven
// here, in one test, and compared to the same value.
func TestTheAbsentReadingIsOneConstantForBothPaths(t *testing.T) {
	if declineNoJournal.reason != "absent" {
		t.Fatalf("the no-journal reading is %q; absent is the only decline that commits, and a host that lost systemd must have its entries retired", declineNoJournal.reason)
	}

	// replay: the payload the variant did not stage
	_, replayErr := replaySource{dir: t.TempDir()}.journal()
	// live: journalctl nowhere on PATH
	t.Setenv("PATH", t.TempDir())
	_, liveErr := (&liveSource{}).journal()

	for label, err := range map[string]error{"replay": replayErr, "live": liveErr} {
		var refused *declined
		if !errors.As(err, &refused) {
			t.Fatalf("%s path answered %v, not a decline", label, err)
		}
		if *refused != declineNoJournal {
			t.Errorf("the %s path spells the no-journal reading %q/%q; the other path spells it %q/%q — one condition, two answers, which is the defect this test exists for",
				label, refused.reason, refused.detail, declineNoJournal.reason, declineNoJournal.detail)
		}
	}
}

// absent is authoritative-empty: it declines AND commits zero, because "there
// is no journal here" establishes something and must be able to retire what a
// previous batch published (DESIGN 19).
func TestAnAbsentJournalDeclinesAndCommitsZero(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect journal:12\n",
		map[string]string{"SE_REPLAY_DIR": t.TempDir()})
	if code != exitOK {
		t.Fatalf("a decline is data, not an error: exit %d, stderr %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["reason"] != "absent" || declines[0]["detail"] != declineNoJournal.detail {
		t.Fatalf("expected one absent decline carrying the shared detail, got %v", declines)
	}
	commits := ofKind(records, "commit")
	if len(commits) != 1 || commits[0]["objects"] != float64(0) {
		t.Fatalf("an absent decline commits zero objects, or it retires nothing: %v", commits)
	}
	if len(ofKind(records, "object")) != 0 {
		t.Fatal("a decline closes its collection to every emitting record")
	}
}

// A payload the variant staged and this binary cannot read is a broken capture,
// never a statement about a machine — so it fails the batch instead of
// declining, and it never falls back to the live journal of whichever
// workstation is replaying the corpus.
func TestAnUnreadablePayloadFailsRatherThanDeclining(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, replayPayload()), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runWith(t, "collect journal:12\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitRuntime {
		t.Fatalf("exit %d; a broken capture is 'I could not run', never a decline", code)
	}
	if stderr == "" {
		t.Fatal("a failed batch with no stderr line tells nobody what broke")
	}
}

// The seam's payload is what _run_journalctl RETURNS — the parsed entries as a
// list — not the NDJSON journalctl wrote. A capture that staged the raw stream
// would be replayed against a document the reference never saw, and the run
// would report about the harness rather than about the collector.
func TestTheStagedStreamIsRefusedInPlaceOfTheParsedList(t *testing.T) {
	dir := t.TempDir()
	raw, _ := json.Marshal(healthyEntries[0])
	if err := os.WriteFile(filepath.Join(dir, replayPayload()), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runWith(t, "collect journal:12\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitRuntime || !strings.Contains(stderr, "list of journal entries") {
		t.Fatalf("exit %d, stderr %q — a single object where the list belongs must be refused by name", code, stderr)
	}
}
