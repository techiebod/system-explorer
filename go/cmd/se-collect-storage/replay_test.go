package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One raidz1 of two disks with a finished scrub, the smallest document that
// exercises every channel at once.
const stagedStatus = `{"pools": {"tank": {
  "name": "tank", "state": "ONLINE", "pool_guid": 18444306082397320711,
  "error_count": 0,
  "scan_stats": {"function": "SCRUB", "state": "FINISHED", "end_time": 1786602071},
  "vdevs": {"tank": {"vdev_type": "root", "state": "ONLINE", "vdevs": {
    "raidz1-0": {"vdev_type": "raidz", "state": "ONLINE",
      "read_errors": 0, "write_errors": 0, "checksum_errors": 0,
      "vdevs": {
        "wwn-0xaa": {"vdev_type": "disk", "state": "ONLINE", "guid": 18444306082397320712,
                     "path": "/dev/disk/by-id/wwn-0xaa-part1", "devid": "scsi-3aa-part1",
                     "read_errors": 0, "write_errors": 0, "checksum_errors": 0},
        "wwn-0xbb": {"vdev_type": "disk", "state": "ONLINE", "guid": 3,
                     "path": "/dev/disk/by-id/wwn-0xbb-part1",
                     "read_errors": 0, "write_errors": 0, "checksum_errors": 0}
      }}
  }}}
}}}`

const stagedList = `{"pools": {"tank": {
  "properties": {"size": {"value": "100"}, "allocated": {"value": "40"},
                 "free": {"value": "60"}, "capacity": {"value": "40"},
                 "fragmentation": {"value": "5"}},
  "vdevs": {"raidz1-0": {"properties": {"size": {"value": "100"},
                                        "allocated": {"value": "40"},
                                        "capacity": {"value": "40"}}}}
}}}`

// stageReplayDir lays out the documents the replay seam reads, by stem. An
// empty string stages no file, so every could-not-read path is reachable.
func stageReplayDir(t *testing.T, status, list, devlinks string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"status.json": status, "list.json": list, "devlinks.json": devlinks,
	} {
		if content == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func replayEnv(dir string) map[string]string {
	return map[string]string{"SE_REPLAY_DIR": dir, "SE_REPLAY_NOW": "2026-08-16T09:00:00Z"}
}

func TestReplayIsByteDeterministicAcrossTwoRuns(t *testing.T) {
	env := replayEnv(stageReplayDir(t, stagedStatus, stagedList, `{}`))
	code1, first, stderr := runWith(t, "collect pools:458\n", env)
	code2, second, _ := runWith(t, "collect pools:458\n", env)
	if code1 != exitOK || code2 != exitOK {
		t.Fatalf("exits %d/%d, stderr: %s", code1, code2, stderr)
	}
	if first != second {
		t.Fatalf("replay is not byte-deterministic:\n%s\nvs\n%s", first, second)
	}
}

func TestReplayPinsEveryRunVaryingMember(t *testing.T) {
	env := replayEnv(stageReplayDir(t, stagedStatus, stagedList, ""))
	code, stdout, stderr := runWith(t, "collect pools:458\n", env)
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
	// The real digest under replay as much as live: a replay does not change
	// which contract this binary holds. begin.declaration is rule-governed
	// rather than byte-compared (DESIGN 19), so this collector publishes its
	// own identity instead of copying the one the committed half carries.
	if begin["declaration"] != declarationDigest {
		t.Errorf("begin.declaration under replay is %q; got %v", declarationDigest, begin["declaration"])
	}
	if at := ofKind(records, "object")[0]["at"]; at != 1.0 {
		t.Errorf("the first replayed object carries at = 1.0 + 0.001*0; got %v", at)
	}
	end := ofKind(records, "end")[0]
	if end["cpu_ms"] != 0.5 || end["wall_ms"] != 1.0 {
		t.Errorf("replay pins cpu_ms=0.5 wall_ms=1.0; got %v/%v", end["cpu_ms"], end["wall_ms"])
	}
}

// The one fact derived against wall time. Without the pin the committed pair
// would report a different age every day it is judged.
func TestScanAgeDaysIsMeasuredAgainstThePinnedClock(t *testing.T) {
	dir := stageReplayDir(t, stagedStatus, stagedList, "")
	_, stdout, _ := runWith(t, "collect pools:1\n", replayEnv(dir))
	facts := ofKind(parseRecords(t, stdout), "object")[0]["facts"].(map[string]any)
	if facts["ScanAgeDays"] != 3.0 {
		t.Fatalf("ScanAgeDays %v, want 3 against 2026-08-16T09:00:00Z", facts["ScanAgeDays"])
	}

	// A day later against the same payload is a day older, which is exactly
	// why the pin exists.
	later := map[string]string{"SE_REPLAY_DIR": dir, "SE_REPLAY_NOW": "2026-08-17T09:00:00Z"}
	_, stdout, _ = runWith(t, "collect pools:1\n", later)
	facts = ofKind(parseRecords(t, stdout), "object")[0]["facts"].(map[string]any)
	if facts["ScanAgeDays"] != 4.0 {
		t.Fatalf("ScanAgeDays %v, want 4 a day later", facts["ScanAgeDays"])
	}
}

// A guid is a full unsigned 64-bit value; through a float64 it comes back as
// a different pool, so it travels as its own decimal digits.
func TestAGuidPast2To53SurvivesWhole(t *testing.T) {
	_, stdout, _ := runWith(t, "collect pools:1\n", replayEnv(stageReplayDir(t, stagedStatus, stagedList, "")))
	if !strings.Contains(stdout, `"guid":"18444306082397320711"`) {
		t.Fatalf("the pool guid did not survive the round trip:\n%s", stdout)
	}
	if !strings.Contains(stdout, `"guid":"18444306082397320712"`) {
		t.Fatalf("a member guid did not survive the round trip:\n%s", stdout)
	}
}

// No payload at all is a host with no zpool: absent is authoritative-empty,
// so it declines AND commits zero, which is what lets it retire pools a
// previous batch published.
func TestNoInterfacePayloadDeclinesAbsentAndCommitsZero(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect pools:77\n", replayEnv(stageReplayDir(t, "", "", "")))
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["reason"] != "absent" || declines[0]["detail"] != "no zpool on this host" {
		t.Fatalf("expected the absent decline; got %v", declines)
	}
	commits := ofKind(records, "commit")
	if len(commits) != 1 || commits[0]["objects"] != 0.0 || commits[0]["generation"] != 77.0 {
		t.Fatalf("absent commits zero under the issued generation; got %v", commits)
	}
	if len(ofKind(records, "object")) != 0 {
		t.Fatal("a declined collection carries no records of any kind")
	}
}

// zpool status is the fact source and cannot degrade: a variant staging the
// enrichment but not the fact source is a broken capture, not a statement
// about any machine.
func TestAnUncapturedStatusPayloadRefusesToRun(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect pools:5\n", replayEnv(stageReplayDir(t, "", stagedList, "")))
	if code != exitRuntime {
		t.Fatalf("exit %d, want %d (stdout %q)", code, exitRuntime, stdout)
	}
	if !strings.Contains(stderr, "not captured") {
		t.Fatalf("stderr must name the missing capture: %q", stderr)
	}
}

// zpool list is enrichment and degrades: five unobservable capacity facts,
// not five absences, and the per-vdev capacity members go quiet with no
// record about them at all.
func TestAnUnreadableListingMakesCapacityUnobservable(t *testing.T) {
	_, stdout, _ := runWith(t, "collect pools:9\n", replayEnv(stageReplayDir(t, stagedStatus, "", "")))
	records := parseRecords(t, stdout)
	object := ofKind(records, "object")[0]
	facts := object["facts"].(map[string]any)
	for _, fact := range []string{"SizeBytes", "AllocatedBytes", "FreeBytes", "CapacityPercent", "FragmentationPercent"} {
		if _, present := facts[fact]; present {
			t.Errorf("%s must not be a fact when the listing could not be read", fact)
		}
	}
	if absent, ok := object["absent"]; ok {
		for _, entry := range absent.([]any) {
			if entry != "StatusMessage" {
				t.Errorf("%v is could-not-read, never has-no-such-property", entry)
			}
		}
	}
	seen := map[string]string{}
	for _, record := range ofKind(records, "unobservable") {
		seen[record["fact"].(string)] = record["detail"].(string)
	}
	if seen["SizeBytes"] != "zpool list could not be read; zpool status alone carries no capacity properties" {
		t.Errorf("capacity detail %q", seen["SizeBytes"])
	}
	// Two disk leaves and no devlinks payload: the Device records too.
	if seen["Vdevs/wwn-0xaa/Device"] == "" {
		t.Error("an unreadable alias tree owes one record per disk leaf")
	}
}

// Readable-but-empty is a different statement from unreadable, and only one
// of them opens a channel.
func TestAnEmptyAliasTreeIsSilentWhereAMissingOneIsNot(t *testing.T) {
	_, unreadable, _ := runWith(t, "collect pools:3\n", replayEnv(stageReplayDir(t, stagedStatus, stagedList, "")))
	_, readable, _ := runWith(t, "collect pools:3\n", replayEnv(stageReplayDir(t, stagedStatus, stagedList, `{}`)))
	if len(ofKind(parseRecords(t, unreadable), "unobservable")) != 2 {
		t.Error("no alias tree at all owes one record per disk leaf")
	}
	if got := ofKind(parseRecords(t, readable), "unobservable"); len(got) != 0 {
		t.Errorf("a tree that was read and holds nothing states nothing; got %v", got)
	}
	// A null document is could-not-read for the same reason a failed listdir
	// is: nobody read the trees, so nobody may say they hold nothing.
	_, nulled, _ := runWith(t, "collect pools:3\n", replayEnv(stageReplayDir(t, stagedStatus, stagedList, `null`)))
	if len(ofKind(parseRecords(t, nulled), "unobservable")) != 2 {
		t.Error("a null alias tree is unreadable, not empty")
	}
}

func TestAResolvedLeafCarriesItsDeviceAndKernelName(t *testing.T) {
	links := `{"/dev/disk/by-id/wwn-0xaa-part1": "sda1"}`
	_, stdout, _ := runWith(t, "collect pools:3\n", replayEnv(stageReplayDir(t, stagedStatus, stagedList, links)))
	records := parseRecords(t, stdout)
	object := records[1]
	if !strings.Contains(stdout, `"Device":"block-device:sda1"`) {
		t.Errorf("resolved leaf carries no Device:\n%s", stdout)
	}
	names := object["names"].(map[string]any)
	kernel := names["ephemeral"].(map[string]any)["kernel"].([]any)
	if len(kernel) != 1 || kernel[0] != "/dev/sda1" {
		t.Errorf("the pool's ephemeral kernel family is a LIST of the resolved leaves; got %v", kernel)
	}
	// The unresolved leaf simply has no Device, and no record claims the
	// resolution could not be done — because it could.
	if len(ofKind(records, "unobservable")) != 0 {
		t.Error("a readable tree holding nothing for a member is a silent absence")
	}
}

func TestACollectionThisCollectorNeverDeclaredIsDeclinedUnsupported(t *testing.T) {
	// lookups is the PERMANENT seat: it is dropped by ruling — lookup is a
	// VERB in the new contract, not a collection — so unlike the owed names
	// that held this seat before (datasets, then arrays), it will never be
	// served and the drill never moves again.
	env := replayEnv(stageReplayDir(t, stagedStatus, stagedList, `{}`))
	code, stdout, _ := runWith(t, "collect lookups:11 pools:12\n", env)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	records := parseRecords(t, stdout)
	var declined map[string]any
	for _, record := range ofKind(records, "decline") {
		if record["collection"] == "lookups" {
			declined = record
		}
	}
	if declined == nil || declined["reason"] != "unsupported" {
		t.Fatalf("a name this collector did not publish is declined, not sanitised; got %v", declined)
	}
	for _, commit := range ofKind(records, "commit") {
		if commit["collection"] == "lookups" {
			t.Fatal("an unsupported decline established nothing and must not commit")
		}
	}
	if len(ofKind(records, "object")) != 1 {
		t.Error("pools must still be served alongside the declined collection")
	}
}

// `at` is one counter across the whole batch, in emission order.
func TestAtAdvancesAcrossEveryEmittedObject(t *testing.T) {
	twoPools := strings.Replace(stagedStatus, `"pools": {"tank"`, `"pools": {"other": {"name": "other"}, "tank"`, 1)
	_, stdout, stderr := runWith(t, "collect pools:4\n", replayEnv(stageReplayDir(t, twoPools, "", "")))
	objects := ofKind(parseRecords(t, stdout), "object")
	if len(objects) != 2 {
		t.Fatalf("expected two objects, got %d (stderr %s)", len(objects), stderr)
	}
	if objects[0]["name"] != "other" || objects[1]["name"] != "tank" {
		t.Errorf("pools are emitted in document order; got %v then %v", objects[0]["name"], objects[1]["name"])
	}
	if objects[0]["at"] != 1.0 || objects[1]["at"] != 1.001 {
		t.Errorf("at: %v then %v", objects[0]["at"], objects[1]["at"])
	}
}

func TestProbeAnswersWithAVerdictNotAnExitCode(t *testing.T) {
	ready := replayEnv(stageReplayDir(t, stagedStatus, stagedList, ""))
	code, stdout, _ := runWith(t, "probe\n", ready)
	if code != exitOK || !strings.Contains(stdout, `"verdict":"yes"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	// A no is still exit zero: the verdict is the answer, and a non-zero
	// exit would read as a crash (DESIGN 18).
	bare := replayEnv(stageReplayDir(t, "", "", ""))
	code, stdout, _ = runWith(t, "probe\n", bare)
	if code != exitOK || !strings.Contains(stdout, `"verdict":"no"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	if record := parseRecords(t, stdout)[0]; record["reason"] == "" || record["reason"] == nil {
		t.Fatal("a verdict without its why is not actionable")
	}
}
