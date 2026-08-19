package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The four documents as the two APIs answer them, trimmed to the members these
// collections read plus enough of their neighbours to keep the shape honest.
// The transmission halves are the `arguments` object — the RPC frame's body,
// which is what the seam hands the parser and what the corpus commits.
const (
	healthySessionGet = `{
	  "config-dir": "/config",
	  "download-dir": "/downloads/complete",
	  "download-dir-free-space": -1,
	  "rpc-version": 19,
	  "session-id": "ANON194DA11066797AA9BAC26E45E0EB440B",
	  "version": "4.1.3 (838877323f)"
	}`
	healthySessionStats = `{
	  "activeTorrentCount": 2,
	  "downloadSpeed": 0,
	  "pausedTorrentCount": 1,
	  "torrentCount": 3,
	  "uploadSpeed": 0
	}`
	healthyTorrentGet = `{
	  "torrents": [
	    {"error": 0, "errorString": "", "hashString": "D92D27BD899A09537A6AD1B7030A7221AC143175",
	     "isStalled": false, "leftUntilDone": 1048576, "name": "lab-specimen-alpha.bin",
	     "percentDone": 0.0, "rateDownload": 0, "rateUpload": 0,
	     "sizeWhenDone": 1048576, "status": 4},
	    {"error": 0, "errorString": "", "hashString": "7c15d567e0ac4376adfa5d1e8749021b42ed1302",
	     "isStalled": false, "leftUntilDone": 2097152, "name": "lab-specimen-beta.bin",
	     "percentDone": 0.0, "rateDownload": 0, "rateUpload": 0,
	     "sizeWhenDone": 2097152, "status": 0}
	  ]
	}`
	healthyQueue = `{
	  "queue": {
	    "version": "5.1.1",
	    "paused": false,
	    "diskspace1": "8.81",
	    "diskspacetotal1": "14.37",
	    "kbpersec": "0.00",
	    "noofslots_total": 1,
	    "noofslots": 2,
	    "slots": [
	      {"nzo_id": "5cb01b2b-aab4-d0c2-ada1-f4818b15edcf", "filename": "lab-specimen-gamma",
	       "mb": "3.00", "mbleft": "3.00", "percentage": "0", "status": "Downloading",
	       "timeleft": "0:00:00", "password": ""},
	      {"nzo_id": "5cb0f633-358d-6e77-1ff4-e2023fdc896a", "filename": "lab-specimen-delta",
	       "mb": "1.00", "mbleft": "1.00", "percentage": "0", "status": "Paused",
	       "timeleft": "0:00:00", "password": ""}
	    ]
	  }
	}`
)

// stage writes one replay directory. Each document is named by the CALL it
// answers, which is how the seam addresses it — the reference keys a dispatched
// method on its first argument, and the corpus commits the same names.
func stage(t *testing.T, documents map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range documents {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func stageHealthy(t *testing.T) string {
	t.Helper()
	return stage(t, map[string]string{
		callSessionGet:   healthySessionGet,
		callSessionStats: healthySessionStats,
		callTorrentGet:   healthyTorrentGet,
		callQueue:        healthyQueue,
	})
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

func factsOf(t *testing.T, records []map[string]any, collection, name string) map[string]any {
	t.Helper()
	for _, record := range ofKind(records, "object") {
		if record["collection"] == collection && record["name"] == name {
			facts, _ := record["facts"].(map[string]any)
			return facts
		}
	}
	t.Fatalf("no %s row named %q in %v", collection, name, records)
	return nil
}

func TestReplayIsByteDeterministicAcrossTwoRuns(t *testing.T) {
	env := map[string]string{"SE_REPLAY_DIR": stageHealthy(t)}
	code1, first, stderr := runWith(t, "collect clients:824 transfers:825\n", env)
	code2, second, _ := runWith(t, "collect clients:824 transfers:825\n", env)
	if code1 != exitOK || code2 != exitOK {
		t.Fatalf("exits %d/%d, stderr: %s", code1, code2, stderr)
	}
	if first != second {
		t.Fatalf("replay is not byte-deterministic:\n%s\nvs\n%s", first, second)
	}
}

func TestReplayPinsEveryRunVaryingMember(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect clients:824 transfers:825\n",
		map[string]string{"SE_REPLAY_DIR": stageHealthy(t)})
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
	if len(objects) != 6 {
		t.Fatalf("two clients and four transfers; got %d objects", len(objects))
	}
	if objects[0]["at"] != 1.0 || objects[5]["at"] != 1.005 {
		t.Errorf("`at` is 1.0 + 0.001*i across the whole batch; got %v … %v", objects[0]["at"], objects[5]["at"])
	}
	end := ofKind(records, "end")[0]
	if end["cpu_ms"] != 0.5 || end["wall_ms"] != 1.0 {
		t.Errorf("replay pins cpu_ms=0.5 wall_ms=1.0; got %v/%v", end["cpu_ms"], end["wall_ms"])
	}
}

func TestReplayBootIDIsTheStagedFileWhenAVariantHasOne(t *testing.T) {
	dir := stageHealthy(t)
	if err := os.WriteFile(filepath.Join(dir, "boot_id"), []byte("8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stdout, _ := runWith(t, "collect clients:1\n", map[string]string{"SE_REPLAY_DIR": dir})
	if got := ofKind(parseRecords(t, stdout), "begin")[0]["boot_id"]; got != "8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44" {
		t.Fatalf("boot_id must be the staged file, trimmed; got %v", got)
	}
}

func TestReplayNowIsIgnoredButNeverACrash(t *testing.T) {
	// Every fact here is a figure a client stated; nothing is derived against a
	// clock, so the pin has nothing to freeze. The contract is only that
	// setting it changes nothing and breaks nothing.
	dir := stageHealthy(t)
	bare := map[string]string{"SE_REPLAY_DIR": dir}
	pinned := map[string]string{"SE_REPLAY_DIR": dir, "SE_REPLAY_NOW": "2026-08-19T12:37:00Z"}

	code1, first, _ := runWith(t, "collect clients:2 transfers:3\n", bare)
	code2, second, _ := runWith(t, "collect clients:2 transfers:3\n", pinned)
	if code1 != exitOK || code2 != exitOK || first != second {
		t.Fatalf("SE_REPLAY_NOW changed the outcome: exits %d/%d", code1, code2)
	}
}

// The seam's whole point: a machine running neither client replays this capture
// without ever dialling an API. Asserted on the OUTPUT, because the development
// machine that runs it has no download client at all — so a seam escape here
// would produce an absent decline, not an error.
func TestTheStagedDocumentsDecideRatherThanTheReplayingHost(t *testing.T) {
	env := map[string]string{
		"SE_REPLAY_DIR": stageHealthy(t),
		// Deliberately pointing somewhere real-looking: under replay these must
		// never be consulted, and a port that fell back to them on a machine
		// that happened to run a client would read the wrong estate.
		transmissionVariable: "http://127.0.0.1:9091",
		sabURLVariable:       "http://127.0.0.1:8085",
		sabKeyVariable:       "not-a-key",
	}
	code, stdout, stderr := runWith(t, "collect clients:9\n", env)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	facts := factsOf(t, parseRecords(t, stdout), collectionClients, clientTransmission)
	if facts["Version"] != "4.1.3 (838877323f)" || facts["TorrentCount"] != 3.0 {
		t.Fatalf("the row must come from the staged documents: %v", facts)
	}
}

func TestAnEmptyReplayDirectoryDeclinesAbsentAndCommitsZero(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect clients:77 transfers:78\n",
		map[string]string{"SE_REPLAY_DIR": t.TempDir()})
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 2 {
		t.Fatalf("both collections decline, because the absence is of the interface and not of one answer: %v", declines)
	}
	for _, decline := range declines {
		if decline["reason"] != "absent" || decline["detail"] != declineNoClient.detail {
			t.Fatalf("expected the shared absent decline, got %v", decline)
		}
	}
	commits := ofKind(records, "commit")
	if len(commits) != 2 {
		t.Fatalf("absent is authoritative-empty and commits zero, once per collection; got %v", commits)
	}
	for _, commit := range commits {
		if commit["objects"] != 0.0 {
			t.Fatalf("an absent commit carries zero objects; got %v", commit)
		}
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
func TestAnUnconfiguredHostIsTheSameAbsentReadingAsAnEmptyCapture(t *testing.T) {
	empty := t.TempDir()
	sources := map[string]source{
		"no client configured": newSource(func(string) string { return "" }),
		"an empty capture": newSource(func(key string) string {
			if key == "SE_REPLAY_DIR" {
				return empty
			}
			return ""
		}),
	}
	for label, src := range sources {
		if src.clients().any() {
			t.Fatalf("%s: the gate says a client is configured", label)
		}
		_, err := src.document(callQueue)
		var refused *declined
		if !errors.As(err, &refused) {
			t.Fatalf("%s: %v is not a decline at all", label, err)
		}
		if *refused != declineNoClient {
			t.Fatalf("%s: reached %v, and the shared constant is %v", label, *refused, declineNoClient)
		}
	}
}

// A capture staging some documents and not others is a broken capture, not a
// statement about a machine: the replay seam pins both clients present, so a
// variant that recorded one client recorded a host this seam cannot describe.
// "I could not run" — never a decline, which would state something about a
// machine nobody observed, and never a dark-client FACT, which would put this
// harness's own error text into a committed row.
func TestAHalfStagedCaptureRefusesToRunRatherThanDeclining(t *testing.T) {
	cases := map[string]string{
		"transmission without sabnzbd": stage(t, map[string]string{
			callSessionGet:   healthySessionGet,
			callSessionStats: healthySessionStats,
			callTorrentGet:   healthyTorrentGet,
		}),
		"sabnzbd without transmission": stage(t, map[string]string{
			callQueue: healthyQueue,
		}),
		"the counters without the session": stage(t, map[string]string{
			callSessionStats: healthySessionStats,
			callTorrentGet:   healthyTorrentGet,
			callQueue:        healthyQueue,
		}),
	}
	for label, dir := range cases {
		code, stdout, stderr := runWith(t, "collect clients:5 transfers:6\n",
			map[string]string{"SE_REPLAY_DIR": dir})
		if code != exitRuntime {
			t.Errorf("%s: exit %d, want %d", label, code, exitRuntime)
		}
		if stderr == "" {
			t.Errorf("%s: refusing without saying why tells nobody anything", label)
		}
		if len(ofKind(parseRecords(t, stdout), "decline")) != 0 {
			t.Errorf("%s: a broken capture must not become a statement about a machine", label)
		}
		for _, record := range ofKind(parseRecords(t, stdout), "object") {
			facts, _ := record["facts"].(map[string]any)
			if _, carried := facts["StatusUnobservable"]; carried {
				t.Errorf("%s: an uncaptured document became a dark-client fact", label)
			}
		}
	}
}

func TestProbeAnswersWithAVerdictNotAnExitCode(t *testing.T) {
	code, stdout, _ := runWith(t, "probe\n",
		map[string]string{"SE_REPLAY_DIR": stageHealthy(t)})
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

// ── the readings themselves ─────────────────────────────────────────────

// The three facts a client states about ITSELF that no other row can supply,
// and the two absences that are half of what a downloader row says.
func TestTheClientRowsCarryEachClientsOwnVantage(t *testing.T) {
	_, stdout, _ := runWith(t, "collect clients:1\n",
		map[string]string{"SE_REPLAY_DIR": stageHealthy(t)})
	records := parseRecords(t, stdout)

	transmission := factsOf(t, records, collectionClients, clientTransmission)
	// -1 is transmission saying it could not measure the directory, and the
	// fact is omitted rather than published as a negative byte count or zeroed.
	if _, carried := transmission["DiskFreeBytes"]; carried {
		t.Errorf("download-dir-free-space -1 is not a reading to publish: %v", transmission)
	}
	// Three different numbers, so a port that read the wrong counter fails.
	if transmission["ActiveTorrentCount"] != 2.0 || transmission["PausedTorrentCount"] != 1.0 ||
		transmission["TorrentCount"] != 3.0 {
		t.Errorf("the three counts are three separate figures: %v", transmission)
	}

	sab := factsOf(t, records, collectionClients, clientSabnzbd)
	// The GB→byte conversion, done once: 8.81 × 1024³ truncated, not rounded,
	// and not a 1000³ conversion.
	if sab["DiskFreeBytes"] != 9459665469.0 || sab["DiskTotalBytes"] != 15429670010.0 {
		t.Errorf("the disk figures are sabnzbd's GB strings converted once: %v", sab)
	}
	// sabnzbd's OWN counting, and deliberately not the number of transfer rows:
	// the paused job sits in the queue and is not counted.
	if sab["QueueCount"] != 1.0 {
		t.Errorf("QueueCount is noofslots_total and not len(slots): %v", sab)
	}
	if sab["Paused"] != false {
		t.Errorf("Paused is a boolean reading and false is a reading: %v", sab)
	}
}

func TestTheTransferRowsSpeakEachClientsOwnVocabulary(t *testing.T) {
	_, stdout, _ := runWith(t, "collect transfers:1\n",
		map[string]string{"SE_REPLAY_DIR": stageHealthy(t)})
	records := parseRecords(t, stdout)

	// The info-hash is LOWERCASED, because the managers state it uppercase and
	// transmission states it lowercase and one side has to own the
	// normalisation. The staged document spells the first one in upper case
	// precisely so this is exercised.
	torrent := factsOf(t, records, collectionTransfers, "d92d27bd899a09537a6ad1b7030a7221ac143175")
	if torrent["Status"] != "download" {
		t.Errorf("status 4 is transmission's own word `download`: %v", torrent)
	}
	if torrent["Error"] != 0.0 {
		t.Errorf("a zero error code is a reading and not an absence: %v", torrent)
	}
	if _, carried := torrent["ErrorString"]; carried {
		t.Errorf("the error line rides only a non-zero code: %v", torrent)
	}
	if torrent["IsStalled"] != false {
		t.Errorf("the client's own stall verdict, false: %v", torrent)
	}
	for _, absent := range []string{"SizeMB", "LeftMB", "TimeLeft"} {
		if _, carried := torrent[absent]; carried {
			t.Errorf("%s is sabnzbd's vocabulary and must not be translated onto a torrent: %v", absent, torrent)
		}
	}

	// sabnzbd's nzo id is VERBATIM — it is case-sensitive and the managers
	// state it exactly as sabnzbd minted it.
	slot := factsOf(t, records, collectionTransfers, "5cb0f633-358d-6e77-1ff4-e2023fdc896a")
	if slot["Status"] != "Paused" || slot["SizeMB"] != 1.0 || slot["TimeLeft"] != "0:00:00" {
		t.Errorf("the sabnzbd row speaks sabnzbd's own words and units: %v", slot)
	}
	for _, absent := range []string{"SizeWhenDoneBytes", "LeftUntilDoneBytes", "Error", "IsStalled"} {
		if _, carried := slot[absent]; carried {
			t.Errorf("%s is transmission's vocabulary and must not appear on a slot: %v", absent, slot)
		}
	}
}

// A status outside transmission's documented seven is a document this collector
// does not recognise, and the fact is OMITTED rather than indexed out of range
// or published as the raw integer — the reference's own `0 <= status < len()`
// guard, which is the only thing standing between a new RPC state and a panic.
func TestAStatusOutsideTheDocumentedVocabularyIsOmitted(t *testing.T) {
	documents := map[string]string{
		callSessionGet:   healthySessionGet,
		callSessionStats: healthySessionStats,
		callQueue:        healthyQueue,
		callTorrentGet: `{"torrents": [
		  {"hashString": "aa11bb22cc33dd44ee55ff6677889900aabbccdd", "name": "future", "status": 9},
		  {"hashString": "bb11bb22cc33dd44ee55ff6677889900aabbccdd", "name": "past", "status": -1}
		]}`,
	}
	code, stdout, stderr := runWith(t, "collect transfers:1\n",
		map[string]string{"SE_REPLAY_DIR": stage(t, documents)})
	if code != exitOK {
		t.Fatalf("an unrecognised status is a fact to omit, not a batch to fail: exit %d, %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	for _, name := range []string{
		"aa11bb22cc33dd44ee55ff6677889900aabbccdd",
		"bb11bb22cc33dd44ee55ff6677889900aabbccdd",
	} {
		if _, carried := factsOf(t, records, collectionTransfers, name)["Status"]; carried {
			t.Errorf("%s published a Status for an undocumented enum position", name)
		}
	}
}

// A torrent with no hash is skipped: the hash is the join key the managers
// state as downloadId, and an object the collator cannot key is one nothing can
// ever join to or retire.
func TestATorrentWithNoHashIsSkippedRatherThanPublishedNameless(t *testing.T) {
	documents := map[string]string{
		callSessionGet:   healthySessionGet,
		callSessionStats: healthySessionStats,
		callQueue:        healthyQueue,
		callTorrentGet:   `{"torrents": [{"name": "nameless", "status": 4}]}`,
	}
	_, stdout, _ := runWith(t, "collect transfers:1\n",
		map[string]string{"SE_REPLAY_DIR": stage(t, documents)})
	records := parseRecords(t, stdout)
	for _, record := range ofKind(records, "object") {
		if record["collection"] == collectionTransfers && record["name"] == "" {
			t.Fatal("a transfer was published under an empty name")
		}
	}
	// Two sabnzbd slots and no torrent, and the commit says so: a skipped row
	// must not leave the count claiming it.
	for _, commit := range ofKind(records, "commit") {
		if commit["collection"] == collectionTransfers && commit["objects"] != 2.0 {
			t.Fatalf("the commit counts what was emitted; got %v", commit)
		}
	}
}
