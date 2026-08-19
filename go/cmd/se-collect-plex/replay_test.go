package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The documents as the API answers them, trimmed to the members this collector
// reads plus enough of their neighbours that the shape is recognisable. The
// values are corpus/plex/healthy's, from a Plex Media Server 1.43.3 stood up
// unclaimed for the capture.
//
// The section KEYS are 1 and 3, and that is the point rather than an accident:
// the TV library was created, deleted and recreated, so the keys are not
// consecutive. A port that walked the listing by position would name the second
// row `2` and ask section 2 for its count.
const (
	healthyRoot = `{"MediaContainer":{"size":25,"allowSync":false,"apiVersion":"1.2.2","friendlyName":"host-e56b83","machineIdentifier":"ANONC2903F9347B4CE39EF7737176D4B484E","myPlexSigninState":"none","myPlexSubscription":false,"platform":"Linux","platformVersion":"6.8.0","transcoderVideo":true,"updater":true,"version":"1.43.3.10896-cb3ebc72d"}}`

	// Nothing playing: `size` 0 and NO Metadata member at all. This is the
	// authoritative emptiness the sessions collection has to commit rather than
	// decline.
	healthySessions = `{"MediaContainer":{"size":0}}`

	healthySections = `{"MediaContainer":{"size":2,"allowSync":false,"title1":"Plex Library","Directory":[{"allowSync":false,"filters":true,"refreshing":false,"key":"1","type":"movie","title":"Movies","agent":"tv.plex.agents.movie","scanner":"Plex Movie","language":"en-US","uuid":"ANON8A584B69A96123FC30DA47A6D8BFDD57","updatedAt":1787141574,"createdAt":1787141574,"scannedAt":1787141586,"Location":[{"id":1,"path":"/media/Movies"}]},{"allowSync":false,"filters":true,"refreshing":false,"key":"3","type":"show","title":"TV Shows","agent":"tv.plex.agents.series","scanner":"Plex TV Series","language":"en-US","uuid":"ANOND3F8F20DC7F6B716A5A62C896E30DE19","updatedAt":1787141656,"createdAt":1787141656,"scannedAt":1787141657,"Location":[{"id":3,"path":"/media/TV"}]}]}}`

	// The zero-size container window's answer. `size` is 0 BY CONSTRUCTION — the
	// window asked for no rows — and `totalSize` is the count. The two sections
	// answer 2 and 1, which is what stops a port that fetched one count and
	// reused it from passing.
	healthySectionOne   = `{"MediaContainer":{"size":0,"totalSize":2,"offset":0,"librarySectionID":1,"librarySectionTitle":"Movies","viewGroup":"movie"}}`
	healthySectionThree = `{"MediaContainer":{"size":0,"totalSize":1,"offset":0,"librarySectionID":3,"librarySectionTitle":"TV Shows","viewGroup":"show"}}`

	// The same server with two streams in flight: an episode being transcoded and
	// a film playing directly. No corpus variant holds one and none can — a
	// session document names a PERSON and what they were watching — so this
	// staged shape is where the sessions derivation is exercised, and the names in
	// it are invented.
	busySessions = `{"MediaContainer":{"size":2,"Metadata":[` +
		`{"sessionKey":"41","ratingKey":"9001","type":"episode","title":"Pilot","grandparentTitle":"Example Series",` +
		`"User":{"id":1,"title":"example-viewer"},"Player":{"product":"Plex for Apple TV","state":"playing"},` +
		`"TranscodeSession":{"key":"tr-1","videoDecision":"transcode","audioDecision":"copy"}},` +
		`{"ratingKey":"9002","type":"movie","title":"Example Film",` +
		`"User":{"id":2,"title":"second-viewer"},"Player":{"product":"Plex Web","state":"paused"}}` +
		`]}}`
)

// stage writes one replay directory. Each document is named by the request PATH
// it answers, which is how the seam addresses it — the reference keys a
// dispatched acquisition on its argument, and the corpus commits the same names.
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

func healthyDocuments() map[string]string {
	return map[string]string{
		"root.json":                   healthyRoot,
		"status-sessions.json":        healthySessions,
		"library-sections.json":       healthySections,
		"library-sections-1-all.json": healthySectionOne,
		"library-sections-3-all.json": healthySectionThree,
	}
}

func stageHealthy(t *testing.T) string {
	t.Helper()
	return stage(t, healthyDocuments())
}

func stageBusy(t *testing.T) string {
	t.Helper()
	documents := healthyDocuments()
	documents["status-sessions.json"] = busySessions
	return stage(t, documents)
}

// The issuance corpus/plex/healthy replays under, so the pinned members below are
// the ones the committed pair carries.
const wholeBatch = "collect libraries:78443 server:78460 sessions:78477\n"

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
	t.Fatalf("no object named %q in %q", name, collection)
	return nil
}

func TestReplayIsByteDeterministicAcrossTwoRuns(t *testing.T) {
	env := map[string]string{"SE_REPLAY_DIR": stageHealthy(t)}
	code1, first, stderr := runWith(t, wholeBatch, env)
	code2, second, _ := runWith(t, wholeBatch, env)
	if code1 != exitOK || code2 != exitOK {
		t.Fatalf("exits %d/%d, stderr: %s", code1, code2, stderr)
	}
	if first != second {
		t.Fatalf("replay is not byte-deterministic:\n%s\nvs\n%s", first, second)
	}
}

func TestReplayPinsEveryRunVaryingMember(t *testing.T) {
	code, stdout, stderr := runWith(t, wholeBatch,
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
	if len(objects) != 3 {
		t.Fatalf("two libraries and one server; got %d objects", len(objects))
	}
	// 1.0 + 0.001*i in emission order, one counter across the whole batch — which
	// is what makes `at` advancing rather than a hardcoded zero.
	for i, want := range []float64{1.0, 1.001, 1.002} {
		if objects[i]["at"] != want {
			t.Errorf("object %d carries at %v, and the reference constant is %v", i, objects[i]["at"], want)
		}
	}
	end := ofKind(records, "end")[0]
	if end["cpu_ms"] != 0.5 || end["wall_ms"] != 1.0 {
		t.Errorf("replay pins cpu_ms=0.5 wall_ms=1.0; got %v/%v", end["cpu_ms"], end["wall_ms"])
	}
}

// The fan-out, asserted where it can go wrong. `/library/sections` names the
// sections and each one costs a further request, so a row's ItemCount comes from
// a DIFFERENT document than every other fact beside it — and the two counts
// differ, so a port that fetched one and reused it fails here.
func TestEachSectionIsCountedByItsOwnKeyedRequest(t *testing.T) {
	_, stdout, _ := runWith(t, wholeBatch, map[string]string{"SE_REPLAY_DIR": stageHealthy(t)})
	records := parseRecords(t, stdout)

	movies := factsOf(t, records, "libraries", "1")
	shows := factsOf(t, records, "libraries", "3")
	if movies["ItemCount"] != 2.0 || shows["ItemCount"] != 1.0 {
		t.Fatalf("counts came from the wrong documents: %v / %v", movies, shows)
	}
	if movies["Type"] != "movie" || shows["Type"] != "show" {
		t.Errorf("both sections hold video and only `type` tells them apart: %v / %v", movies, shows)
	}
	// The rows are named by the section KEY, non-consecutive on purpose.
	var names []string
	for _, record := range ofKind(records, "object") {
		if record["collection"] == "libraries" {
			names = append(names, record["name"].(string))
		}
	}
	if len(names) != 2 || names[0] != "1" || names[1] != "3" {
		t.Fatalf("library rows are named by their section key; got %v", names)
	}
}

// The count comes from `totalSize` and never from `size`. Under a zero-size
// container window `size` is 0 by construction, so a port that read it publishes
// 0 for every section — which reads exactly like the emptied-library shape the
// fact exists to rule out. Asserted on the BYTES as well, because the tokens the
// wire carries are integers and a float64 round trip would spell them 2 and 1
// again while changing their type.
func TestTheCountIsTotalSizeAndTravelsAsAnInteger(t *testing.T) {
	_, stdout, _ := runWith(t, wholeBatch, map[string]string{"SE_REPLAY_DIR": stageHealthy(t)})
	if !strings.Contains(stdout, `"ItemCount":2`) || !strings.Contains(stdout, `"ItemCount":1`) {
		t.Fatalf("the counts did not survive as the integers the container spelled:\n%s", stdout)
	}
	for _, wrong := range []string{`"ItemCount":0`, `"ItemCount":2.0`, `"ItemCount":1.0`, `"SessionCount":0.0`} {
		if strings.Contains(stdout, wrong) {
			t.Fatalf("a number was re-rendered or read from the wrong member (%q):\n%s", wrong, stdout)
		}
	}
	if !strings.Contains(stdout, `"SessionCount":0`) {
		t.Fatalf("SessionCount 0 is a reading and must be published:\n%s", stdout)
	}
}

// Refreshing false is a READING. The reference publishes it whenever the member
// is stated, so the classic falsy test drops it from every idle library — which
// is nearly every library, nearly always — and leaves the count unqualified.
func TestRefreshingFalseIsPublishedRatherThanDroppedAsFalsy(t *testing.T) {
	_, stdout, _ := runWith(t, wholeBatch, map[string]string{"SE_REPLAY_DIR": stageHealthy(t)})
	records := parseRecords(t, stdout)
	for _, name := range []string{"1", "3"} {
		facts := factsOf(t, records, "libraries", name)
		value, carried := facts["Refreshing"]
		if !carried {
			t.Errorf("library %s dropped Refreshing because it was false: %v", name, facts)
			continue
		}
		if value != false {
			t.Errorf("library %s carries Refreshing %v, and the document said false", name, value)
		}
	}
	if !strings.Contains(stdout, `"Refreshing":false`) {
		t.Fatalf("false must travel as the boolean false, not as 0 or \"false\":\n%s", stdout)
	}
}

// The most important reading in this collector. Nothing is playing, so the
// sessions document carries no `Metadata` member at all — and that is an
// authoritative emptiness: zero objects COMMITTED, which retires every session a
// previous batch published. A port that declined would leave stale sessions
// standing forever, and one that crashed on the missing key would never commit.
func TestAnEmptySessionListCommitsZeroObjectsRatherThanDeclining(t *testing.T) {
	code, stdout, stderr := runWith(t, wholeBatch, map[string]string{"SE_REPLAY_DIR": stageHealthy(t)})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	for _, decline := range ofKind(records, "decline") {
		if decline["collection"] == "sessions" {
			t.Fatalf("an authoritative emptiness is committed, never declined: %v", decline)
		}
	}
	var found bool
	for _, commit := range ofKind(records, "commit") {
		if commit["collection"] != "sessions" {
			continue
		}
		found = true
		if commit["objects"] != 0.0 || commit["assertions"] != 0.0 || commit["unobservable"] != 0.0 {
			t.Fatalf("the sessions commit must carry three zeroes; got %v", commit)
		}
		if commit["generation"] != 78477.0 {
			t.Fatalf("the commit echoes the issued generation; got %v", commit["generation"])
		}
	}
	if !found {
		t.Fatal("the sessions collection was opened by the request line and neither committed nor declined")
	}
}

// One document, two collections. `server` reads the session list for its count
// and `sessions` reads it for its rows, and a port that let either supply the
// other's answer satisfies one of these and fails the other.
func TestOneSessionDocumentFeedsBothCollections(t *testing.T) {
	_, stdout, _ := runWith(t, wholeBatch, map[string]string{"SE_REPLAY_DIR": stageBusy(t)})
	records := parseRecords(t, stdout)

	if got := factsOf(t, records, "server", serverName)["SessionCount"]; got != 2.0 {
		t.Errorf("the server row's count comes from the document's own size; got %v", got)
	}
	rows := 0
	for _, record := range ofKind(records, "object") {
		if record["collection"] == "sessions" {
			rows++
		}
	}
	if rows != 2 {
		t.Fatalf("two streams in the document, %d session rows", rows)
	}

	// An episode titles itself with its series; a film keeps its own name. The
	// row is named by the session key where there is one, and falls back to the
	// rating key where there is not.
	episode := factsOf(t, records, "sessions", "41")
	if episode["Title"] != "Example Series — Pilot" {
		t.Errorf("an episode is titled with its series: %v", episode["Title"])
	}
	if episode["User"] != "example-viewer" || episode["Player"] != "Plex for Apple TV" ||
		episode["State"] != "playing" || episode["VideoDecision"] != "transcode" {
		t.Errorf("the episode row lost a member: %v", episode)
	}
	film := factsOf(t, records, "sessions", "9002")
	if film["Title"] != "Example Film" {
		t.Errorf("a film with no grandparent keeps its own name: %v", film["Title"])
	}
	if _, carried := film["VideoDecision"]; carried {
		t.Errorf("no transcode session was opened, so the row states no decision: %v", film)
	}
}

func TestReplayBootIDIsTheStagedFileWhenAVariantHasOne(t *testing.T) {
	dir := stageHealthy(t)
	if err := os.WriteFile(filepath.Join(dir, "boot_id"), []byte("8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stdout, _ := runWith(t, wholeBatch, map[string]string{"SE_REPLAY_DIR": dir})
	if got := ofKind(parseRecords(t, stdout), "begin")[0]["boot_id"]; got != "8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44" {
		t.Fatalf("boot_id must be the staged file, trimmed; got %v", got)
	}
}

func TestReplayNowIsIgnoredButNeverACrash(t *testing.T) {
	// The two timestamps this collector publishes are converted from epoch
	// seconds the SERVER stated; nothing is derived against a clock, so the pin
	// has nothing to freeze. The contract is only that setting it changes nothing
	// and breaks nothing.
	dir := stageHealthy(t)
	bare := map[string]string{"SE_REPLAY_DIR": dir}
	pinned := map[string]string{"SE_REPLAY_DIR": dir, "SE_REPLAY_NOW": "2026-08-19T12:15:00Z"}

	code1, first, _ := runWith(t, wholeBatch, bare)
	code2, second, _ := runWith(t, wholeBatch, pinned)
	if code1 != exitOK || code2 != exitOK || first != second {
		t.Fatalf("SE_REPLAY_NOW changed the outcome: exits %d/%d", code1, code2)
	}
}

// The epoch seconds the section listing states become UTC to the second. Read off
// the committed capture by hand at staging, before any stream existed.
func TestTheScanStampsAreTheDocumentsEpochSecondsInUTC(t *testing.T) {
	_, stdout, _ := runWith(t, wholeBatch, map[string]string{"SE_REPLAY_DIR": stageHealthy(t)})
	records := parseRecords(t, stdout)
	movies := factsOf(t, records, "libraries", "1")
	if movies["ScannedAt"] != "2026-08-19T12:13:06Z" || movies["UpdatedAt"] != "2026-08-19T12:12:54Z" {
		t.Fatalf("the Movies stamps are wrong: %v", movies)
	}
	shows := factsOf(t, records, "libraries", "3")
	if shows["ScannedAt"] != "2026-08-19T12:14:17Z" || shows["UpdatedAt"] != "2026-08-19T12:14:16Z" {
		t.Fatalf("the TV Shows stamps are wrong: %v", shows)
	}
}

// The seam's whole point: a machine with no media server of its own replays this
// capture without ever opening a socket. Asserted on the OUTPUT, because the
// development machine that runs it has no Plex at all — so a seam escape here
// would produce an absent decline, not an error.
func TestTheStagedDocumentsDecideRatherThanTheReplayingHost(t *testing.T) {
	env := map[string]string{
		"SE_REPLAY_DIR": stageHealthy(t),
		// Deliberately pointing somewhere real-looking, and carrying a token: under
		// replay neither must ever be consulted, and a port that fell back to them
		// on a machine that happened to run a Plex would read the wrong one.
		urlVariable:   "http://127.0.0.1:32400",
		tokenVariable: "not-a-real-token",
	}
	code, stdout, stderr := runWith(t, wholeBatch, env)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	facts := factsOf(t, parseRecords(t, stdout), "server", serverName)
	if facts["FriendlyName"] != "host-e56b83" || facts["Version"] != "1.43.3.10896-cb3ebc72d" {
		t.Fatalf("the row must come from the staged documents: %v", facts)
	}
}

// The receipts are NOT read on the replaying machine, and this is what makes the
// corpus anchor on ConfigMissing being ABSENT load-bearing: unpinned, this binary
// would find no SE_PLEX_TOKEN on whatever workstation is replaying and publish a
// receipts-incomplete row from a variant whose payloads are the API answering.
func TestReplayNeverReadsTheReplayingMachinesReceipts(t *testing.T) {
	_, stdout, _ := runWith(t, wholeBatch, map[string]string{"SE_REPLAY_DIR": stageHealthy(t)})
	facts := factsOf(t, parseRecords(t, stdout), "server", serverName)
	if _, carried := facts["ConfigMissing"]; carried {
		t.Fatalf("a replay read the replaying machine's environment: %v", facts)
	}
	if _, carried := facts["StatusUnobservable"]; carried {
		t.Fatalf("the staged documents ARE the API answering: %v", facts)
	}
}

func TestAnEmptyReplayDirectoryDeclinesUnavailableAndCommitsNothing(t *testing.T) {
	code, stdout, stderr := runWith(t, wholeBatch,
		map[string]string{"SE_REPLAY_DIR": t.TempDir()})
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 3 {
		t.Fatalf("every requested collection is declined, not just the first: %v", declines)
	}
	for _, decline := range declines {
		if decline["reason"] != "unavailable" || decline["detail"] != declineNoServer.detail {
			t.Fatalf("expected the shared unavailable decline, got %v", decline)
		}
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
// opposite ways for as long as it existed — live `unsupported`, replay `absent` —
// because replay exercises only the replay half; this asserts the two paths reach
// the same VALUE, which is what makes the disagreement unspellable rather than
// merely currently-absent.
//
// At the source rather than through run(), because the live path's other half is
// a Linux clock: the whole batch cannot run on the machine this test is written
// on, and the deployment reading is taken before that clock precisely so an
// absence answers truthfully on any platform.
func TestAnUnconfiguredServerIsTheSameAbsentReadingAsAnEmptyCapture(t *testing.T) {
	empty := t.TempDir()
	sources := map[string]source{
		"no url configured": newSource(func(string) string { return "" }),
		"an empty capture": newSource(func(key string) string {
			if key == "SE_REPLAY_DIR" {
				return empty
			}
			return ""
		}),
	}
	for label, src := range sources {
		if got := src.deployment(); !got.absent {
			t.Fatalf("%s: %+v is not an absence at all", label, got)
		}
		for name, build := range served {
			_, err := build(src)
			var refused *declined
			if !errors.As(err, &refused) {
				t.Fatalf("%s/%s: %v is not a decline at all", label, name, err)
			}
			if *refused != declineNoServer {
				t.Fatalf("%s/%s: reached %v, and the shared constant is %v", label, name, *refused, declineNoServer)
			}
		}
	}
}

// A URL with no token is a different verdict from no URL, and the difference is
// the whole of what this gate is for: the estate asked for a server this process
// cannot open. The `server` row STAYS and names the receipt — that is the
// standing signal — while the other two are not asked at all, because guessing at
// a token would only manufacture 401s and a config gap must not dress as an
// outage. Neither of those two commits, so what a previous batch published stands.
func TestAConfiguredServerWithNoTokenPublishesTheRowAndAsksNothingElse(t *testing.T) {
	src := newSource(func(key string) string {
		if key == urlVariable {
			return "http://127.0.0.1:32400"
		}
		return ""
	})
	got := src.deployment()
	if got.absent || len(got.missing) != 1 || got.missing[0] != tokenVariable {
		t.Fatalf("a URL with no token is a receipts gap naming the variable; got %+v", got)
	}

	// The deployment gate above is read from the environment and needs no
	// clock, so the LIVE source answers it on any platform. The row builder
	// below now does need one: a ConfigMissing row rests on no document, so
	// nothing else takes its `at`, and it used to publish `at: 0`. Driving it
	// through stubSource — which carries the same deployment and inherits
	// replay's stamping — keeps this a test of the DERIVATION rather than of
	// whether the host running the tests has CLOCK_BOOTTIME.
	rows, err := serverRows(stubSource{deploy: got})
	if err != nil || len(rows) != 1 {
		t.Fatalf("the server row stays: %v rows, err %v", len(rows), err)
	}
	if string(rows[0].facts.encode()) != `{"ConfigMissing":["`+tokenVariable+`"]}` {
		t.Fatalf("the row names the receipt and nothing else: %s", rows[0].facts.encode())
	}
	for _, name := range []string{"libraries", "sessions"} {
		_, err := served[name](src)
		var refused *declined
		if !errors.As(err, &refused) || *refused != declineNoReceipts {
			t.Fatalf("%s: %v, want the shared no-receipts decline", name, err)
		}
		if refused.reason == "absent" {
			t.Fatalf("%s: a receipts gap must not retire what a previous batch published", name)
		}
	}
}

// A token unfit to put in a header names the PROBLEM rather than the variable,
// and never the value — the point of the refusal is that the value is unfit to
// send, and repeating it in a fact would put it somewhere far worse.
func TestATokenUnfitForAHeaderIsRefusedByName(t *testing.T) {
	src := newSource(func(key string) string {
		switch key {
		case urlVariable:
			return "http://127.0.0.1:32400"
		case tokenVariable:
			return "bad\ntoken"
		}
		return ""
	})
	got := src.deployment()
	if len(got.missing) != 1 || got.missing[0] != tokenProblemDetail {
		t.Fatalf("got %+v, want the spelled-out refusal", got)
	}
	if strings.Contains(got.missing[0], "bad") {
		t.Fatal("the refusal repeated the value it refused to send")
	}
}

// A capture staging some documents and not others is a broken capture, not a
// statement about a machine: the API that answered / was there to answer
// /library/sections too. "I could not run" — never a decline, which would state
// something about a machine nobody observed, and never a fall back to the server
// of whichever host is replaying.
func TestAHalfStagedCaptureRefusesToRunRatherThanDeclining(t *testing.T) {
	cases := map[string]string{
		"the root document without the session list": stage(t, map[string]string{
			"root.json": healthyRoot}),
		"the sections listing without its per-section counts": stage(t, map[string]string{
			"library-sections.json": healthySections}),
	}
	for label, dir := range cases {
		code, stdout, stderr := runWith(t, wholeBatch, map[string]string{"SE_REPLAY_DIR": dir})
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

	// A server configured with no token is still a YES: the collection is served
	// and the row it publishes says which receipt is missing, which is a reading
	// rather than an inability.
	var stdoutBuf, stderrBuf strings.Builder
	if code := probe(&stdoutBuf, &stderrBuf, newSource(func(key string) string {
		if key == urlVariable {
			return "http://127.0.0.1:32400"
		}
		return ""
	})); code != exitOK {
		t.Fatalf("probe exit %d", code)
	}
	if !strings.Contains(stdoutBuf.String(), `"verdict":"yes"`) ||
		!strings.Contains(stdoutBuf.String(), tokenVariable) {
		t.Fatalf("a receipts gap is a yes that names the receipt: %q", stdoutBuf.String())
	}
}

// A fact value is never null at any depth (DESIGN 19), and the judge refuses the
// whole stream for one. Asserted on the raw lines, because a decode and
// re-encode would spell a null the way this side spells one rather than the way
// it travelled; begin's `instance` is the one legitimate null on the wire.
func TestAMemberTheDocumentDoesNotCarryIsOffTheRowRatherThanNulled(t *testing.T) {
	// A section listing missing every member this collector reads except its key,
	// which the reference would publish as `{"Title": null, "Type": null}`.
	sparse := stage(t, map[string]string{
		"root.json":                   `{"MediaContainer":{}}`,
		"status-sessions.json":        healthySessions,
		"library-sections.json":       `{"MediaContainer":{"Directory":[{"key":"7"}]}}`,
		"library-sections-7-all.json": `{"MediaContainer":{"size":0}}`,
	})
	code, stdout, stderr := runWith(t, wholeBatch, map[string]string{"SE_REPLAY_DIR": sparse})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if strings.HasPrefix(line, `{"record":"object"`) && strings.Contains(line, "null") {
			t.Fatalf("a null reached a fact, and a fact value is never null at any depth:\n%s", line)
		}
	}
	// The row is still published: the key names it, and what the document did not
	// state is simply absent from it.
	if facts := factsOf(t, parseRecords(t, stdout), "libraries", "7"); len(facts) != 0 {
		t.Fatalf("the listing stated nothing but the key, so the row carries nothing: %v", facts)
	}
	// And a container with no totalSize states no count rather than zero.
	if strings.Contains(stdout, `"ItemCount"`) {
		t.Fatalf("a container that stated no totalSize must not become a count:\n%s", stdout)
	}
}
