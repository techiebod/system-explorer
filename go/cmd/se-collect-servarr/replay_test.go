package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A two-instance fleet, because one instance exercises no fan-out at all: every
// collection asks each app in turn and namespaces its rows by the app's name,
// and a single-app capture would replay perfectly while proving none of it.
// prowlarr is the second because it is the one that is DIFFERENT — no queue
// endpoint, and excluded from the acquisition trail by its own appName.
const stagedInstances = `[
 {"name": "radarr", "api": "v3", "missing": [], "duplicates": []},
 {"name": "prowlarr", "api": "v1", "missing": [], "duplicates": []}
]`

const stagedRadarrStatus = `{"appName": "Radarr", "instanceName": "Radarr",
 "version": "6.3.0.10514", "isDocker": true, "urlBase": ""}`

const stagedProwlarrStatus = `{"appName": "Prowlarr", "instanceName": "Prowlarr",
 "version": "2.5.2.5491", "isDocker": true, "urlBase": ""}`

// One error and two warnings, which is what makes the two health counts a PAIR
// rather than a tally: a port that counted items publishes 3 and 0.
const stagedRadarrHealth = `[
 {"source": "IndexerRssCheck", "type": "error",
  "message": "No indexers available with RSS sync enabled",
  "wikiUrl": "https://wiki.servarr.com/radarr/system#no-indexers"},
 {"source": "DownloadClientCheck", "type": "warning",
  "message": "No download client is available",
  "wikiUrl": "https://wiki.servarr.com/radarr/system#no-download-client"},
 {"source": "IndexerSearchCheck", "type": "warning",
  "message": "No indexers available with Automatic Search enabled",
  "wikiUrl": "https://wiki.servarr.com/radarr/system#no-search-indexers"}
]`

const stagedProwlarrHealth = `[
 {"source": "IndexerCheck", "type": "error",
  "message": "No indexers enabled, Prowlarr will not return search results",
  "wikiUrl": "https://wiki.servarr.com/prowlarr/system#no-indexers"}
]`

// A stuck download: completed, nothing left to fetch, and the app's own verdict
// that it will not import. The shape the collection exists to surface.
const stagedRadarrQueue = `{"page": 1, "pageSize": 250, "totalRecords": 1,
 "records": [
  {"id": 91, "title": "Mut.Release.2026.1080p.WEB-DL.MUTGRP",
   "status": "completed", "trackedDownloadStatus": "warning",
   "trackedDownloadState": "importPending",
   "downloadClient": "mut-transmission", "indexer": "mut-indexer",
   "protocol": "torrent",
   "downloadId": "3ab0000000000000000000000000000000c0ffee",
   "size": 8589934592, "sizeleft": 0,
   "errorMessage": "The download is missing files",
   "statusMessages": [{"title": "Mut.Release.2026.1080p.WEB-DL.MUTGRP",
                       "messages": ["Not an upgrade for existing movie file(s)"]}]}
 ]}`

const stagedRadarrQueueStatus = `{"totalCount": 1, "count": 1, "errors": false,
 "warnings": true}`

const stagedRadarrHistory = `{"page": 1, "pageSize": 100, "totalRecords": 2,
 "records": [
  {"id": 4711, "eventType": "grabbed",
   "sourceTitle": "Mut.Release.2026.1080p.WEB-DL.MUTGRP",
   "downloadId": "3ab0000000000000000000000000000000c0ffee",
   "date": "2026-08-19T09:58:11Z",
   "quality": {"quality": {"id": 7, "name": "Bluray-1080p"}},
   "data": {"indexer": "mut-indexer", "downloadClient": "mut-transmission"}},
  {"eventType": "downloadFolderImported",
   "sourceTitle": "Mut.Release.2026.1080p.WEB-DL.MUTGRP",
   "date": "2026-08-19T09:59:02Z",
   "quality": {"quality": {"name": "Bluray-1080p"}},
   "data": {"downloadClient": "mut-transmission"}}
 ]}`

// prowlarr's trail, captured and never read: the adapter excludes it by the
// app's own appName. Staged here for the same reason the corpus commits it —
// a port that keyed the exclusion on the operator's instance name instead
// would read this document, and only its presence can catch that.
const stagedProwlarrHistory = `{"page": 1, "pageSize": 100, "totalRecords": 1,
 "records": [{"id": 812, "eventType": "releaseGrabbed",
              "date": "2026-08-19T09:58:10Z",
              "data": {"source": "Prowlarr"}}]}`

// The 404s, which carry no body at all: the response's whole content is its
// status line, so the capture records the code rather than an empty file.
const stagedResponseCodes = `{"prowlarr-api-v1-queue": 404,
 "prowlarr-api-v1-queue-status": 404}`

const wholeRequest = "collect apps:234 health:251 queue:285 history:268\n"

// stageReplayDir lays out the documents the replay seam reads. An empty body
// stages no file for that stem, and staging none at all is a host that fronts
// no fleet.
func stageReplayDir(t *testing.T, documents map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for stem, body := range documents {
		if body == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, stem+".json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func stagedFleet() map[string]string {
	return map[string]string{
		stemInstances:                   stagedInstances,
		stemResponses:                   stagedResponseCodes,
		"radarr-api-v3-system-status":   stagedRadarrStatus,
		"radarr-api-v3-health":          stagedRadarrHealth,
		"radarr-api-v3-queue-status":    stagedRadarrQueueStatus,
		"radarr-api-v3-queue":           stagedRadarrQueue,
		"radarr-api-v3-history":         stagedRadarrHistory,
		"prowlarr-api-v1-system-status": stagedProwlarrStatus,
		"prowlarr-api-v1-health":        stagedProwlarrHealth,
		"prowlarr-api-v1-history":       stagedProwlarrHistory,
	}
}

func stagedAll(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{"SE_REPLAY_DIR": stageReplayDir(t, stagedFleet())}
}

func factsOf(t *testing.T, records []map[string]any, collection, name string) map[string]any {
	t.Helper()
	for _, record := range ofKind(records, "object") {
		if record["collection"] == collection && record["name"] == name {
			return record["facts"].(map[string]any)
		}
	}
	t.Fatalf("no %s row named %q", collection, name)
	return nil
}

func namesOf(records []map[string]any, collection string) []string {
	var out []string
	for _, record := range ofKind(records, "object") {
		if record["collection"] == collection {
			out = append(out, record["name"].(string))
		}
	}
	return out
}

func TestReplayIsByteDeterministicAcrossTwoRuns(t *testing.T) {
	env := stagedAll(t)
	code1, first, stderr := runWith(t, wholeRequest, env)
	code2, second, _ := runWith(t, wholeRequest, env)
	if code1 != exitOK || code2 != exitOK {
		t.Fatalf("exits %d/%d, stderr: %s", code1, code2, stderr)
	}
	if first != second {
		t.Fatalf("replay is not byte-deterministic:\n%s\nvs\n%s", first, second)
	}
}

func TestReplayPinsEveryRunVaryingMember(t *testing.T) {
	code, stdout, stderr := runWith(t, wholeRequest, stagedAll(t))
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	begin := ofKind(records, "begin")[0]
	if begin["request"] != "replay" || begin["batch"] != "replay" {
		t.Errorf("replay pins batch and request to the constant \"replay\"; got %v/%v",
			begin["request"], begin["batch"])
	}
	if begin["boot_id"] != replayBootID {
		t.Errorf("a variant staging no boot_id gets the fixed v4-shaped id; got %v", begin["boot_id"])
	}
	if begin["timens"] != 0.0 {
		t.Errorf("no time namespace was observed at capture, so timens is 0; got %v", begin["timens"])
	}
	// Host-native, on the one collector that fronts a fleet. `instance` scopes
	// a collector that IS one of several; this is one process fronting several,
	// and it keeps them apart by namespacing every row's name.
	if begin["instance"] != nil {
		t.Errorf("this collector fronts a fleet and is still host-native; got %v", begin["instance"])
	}
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

// `at` is one counter across the WHOLE batch, and the collections come out in
// the request line's order — not the table's.
func TestAtAdvancesAcrossTheWholeBatchInRequestOrder(t *testing.T) {
	_, stdout, stderr := runWith(t, wholeRequest, stagedAll(t))
	objects := ofKind(parseRecords(t, stdout), "object")
	if len(objects) != 9 {
		t.Fatalf("two apps, four health items, one queue record and two events; "+
			"got %d (stderr %s)", len(objects), stderr)
	}
	if objects[0]["collection"] != "apps" || objects[2]["collection"] != "health" ||
		objects[6]["collection"] != "queue" || objects[7]["collection"] != "history" {
		t.Errorf("the collections come out in the request line's order; got %v",
			[]any{objects[0]["collection"], objects[2]["collection"],
				objects[6]["collection"], objects[7]["collection"]})
	}
	for i, object := range objects {
		want := float64(int64((1.0+0.001*float64(i))*1000+0.5)) / 1000
		if object["at"] != want {
			t.Errorf("object %d carries at %v, want %v — one counter across the batch",
				i, object["at"], want)
		}
	}
}

// The fan-out, which is what a fleet collector is FOR: every collection asks
// every instance, in configuration order, and namespaces the rows by the app.
func TestEveryCollectionFansOutOverTheFleetInConfigurationOrder(t *testing.T) {
	_, stdout, _ := runWith(t, wholeRequest, stagedAll(t))
	records := parseRecords(t, stdout)
	if got := namesOf(records, "apps"); !equal(got, []string{"radarr", "prowlarr"}) {
		t.Errorf("the apps rows are the configured fleet, in its own order; got %v", got)
	}
	want := []string{
		"radarr/IndexerRssCheck", "radarr/DownloadClientCheck",
		"radarr/IndexerSearchCheck", "prowlarr/IndexerCheck",
	}
	if got := namesOf(records, "health"); !equal(got, want) {
		t.Errorf("health fans out over both apps and namespaces every row; got %v", got)
	}
}

// The two health counts are a PAIR, and they are counts of GRADES rather than
// of items: three items become one critical and two warnings, and a port that
// tallied the list publishes 3 and 0.
func TestTheHealthCountsGradeTheItemsRatherThanCountingThem(t *testing.T) {
	_, stdout, _ := runWith(t, wholeRequest, stagedAll(t))
	records := parseRecords(t, stdout)
	radarr := factsOf(t, records, "apps", "radarr")
	if radarr["HealthErrors"] != 1.0 || radarr["HealthWarnings"] != 2.0 {
		t.Errorf("one error and two warnings; got %v/%v",
			radarr["HealthErrors"], radarr["HealthWarnings"])
	}
	prowlarr := factsOf(t, records, "apps", "prowlarr")
	if prowlarr["HealthErrors"] != 1.0 || prowlarr["HealthWarnings"] != 0.0 {
		t.Errorf("one error and no warnings; got %v/%v",
			prowlarr["HealthErrors"], prowlarr["HealthWarnings"])
	}
	// A grade below attention and a grade this collector has never met: notice
	// counts as neither, and an unknown word still counts as the app raising
	// its hand. Not a captured shape — staged here because the alternative is
	// a closed enum that refuses the reading.
	document, err := decodeDocument([]byte(`[
	 {"source": "A", "type": "notice", "message": "m"},
	 {"source": "B", "type": "haywire", "message": "m"},
	 {"source": "C", "type": "ok", "message": "m"},
	 {"source": "D", "type": "warning", "message": ""}]`))
	if err != nil {
		t.Fatal(err)
	}
	errs, warns, err := healthCounts(instance{name: "x"}, document)
	if err != nil || errs != 0 || warns != 1 {
		t.Errorf("notice, ok and a message-less item count as nothing and an "+
			"unmet grade counts as a warning; got %d/%d (%v)", errs, warns, err)
	}
}

// The two prowlarr absences, which are the load-bearing pair of this whole
// port: a 404 with no body is this app having NO queue, and the row must carry
// neither the figure a port might default to zero nor the reason a port might
// invent from a failed request.
func TestAFourOhFourIsSilenceByDesignAndNotAFault(t *testing.T) {
	_, stdout, stderr := runWith(t, wholeRequest, stagedAll(t))
	records := parseRecords(t, stdout)
	prowlarr := factsOf(t, records, "apps", "prowlarr")
	if _, present := prowlarr["QueueTotal"]; present {
		t.Errorf("an app with no queue endpoint publishes no depth: %v", prowlarr["QueueTotal"])
	}
	if _, present := prowlarr["QueueUnobservable"]; present {
		t.Errorf("a 404 is not a narrowed observation: %v", prowlarr["QueueUnobservable"])
	}
	// And the queue collection serves the app that HAS one, without dropping
	// the instance that does not: a 404 on page one ends that app's walk.
	if got := namesOf(records, "queue"); !equal(got, []string{"radarr/91"}) {
		t.Errorf("the queue is radarr's alone, and prowlarr is not a failure; got %v", got)
	}
	if strings.Contains(stderr, "404") {
		t.Errorf("a reading needs no stderr line: %q", stderr)
	}
	// A zero from an app that HAS a queue is a reading and stays.
	radarr := factsOf(t, records, "apps", "radarr")
	if radarr["QueueTotal"] != 1.0 {
		t.Errorf("QueueTotal is the app's own figure; got %v", radarr["QueueTotal"])
	}
}

// An unrecorded request is not a 404. Turning a capture's omission into "this
// app has no such endpoint" would be absence read as an answer, in the one
// place this collector's rows turn on it.
func TestAnUnrecordedRequestIsNotAFourOhFour(t *testing.T) {
	staged := stagedFleet()
	delete(staged, stemResponses)
	staged["prowlarr-api-v1-queue"] = ""
	staged["prowlarr-api-v1-queue-status"] = ""
	code, stdout, stderr := runWith(t, wholeRequest,
		map[string]string{"SE_REPLAY_DIR": stageReplayDir(t, staged)})
	if code != exitRuntime {
		t.Fatalf("exit %d, want %d (stdout %q)", code, exitRuntime, stdout)
	}
	if !strings.Contains(stderr, "not captured") {
		t.Errorf("the refusal must name the uncaptured document; got %q", stderr)
	}
	if strings.Contains(stdout, `"QueueUnobservable"`) {
		t.Error("a document the capture forgot must never become a fact about an app")
	}
}

// Only 404 replays. Every other status reaches a fact value spelled by the
// reference's own exception rendering, which no independent implementation can
// reproduce — so a capture carrying one is an adjudication, not a payload.
func TestANonFourOhFourResponseCodeIsRefusedRatherThanInvented(t *testing.T) {
	staged := stagedFleet()
	staged[stemResponses] = `{"prowlarr-api-v1-queue-status": 500,
	 "prowlarr-api-v1-queue": 404}`
	code, stdout, stderr := runWith(t, wholeRequest,
		map[string]string{"SE_REPLAY_DIR": stageReplayDir(t, staged)})
	if code != exitRuntime {
		t.Fatalf("exit %d, want %d", code, exitRuntime)
	}
	if !strings.Contains(stderr, "404 only") {
		t.Errorf("the refusal must say which statuses this seam replays; got %q", stderr)
	}
	if strings.Contains(stdout, `"QueueUnobservable"`) {
		t.Error("the seam must not invent the failure text a fact would carry")
	}
}

// The whole trail, and the app that is not in it. prowlarr excludes itself by
// its own appName and never by the name the operator gave it — the document is
// staged and must go unread.
func TestTheTrailExcludesTheIndexerProxyByItsOwnStatement(t *testing.T) {
	_, stdout, _ := runWith(t, wholeRequest, stagedAll(t))
	records := parseRecords(t, stdout)
	// index-1 is the second record's POSITION in the page: the app stated no
	// id for it, and the numbering counts every position so two
	// implementations cannot drift over a page with a gap in it.
	if got := namesOf(records, "history"); !equal(got, []string{"radarr/4711", "radarr/index-1"}) {
		t.Errorf("the trail is radarr's alone, positionally numbered where the "+
			"app states no id; got %v", got)
	}
	grab := factsOf(t, records, "history", "radarr/4711")
	if grab["EventType"] != "grabbed" || grab["Indexer"] != "mut-indexer" ||
		grab["Quality"] != "Bluray-1080p" {
		t.Errorf("a grab states its indexer and quality: %v", grab)
	}
	// An import names its client and its download id; its indexer lives on the
	// grab that preceded it, which the bounded tail may no longer hold. An
	// absent member is an absent fact, never a guess.
	arrival := factsOf(t, records, "history", "radarr/index-1")
	if _, present := arrival["Indexer"]; present {
		t.Errorf("an import states no indexer: %v", arrival["Indexer"])
	}
	if _, present := arrival["DownloadId"]; present {
		t.Errorf("this import states no download id: %v", arrival["DownloadId"])
	}
}

// The stuck download, whole: the app's verdict AND its own explanation of it.
// The second half is what a9_queue_reason_blind.py drops, and the row is what
// an operator opens this collection to read.
func TestAStuckDownloadCarriesTheAppsOwnVerdictAndItsReason(t *testing.T) {
	_, stdout, _ := runWith(t, wholeRequest, stagedAll(t))
	facts := factsOf(t, parseRecords(t, stdout), "queue", "radarr/91")
	for member, want := range map[string]any{
		"App":                   "radarr",
		"Status":                "completed",
		"TrackedDownloadStatus": "warning",
		"TrackedDownloadState":  "importPending",
		"Protocol":              "torrent",
		"DownloadId":            "3ab0000000000000000000000000000000c0ffee",
		"ErrorMessage":          "The download is missing files",
		"StatusMessages":        "Not an upgrade for existing movie file(s)",
	} {
		if facts[member] != want {
			t.Errorf("%s = %v, want %v", member, facts[member], want)
		}
	}
	// Zero bytes left beside a warning verdict IS the stuck shape, so the zero
	// is published rather than dropped as uninteresting — and it travels as the
	// integer the app spelled, because `0` is not `0.0` to a typed consumer.
	if facts["SizeLeftBytes"] != 0.0 {
		t.Errorf("SizeLeftBytes = %v, want 0", facts["SizeLeftBytes"])
	}
	if !strings.Contains(stdout, `"SizeLeftBytes":0`) {
		t.Errorf("the byte count travels as the token the app spelled:\n%s", stdout)
	}
}

// No fact on any row may be null at ANY DEPTH, which is the rule the judge
// applies (replay.py _null_paths) and the contract's recursive fact_value. It
// is load-bearing here rather than decorative: the reference writes seven
// members unconditionally, so an app that omits one publishes a null — and this
// port omits the fact instead.
func TestNoFactIsNullAtAnyDepthEvenWhereTheReferenceWouldWriteOne(t *testing.T) {
	staged := stagedFleet()
	// A health item with no source, type or message, and a queue record with
	// none of the four members the reference writes unconditionally.
	staged["radarr-api-v3-health"] = `[{"wikiUrl": "https://wiki.servarr.com/x"}]`
	staged["radarr-api-v3-queue"] = `{"totalRecords": 1, "records": [{"id": 92}]}`
	code, stdout, stderr := runWith(t, wholeRequest,
		map[string]string{"SE_REPLAY_DIR": stageReplayDir(t, staged)})
	if code != exitOK {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	for _, object := range ofKind(records, "object") {
		for _, path := range nullPaths(object["facts"], object["name"].(string)) {
			t.Errorf("fact %s is null: value, absent and unobservable each have "+
				"their own channel and a null names none of them", path)
		}
	}
	// The row still exists, named `unknown`, because an item with no source is
	// still the app saying something is wrong.
	if got := namesOf(records, "health"); got[0] != "radarr/unknown" {
		t.Errorf("a health item stating no source is still a row; got %v", got)
	}
	// And the health counts stay honest: an item with no type and no message
	// states nothing gradeable.
	if facts := factsOf(t, records, "apps", "radarr"); facts["HealthErrors"] != 0.0 ||
		facts["HealthWarnings"] != 0.0 {
		t.Errorf("an ungradeable item counts as neither; got %v", facts)
	}
}

// nullPaths is replay.py's _null_paths: every path at which a null sits inside
// a fact value, to any depth. Depth one was the judge's own subset guard once —
// it refused a null at the top of the facts dict and passed the same null one
// level down, which is exactly where marshalling a struct with nil members puts
// it.
func nullPaths(node any, path string) []string {
	switch value := node.(type) {
	case nil:
		return []string{path}
	case map[string]any:
		var found []string
		for key, inner := range value {
			found = append(found, nullPaths(inner, path+"/"+key)...)
		}
		return found
	case []any:
		var found []string
		for i, inner := range value {
			found = append(found, nullPaths(inner, path+"["+strconv.Itoa(i)+"]")...)
		}
		return found
	}
	return nil
}

// No payload at all is a host whose deployment named no fleet — which is not
// the same as a host that fronts none, and RULED 2026-08-19 it may not retire.
// Every requested collection declines `unavailable`, and NOTHING commits: no
// reason but `absent` commits, so prior state stands and the collator marks it
// stale. This test asserted the opposite until that ruling, and the assertion
// moved with it rather than being deleted.
func TestNoFleetDeclinesUnavailableForEveryCollectionAndCommitsNothing(t *testing.T) {
	env := map[string]string{"SE_REPLAY_DIR": t.TempDir()}
	code, stdout, stderr := runWith(t, wholeRequest, env)
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	if declines := ofKind(records, "decline"); len(declines) != 4 {
		t.Fatalf("every requested collection is declined, not just the first; got %v", declines)
	}
	if commits := ofKind(records, "commit"); len(commits) != 0 {
		t.Fatalf("an unnamed fleet establishes nothing, so no collection may be "+
			"retired here; got %v", commits)
	}
	if len(ofKind(records, "object")) != 0 {
		t.Fatal("a declined collection carries no records of any kind")
	}
}

// An instance whose receipts are missing is a ROW wearing its fault, and the
// fan-out collections still serve the instances that have theirs. A typo in
// SE_SERVARR_INSTANCES vanishing into green is what this refuses.
func TestAnInstanceWithNoReceiptsIsARowAndNotASilentSkip(t *testing.T) {
	staged := stagedFleet()
	staged[stemInstances] = `[
	 {"name": "radarr", "api": "v3", "missing": [], "duplicates": []},
	 {"name": "sonarr", "api": "v3",
	  "missing": ["SE_SONARR_API_KEY", "SE_SONARR_URL"], "duplicates": ["sonarr:v3"]}]`
	code, stdout, stderr := runWith(t, wholeRequest,
		map[string]string{"SE_REPLAY_DIR": stageReplayDir(t, staged)})
	if code != exitOK {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	facts := factsOf(t, records, "apps", "sonarr")
	// Sorted, so the row is stable whichever order the faults were found in.
	missing, ok := facts["ConfigMissing"].([]any)
	if !ok || len(missing) != 2 || missing[0] != "SE_SONARR_API_KEY" {
		t.Errorf("ConfigMissing = %v", facts["ConfigMissing"])
	}
	if duplicates, ok := facts["ConfigDuplicate"].([]any); !ok || duplicates[0] != "sonarr:v3" {
		t.Errorf("ConfigDuplicate = %v", facts["ConfigDuplicate"])
	}
	// Nothing was asked of it, so there is no reading to narrow: an
	// unaddressable instance is not a dark one.
	if _, present := facts["StatusUnobservable"]; present {
		t.Errorf("an instance nothing asked has no failed reading: %v", facts)
	}
	if _, present := facts["Version"]; present {
		t.Errorf("an instance nothing asked states no version: %v", facts)
	}
	// And the other instance's rows are all there.
	if got := namesOf(records, "queue"); !equal(got, []string{"radarr/91"}) {
		t.Errorf("a receipt-less instance must not cost the fleet its other rows; got %v", got)
	}
}

// Every configured instance missing its receipts is not a fleet that answered
// nothing — it is a collector that could not run. Committing zero here would
// retire a whole subsystem on the strength of a configuration fault, which is
// the direction that destroys data.
func TestAFleetWithNoCompleteReceiptsCannotRunTheFanOut(t *testing.T) {
	staged := map[string]string{
		stemInstances: `[{"name": "sonarr", "api": "v3",
		 "missing": ["SE_SONARR_URL"], "duplicates": []}]`,
	}
	code, stdout, stderr := runWith(t, "collect health:12\n",
		map[string]string{"SE_REPLAY_DIR": stageReplayDir(t, staged)})
	if code != exitRuntime {
		t.Fatalf("exit %d, want %d", code, exitRuntime)
	}
	if !strings.Contains(stderr, "complete receipts") {
		t.Errorf("the refusal must name what is missing; got %q", stderr)
	}
	if strings.Contains(stdout, `"record":"commit"`) {
		t.Error("nothing was established, so nothing may be committed")
	}
}

// A capture that staged a fleet and not one of its documents is a broken
// capture, which is a statement about nobody's machine — never a decline, and
// never a fall back to whatever fleet the replaying machine is configured with.
func TestAPartiallyStagedFleetRefusesToRun(t *testing.T) {
	staged := stagedFleet()
	staged["radarr-api-v3-health"] = ""
	code, stdout, stderr := runWith(t, wholeRequest,
		map[string]string{"SE_REPLAY_DIR": stageReplayDir(t, staged)})
	if code != exitRuntime {
		t.Fatalf("exit %d, want %d (stdout %q)", code, exitRuntime, stdout)
	}
	if !strings.Contains(stderr, "not captured") {
		t.Errorf("the refusal must name the uncaptured document; got %q", stderr)
	}
	if strings.Contains(stdout, `"record":"decline"`) {
		t.Error("a capture that staged a fleet must not be read as a host without one")
	}
}

// A staged document this seam cannot read is a broken capture too, and the
// batch reports "I could not run" rather than inventing a decline or a fact.
func TestAnUnreadablePayloadRefusesToRun(t *testing.T) {
	for label, broken := range map[string]map[string]string{
		"the receipt is not a document":    {stemInstances: "{"},
		"the receipt is not a list":        {stemInstances: `{"radarr": "v3"}`},
		"a status answer is truncated":     {"radarr-api-v3-system-status": `{"appName":`},
		"the response codes are not a map": {stemResponses: `[404]`},
	} {
		staged := stagedFleet()
		for stem, body := range broken {
			staged[stem] = body
		}
		code, stdout, stderr := runWith(t, wholeRequest,
			map[string]string{"SE_REPLAY_DIR": stageReplayDir(t, staged)})
		if code != exitRuntime {
			t.Errorf("%s: exit %d, want %d (stdout %q)", label, code, exitRuntime, stdout)
		}
		if strings.TrimSpace(stderr) == "" {
			t.Errorf("%s: a refusal with no stderr line is indistinguishable from a crash", label)
		}
	}
}

// An app that answers with something that is not the document it should be
// NARROWS its own rows and nothing else: its apps row states that it could not
// be read, the collections it would have contributed to serve the instances
// that answered, and the batch exits zero. A dark or broken app must not cost
// the fleet its other rows — and it must not be silent either, which is what
// the apps row is for.
func TestAnAppAnsweringNonsenseNarrowsItsOwnRowsAndNotTheBatch(t *testing.T) {
	for label, broken := range map[string]map[string]string{
		"the health answer is an object":   {"radarr-api-v3-health": `{"source": "x"}`},
		"a health item is not an object":   {"radarr-api-v3-health": `["IndexerCheck"]`},
		"the queue records are not a list": {"radarr-api-v3-queue": `{"records": 7}`},
	} {
		staged := stagedFleet()
		for stem, body := range broken {
			staged[stem] = body
		}
		code, stdout, stderr := runWith(t, wholeRequest,
			map[string]string{"SE_REPLAY_DIR": stageReplayDir(t, staged)})
		if code != exitOK {
			t.Fatalf("%s: exit %d, stderr %s", label, code, stderr)
		}
		records := parseRecords(t, stdout)
		// prowlarr answered and its rows are all there.
		if _, present := factsOf(t, records, "apps", "prowlarr")["HealthErrors"]; !present {
			t.Errorf("%s: one app's failure must not cost the other its facts", label)
		}
		if len(ofKind(records, "decline")) != 0 {
			t.Errorf("%s: an app that answered badly is not a fleet that is absent", label)
		}
	}
	// And the narrowing is STATED: the apps row carries the reason, so a dark
	// app is a statement rather than a gap.
	staged := stagedFleet()
	staged["radarr-api-v3-health"] = `{"source": "x"}`
	_, stdout, _ := runWith(t, wholeRequest,
		map[string]string{"SE_REPLAY_DIR": stageReplayDir(t, staged)})
	records := parseRecords(t, stdout)
	facts := factsOf(t, records, "apps", "radarr")
	if facts["StatusUnobservable"] == nil {
		t.Errorf("a narrowed reading is stated on the row: %v", facts)
	}
	// The two facts the app DID state before it stopped stay beside the reason:
	// a partial reading is published rather than discarded.
	if facts["Version"] != "6.3.0.10514" || facts["AppName"] != "Radarr" {
		t.Errorf("the status document was read and its facts stand: %v", facts)
	}
	// The queue was not asked at all, because an app that could not say what is
	// wrong with it cannot be asked what it is downloading.
	if _, present := facts["QueueTotal"]; present {
		t.Errorf("a narrowed app is not asked for its queue depth: %v", facts)
	}
	if got := namesOf(records, "health"); !equal(got, []string{"prowlarr/IndexerCheck"}) {
		t.Errorf("the collection serves the instances that answered; got %v", got)
	}
}

func TestACollectionThisCollectorNeverDeclaredIsDeclinedUnsupported(t *testing.T) {
	code, stdout, _ := runWith(t, "collect indexers:11 apps:12\n", stagedAll(t))
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	records := parseRecords(t, stdout)
	var refused map[string]any
	for _, record := range ofKind(records, "decline") {
		if record["collection"] == "indexers" {
			refused = record
		}
	}
	if refused == nil || refused["reason"] != "unsupported" {
		t.Fatalf("a name this collector did not publish is declined, not sanitised; got %v", refused)
	}
	for _, commit := range ofKind(records, "commit") {
		if commit["collection"] == "indexers" {
			t.Fatal("an unsupported decline established nothing and must not commit")
		}
	}
	if len(ofKind(records, "object")) != 2 {
		t.Error("apps must still be served alongside the declined collection")
	}
}

// The same rule when there is nothing to serve at all: a fleet-less host still
// refuses a collection it never published, rather than declining it absent and
// committing zero over a name it does not own.
func TestAnUnsupportedCollectionStaysUnsupportedOnAFleetLessHost(t *testing.T) {
	code, stdout, _ := runWith(t, "collect indexers:11 apps:12\n",
		map[string]string{"SE_REPLAY_DIR": t.TempDir()})
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	for _, decline := range ofKind(parseRecords(t, stdout), "decline") {
		if decline["collection"] == "indexers" && decline["reason"] != "unsupported" {
			t.Fatalf("an unserved collection is unsupported even here; got %v", decline)
		}
	}
	for _, commit := range ofKind(parseRecords(t, stdout), "commit") {
		if commit["collection"] == "indexers" {
			t.Fatal("an unsupported decline must not commit, absent fleet or not")
		}
	}
}

func TestProbeAnswersWithAVerdictNotAnExitCode(t *testing.T) {
	code, stdout, _ := runWith(t, "probe\n", stagedAll(t))
	if code != exitOK || !strings.Contains(stdout, `"verdict":"yes"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	// A no is still exit zero: the verdict is the answer, and a non-zero exit
	// would read as a crash (DESIGN 18).
	code, stdout, _ = runWith(t, "probe\n", map[string]string{"SE_REPLAY_DIR": t.TempDir()})
	if code != exitOK || !strings.Contains(stdout, `"verdict":"no"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	var verdict probeVerdict
	if err := json.Unmarshal([]byte(stdout), &verdict); err != nil || verdict.Reason == "" {
		t.Fatalf("a verdict without its why is not actionable: %q", stdout)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
