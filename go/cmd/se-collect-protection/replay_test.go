package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A small invented estate in the shape the real documents have. Every member
// below appears in corpus/protection/healthy, which was itself read off a real
// capture; only the content is written. Four targets and five jobs is the
// smallest set that stages all three distinctions this collector exists to
// keep, and each is asserted by its own test rather than by this fixture.
const (
	stagedManifest = `{
  "schema": 1,
  "destinations": {
    "nearline-zfs": {
      "kind": "zfs-recv",
      "independent": false,
      "immutability": "Received snapshots are read-only and the sending host still holds send rights.",
      "pruneAuthority": "the receiving host's own retention policy"
    },
    "offsite-object": {
      "kind": "restic-s3",
      "independent": true,
      "immutability": "Versioning with Object Lock in governance mode.",
      "pruneAuthority": "a maintenance identity that exists only in the recovery kit"
    }
  },
  "targets": {
    "photo-library": {
      "class": "backup", "kind": "zfs-dataset", "ownerHost": "vault",
      "cadence": "daily", "retention": "irreplaceable-zfs",
      "source": "dataset:tank/photos",
      "destinations": ["nearline-zfs", "offsite-object"],
      "implementedBy": {
        "nearline-zfs": "vault:photo-library",
        "offsite-object": "annex:photo-library-offsite"
      },
      "lastProvenAt": {"offsite-object": "2026-07-30"},
      "proofs": [{
        "rung": "offsite-object", "at": "2026-07-30", "result": "pass",
        "scope": "4 files sampled from the 2019 subtree",
        "comparedAgainst": "the LIVE dataset on vault",
        "record": "docs/recovery-proofs.md"
      }]
    },
    "document-archive": {
      "class": "backup", "kind": "container", "ownerHost": "vault",
      "cadence": "daily", "retention": "irreplaceable-app",
      "source": "container:document-archive",
      "destinations": ["nearline-zfs", "offsite-object"],
      "implementedBy": {
        "nearline-zfs": "vault:document-archive",
        "offsite-object": "annex:document-archive-offsite"
      },
      "lastProvenAt": {},
      "proofs": [{
        "rung": "offsite-object", "at": "2026-06-11", "result": "fail",
        "record": "docs/recovery-proofs.md"
      }]
    },
    "music-library": {
      "class": "backup", "kind": "zfs-dataset", "ownerHost": "annex",
      "cadence": "daily", "retention": "irreplaceable-zfs",
      "source": "dataset:tank/music",
      "destinations": ["nearline-zfs"],
      "implementedBy": {"nearline-zfs": "annex:music-library"},
      "lastProvenAt": {}, "proofs": []
    },
    "runtime-state": {
      "class": "replicate", "kind": "container", "ownerHost": "vault",
      "cadence": "hourly", "retention": "derived",
      "source": "container:runtime-state",
      "destinations": ["nearline-zfs"],
      "implementedBy": {"nearline-zfs": "vault:runtime-state"},
      "lastProvenAt": {}, "proofs": []
    }
  }
}`

	// checkedAt is 2026-08-19T13:30:00Z. The maxAgeSeconds two below 2^63 is
	// not decoration: decoded through a float64 it comes back as 2^63 exactly,
	// and the judge's typed equality sees it.
	stagedStatus = `{
  "schema": 1, "host": "vault", "checkedAt": 1787146200,
  "unimplemented": ["definitions-repo"],
  "unimplementedHops": [{"target": "appliance-config", "destination": "offsite-object"}],
  "jobs": [
    {"job": "config-sweep", "state": "ok", "basis": "last-success",
     "ageSeconds": 900, "maxAgeSeconds": 9223372036854775806,
     "lastResult": "success", "target": null},
    {"job": "document-archive", "state": "ok", "basis": "last-success",
     "ageSeconds": 5400, "maxAgeSeconds": 129600,
     "lastResult": "success", "target": null},
    {"job": "photo-library", "state": "ok", "basis": "last-success",
     "ageSeconds": 3600, "maxAgeSeconds": 129600,
     "lastResult": "success", "target": null},
    {"job": "photo-library-capture", "state": "ok", "basis": "last-success",
     "ageSeconds": 4100, "maxAgeSeconds": 129600,
     "lastResult": "success", "target": "photo-library"},
    {"job": "runtime-state", "state": "stale", "basis": "registered-never-succeeded",
     "ageSeconds": 604800, "maxAgeSeconds": 86400,
     "lastResult": "none", "target": null}
  ]
}`

	// The unreadable receipt's reason, spelled as the reference's own parser
	// spelled it in the committed variant. Under replay it is served from the
	// payload verbatim, which is what makes the two implementations agree on a
	// text neither could reproduce from the other's library.
	stagedDecodeError = "JSONDecodeError: Expecting ',' delimiter: line 1 column 78 (char 77)"
)

// pair wraps a document as the (document, why-not) PAIR `_load` returns, which
// is what every payload of this collector is. Capturing the document alone
// would erase the only member that separates a file which is not there from
// one that exists and will not parse.
func pair(document string) string { return "[" + document + ",null]" }

// unreadable is the other half of that pair: no document, and a reason.
func unreadable(why string) string {
	encoded, _ := json.Marshal(why)
	return "[null," + string(encoded) + "]"
}

// absentFile is the third shape, and the one a port most easily collapses into
// the second: no document and NO reason. The file was never written, which is
// not a fault to report.
const absentFile = "[null,null]"

// stage writes one replay directory. Each document is keyed by the PATH it
// answers, run through the port's own slug — bound to the seam rather than to
// a retyped file name, so a change to the addressing fails here rather than
// drifting silently out of agreement with the corpus.
func stage(t *testing.T, hostname string, documents map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	if hostname != "" {
		write(t, dir, payloadHostname, hostname+"\n")
	}
	for path, text := range documents {
		write(t, dir, slug(path)+".json", text)
	}
	return dir
}

func write(t *testing.T, dir, name, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func receipt(job, unit, finished, result, exit string) string {
	return pair(`{"schema":1,"job":"` + job + `","host":"vault","unit":"` + unit +
		`","finishedAt":"` + finished + `","result":"` + result + `","exitStatus":"` + exit + `"}`)
}

func healthyDocuments() map[string]string {
	return map[string]string{
		manifestPath: pair(stagedManifest),
		statusPath:   pair(stagedStatus),

		// document-archive is the one-row-one-vintage pair: the verdict says
		// success, the receipt says the run since then failed.
		receiptPath("document-archive", "last"):         receipt("document-archive", "protect-document-archive.service", "2026-08-19T13:25:00Z", "exit-code", "1"),
		receiptPath("document-archive", "last-success"): receipt("document-archive", "protect-document-archive.service", "2026-08-19T12:30:00Z", "success", "0"),

		// runtime-state has never succeeded: its last-success receipt is not
		// there at all, which is an absence and not a fault.
		receiptPath("runtime-state", "last"):         receipt("runtime-state", "replicate-runtime-state.service", "2026-08-19T13:20:00Z", "exit-code", "2"),
		receiptPath("runtime-state", "last-success"): absentFile,

		// config-sweep is the mirror: its last receipt EXISTS and will not
		// parse, which is a fault to state.
		receiptPath("config-sweep", "last"):         unreadable(stagedDecodeError),
		receiptPath("config-sweep", "last-success"): receipt("config-sweep", "config-sweep.service", "2026-08-19T13:15:00Z", "success", "0"),

		receiptPath("photo-library", "last"):         receipt("photo-library", "protect-photo-library.service", "2026-08-19T13:00:00Z", "success", "0"),
		receiptPath("photo-library", "last-success"): receipt("photo-library", "protect-photo-library.service", "2026-08-19T13:00:00Z", "success", "0"),

		receiptPath("photo-library-capture", "last"):         receipt("photo-library-capture", "capture-photo-library.service", "2026-08-19T12:51:40Z", "success", "0"),
		receiptPath("photo-library-capture", "last-success"): receipt("photo-library-capture", "capture-photo-library.service", "2026-08-19T12:51:40Z", "success", "0"),
	}
}

func stageHealthy(t *testing.T) string {
	t.Helper()
	return stage(t, "vault", healthyDocuments())
}

// The variant's captured stamp: 2026-08-19T14:00:00Z, thirty minutes after the
// verdict was computed.
const stagedNow = "2026-08-19T14:00:00Z"

const wholeBatch = "collect destinations:809 jobs:826 targets:843\n"

func replayEnv(dir string) map[string]string {
	return map[string]string{"SE_REPLAY_DIR": dir, "SE_REPLAY_NOW": stagedNow}
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

// objectIn finds one row's facts, failing rather than returning an empty map:
// a test that silently asserted over a row that is not there proves nothing.
func objectIn(t *testing.T, records []map[string]any, collection, name string) map[string]any {
	t.Helper()
	for _, record := range ofKind(records, "object") {
		if record["collection"] == collection && record["name"] == name {
			return record["facts"].(map[string]any)
		}
	}
	t.Fatalf("no object named %q in %q", name, collection)
	return nil
}

func replayHealthy(t *testing.T) []map[string]any {
	t.Helper()
	code, stdout, stderr := runWith(t, wholeBatch, replayEnv(stageHealthy(t)))
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	return parseRecords(t, stdout)
}

func TestReplayIsByteDeterministicAcrossTwoRuns(t *testing.T) {
	env := replayEnv(stageHealthy(t))
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
	records := replayHealthy(t)

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
	if len(objects) != 2+5+4 {
		t.Fatalf("two destinations, five jobs, four targets; got %d objects", len(objects))
	}
	// 1.0 + 0.001*i in emission order, ONE counter across the whole batch —
	// which is what makes `at` advancing rather than a hardcoded zero.
	for i := range objects {
		want := float64(int64((1.0+0.001*float64(i))*1000+0.5)) / 1000
		if objects[i]["at"] != want {
			t.Errorf("object %d carries at %v, and the reference constant is %v", i, objects[i]["at"], want)
		}
	}
	end := ofKind(records, "end")[0]
	if end["cpu_ms"] != 0.5 || end["wall_ms"] != 1.0 {
		t.Errorf("replay pins cpu_ms=0.5 wall_ms=1.0; got %v/%v", end["cpu_ms"], end["wall_ms"])
	}
}

// ONE ROW, ONE VINTAGE. The verdict is recomputed hourly and the receipt is
// written by the run, so a run that failed since the last check must not read
// as success. The receipt is the authority; a port that preferred the status
// row publishes LastResult "success" beside a failure's exit status.
func TestTheReceiptOutranksTheStatusRowForTheLastResult(t *testing.T) {
	facts := objectIn(t, replayHealthy(t), "jobs", "document-archive")
	if facts["LastResult"] != "exit-code" {
		t.Errorf("LastResult is %v; the verdict's copy says \"success\" and the RECEIPT says exit-code", facts["LastResult"])
	}
	if facts["ExitStatus"] != "1" {
		t.Errorf("ExitStatus is %v, want the receipt's \"1\"", facts["ExitStatus"])
	}
	// Green AND failed at once is a real row, and a port that inferred one
	// from the other cannot produce it: the job ran inside its window, and it
	// failed.
	if facts["State"] != "ok" {
		t.Errorf("State is %v; the job is not stale, it ran inside its window and failed", facts["State"])
	}
	// Two receipts read as two files: the last run and the last SUCCESS carry
	// different times, which is what proves the pair was not read as one.
	if facts["LastFinishedAt"] != "2026-08-19T13:25:00Z" || facts["LastSuccessAt"] != "2026-08-19T12:30:00Z" {
		t.Errorf("the two receipts collapsed into one: finished %v, succeeded %v",
			facts["LastFinishedAt"], facts["LastSuccessAt"])
	}
}

// ABSENT IS NOT UNREADABLE, and each side carries the other's absence to make
// the pair discriminating. A port that collapsed the two payload shapes into
// "no document" satisfies neither.
func TestAMissingReceiptIsNotAnUnreadableOne(t *testing.T) {
	records := replayHealthy(t)

	// runtime-state has never succeeded, so its last-success receipt is not
	// there at all. A missing file is not a fault, and a port that reported
	// one would alarm on every job that has never succeeded.
	never := objectIn(t, records, "jobs", "runtime-state")
	if _, present := never["ReceiptsUnobservable"]; present {
		t.Errorf("a receipt that was never written is not a receipt nobody can read: %v", never["ReceiptsUnobservable"])
	}
	if _, present := never["LastSuccessAt"]; present {
		t.Errorf("a job that has never succeeded carries no LastSuccessAt: %v", never["LastSuccessAt"])
	}
	if never["Basis"] != "registered-never-succeeded" || never["ExitStatus"] != "2" {
		t.Errorf("the last run still spoke for itself: basis %v, exit %v", never["Basis"], never["ExitStatus"])
	}

	// config-sweep is the mirror: its last receipt exists and will not parse.
	// The reason is carried verbatim, and the facts that receipt would have
	// held are absent — because the receipt that would have carried them is
	// the unreadable one.
	unreadable := objectIn(t, records, "jobs", "config-sweep")
	want := "config-sweep.last.json: " + stagedDecodeError
	if unreadable["ReceiptsUnobservable"] != want {
		t.Errorf("ReceiptsUnobservable is %v, want %q", unreadable["ReceiptsUnobservable"], want)
	}
	for _, fact := range []string{"ExitStatus", "LastFinishedAt"} {
		if _, present := unreadable[fact]; present {
			t.Errorf("%s came from somewhere, and the only receipt that could hold it would not open", fact)
		}
	}
	// The verdict still stands and the last-success receipt still opened, so
	// silence about the run is not silence about the job.
	if unreadable["State"] != "ok" || unreadable["LastSuccessAt"] != "2026-08-19T13:15:00Z" {
		t.Errorf("an unreadable receipt cost the row facts it could still read: %v", unreadable)
	}
	// The status row's own lastResult is the fallback for exactly this case —
	// a receipt this host cannot open — and it is the only case it serves.
	if unreadable["LastResult"] != "success" {
		t.Errorf("LastResult is %v; with no readable receipt the verdict's copy is the fallback", unreadable["LastResult"])
	}
}

// OWNED IS NOT JUDGED, and the FACTS move with the owner too: which
// implementedBy hops count as local decides a job's class and its
// ImplementsHops. The host comes from the captured hostname payload and never
// from the machine running this, so one capture produces one answer everywhere.
func TestOwnershipComesFromTheCapturedHostnameAndNotTheReplayingMachine(t *testing.T) {
	asVault := replayHealthy(t)
	if got := objectIn(t, asVault, "targets", "music-library")["OwnerHost"]; got != "annex" {
		t.Fatalf("music-library is owned by annex; got %v", got)
	}
	if got := objectIn(t, asVault, "targets", "photo-library")["OwnerHost"]; got != "vault" {
		t.Fatalf("photo-library is owned by vault; got %v", got)
	}
	// vault runs the nearline hop for photo-library, so the job joins the
	// target's class and states the hop it carries.
	vaultJob := objectIn(t, asVault, "jobs", "photo-library")
	if vaultJob["TargetClass"] != "backup" {
		t.Errorf("TargetClass is %v; vault implements photo-library's nearline hop", vaultJob["TargetClass"])
	}
	hops, _ := vaultJob["ImplementsHops"].([]any)
	if len(hops) != 1 {
		t.Fatalf("ImplementsHops is %v, want the one hop this host implements", vaultJob["ImplementsHops"])
	}
	hop, _ := hops[0].(map[string]any)
	if hop["Target"] != "photo-library" || hop["Destination"] != "nearline-zfs" {
		t.Errorf("the hop names %v", hop)
	}

	// The SAME payloads read as annex: the implementedBy references that
	// qualified vault no longer name this host, so neither the class nor the
	// hop joins. Nothing about the documents changed.
	documents := healthyDocuments()
	code, stdout, stderr := runWith(t, wholeBatch, replayEnv(stage(t, "annex", documents)))
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	asAnnex := parseRecords(t, stdout)
	annexJob := objectIn(t, asAnnex, "jobs", "photo-library")
	if _, present := annexJob["ImplementsHops"]; present {
		t.Errorf("annex claimed a hop the declaration qualifies to vault: %v", annexJob["ImplementsHops"])
	}
	// The class still joins, because the JOB's name equals the target's — the
	// name route and the hop route are a union, and only the hop route is
	// host-filtered.
	if annexJob["TargetClass"] != "backup" {
		t.Errorf("TargetClass is %v; the name route still joins on either host", annexJob["TargetClass"])
	}
	// And the hop route alone: photo-library-capture names its own target and
	// implements no hop, so it is unaffected — which is what shows the two
	// routes apart.
	if got := objectIn(t, asAnnex, "jobs", "photo-library-capture")["Target"]; got != "photo-library" {
		t.Errorf("a job's own declared target is not host-scoped; got %v", got)
	}
}

// A job named for the HOP it carries rather than the data it moves still
// grades by the worst consequence it is responsible for, and a hop reference
// this host does not own is left unattributed rather than claimed.
func TestAHopIsAttributedToTheHostTheDeclarationNames(t *testing.T) {
	facts := objectIn(t, replayHealthy(t), "targets", "photo-library")
	hops, _ := facts["HopImplementedBy"].([]any)
	if len(hops) != 2 {
		t.Fatalf("HopImplementedBy is %v, want both implemented hops", facts["HopImplementedBy"])
	}
	first, _ := hops[0].(map[string]any)
	second, _ := hops[1].(map[string]any)
	if first["Host"] != "vault" || first["Job"] != "photo-library" {
		t.Errorf("the nearline hop is %v", first)
	}
	if second["Host"] != "annex" || second["Job"] != "photo-library-offsite" {
		t.Errorf("the offsite hop belongs to another host and must say so: %v", second)
	}
}

// A restore ATTEMPTED and not matched is a third answer, never a silence — and
// its absence on the target whose proof PASSED is what makes the pair
// discriminating. A port that published the rung list without reading `result`
// marks both failed; one that ignored failures marks neither.
func TestATriedAndFailedRestoreIsStatedAndAPassingOneIsNot(t *testing.T) {
	records := replayHealthy(t)

	failed := objectIn(t, records, "targets", "document-archive")
	rungs, _ := failed["FailedProofRungs"].([]any)
	if len(rungs) != 1 || rungs[0] != "offsite-object" {
		t.Errorf("FailedProofRungs is %v, want the one rung a restore was tried from", failed["FailedProofRungs"])
	}
	if failed["LastFailedProofAt"] != "2026-06-11" {
		t.Errorf("LastFailedProofAt is %v", failed["LastFailedProofAt"])
	}

	passed := objectIn(t, records, "targets", "photo-library")
	if _, present := passed["FailedProofRungs"]; present {
		t.Errorf("a passing proof was published as a failure: %v", passed["FailedProofRungs"])
	}
	proven, _ := passed["ProvenRungs"].([]any)
	if len(proven) != 1 || proven[0] != "offsite-object" {
		t.Errorf("ProvenRungs is %v", passed["ProvenRungs"])
	}
	// Per RUNG, never collapsed: proving the off-site copy says nothing about
	// the nearline one, and the row must keep saying so.
	unproven, _ := passed["UnprovenRungs"].([]any)
	if len(unproven) != 1 || unproven[0] != "nearline-zfs" {
		t.Errorf("UnprovenRungs is %v; a proof at one rung certifies that rung and no other", passed["UnprovenRungs"])
	}
}

// `independent: false` is the reading a falsy test drops, and it is the
// destination that looks like a second copy and is not one.
func TestIndependentFalseIsAReadingAndNotAnAbsence(t *testing.T) {
	records := replayHealthy(t)
	if got := objectIn(t, records, "destinations", "nearline-zfs")["Independent"]; got != false {
		t.Errorf("nearline-zfs Independent is %v, want the boolean false", got)
	}
	if got := objectIn(t, records, "destinations", "offsite-object")["Independent"]; got != true {
		t.Errorf("offsite-object Independent is %v, want the boolean true", got)
	}
	// Booleans, not the strings or the integers a re-render would leave.
	_, stdout, _ := runWith(t, wholeBatch, replayEnv(stageHealthy(t)))
	if !strings.Contains(stdout, `"Independent":false`) || !strings.Contains(stdout, `"Independent":true`) {
		t.Fatalf("Independent did not travel as a JSON boolean:\n%s", stdout)
	}
}

// CheckedAgeSeconds is the one number here derived against a clock, and the
// one a port can get wrong without touching a payload. The verdict was
// computed at 13:30:00Z and the stamp is 14:00:00Z, so the answer is exactly
// 1800 — on every machine and on every day the corpus sits on the shelf.
func TestTheVerdictsAgeIsPinnedByTheReplayClock(t *testing.T) {
	facts := objectIn(t, replayHealthy(t), "jobs", "photo-library")
	if facts["CheckedAt"] != "2026-08-19T13:30:00Z" {
		t.Errorf("CheckedAt is %v", facts["CheckedAt"])
	}
	if facts["CheckedAgeSeconds"] != 1800.0 {
		t.Errorf("CheckedAgeSeconds is %v, want 1800", facts["CheckedAgeSeconds"])
	}

	// A later pin moves it, which is what proves the pin is read rather than
	// the answer baked in.
	dir := stageHealthy(t)
	later := map[string]string{"SE_REPLAY_DIR": dir, "SE_REPLAY_NOW": "2026-08-19T18:00:00Z"}
	code, stdout, stderr := runWith(t, wholeBatch, later)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if got := objectIn(t, parseRecords(t, stdout), "jobs", "photo-library")["CheckedAgeSeconds"]; got != 16200.0 {
		t.Errorf("CheckedAgeSeconds is %v under a pin four and a half hours later, want 16200", got)
	}

	// A verdict nobody has recomputed is stated as old rather than repeated as
	// current — the fact exists so a dead checker cannot render as a green
	// board, so its absence would be the defect.
	if _, present := objectIn(t, parseRecords(t, stdout), "jobs", "config-sweep")["CheckedAgeSeconds"]; !present {
		t.Error("a row published its verdict with no vintage")
	}
}

// Pass-through numbers keep the wire's type, not the language's. Asserted on
// the BYTES, because a Go test that unmarshalled the stream into a map would
// take the same round trip it is testing for.
func TestANumberSurvivesAsTheTokenTheDocumentSpelled(t *testing.T) {
	_, stdout, _ := runWith(t, wholeBatch, replayEnv(stageHealthy(t)))
	if !strings.Contains(stdout, `"MaxAgeSeconds":9223372036854775806`) {
		t.Fatalf("the threshold did not survive as its own token:\n%s", stdout)
	}
	for _, wrong := range []string{"9223372036854775808", "9.223372036854776e+18", "129600.0", "604800.0"} {
		if strings.Contains(stdout, wrong) {
			t.Fatalf("a number was re-rendered as %q — pass-through numbers keep the wire's type, not the language's", wrong)
		}
	}
}

// The rows come from the verdict's own job list. A receipt left behind by a job
// the declaration has dropped is on the evidence path alone, so no collection
// depends on a directory walk — which is also why a replaying machine's
// /var/lib is never enumerated.
func TestJobsAreEnumeratedFromTheVerdictAndNotFromTheReceiptDirectory(t *testing.T) {
	documents := healthyDocuments()
	documents[receiptPath("retired-job", "last")] = receipt("retired-job", "retired.service", "2026-01-01T00:00:00Z", "success", "0")
	code, stdout, stderr := runWith(t, wholeBatch, replayEnv(stage(t, "vault", documents)))
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	for _, record := range ofKind(parseRecords(t, stdout), "object") {
		if record["collection"] == "jobs" && record["name"] == "retired-job" {
			t.Fatal("a receipt with no registration minted a row")
		}
	}
}

// A variant that staged nothing is a capture of a host with no protection
// surfaces. absent is authoritative-empty: it declines AND commits zero, so it
// can retire the rows a previous batch published.
func TestAnEmptyReplayDirectoryDeclinesAbsentAndCommitsZero(t *testing.T) {
	code, stdout, stderr := runWith(t, wholeBatch, replayEnv(t.TempDir()))
	if code != exitOK {
		t.Fatalf("an absent interface is a reading, not an inability: exit %d, stderr %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	if got := len(ofKind(records, "object")); got != 0 {
		t.Fatalf("%d objects from a host with no manifest", got)
	}
	declines := ofKind(records, "decline")
	commits := ofKind(records, "commit")
	if len(declines) != 3 || len(commits) != 3 {
		t.Fatalf("every requested collection declines and commits zero: %d declines, %d commits", len(declines), len(commits))
	}
	for _, decline := range declines {
		if decline["reason"] != "absent" || decline["detail"] != declineNoManifest.detail {
			t.Errorf("decline is %v", decline)
		}
	}
	for _, commit := range commits {
		if commit["objects"] != 0.0 || commit["assertions"] != 0.0 || commit["unobservable"] != 0.0 {
			t.Errorf("commit is %v", commit)
		}
	}
}

// A manifest the capture recorded as unreadable is NOT an absence: unavailable
// commits nothing, so a half-written render leaves the declared targets
// standing instead of retiring an estate that is protecting itself perfectly
// well. The parser's own words stay on stderr; the record carries the constant.
func TestAnUnreadableManifestDeclinesUnavailableAndCommitsNothing(t *testing.T) {
	documents := healthyDocuments()
	documents[manifestPath] = unreadable(stagedDecodeError)
	code, stdout, stderr := runWith(t, wholeBatch, replayEnv(stage(t, "vault", documents)))
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	if got := len(ofKind(records, "commit")); got != 0 {
		t.Fatalf("%d commits over a manifest nobody could read", got)
	}
	for _, decline := range ofKind(records, "decline") {
		if decline["reason"] != "unavailable" || decline["detail"] != declineManifestUnreadable.detail {
			t.Errorf("decline is %v", decline)
		}
	}
	if !strings.Contains(stderr, stagedDecodeError) {
		t.Errorf("the parser's own words belong on stderr, where no redaction path has to be reviewed for them: %q", stderr)
	}
	if strings.Contains(stdout, stagedDecodeError) {
		t.Error("a decline detail carried a parser's words about an estate's own document to whoever reads the hub")
	}
}

// A missing staleness verdict costs the JOBS collection and nothing else, and
// it is unobservable rather than absent: the same declaration that renders the
// manifest installs the checker, so a missing verdict is one nobody has written
// yet or one that stopped. Committing here would retire every job on a host
// whose timer was masked.
func TestAMissingVerdictCostsOnlyTheJobsCollectionAndCommitsNothing(t *testing.T) {
	documents := healthyDocuments()
	documents[statusPath] = absentFile
	code, stdout, stderr := runWith(t, wholeBatch, replayEnv(stage(t, "vault", documents)))
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["collection"] != "jobs" ||
		declines[0]["reason"] != "unavailable" || declines[0]["detail"] != declineNoVerdict.detail {
		t.Fatalf("declines are %v", declines)
	}
	for _, commit := range ofKind(records, "commit") {
		if commit["collection"] == "jobs" {
			t.Fatal("a host whose checker stopped had every job retired")
		}
	}
	if len(ofKind(records, "commit")) != 2 {
		t.Fatal("the declaration is still readable, so targets and destinations still commit")
	}
	// The discriminators that tell a fresh deploy from a dead timer are stated
	// on stderr, where a person debugging reads them — never in a decline
	// detail, which travels to a hub and out over MCP.
	if !strings.Contains(stderr, "photo-library") || !strings.Contains(stderr, "homelab-protection-staleness.service") {
		t.Errorf("stderr says nothing a person could act on: %q", stderr)
	}
	if strings.Contains(stdout, "photo-library-capture") {
		t.Error("a decline detail carried the estate's target names")
	}
}

// A path the capture did not record is a broken transcription, not a statement
// about any machine — so it fails the batch rather than declining, and it
// never falls back to the filesystem of whichever host is replaying.
func TestAnUncapturedPayloadFailsRatherThanReadingTheReplayingHost(t *testing.T) {
	documents := healthyDocuments()
	delete(documents, receiptPath("photo-library", "last"))
	code, stdout, stderr := runWith(t, "collect jobs:826\n", replayEnv(stage(t, "vault", documents)))
	if code != exitRuntime {
		t.Fatalf("exit %d, want %d: an uncaptured document is an inability to run", code, exitRuntime)
	}
	if !strings.Contains(stderr, "not captured") {
		t.Errorf("stderr must say the capture is broken: %q", stderr)
	}
	for _, record := range parseRecords(t, stdout) {
		if record["record"] == "commit" {
			t.Fatal("a batch that could not read its documents committed authority over a collection")
		}
	}
}

// The host identity is required rather than defaulted. Without it the facts
// would be derived against the machine REPLAYING — silently, because a
// hostname is a plausible value wherever it came from.
func TestAMissingHostnamePayloadRefusesRatherThanNamingTheReplayingMachine(t *testing.T) {
	code, _, stderr := runWith(t, "collect jobs:826\n", replayEnv(stage(t, "", healthyDocuments())))
	if code != exitRuntime {
		t.Fatalf("exit %d, want %d", code, exitRuntime)
	}
	if !strings.Contains(stderr, payloadHostname) {
		t.Errorf("stderr must name the payload that pins the host: %q", stderr)
	}
}

// The seam's whole point: a machine with no protection layer of its own
// replays this capture without opening a single file outside the payload
// directory. Asserted on the OUTPUT, because the development machine that runs
// this has no /etc/homelab at all — so a seam escape here would produce an
// absent decline, not an error.
func TestTheStagedDocumentsDecideRatherThanTheReplayingHost(t *testing.T) {
	records := replayHealthy(t)
	if got := len(ofKind(records, "decline")); got != 0 {
		t.Fatalf("%d declines from a staged capture on a host with no manifest", got)
	}
	if got := objectIn(t, records, "targets", "photo-library")["Source"]; got != "dataset:tank/photos" {
		t.Fatalf("the row came from somewhere other than the payload: %v", got)
	}
}

// The two members the declaration carries and this collector reads by nothing.
// They are in every real status.json, and no fact anywhere derives from them —
// stated here so their presence is never read as a claim that the collector
// uses them.
func TestTheVerdictsUnimplementedMembersReachNoFact(t *testing.T) {
	_, stdout, _ := runWith(t, wholeBatch, replayEnv(stageHealthy(t)))
	for _, unread := range []string{"definitions-repo", "appliance-config"} {
		if strings.Contains(stdout, unread) {
			t.Fatalf("%q is only in status.json's unimplemented members, which this collector does not read", unread)
		}
	}
}
