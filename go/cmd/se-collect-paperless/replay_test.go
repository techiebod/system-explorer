package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The two documents as paperless answers them, carried whole rather than
// trimmed: the members this collection ignores are the point of several tests
// below — `sanity_check_status` and `llmindex_status` are status words the
// reference does not publish, and the four `*_error` members are spelled and
// hold null on a healthy instance.
const healthyStatistics = `{
  "documents_total": 3,
  "documents_inbox": 1,
  "inbox_tag": 1,
  "inbox_tags": [1],
  "document_file_type_counts": [{"mime_type": "text/plain", "mime_type_count": 3}],
  "character_count": 223,
  "tag_count": 2,
  "correspondent_count": 1,
  "document_type_count": 1,
  "storage_path_count": 0,
  "current_asn": 0
}`

const healthyStatus = `{
  "pngx_version": "3.0.5",
  "server_os": "Linux-6.12.101+deb13-amd64-x86_64-with-glibc2.41",
  "install_type": "docker",
  "storage": {"total": 63195054080, "available": 54911987712},
  "database": {
    "type": "sqlite",
    "url": "/usr/src/paperless/data/db.sqlite3",
    "status": "OK",
    "error": null,
    "migration_status": {"latest_migration": "paperless_mail.0001_squashed", "unapplied_migrations": []}
  },
  "tasks": {
    "redis_url": "redis://paperless-redis:6379",
    "redis_status": "OK",
    "redis_error": null,
    "celery_status": "OK",
    "celery_url": "celery@689c8a4c0b8c",
    "celery_error": null,
    "index_status": "OK",
    "index_last_modified": "2026-08-19T13:27:40.535034+01:00",
    "index_error": null,
    "classifier_status": "WARNING",
    "classifier_last_trained": null,
    "classifier_error": "No classifier training tasks found",
    "sanity_check_status": "WARNING",
    "sanity_check_last_run": null,
    "sanity_check_error": "No sanity check tasks found",
    "llmindex_status": "DISABLED",
    "llmindex_last_modified": null,
    "llmindex_error": null,
    "summary": {"days": 30, "total_count": 4, "pending_count": 0, "success_count": 4, "failure_count": 0}
  }
}`

// stage writes one replay directory. Each document is named by the PATH it
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

func stageInstance(t *testing.T, statistics, status string) string {
	t.Helper()
	return stage(t, map[string]string{
		payloadStem(statisticsPath) + ".json": statistics,
		payloadStem(statusPath) + ".json":     status,
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

// rowFacts drives one whole batch over a staged pair and hands back the single
// row's facts, so a derivation test reads as a document in and a row out.
func rowFacts(t *testing.T, statistics, status string) map[string]any {
	t.Helper()
	code, stdout, stderr := runWith(t, "collect instance:41\n",
		map[string]string{"SE_REPLAY_DIR": stageInstance(t, statistics, status)})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	objects := ofKind(parseRecords(t, stdout), "object")
	if len(objects) != 1 {
		t.Fatalf("two documents describe ONE instance; got %d objects", len(objects))
	}
	facts, ok := objects[0]["facts"].(map[string]any)
	if !ok {
		t.Fatalf("the row carries no facts object: %v", objects[0])
	}
	return facts
}

// The stems the corpus commits, pinned. slug() is the reference's and this is
// its port: a stem that drifted would make the seam raise "not captured in this
// variant" against a file sitting right beside it.
func TestThePayloadStemsAreTheOnesTheCorpusCommits(t *testing.T) {
	for path, want := range map[string]string{
		statisticsPath: "api-statistics",
		statusPath:     "api-status",
	} {
		if got := payloadStem(path); got != want {
			t.Errorf("payloadStem(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestReplayIsByteDeterministicAcrossTwoRuns(t *testing.T) {
	env := map[string]string{"SE_REPLAY_DIR": stageInstance(t, healthyStatistics, healthyStatus)}
	code1, first, stderr := runWith(t, "collect instance:820\n", env)
	code2, second, _ := runWith(t, "collect instance:820\n", env)
	if code1 != exitOK || code2 != exitOK {
		t.Fatalf("exits %d/%d, stderr: %s", code1, code2, stderr)
	}
	if first != second {
		t.Fatalf("replay is not byte-deterministic:\n%s\nvs\n%s", first, second)
	}
}

func TestReplayPinsEveryRunVaryingMember(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect instance:820\n",
		map[string]string{"SE_REPLAY_DIR": stageInstance(t, healthyStatistics, healthyStatus)})
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
		t.Fatalf("two documents describe ONE instance; got %d objects", len(objects))
	}
	if objects[0]["at"] != 1.0 {
		t.Errorf("the first object carries the reference constant 1.0; got %v", objects[0]["at"])
	}
	if objects[0]["name"] != instanceName {
		t.Errorf("the row's native name is %q; got %v", instanceName, objects[0]["name"])
	}
	// One row, and the commit says so. A port that published a row per DOCUMENT
	// satisfies every fact anchor the corpus plants and reports 2 here.
	commits := ofKind(records, "commit")
	if len(commits) != 1 || commits[0]["objects"] != 1.0 || commits[0]["generation"] != 820.0 {
		t.Fatalf("one object committed under the issued generation; got %v", commits)
	}
	if commits[0]["assertions"] != 0.0 || commits[0]["unobservable"] != 0.0 {
		t.Errorf("this collection asserts no relations and files no unobservable records; got %v", commits[0])
	}
	end := ofKind(records, "end")[0]
	if end["cpu_ms"] != 0.5 || end["wall_ms"] != 1.0 {
		t.Errorf("replay pins cpu_ms=0.5 wall_ms=1.0; got %v/%v", end["cpu_ms"], end["wall_ms"])
	}
}

func TestReplayBootIDIsTheStagedFileWhenAVariantHasOne(t *testing.T) {
	dir := stageInstance(t, healthyStatistics, healthyStatus)
	if err := os.WriteFile(filepath.Join(dir, "boot_id"), []byte("8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stdout, _ := runWith(t, "collect instance:1\n", map[string]string{"SE_REPLAY_DIR": dir})
	if got := ofKind(parseRecords(t, stdout), "begin")[0]["boot_id"]; got != "8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44" {
		t.Fatalf("boot_id must be the staged file, trimmed; got %v", got)
	}
}

func TestReplayNowIsIgnoredButNeverACrash(t *testing.T) {
	// Every fact here is a number or a word the instance stated; nothing is
	// derived against a clock, so the pin has nothing to freeze. The contract is
	// only that setting it changes nothing and breaks nothing.
	dir := stageInstance(t, healthyStatistics, healthyStatus)
	bare := map[string]string{"SE_REPLAY_DIR": dir}
	pinned := map[string]string{"SE_REPLAY_DIR": dir, "SE_REPLAY_NOW": "2026-08-19T13:40:00Z"}

	code1, first, _ := runWith(t, "collect instance:2\n", bare)
	code2, second, _ := runWith(t, "collect instance:2\n", pinned)
	if code1 != exitOK || code2 != exitOK || first != second {
		t.Fatalf("SE_REPLAY_NOW changed the outcome: exits %d/%d", code1, code2)
	}
}

// The seam's whole point: a machine fronting no paperless replays this capture
// without ever making a request. The receipts are the sharper half here — the
// live path declines the whole subsystem when SE_PAPERLESS_TOKEN is unset, so a
// port that consulted the environment under replay would decline a variant
// whose payloads are the API answering. The reference's seam pins the same four
// attributes for the same reason.
func TestTheStagedDocumentsDecideRatherThanTheReplayingHost(t *testing.T) {
	env := map[string]string{
		"SE_REPLAY_DIR": stageInstance(t, healthyStatistics, healthyStatus),
		// Deliberately pointing somewhere real-looking, and deliberately with
		// no token beside it: under replay neither must be consulted.
		urlVariable: "http://127.0.0.1:8000",
	}
	code, stdout, stderr := runWith(t, "collect instance:9\n", env)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	if len(ofKind(records, "decline")) != 0 {
		t.Fatalf("the replaying machine's environment declined a committed capture: %v", records)
	}
	facts, _ := ofKind(records, "object")[0]["facts"].(map[string]any)
	if facts[factDocumentCount] != 3.0 || facts[factPngxVersion] != "3.0.5" {
		t.Fatalf("the row must come from the staged documents: %v", facts)
	}
}

func TestAnEmptyReplayDirectoryDeclinesUnavailableAndCommitsNothing(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect instance:77\n",
		map[string]string{"SE_REPLAY_DIR": t.TempDir()})
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["reason"] != "unavailable" ||
		declines[0]["detail"] != declineNoInstance.detail {
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
func TestAnUnconfiguredURLIsTheSameAbsentReadingAsAnEmptyCapture(t *testing.T) {
	empty := t.TempDir()
	sources := map[string]source{
		"no URL configured": newSource(func(string) string { return "" }),
		"an empty capture": newSource(func(key string) string {
			if key == "SE_REPLAY_DIR" {
				return empty
			}
			return ""
		}),
	}
	for label, src := range sources {
		_, err := src.instance()
		var refused *declined
		if !errors.As(err, &refused) {
			t.Fatalf("%s: %v is not a decline at all", label, err)
		}
		if *refused != declineNoInstance {
			t.Fatalf("%s: reached %v, and the shared constant is %v", label, *refused, declineNoInstance)
		}
	}
}

// A configured archive this deployment cannot open is NOT an absence, and the
// difference is the whole of what the two reasons mean. `absent` commits zero
// and retires the row; a missing or unusable token must leave the last readable
// row standing, because an archive whose token was rotated has not lost its
// documents — and a row that vanished would read exactly like the emptied
// library this subsystem exists to catch.
func TestAWithheldTokenDeclinesUnavailableAndNeverAbsent(t *testing.T) {
	cases := map[string]struct {
		token string
		want  string
	}{
		"no token at all":               {"", tokenMissingDetail},
		"a token with a pasted newline": {"secret\ntoken", tokenProblemDetail},
		"a token with a control byte":   {"secret\x01token", tokenProblemDetail},
		"a non-ASCII token":             {"sécret-token", tokenProblemDetail},
	}
	for label, expected := range cases {
		src := newSource(func(key string) string {
			switch key {
			case urlVariable:
				return "http://paperless.invalid"
			case tokenVariable:
				return expected.token
			}
			return ""
		})
		_, err := src.instance()
		var refused *declined
		if !errors.As(err, &refused) {
			t.Errorf("%s: %v is not a decline at all", label, err)
			continue
		}
		if refused.reason != "unavailable" {
			t.Errorf("%s: declined %q; a configured archive is not an absence", label, refused.reason)
		}
		if refused.detail != expected.want {
			t.Errorf("%s: detail %q, want %q", label, refused.detail, expected.want)
		}
		// The refusal names the shape of the problem and never the value: the
		// point of refusing is that the token is unfit to put in a header, and
		// repeating it in a decline that travels to a hub is far worse.
		if expected.token != "" && strings.Contains(refused.detail, "secret") {
			t.Errorf("%s: the decline detail carries the token itself: %q", label, refused.detail)
		}
	}
}

// A capture staging one document and not the other is a broken capture, not a
// statement about a machine. "I could not run" — never a decline, which would
// state something about a machine nobody observed, and never a fall-back to the
// live instance of whichever host is replaying.
//
// The admin-only direction is the one worth stating: a capture taken with a
// NARROWED token really would stage the inventory alone, and no committed
// variant does. Until one exists — and it is an adjudication rather than a
// payload set, because the reference's answer there is its replay shim's Python
// exception text — a half-staged directory is the broken capture it almost
// certainly is.
func TestAHalfStagedCaptureRefusesToRunRatherThanDeclining(t *testing.T) {
	cases := map[string]string{
		"the component checks without the inventory": stage(t, map[string]string{
			payloadStem(statusPath) + ".json": healthyStatus}),
		"the inventory without the component checks": stage(t, map[string]string{
			payloadStem(statisticsPath) + ".json": healthyStatistics}),
	}
	for label, dir := range cases {
		code, stdout, stderr := runWith(t, "collect instance:5\n", map[string]string{"SE_REPLAY_DIR": dir})
		if code != exitRuntime {
			t.Errorf("%s: exit %d, want %d", label, code, exitRuntime)
		}
		if stderr == "" {
			t.Errorf("%s: refusing without saying why tells nobody anything", label)
		}
		records := parseRecords(t, stdout)
		if len(ofKind(records, "decline")) != 0 {
			t.Errorf("%s: a broken capture must not become a statement about a machine", label)
		}
		if len(ofKind(records, "object")) != 0 {
			t.Errorf("%s: a broken capture must not become a row", label)
		}
	}
}

// A staged file that is not a document is the harness's problem, not the
// machine's: it fails the batch rather than declining or publishing a row of
// whatever survived the parse.
func TestAStagedNonDocumentRefusesToRun(t *testing.T) {
	for label, dir := range map[string]string{
		"the inventory":        stageInstance(t, "not json at all", healthyStatus),
		"the component checks": stageInstance(t, healthyStatistics, "not json at all"),
	} {
		code, stdout, stderr := runWith(t, "collect instance:6\n", map[string]string{"SE_REPLAY_DIR": dir})
		if code != exitRuntime || stderr == "" {
			t.Errorf("%s: exit %d, stderr %q", label, code, stderr)
		}
		if len(ofKind(parseRecords(t, stdout), "object")) != 0 {
			t.Errorf("%s: a document that would not parse must not become a row", label)
		}
	}
}

func TestProbeAnswersWithAVerdictNotAnExitCode(t *testing.T) {
	code, stdout, _ := runWith(t, "probe\n",
		map[string]string{"SE_REPLAY_DIR": stageInstance(t, healthyStatistics, healthyStatus)})
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
