package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The five documents as the API answers them, from a Traefik 3.1.7 with no
// dynamic providers — the same shape corpus/traefik/healthy commits, which is
// the universal one: api@internal, dashboard@internal and noop@internal are
// present on every Traefik that has ever run.
const (
	healthyOverview = `{"http":{"routers":{"total":2,"warnings":0,"errors":0},"services":{"total":3,"warnings":0,"errors":0},"middlewares":{"total":2,"warnings":0,"errors":0}},"tcp":{"routers":{"total":0,"warnings":0,"errors":0},"services":{"total":0,"warnings":0,"errors":0},"middlewares":{"total":0,"warnings":0,"errors":0}},"udp":{"routers":{"total":0,"warnings":0,"errors":0},"services":{"total":0,"warnings":0,"errors":0}},"features":{"tracing":"","metrics":"","accessLog":false}}`

	healthyVersion = `{"Version":"3.1.7","Codename":"comte","startDate":"2026-08-19T07:34:33.167593397Z"}`

	healthyEntrypoints = `[{"address":":8080","transport":{"lifeCycle":{"graceTimeOut":"10s"}},"name":"traefik"},{"address":":80","transport":{"lifeCycle":{"graceTimeOut":"10s"}},"name":"web"}]`

	// The priority two below 2^63 is not decoration: decoded through a float64
	// it comes back as 2^63 exactly, and the judge's typed equality sees it.
	healthyRouters = `[{"entryPoints":["traefik"],"service":"api@internal","rule":"PathPrefix(` + "`/api`" + `)","ruleSyntax":"v3","priority":9223372036854775806,"status":"enabled","using":["traefik"],"name":"api@internal","provider":"internal"},{"entryPoints":["traefik"],"middlewares":["dashboard_redirect@internal","dashboard_stripprefix@internal"],"service":"dashboard@internal","rule":"PathPrefix(` + "`/`" + `)","ruleSyntax":"v3","priority":9223372036854775805,"status":"enabled","using":["traefik"],"name":"dashboard@internal","provider":"internal"}]`

	healthyServices = `[{"status":"enabled","usedBy":["api@internal"],"name":"api@internal","provider":"internal"},{"status":"enabled","usedBy":["dashboard@internal"],"name":"dashboard@internal","provider":"internal"},{"status":"enabled","name":"noop@internal","provider":"internal"}]`
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

func stageHealthy(t *testing.T) string {
	t.Helper()
	return stage(t, map[string]string{
		"api-overview.json":      healthyOverview,
		"api-version.json":       healthyVersion,
		"api-entrypoints.json":   healthyEntrypoints,
		"api-http-routers.json":  healthyRouters,
		"api-http-services.json": healthyServices,
	})
}

const wholeBatch = "collect overview:809 routers:826 services:843\n"

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
	if len(objects) != 6 {
		t.Fatalf("one overview, two routers, three services; got %d objects", len(objects))
	}
	// 1.0 + 0.001*i in emission order, one counter across the whole batch —
	// which is what makes `at` advancing rather than a hardcoded zero.
	for i, want := range []float64{1.0, 1.001, 1.002, 1.003, 1.004, 1.005} {
		if objects[i]["at"] != want {
			t.Errorf("object %d carries at %v, and the reference constant is %v", i, objects[i]["at"], want)
		}
	}
	if objects[0]["name"] != overviewName {
		t.Errorf("the overview row's native name is %q; got %v", overviewName, objects[0]["name"])
	}
	end := ofKind(records, "end")[0]
	if end["cpu_ms"] != 0.5 || end["wall_ms"] != 1.0 {
		t.Errorf("replay pins cpu_ms=0.5 wall_ms=1.0; got %v/%v", end["cpu_ms"], end["wall_ms"])
	}
}

// The hazard this corpus was captured for. Traefik gives its own API router a
// priority of 9223372036854775806 — two below 2^63 — and a decode through a
// float64 returns 9223372036854775808, which reads plausibly and is a different
// number. Asserted on the BYTES, because a Go test that unmarshalled the stream
// into a map would take the same round trip it is testing for.
func TestALargeIntegerSurvivesAsTheTokenTheDocumentSpelled(t *testing.T) {
	_, stdout, _ := runWith(t, wholeBatch, map[string]string{"SE_REPLAY_DIR": stageHealthy(t)})
	if !strings.Contains(stdout, `"Priority":9223372036854775806`) {
		t.Fatalf("the priority did not survive as its own token:\n%s", stdout)
	}
	for _, wrong := range []string{"9223372036854775808", "9.223372036854776e+18", "9223372036854775806.0"} {
		if strings.Contains(stdout, wrong) {
			t.Fatalf("a number was re-rendered as %q — pass-through numbers keep the wire's type, not the language's", wrong)
		}
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
	// Every fact here is a figure Traefik stated; nothing is derived against a
	// clock, so the pin has nothing to freeze. The contract is only that setting
	// it changes nothing and breaks nothing.
	dir := stageHealthy(t)
	bare := map[string]string{"SE_REPLAY_DIR": dir}
	pinned := map[string]string{"SE_REPLAY_DIR": dir, "SE_REPLAY_NOW": "2026-08-19T08:10:00Z"}

	code1, first, _ := runWith(t, wholeBatch, bare)
	code2, second, _ := runWith(t, wholeBatch, pinned)
	if code1 != exitOK || code2 != exitOK || first != second {
		t.Fatalf("SE_REPLAY_NOW changed the outcome: exits %d/%d", code1, code2)
	}
}

// The seam's whole point: a machine with no proxy of its own replays this
// capture without ever opening a socket. Asserted on the OUTPUT, because the
// development machine that runs it has no traefik at all — so a seam escape
// here would produce an absent decline, not an error.
func TestTheStagedDocumentsDecideRatherThanTheReplayingHost(t *testing.T) {
	env := map[string]string{
		"SE_REPLAY_DIR": stageHealthy(t),
		// Deliberately pointing somewhere real-looking: under replay it must
		// never be consulted, and a port that fell back to it on a machine that
		// happened to run a proxy would read the wrong one.
		urlVariable: "http://127.0.0.1:8080",
	}
	code, stdout, stderr := runWith(t, wholeBatch, env)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	facts, _ := ofKind(parseRecords(t, stdout), "object")[0]["facts"].(map[string]any)
	if facts["Version"] != "3.1.7" || facts["ServicesTotal"] != 3.0 {
		t.Fatalf("the row must come from the staged documents: %v", facts)
	}
}

func TestAnEmptyReplayDirectoryDeclinesAbsentAndCommitsZero(t *testing.T) {
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
		if decline["reason"] != "absent" || decline["detail"] != declineNoAPI.detail {
			t.Fatalf("expected the shared absent decline, got %v", decline)
		}
	}
	commits := ofKind(records, "commit")
	if len(commits) != 3 {
		t.Fatalf("absent is authoritative-empty and commits zero for each collection; got %v", commits)
	}
	for _, commit := range commits {
		if commit["objects"] != 0.0 || commit["assertions"] != 0.0 || commit["unobservable"] != 0.0 {
			t.Fatalf("an absent commit carries three zeroes; got %v", commit)
		}
	}
	if got := ofKind(records, "commit")[0]["generation"]; got != 809.0 {
		t.Fatalf("the commit echoes the issued generation; got %v", got)
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
func TestAnUnconfiguredEndpointIsTheSameAbsentReadingAsAnEmptyCapture(t *testing.T) {
	empty := t.TempDir()
	sources := map[string]source{
		"no endpoint configured": newSource(func(string) string { return "" }),
		"an empty capture": newSource(func(key string) string {
			if key == "SE_REPLAY_DIR" {
				return empty
			}
			return ""
		}),
	}
	for label, src := range sources {
		for _, probe := range []struct {
			what string
			run  func() error
		}{
			{"document", func() error { _, err := src.document(pathOverview); return err }},
			{"list", func() error { _, err := src.list(pathRouters); return err }},
			{"reachable", src.reachable},
		} {
			err := probe.run()
			var refused *declined
			if !errors.As(err, &refused) {
				t.Fatalf("%s/%s: %v is not a decline at all", label, probe.what, err)
			}
			if *refused != declineNoAPI {
				t.Fatalf("%s/%s: reached %v, and the shared constant is %v", label, probe.what, *refused, declineNoAPI)
			}
		}
	}
}

// A capture staging some documents and not others is a broken capture, not a
// statement about a machine: the API that answered /api/overview was there to
// answer /api/http/routers too. "I could not run" — never a decline, which would
// state something about a machine nobody observed, and never a fall back to the
// proxy of whichever host is replaying.
func TestAHalfStagedCaptureRefusesToRunRatherThanDeclining(t *testing.T) {
	cases := map[string]string{
		"the counts without the version document": stage(t, map[string]string{
			"api-overview.json": healthyOverview}),
		"the routers without the services listing": stage(t, map[string]string{
			"api-http-routers.json": healthyRouters}),
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
}

// Traefik's own internal services carry no `type` member at all, and this is
// the collection that found the reference publishing "Type": null for three of
// three services on a stock install. The absence is the statement — the row
// omits the key, and a null in its place is refused by the contract at any
// depth.
func TestAMemberTheDocumentDoesNotCarryIsOffTheRowRatherThanNulled(t *testing.T) {
	_, stdout, _ := runWith(t, wholeBatch, map[string]string{"SE_REPLAY_DIR": stageHealthy(t)})
	// On the raw lines, because a decode and re-encode would spell a null the
	// way this side spells one rather than the way it travelled. begin's
	// `instance` is the one legitimate null on the wire — host-native, and only
	// null means it — so the sweep is over object records alone.
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if strings.HasPrefix(line, `{"record":"object"`) && strings.Contains(line, "null") {
			t.Fatalf("a null reached a fact, and a fact value is never null at any depth:\n%s", line)
		}
	}
	for _, record := range ofKind(parseRecords(t, stdout), "object") {
		if record["collection"] != "services" {
			continue
		}
		facts, _ := record["facts"].(map[string]any)
		if _, carried := facts["Type"]; carried {
			t.Errorf("%v carries a Type, and no internal service has one: %v", record["name"], facts)
		}
		if record["name"] == "noop@internal" {
			if _, carried := facts["UsedBy"]; carried {
				t.Errorf("nothing routes to noop@internal, so the row carries no UsedBy: %v", facts)
			}
		} else if _, carried := facts["UsedBy"]; !carried {
			t.Errorf("%v is used by its own router and must carry UsedBy: %v", record["name"], facts)
		}
	}
}
