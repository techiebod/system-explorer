package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The five documents as the control socket answers them, trimmed to the members
// these collections read plus enough of their neighbours to keep the shape
// honest. Written here rather than read from the corpus so a unit test can stage
// a shape no capture holds — the shared-network subnet, the never-send
// suppression and the lease table all live below and none of them exists on the
// lab guest.
const (
	healthyVersion = `{"arguments": {"extended": "3.0.3 (tarball)"}, "result": 0, "text": "3.0.3"}`

	healthyStatus = `{"arguments": {"multi-threading-enabled": true,
	  "packet-queue-size": 64, "packet-queue-statistics": [0.0, 0.5, 1.25],
	  "pid": 33392, "reload": 8821, "sockets": {"status": "ready"},
	  "thread-pool-size": 2, "uptime": 8821}, "result": 0}`

	healthyStatistics = `{"arguments": {
	  "pkt4-received": [[12, "2026-08-19 07:33:23.599197"]],
	  "subnet[1].total-addresses": [[200, "2026-08-19 07:33:23.599197"]],
	  "subnet[1].assigned-addresses": [[3, "2026-08-19 07:33:23.599207"]],
	  "subnet[1].declined-addresses": [[0, "2026-08-19 07:33:23.599208"]],
	  "subnet[1].pool[0].total-addresses": [[999, "2026-08-19 07:33:23.599201"]]
	}, "result": 0}`

	healthyConfig = `{"arguments": {"Dhcp4": {
	  "valid-lifetime": 1800,
	  "option-data": [
	    {"name": "domain-name-servers", "data": "192.0.2.5, 192.0.2.6",
	     "never-send": false, "space": "dhcp4", "code": 6},
	    {"name": "routers", "data": "192.0.2.1", "never-send": false}
	  ],
	  "subnet4": [
	    {"id": 1, "subnet": "192.0.2.0/24", "valid-lifetime": 3600,
	     "option-data": [{"name": "routers", "data": "192.0.2.9", "never-send": false}],
	     "pools": [{"pool": "192.0.2.10-192.0.2.209"}],
	     "reservations": [
	       {"ip-address": "192.0.2.145", "hw-address": "02:d3:cc:e0:41:80",
	        "hostname": "", "client-classes": []},
	       {"ip-address": "192.0.2.82", "client-id": "ANONE0F3", "hostname": "host-f6f88b"}
	     ]}
	  ]
	}}, "result": 0}`

	healthyList = `{"arguments": ["config-get", "list-commands", "statistic-get-all",
	  "status-get", "version-get"], "result": 0}`
)

// stage writes one replay directory. Each document is named by the COMMAND it
// answers, which is how the seam addresses it — the reference keys a dispatched
// acquisition on its argument, and the corpus commits the same names.
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
		commandVersion:    healthyVersion,
		commandStatus:     healthyStatus,
		commandStatistics: healthyStatistics,
		commandConfig:     healthyConfig,
		commandList:       healthyList,
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
	t.Fatalf("no %s object named %q in the stream", collection, name)
	return nil
}

const wholeRequest = "collect daemon:11 subnets:12 reservations:13\n"

func TestReplayIsByteDeterministicAcrossTwoRuns(t *testing.T) {
	env := map[string]string{"SE_REPLAY_DIR": stageHealthy(t)}
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
	code, stdout, stderr := runWith(t, wholeRequest,
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

	// One counter across the WHOLE batch, not one per collection: the first
	// object is 1.0 and the eighth is 1.007, which is what the reference emits
	// and what a port keeping a per-collection index would get wrong.
	objects := ofKind(records, "object")
	if len(objects) != 4 {
		t.Fatalf("one daemon, one subnet, two reservations; got %d objects", len(objects))
	}
	for i, want := range []float64{1.0, 1.001, 1.002, 1.003} {
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
	dir := stageHealthy(t)
	if err := os.WriteFile(filepath.Join(dir, "boot_id"), []byte("8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stdout, _ := runWith(t, "collect daemon:1\n", map[string]string{"SE_REPLAY_DIR": dir})
	if got := ofKind(parseRecords(t, stdout), "begin")[0]["boot_id"]; got != "8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44" {
		t.Fatalf("boot_id must be the staged file, trimmed; got %v", got)
	}
}

func TestReplayNowIsIgnoredButNeverACrash(t *testing.T) {
	// Nothing here is derived against wall-clock now — a lease's expiry is its
	// own allocation time plus its own lifetime — so the pin has nothing to
	// freeze. The contract is only that setting it changes nothing and breaks
	// nothing.
	dir := stageHealthy(t)
	bare := map[string]string{"SE_REPLAY_DIR": dir}
	pinned := map[string]string{"SE_REPLAY_DIR": dir, "SE_REPLAY_NOW": "2026-08-19T10:00:24Z"}

	code1, first, _ := runWith(t, wholeRequest, bare)
	code2, second, _ := runWith(t, wholeRequest, pinned)
	if code1 != exitOK || code2 != exitOK || first != second {
		t.Fatalf("SE_REPLAY_NOW changed the outcome: exits %d/%d", code1, code2)
	}
}

// The seam's whole point: a machine with no DHCP server of its own replays this
// capture without ever dialling a socket. Asserted on the OUTPUT, because the
// development machine that runs it has no Kea at all — so a seam escape here
// would produce an absent decline, not an error.
func TestTheStagedDocumentsDecideRatherThanTheReplayingHost(t *testing.T) {
	env := map[string]string{
		"SE_REPLAY_DIR": stageHealthy(t),
		// Deliberately pointing somewhere real-looking: under replay it must
		// never be consulted, and a port that fell back to it on a machine that
		// happened to have a socket would read the wrong server.
		socketVariable: "/run/kea/kea4-ctrl-socket",
	}
	code, stdout, stderr := runWith(t, wholeRequest, env)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	facts := factsOf(t, parseRecords(t, stdout), "subnets", "192.0.2.0/24")
	if facts["TotalAddresses"] != 200.0 {
		t.Fatalf("the row must come from the staged documents: %v", facts)
	}
}

func TestAnEmptyReplayDirectoryDeclinesAbsentAndCommitsZeroForEveryCollection(t *testing.T) {
	code, stdout, stderr := runWith(t, wholeRequest,
		map[string]string{"SE_REPLAY_DIR": t.TempDir()})
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 3 {
		t.Fatalf("every requested collection states the absence; got %v", declines)
	}
	for _, decline := range declines {
		if decline["reason"] != "absent" || decline["detail"] != declineNoSocket.detail {
			t.Fatalf("expected the shared absent decline, got %v", decline)
		}
	}
	commits := ofKind(records, "commit")
	if len(commits) != 3 {
		t.Fatalf("absent is authoritative-empty and commits zero; got %v", commits)
	}
	for _, commit := range commits {
		if commit["objects"] != 0.0 {
			t.Fatalf("an absent commit retires what a previous batch published: %v", commit)
		}
	}
}

// The absent reading is spelled ONCE. Storage answered this same question two
// opposite ways for as long as it existed — live `unsupported`, replay `absent`
// — because replay exercises only the replay half; this asserts the two paths
// reach the same VALUE, which is what makes the disagreement unspellable rather
// than merely currently-absent.
//
// At the source rather than through run(), because the live path's other half is
// a Linux clock: the whole batch cannot run on the machine this test is written
// on, and the reading under test is taken before that clock is read precisely so
// an absence answers truthfully on any platform.
func TestAnUnconfiguredSocketIsTheSameAbsentReadingAsAnEmptyCapture(t *testing.T) {
	empty := t.TempDir()
	sources := map[string]source{
		"no socket configured": newSource(func(string) string { return "" }),
		"an empty capture": newSource(func(key string) string {
			if key == "SE_REPLAY_DIR" {
				return empty
			}
			return ""
		}),
	}
	for label, src := range sources {
		_, err := src.document(commandConfig)
		var refused *declined
		if !errors.As(err, &refused) {
			t.Fatalf("%s: %v is not a decline at all", label, err)
		}
		if *refused != declineNoSocket {
			t.Fatalf("%s: reached %v, and the shared constant is %v", label, *refused, declineNoSocket)
		}
	}
}

// A capture staging some documents and not others is a broken capture, not a
// statement about a machine: the socket that answered `status-get` was there to
// answer `version-get` too. "I could not run" — never a decline, which would
// state something about a machine nobody observed, and never a fall-back to the
// Kea of whichever host is replaying.
func TestAHalfStagedCaptureRefusesToRunRatherThanDeclining(t *testing.T) {
	cases := map[string]string{
		"the status document without the version": stage(t, map[string]string{
			commandStatus: healthyStatus}),
		"the statistics without the configuration": stage(t, map[string]string{
			commandStatistics: healthyStatistics}),
	}
	for label, dir := range cases {
		code, stdout, stderr := runWith(t, wholeRequest, map[string]string{"SE_REPLAY_DIR": dir})
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

// The one missing document that is NOT a broken capture. lease4-get-all ships in
// a hook library, so a Kea with no hooks loaded offers no lease table at all —
// and the capture's own list-commands says so. Both paths reach the same
// constant: live from Kea's result 2, replay from the committed command list,
// which is why that document is captured even though no fact is lifted from it.
func TestAMissingLeaseDocumentIsTheHookGateAndNotABrokenCapture(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect leases:9\n",
		map[string]string{"SE_REPLAY_DIR": stageHealthy(t)})
	if code != exitOK {
		t.Fatalf("a gated collection is a decline, not an inability: exit %d, stderr %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["reason"] != "unsupported" ||
		declines[0]["detail"] != declineLeaseCommands.detail {
		t.Fatalf("expected the lease-hook decline, got %v", declines)
	}
	// unsupported establishes nothing, so it must NOT commit: a host that
	// unloaded the hook keeps the leases a previous batch published, marked
	// stale, rather than having them retired by a batch that never looked.
	if commits := ofKind(records, "commit"); len(commits) != 0 {
		t.Fatalf("an unsupported decline must not commit; got %v", commits)
	}
}

// The middle answer of the three. Without a command list there is nothing to
// distinguish "this Kea has no hook" from "this capture is missing a file", and
// guessing the first would turn a broken capture into a confident statement
// about a machine.
func TestAMissingLeaseDocumentWithNoCommandListIsStillABrokenCapture(t *testing.T) {
	dir := stage(t, map[string]string{
		commandVersion:    healthyVersion,
		commandStatus:     healthyStatus,
		commandStatistics: healthyStatistics,
		commandConfig:     healthyConfig,
	})
	code, stdout, _ := runWith(t, "collect leases:9\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitRuntime {
		t.Fatalf("exit %d, want %d", code, exitRuntime)
	}
	if len(ofKind(parseRecords(t, stdout), "decline")) != 0 {
		t.Fatal("a capture that never said which commands this Kea offers cannot claim it had no hook")
	}
}

// A staged answer is held to the same result check a live one is. A capture that
// committed Kea's own refusal is not a reading, and serving it as one would put
// "I do not implement that" into a subnet row.
func TestAStagedRefusalIsNotAReading(t *testing.T) {
	dir := stage(t, map[string]string{
		commandVersion:    healthyVersion,
		commandStatus:     healthyStatus,
		commandStatistics: healthyStatistics,
		commandConfig:     `{"result": 1, "text": "configuration is not available"}`,
		commandList:       healthyList,
	})
	code, stdout, stderr := runWith(t, "collect subnets:4\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	declines := ofKind(parseRecords(t, stdout), "decline")
	if len(declines) != 1 || declines[0]["reason"] != "unavailable" {
		t.Fatalf("a refusal is a decline, not a row: %v", declines)
	}
}

func TestProbeAnswersWithAVerdictNotAnExitCode(t *testing.T) {
	code, stdout, _ := runWith(t, "probe\n",
		map[string]string{"SE_REPLAY_DIR": stageHealthy(t)})
	if code != exitOK || !strings.Contains(stdout, `"verdict":"yes"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	// The capture's Kea offers no lease4-get-all, and the probe SAYS so rather
	// than answering a bare yes: the reference's capability() returns the served
	// collections minus the gated one, and this reason is where that lands.
	if !strings.Contains(stdout, "lease4-get-all") {
		t.Fatalf("a yes that hides a gated collection is half an answer: %q", stdout)
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

func TestProbeSaysSoWhenTheLeaseTableIsReadable(t *testing.T) {
	dir := stageHealthy(t)
	if err := os.WriteFile(filepath.Join(dir, commandList+".json"),
		[]byte(`{"arguments": ["config-get", "lease4-get-all", "status-get", "version-get"], "result": 0}`),
		0o644); err != nil {
		t.Fatal(err)
	}
	_, stdout, _ := runWith(t, "probe\n", map[string]string{"SE_REPLAY_DIR": dir})
	if !strings.Contains(stdout, "all four collections") {
		t.Fatalf("a Kea that offers lease4-get-all serves all four: %q", stdout)
	}
}
