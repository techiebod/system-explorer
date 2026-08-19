package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A capture small enough to read and wide enough to exercise every arm the
// derivation has: the root slice and one child slice, a service inside it, a
// transient docker scope beside it, a mount nothing wrote a file for, and a
// name systemd could not load that something is ordered after. Written as the
// four request/response maps the corpus commits, keyed exactly as the seam
// addresses them — the busctl argument line after the destination.
const (
	pathRoot     = "/org/freedesktop/systemd1/unit/_2d_2eslice"
	pathSystem   = "/org/freedesktop/systemd1/unit/system_2eslice"
	pathSSH      = "/org/freedesktop/systemd1/unit/ssh_2eservice"
	pathAbsent   = "/org/freedesktop/systemd1/unit/firewalld_2eservice"
	pathScope    = "/org/freedesktop/systemd1/unit/docker_2d0123456789ab0123456789ab_2escope"
	pathMount    = "/org/freedesktop/systemd1/unit/run_2ddocker_2dnetns_2daaaa_2emount"
	scopeUnit    = "docker-0123456789ab0123456789ab.scope"
	mountUnit    = "run-docker-netns-aaaa.mount"
	absentUnit   = "firewalld.service"
	serviceIface = "org.freedesktop.systemd1.Service"
	scopeIface   = "org.freedesktop.systemd1.Scope"
)

func listUnitsDocument(rows ...string) string {
	return fmt.Sprintf(`{"%s": {"type":"%s","data":[[%s]]}}`,
		listUnitsRequest(), sigListUnits, strings.Join(rows, ","))
}

func unitRowJSON(name, description, load, active, sub, path string) string {
	return fmt.Sprintf(`["%s","%s","%s","%s","%s","","%s",0,"","/"]`,
		name, description, load, active, sub, path)
}

func healthyCapture() map[string]string {
	listing := listUnitsDocument(
		unitRowJSON("-.slice", "Root Slice", "loaded", "active", "active", pathRoot),
		unitRowJSON("system.slice", "System Slice", "loaded", "active", "active", pathSystem),
		unitRowJSON("ssh.service", "OpenBSD Secure Shell server", "loaded", "active", "running", pathSSH),
		unitRowJSON(scopeUnit, "libcontainer container 0123456789ab0123456789ab", "loaded", "active", "running", pathScope),
		unitRowJSON(mountUnit, "/run/docker/netns/aaaa", "loaded", "active", "mounted", pathMount),
		unitRowJSON(absentUnit, absentUnit, "not-found", "inactive", "dead", pathAbsent),
	)
	files := fmt.Sprintf(
		`{"%s": {"type":"%s","data":[[["/usr/lib/systemd/system/ssh.service","enabled"]]]}}`,
		listUnitFilesRequest(), sigListUnitFiles)
	// The absent unit's reverse side: `Before` on a name systemd could not
	// load lists the units ordered After= it, which is the backwards arrow the
	// whole walk turns on.
	properties := fmt.Sprintf(
		`{"%s": {"type":"%s","data":[{`+
			`"Id":{"type":"s","data":"%s"},`+
			`"Before":{"type":"as","data":["ssh.service"]},`+
			`"After":{"type":"as","data":[]},`+
			`"RequiredBy":{"type":"as","data":[]},`+
			`"WantedBy":{"type":"as","data":[]},`+
			`"LoadState":{"type":"s","data":"not-found"}`+
			`}]}}`,
		propertiesRequest(pathAbsent), sigProperties, absentUnit)
	slices := fmt.Sprintf(
		`{"%s": {"type":"v","data":[{"type":"s","data":"system.slice"}]},`+
			`"%s": {"type":"v","data":[{"type":"s","data":"system.slice"}]},`+
			`"%s": {"type":"v","data":[{"type":"s","data":""}]}}`,
		sliceRequest(pathSSH, serviceIface),
		sliceRequest(pathScope, scopeIface),
		sliceRequest(pathAbsent, serviceIface))
	return map[string]string{
		"listunits.json":       listing,
		"listunitfiles.json":   files,
		"unit-properties.json": properties,
		"unit-slice.json":      slices,
	}
}

func stageUnits(t *testing.T, documents map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, text := range documents {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
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

func factsOf(t *testing.T, records []map[string]any, name string) map[string]any {
	t.Helper()
	for _, record := range ofKind(records, "object") {
		if record["name"] == name {
			facts, _ := record["facts"].(map[string]any)
			return facts
		}
	}
	t.Fatalf("no object named %q in the stream", name)
	return nil
}

func TestReplayIsByteDeterministicAcrossTwoRuns(t *testing.T) {
	env := map[string]string{"SE_REPLAY_DIR": stageUnits(t, healthyCapture())}
	code1, first, stderr := runWith(t, "collect units:824\n", env)
	code2, second, _ := runWith(t, "collect units:824\n", env)
	if code1 != exitOK || code2 != exitOK {
		t.Fatalf("exits %d/%d, stderr: %s", code1, code2, stderr)
	}
	if first != second {
		t.Fatalf("replay is not byte-deterministic:\n%s\nvs\n%s", first, second)
	}
}

func TestReplayPinsEveryRunVaryingMember(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect units:824\n",
		map[string]string{"SE_REPLAY_DIR": stageUnits(t, healthyCapture())})
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
		t.Fatalf("every listed unit is one row; got %d objects", len(objects))
	}
	if objects[0]["at"] != 1.0 {
		t.Errorf("the first object carries the reference constant 1.0; got %v", objects[0]["at"])
	}
	end := ofKind(records, "end")[0]
	if end["cpu_ms"] != 0.5 || end["wall_ms"] != 1.0 {
		t.Errorf("replay pins cpu_ms=0.5 wall_ms=1.0; got %v/%v", end["cpu_ms"], end["wall_ms"])
	}
	commits := ofKind(records, "commit")
	if len(commits) != 1 || commits[0]["objects"] != 6.0 || commits[0]["generation"] != 824.0 {
		t.Fatalf("one commit, six objects, the issued generation; got %v", commits)
	}
	// The two channels this acquisition does not publish, counted as zero
	// rather than omitted: an omitted count is a truncation check switched off
	// (DESIGN 19).
	if commits[0]["assertions"] != 0.0 || commits[0]["unobservable"] != 0.0 {
		t.Fatalf("the acquisition path emits no assertion and no unobservable: %v", commits)
	}
}

// The four derivations that make this collection more than a listing, each
// asserted on the row it lands on. Together they are what a port that read
// only ListUnits would fail.
func TestTheDerivedFactsLandOnTheRowsThatOwnThem(t *testing.T) {
	_, stdout, _ := runWith(t, "collect units:7\n",
		map[string]string{"SE_REPLAY_DIR": stageUnits(t, healthyCapture())})
	records := parseRecords(t, stdout)

	if got := factsOf(t, records, "ssh.service")["Slice"]; got != "system.slice" {
		t.Errorf("the per-unit Slice read is what makes the listing a tree; got %v", got)
	}
	if got := factsOf(t, records, scopeUnit)["ContainerID"]; got != "0123456789ab" {
		t.Errorf("a docker scope's id is the first twelve characters of its name; got %v", got)
	}
	if got := factsOf(t, records, mountUnit)["RuntimeSynthesised"]; got != true {
		t.Errorf("a mount in the listing and in no unit file was synthesised; got %v", got)
	}
	// The two ends of ONE edge. The absent unit's Before names ssh.service, so
	// the finding lands on ssh.service — which has a file and an owner — and
	// the absent row says who asked for it.
	ordering, _ := factsOf(t, records, "ssh.service")["MissingOrdering"].([]any)
	if len(ordering) != 1 || ordering[0] != "firewalld.service (After=)" {
		t.Errorf("the backwards walk must land the ordering fact on the referrer; got %v", ordering)
	}
	referenced, _ := factsOf(t, records, absentUnit)["ReferencedBy"].([]any)
	if len(referenced) != 1 || referenced[0] != "ssh.service (After=)" {
		t.Errorf("an absent name's row says who references it; got %v", referenced)
	}
	// systemd answers Slice for a name it could not load with the empty
	// string, and an empty read is not a slice membership.
	if _, present := factsOf(t, records, absentUnit)["Slice"]; present {
		t.Error("an empty Slice reading must be an absent fact, never an empty one")
	}
	// A unit type that is not in the cgroup tree is never asked at all, which
	// is why the capture stages no reply for it.
	if _, present := factsOf(t, records, mountUnit)["Slice"]; present {
		t.Error("a mount is not in the cgroup tree and must not carry a Slice")
	}
}

// The order the corpus cannot see. `at` is dropped from the byte diff and a
// stream's record order is not significant (DESIGN 19), so replay equivalence
// would pass a port that emitted these rows in any order at all — which is
// exactly why the tree the reference walks is pinned here instead.
func TestTheRowsComeOutInTheCgroupTreeOrder(t *testing.T) {
	_, stdout, _ := runWith(t, "collect units:7\n",
		map[string]string{"SE_REPLAY_DIR": stageUnits(t, healthyCapture())})
	var names []string
	for _, record := range ofKind(parseRecords(t, stdout), "object") {
		names = append(names, record["name"].(string))
	}
	want := []string{
		"-.slice",      // the root, depth 0
		"system.slice", // its only child
		scopeUnit,      // system.slice's children, sorted: 'd' before 's'
		"ssh.service",
		absentUnit, // in no slice, so a root of its own after the tree
		mountUnit,  // the tail, ordered by type
	}
	if len(names) != len(want) {
		t.Fatalf("got %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("row %d is %q, want %q\nfull order: %v", i, names[i], want[i], names)
		}
	}
}

// The seam's whole point: a machine with no systemd of its own replays this
// capture without ever dialling a bus. Asserted on the OUTPUT, because the
// development machine that runs it has no systemd at all — so a seam escape
// here would produce an absent decline, not an error.
func TestTheStagedDocumentsDecideRatherThanTheReplayingHost(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect units:9\n",
		map[string]string{"SE_REPLAY_DIR": stageUnits(t, healthyCapture())})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if got := factsOf(t, parseRecords(t, stdout), "ssh.service")["Description"]; got != "OpenBSD Secure Shell server" {
		t.Fatalf("the row must come from the staged documents: %v", got)
	}
}

func TestAnEmptyReplayDirectoryDeclinesAbsentAndCommitsZero(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect units:77\n",
		map[string]string{"SE_REPLAY_DIR": t.TempDir()})
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["reason"] != "absent" ||
		declines[0]["detail"] != declineNoSystemd.detail {
		t.Fatalf("expected the shared absent decline, got %v", declines)
	}
	commits := ofKind(records, "commit")
	if len(commits) != 1 || commits[0]["objects"] != 0.0 || commits[0]["generation"] != 77.0 {
		t.Fatalf("absent is authoritative-empty and commits zero under the issued generation; got %v", commits)
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
func TestNoBusctlIsTheSameAbsentReadingAsAnEmptyCapture(t *testing.T) {
	empty := t.TempDir()
	// PATH emptied so LookPath cannot find systemd's own binary, which is the
	// live spelling of "this host runs no systemd".
	t.Setenv("PATH", filepath.Join(empty, "nowhere"))
	sources := map[string]source{
		"no busctl on PATH": newSource(func(string) string { return "" }),
		"an empty capture": newSource(func(key string) string {
			if key == "SE_REPLAY_DIR" {
				return empty
			}
			return ""
		}),
	}
	for label, src := range sources {
		_, err := src.listUnits()
		var refused *declined
		if !errors.As(err, &refused) {
			t.Fatalf("%s: %v is not a decline at all", label, err)
		}
		if *refused != declineNoSystemd {
			t.Fatalf("%s: reached %v, and the shared constant is %v", label, *refused, declineNoSystemd)
		}
	}
}

// A capture staging some replies and not the listing is a broken capture, not a
// statement about a machine: the bus that answered a per-unit GetAll answered
// ListUnits first, because the object path came from it. "I could not run" —
// never a decline, which would state something about a machine nobody observed,
// and never a fall-back to the manager of whichever host is replaying.
func TestAHalfStagedCaptureRefusesToRunRatherThanDeclining(t *testing.T) {
	documents := healthyCapture()
	cases := map[string]map[string]string{
		"the properties without the listing": {"unit-properties.json": documents["unit-properties.json"]},
		"the listing without the slices": {
			"listunits.json":     documents["listunits.json"],
			"listunitfiles.json": documents["listunitfiles.json"],
		},
	}
	for label, staged := range cases {
		code, stdout, stderr := runWith(t, "collect units:5\n",
			map[string]string{"SE_REPLAY_DIR": stageUnits(t, staged)})
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

// A missing ListUnitFiles is the one acquisition whose failure is NOT a
// statement about the host: an older systemd or a denied call leaves the claim
// unmade rather than accusing every mount of being synthesised.
func TestAMissingUnitFileListingCostsOneFactAndNotTheCollection(t *testing.T) {
	documents := healthyCapture()
	delete(documents, "listunitfiles.json")
	code, stdout, stderr := runWith(t, "collect units:5\n",
		map[string]string{"SE_REPLAY_DIR": stageUnits(t, documents)})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	if got := len(ofKind(records, "object")); got != 6 {
		t.Fatalf("the collection still reports every unit; got %d", got)
	}
	if _, present := factsOf(t, records, mountUnit)["RuntimeSynthesised"]; present {
		t.Error("a file list nobody could read must not become an accusation against every mount")
	}
	if !strings.Contains(stderr, "ListUnitFiles") {
		t.Errorf("a degraded reading says so on stderr; got %q", stderr)
	}
}

func TestProbeAnswersWithAVerdictNotAnExitCode(t *testing.T) {
	code, stdout, _ := runWith(t, "probe\n",
		map[string]string{"SE_REPLAY_DIR": stageUnits(t, healthyCapture())})
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
