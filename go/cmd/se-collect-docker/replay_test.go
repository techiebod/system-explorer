package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Four containers that between them reach every branch the row has: a compose
// service on its own network with a published port, a compose service on host
// networking with none, a stopped one-shot, and an exposed-but-unpublished
// port. The shape the committed corpus holds, in the smallest document that
// still is one dockerd could have produced.
const stagedContainers = `[
 {"Id": "aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111",
  "Names": ["/stack-web-1"], "Image": "busybox:latest", "Created": 1787128171,
  "Ports": [{"IP": "0.0.0.0", "PrivatePort": 8080, "PublicPort": 18080, "Type": "tcp"},
            {"IP": "::", "PrivatePort": 8080, "PublicPort": 18080, "Type": "tcp"},
            {"IP": "", "PrivatePort": 9000, "Type": "udp"}],
  "Labels": {"com.docker.compose.project": "stack"},
  "State": "running", "Status": "Up 2 minutes (healthy)",
  "HostConfig": {"NetworkMode": "stack_default"}, "Mounts": []},
 {"Id": "bbbbbbbbbbbb2222222222222222222222222222222222222222222222222222",
  "Names": ["/stack-worker-1"], "Image": "busybox:latest", "Created": 1787128171,
  "Ports": [], "Labels": {"com.docker.compose.project": "stack"},
  "State": "running", "Status": "Up 2 minutes",
  "HostConfig": {"NetworkMode": "host"}, "Mounts": []},
 {"Id": "cccccccccccc3333333333333333333333333333333333333333333333333333",
  "Names": ["/oneshot"], "Image": "busybox:latest", "Created": 1787128178,
  "Ports": [], "Labels": {},
  "State": "exited", "Status": "Exited (0) About a minute ago",
  "HostConfig": {"NetworkMode": "bridge"}, "Mounts": []}
]`

// The default three plus one compose-created bridge, which is the only way the
// derived br-<id> branch is reached.
const stagedNetworks = `[
 {"Name": "none", "Id": "6c635af02351ea8e1dca629b0b31fc93b99fb13688b4eb1ff0838ce8bd12a7b7",
  "Scope": "local", "Driver": "null", "Internal": false, "Options": {}, "Labels": {}},
 {"Name": "host", "Id": "7d947b07bcfc813d7f3abc591030804f3f0e3a4595747707ca3824f7077a9664",
  "Scope": "local", "Driver": "host", "Internal": false, "Options": {}, "Labels": {}},
 {"Name": "bridge", "Id": "b76f2a0af19dfb0f1e495a462b3cc64d579e30232a14fb0692316b845f8fafe0",
  "Scope": "local", "Driver": "bridge", "Internal": false,
  "Options": {"com.docker.network.bridge.name": "docker0"}, "Labels": {}},
 {"Name": "stack_default", "Id": "2a0990979cde990478e957534806660c47feee926a3a3bf6a3f9d152ccaf6e93",
  "Scope": "local", "Driver": "bridge", "Internal": true, "Options": {},
  "Labels": {"com.docker.compose.project": "stack"}}
]`

const stagedVolumes = `{"Volumes": [
 {"Name": "stack_state", "Driver": "local",
  "Mountpoint": "/var/lib/docker/volumes/stack_state/_data",
  "Labels": {"com.docker.compose.project": "stack"}, "Scope": "local"}
], "Warnings": null}`

// The whole request, so every collection is exercised on every run: a
// comparator or a judge that drove one collection would report clean over the
// two it never opened.
const wholeRequest = "collect containers:412 volumes:429 networks:446\n"

// stageReplayDir lays out the documents the replay seam reads. An empty string
// stages no file for that path, and staging none at all is a host with no
// docker.
func stageReplayDir(t *testing.T, containers, volumes, networks string) string {
	t.Helper()
	dir := t.TempDir()
	for stem, body := range map[string]string{
		"containers-json-all-1": containers,
		"volumes":               volumes,
		"networks":              networks,
	} {
		if body == "" {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, stem+".json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func stagedAll(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"SE_REPLAY_DIR": stageReplayDir(t, stagedContainers, stagedVolumes, stagedNetworks),
	}
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
	// rather than byte-compared (DESIGN 19), so this collector publishes its own
	// identity instead of copying the one the committed half carries.
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

// `at` is one counter across the WHOLE batch, not per collection, and the
// collections come out in the request line's order.
func TestAtAdvancesAcrossTheWholeBatchInRequestOrder(t *testing.T) {
	_, stdout, stderr := runWith(t, wholeRequest, stagedAll(t))
	objects := ofKind(parseRecords(t, stdout), "object")
	if len(objects) != 8 {
		t.Fatalf("three containers, one volume and four networks; got %d (stderr %s)", len(objects), stderr)
	}
	if objects[0]["collection"] != "containers" || objects[3]["collection"] != "volumes" ||
		objects[4]["collection"] != "networks" {
		t.Errorf("the collections come out in the request line's order; got %v",
			[]any{objects[0]["collection"], objects[3]["collection"], objects[4]["collection"]})
	}
	for i, object := range objects {
		want := float64(int64((1.0+0.001*float64(i))*1000+0.5)) / 1000
		if object["at"] != want {
			t.Errorf("object %d carries at %v, want %v — one counter across the batch", i, object["at"], want)
		}
	}
}

// The three absences that are the point of the row, each a different reason a
// fact does not apply, and none of them a null.
func TestTheRowOmitsWhatDoesNotApplyRatherThanNullingIt(t *testing.T) {
	_, stdout, _ := runWith(t, wholeRequest, stagedAll(t))
	records := parseRecords(t, stdout)

	// Exited: systemd deleted the transient scope with the last process, so
	// naming one would hang the runs edge on a unit that does not exist.
	oneshot := factsOf(t, records, "containers", "oneshot")
	if _, present := oneshot["ScopeUnit"]; present {
		t.Errorf("an exited container has no scope unit: %v", oneshot["ScopeUnit"])
	}
	// Nothing labelled it, and null is not the way to say so.
	if _, present := oneshot["ComposeProject"]; present {
		t.Errorf("a container no compose file created carries no project: %v", oneshot["ComposeProject"])
	}
	// Host networking: `"Ports": []` in the document must not become `[]` on
	// the row. NetworkMode is what states which portless shape this is.
	worker := factsOf(t, records, "containers", "stack-worker-1")
	if _, present := worker["Ports"]; present {
		t.Errorf("a host-networked container publishes no ports: %v", worker["Ports"])
	}
	if worker["NetworkMode"] != "host" {
		t.Errorf("NetworkMode %v: the row must still say which portless shape this is", worker["NetworkMode"])
	}
	// The host and null drivers plumb no device and must claim none.
	if facts := factsOf(t, records, "networks", "host"); facts["BridgeInterface"] != nil {
		t.Errorf("the host driver plumbs no interface: %v", facts["BridgeInterface"])
	}

	// Not one member at a time: no fact on any row may be null at ANY DEPTH,
	// which is the rule the judge applies (replay.py _null_paths) and the
	// contract's recursive fact_value. `instance` in begin is the one null the
	// contract requires, so the sweep is scoped to the rows.
	//
	// Walked over the decoded value rather than grepped for "null" in the
	// bytes, because the `none` network's Driver IS the four-character string
	// null — docker's own word for the driver that plumbs nothing — and a
	// substring check calls that a defect while missing a real null inside an
	// array.
	for _, object := range ofKind(records, "object") {
		for _, path := range nullPaths(object["facts"], object["name"].(string)) {
			t.Errorf("fact %s is null: value, absent and unobservable each have "+
				"their own channel and a null names none of them", path)
		}
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

// A running container keeps its scope, named from the FULL id rather than the
// twelve characters the row shows — that is the join back to units/units, and
// the short form resolves to no unit at all.
func TestARunningContainerNamesItsScopeFromTheWholeID(t *testing.T) {
	_, stdout, _ := runWith(t, wholeRequest, stagedAll(t))
	facts := factsOf(t, parseRecords(t, stdout), "containers", "stack-web-1")
	const id = "aaaaaaaaaaaa1111111111111111111111111111111111111111111111111111"
	if facts["ScopeUnit"] != "docker-"+id+".scope" {
		t.Errorf("ScopeUnit %v: the transient scope is named for the whole id", facts["ScopeUnit"])
	}
	if facts["ContainerID"] != "aaaaaaaaaaaa" {
		t.Errorf("ContainerID %v: the row shows the twelve characters docker shows", facts["ContainerID"])
	}
	// The listing's epoch seconds, rendered UTC — not passed through as a
	// number, which would prime an age rule to read it as milliseconds.
	if facts["Created"] != "2026-08-19T08:29:31Z" {
		t.Errorf("Created %v", facts["Created"])
	}
}

// Both BridgeInterface authorities, because a port implementing one would pass
// a corpus holding only the other.
func TestBridgeInterfaceIsReadWhereDockerNamesItAndDerivedWhereItDoesNot(t *testing.T) {
	_, stdout, _ := runWith(t, wholeRequest, stagedAll(t))
	records := parseRecords(t, stdout)
	if facts := factsOf(t, records, "networks", "bridge"); facts["BridgeInterface"] != "docker0" {
		t.Errorf("the default bridge's device is READ from the daemon's own option; got %v",
			facts["BridgeInterface"])
	}
	facts := factsOf(t, records, "networks", "stack_default")
	if facts["BridgeInterface"] != "br-2a0990979cde" {
		t.Errorf("a user-defined bridge's device is DERIVED as br- plus the first "+
			"twelve characters of the network id; got %v", facts["BridgeInterface"])
	}
	// Typed, not merely valued: `true` is not `1`, and a consumer in a typed
	// language sees the difference the reference's dynamic one does not.
	if facts["Internal"] != true {
		t.Errorf("Internal is a boolean; got %T %v", facts["Internal"], facts["Internal"])
	}
	if !strings.Contains(stdout, `"Internal":false`) {
		t.Errorf("a false Internal travels as the boolean the document spelled:\n%s", stdout)
	}
	// The `none` network's driver is the four-character STRING "null", which is
	// docker's word for the driver that plumbs nothing — a port that decoded it
	// as a JSON null would drop the fact.
	if driver := factsOf(t, records, "networks", "none")["Driver"]; driver != "null" {
		t.Errorf("Driver %v: docker names this driver with the string \"null\"", driver)
	}
}

// No payload at all is a host with no docker socket: absent is
// authoritative-empty, so it declines AND commits zero for every collection,
// which is what lets it retire the containers a previous batch published.
func TestNoInterfacePayloadDeclinesAbsentAndCommitsZeroForEveryCollection(t *testing.T) {
	env := map[string]string{"SE_REPLAY_DIR": stageReplayDir(t, "", "", "")}
	code, stdout, stderr := runWith(t, wholeRequest, env)
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 3 {
		t.Fatalf("every requested collection is declined, not just the first; got %v", declines)
	}
	for _, decline := range declines {
		if decline["reason"] != "absent" || decline["detail"] != declineNoSocket.detail {
			t.Errorf("expected the shared absent reading; got %v", decline)
		}
	}
	commits := ofKind(records, "commit")
	if len(commits) != 3 {
		t.Fatalf("absent commits zero, and it must commit for EVERY collection or "+
			"the ones it skipped are never retired; got %v", commits)
	}
	for _, commit := range commits {
		if commit["objects"] != 0.0 || commit["assertions"] != 0.0 || commit["unobservable"] != 0.0 {
			t.Errorf("absent commits zero of all three; got %v", commit)
		}
	}
	if len(ofKind(records, "object")) != 0 {
		t.Fatal("a declined collection carries no records of any kind")
	}
}

// Some of the interface staged and not the rest is a broken CAPTURE, never a
// statement about a machine — and never a fall back to the live daemon of
// whatever workstation is replaying the corpus.
func TestAPartiallyStagedInterfaceRefusesToRun(t *testing.T) {
	env := map[string]string{"SE_REPLAY_DIR": stageReplayDir(t, stagedContainers, "", "")}
	code, stdout, stderr := runWith(t, wholeRequest, env)
	if code != exitRuntime {
		t.Fatalf("exit %d, want %d (stdout %q)", code, exitRuntime, stdout)
	}
	if !strings.Contains(stderr, "not captured") {
		t.Errorf("the refusal must name the uncaptured document; got %q", stderr)
	}
	if strings.Contains(stdout, `"record":"decline"`) {
		t.Error("a capture that staged docker must not be read as a host without it")
	}
}

// A staged document this seam cannot read is a broken capture too, and the
// batch reports "I could not run" rather than inventing a decline.
func TestAnUnreadablePayloadRefusesToRun(t *testing.T) {
	for label, staged := range map[string][3]string{
		"containers not a document": {"{", stagedVolumes, stagedNetworks},
		"containers not a list":     {`{"Volumes": []}`, stagedVolumes, stagedNetworks},
		"a container name is not a string": {
			`[{"Id": "a", "Names": [7], "State": "running"}]`, stagedVolumes, stagedNetworks},
		"a port is not a number": {
			`[{"Id": "a", "Names": ["/x"], "State": "running", "Ports": [{"PrivatePort": "80"}]}]`,
			stagedVolumes, stagedNetworks},
		"a created time is not a number": {
			`[{"Id": "a", "Names": ["/x"], "State": "running", "Created": "yesterday"}]`,
			stagedVolumes, stagedNetworks},
		"a network has no name": {stagedContainers, stagedVolumes, `[{"Id": "a", "Driver": "bridge"}]`},
		"a volume has no name":  {stagedContainers, `{"Volumes": [{"Driver": "local"}]}`, stagedNetworks},
	} {
		env := map[string]string{"SE_REPLAY_DIR": stageReplayDir(t, staged[0], staged[1], staged[2])}
		code, stdout, stderr := runWith(t, wholeRequest, env)
		if code != exitRuntime {
			t.Errorf("%s: exit %d, want %d (stdout %q)", label, code, exitRuntime, stdout)
		}
		if strings.TrimSpace(stderr) == "" {
			t.Errorf("%s: a refusal with no stderr line is indistinguishable from a crash", label)
		}
	}
}

// A daemon holding no volumes answers `"Volumes": null`, and that is a reading
// of zero volumes rather than a failure or an absence.
func TestAnEmptyVolumeListCommitsZeroWithoutDeclining(t *testing.T) {
	env := map[string]string{
		"SE_REPLAY_DIR": stageReplayDir(t, stagedContainers, `{"Volumes": null, "Warnings": null}`, stagedNetworks),
	}
	code, stdout, stderr := runWith(t, wholeRequest, env)
	if code != exitOK {
		t.Fatalf("exit %d, stderr %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	if len(ofKind(records, "decline")) != 0 {
		t.Error("a docker that answered with no volumes is not a docker that is absent")
	}
	for _, commit := range ofKind(records, "commit") {
		if commit["collection"] == "volumes" && commit["objects"] != 0.0 {
			t.Errorf("volumes commits zero; got %v", commit)
		}
	}
}

func TestACollectionThisCollectorNeverDeclaredIsDeclinedUnsupported(t *testing.T) {
	code, stdout, _ := runWith(t, "collect images:11 containers:12\n", stagedAll(t))
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	records := parseRecords(t, stdout)
	var refused map[string]any
	for _, record := range ofKind(records, "decline") {
		if record["collection"] == "images" {
			refused = record
		}
	}
	if refused == nil || refused["reason"] != "unsupported" {
		t.Fatalf("a name this collector did not publish is declined, not sanitised; got %v", refused)
	}
	for _, commit := range ofKind(records, "commit") {
		if commit["collection"] == "images" {
			t.Fatal("an unsupported decline established nothing and must not commit")
		}
	}
	if len(ofKind(records, "object")) != 3 {
		t.Error("containers must still be served alongside the declined collection")
	}
}

func TestProbeAnswersWithAVerdictNotAnExitCode(t *testing.T) {
	code, stdout, _ := runWith(t, "probe\n", stagedAll(t))
	if code != exitOK || !strings.Contains(stdout, `"verdict":"yes"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	// A no is still exit zero: the verdict is the answer, and a non-zero exit
	// would read as a crash (DESIGN 18).
	bare := map[string]string{"SE_REPLAY_DIR": stageReplayDir(t, "", "", "")}
	code, stdout, _ = runWith(t, "probe\n", bare)
	if code != exitOK || !strings.Contains(stdout, `"verdict":"no"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	if record := parseRecords(t, stdout)[0]; record["reason"] == "" || record["reason"] == nil {
		t.Fatal("a verdict without its why is not actionable")
	}
}
