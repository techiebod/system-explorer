package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A cgroup tree small enough to read and large enough to exercise the four
// rules that decide what becomes a row: the root, a slice, a service inside
// it, a nested slice, a DELEGATED service with a subtree of its own, and a
// cgroup below that delegation whose name collides with a system unit's.
//
// The listings are the walk transcribed, in walk order. The SHALLOW
// `init.scope` is yielded FIRST here, and that ordering is the whole reason
// this fixture can judge the collision rule at all: a walk that reaches the
// shallow occurrence first and then meets the deep one is the only order in
// which "the shallowest wins" and "whichever the walk reached last wins"
// disagree. The committed capture happens to yield them the other way round,
// where the two rules agree — so the corpus cannot discriminate this and this
// fixture must (found by reverting the rule and watching the suite stay
// green).
var healthyListings = [][]any{
	{"/sys/fs/cgroup", []string{"init.scope", "user.slice", "system.slice"}, []string{"cgroup.controllers", "cpu.stat"}},
	{"/sys/fs/cgroup/init.scope", []string{}, []string{"cpu.stat"}},
	{"/sys/fs/cgroup/user.slice", []string{"user@1000.service"}, []string{"cpu.stat"}},
	{"/sys/fs/cgroup/user.slice/user@1000.service", []string{"init.scope", "app.slice"}, []string{"cpu.stat"}},
	{"/sys/fs/cgroup/user.slice/user@1000.service/init.scope", []string{}, []string{"cpu.stat"}},
	{"/sys/fs/cgroup/user.slice/user@1000.service/app.slice", []string{}, []string{"cpu.stat"}},
	{"/sys/fs/cgroup/system.slice", []string{"nginx.service", "system-getty.slice"}, []string{"cpu.stat"}},
	{"/sys/fs/cgroup/system.slice/nginx.service", []string{}, []string{"cpu.stat"}},
	{"/sys/fs/cgroup/system.slice/system-getty.slice", []string{}, []string{"cpu.stat"}},
}

// One cgroup's readings, keyed by the file name the collector opens. Absent
// files are simply not listed here and are staged as `null`, which is the
// transcription's word for "this path was not there" — never an empty file,
// because absent and empty are different answers.
func cgroupFiles(usec int64, ioFull string) map[string]string {
	files := map[string]string{
		"cpu.stat": "usage_usec " + itoa(usec) + "\nuser_usec 1\nsystem_usec 2\n" +
			"nr_throttled 0\nthrottled_usec 0\n",
		"memory.current":      "4096\n",
		"memory.peak":         "8192\n",
		"memory.swap.current": "0\n",
		"memory.events":       "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n",
		"io.stat":             "253:0 rbytes=1024 wbytes=2048 rios=1 wios=2\n",
		"cpu.pressure":        "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
		"memory.pressure":     "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
		"io.pressure": "some avg10=0.00 avg60=" + ioFull + " avg300=0.00 total=0\n" +
			"full avg10=0.00 avg60=" + ioFull + " avg300=0.00 total=0\n",
	}
	return files
}

func itoa(v int64) string {
	out := []byte{}
	if v == 0 {
		return "0"
	}
	for v > 0 {
		out = append([]byte{byte('0' + v%10)}, out...)
		v /= 10
	}
	return string(out)
}

// stageTree writes one replay directory: the walk transcription under the
// stem the seam slugs from the tree's root, and one file per path read under
// the stem it slugs from that path. Every path the collector will open must be
// staged, including the ones that were not there — an uncaptured path is a
// broken transcription and this collector says so rather than reading the
// machine it is running on.
func stageTree(t *testing.T, listings [][]any, reads map[string]*string) string {
	t.Helper()
	dir := t.TempDir()
	encoded, err := json.Marshal(listings)
	if err != nil {
		t.Fatal(err)
	}
	write(t, dir, slug(cgroupRoot)+".json", string(encoded))
	for path, text := range reads {
		if text == nil {
			write(t, dir, slug(path)+".json", "null\n")
			continue
		}
		write(t, dir, slug(path)+".txt", *text)
	}
	return dir
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// healthyReads stages every path the collector opens for the tree above, plus
// /proc/stat. `omit` names files to stage as `null` instead of present, and
// `stalls` overrides one cgroup's io.pressure avg60.
func healthyReads(stalls map[string]string, omit map[string]bool) map[string]*string {
	reads := map[string]*string{}
	dirs := []string{}
	for _, entry := range healthyListings {
		dirs = append(dirs, entry[0].(string))
	}
	for i, dir := range dirs {
		stall := "0.00"
		if override, ok := stalls[dir]; ok {
			stall = override
		}
		for name, body := range cgroupFiles(int64(1000*(i+1)), stall) {
			path := dir + "/" + name
			if omit[path] {
				reads[path] = nil
				continue
			}
			text := body
			reads[path] = &text
		}
	}
	// user + nice + system + irq + softirq = 40000 ticks; steal = 0, which is
	// what a bare-metal host reads and what makes HostCpuStolenUsec absent.
	stat := "cpu  10000 10000 10000 900000 500 5000 5000 0 0 0\ncpu0 1 1 1 1 1 1 1 1 0 0\n"
	reads[procStat] = &stat
	return reads
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

func objectsByName(records []map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, record := range ofKind(records, "object") {
		out[record["name"].(string)] = record["facts"].(map[string]any)
	}
	return out
}

// stagedDepthOneUsage is the CpuUsageUsec the staged tree puts in the
// top-level cgroups — the sum the unattributed remainder is measured against.
func stagedDepthOneUsage() float64 {
	total := 0.0
	for i, entry := range healthyListings {
		dir := entry[0].(string)
		if strings.Count(dir, "/")-strings.Count(cgroupRoot, "/") == 1 {
			total += float64(1000 * (i + 1))
		}
	}
	return total
}

func stageHealthy(t *testing.T) string {
	t.Helper()
	return stageTree(t, healthyListings, healthyReads(nil, nil))
}

func collectHealthy(t *testing.T, dir string) []map[string]any {
	t.Helper()
	code, stdout, stderr := runWith(t, "collect workloads:824\n",
		map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	return parseRecords(t, stdout)
}

func TestReplayIsByteDeterministicAcrossTwoRuns(t *testing.T) {
	env := map[string]string{"SE_REPLAY_DIR": stageHealthy(t)}
	code1, first, stderr := runWith(t, "collect workloads:824\n", env)
	code2, second, _ := runWith(t, "collect workloads:824\n", env)
	if code1 != exitOK || code2 != exitOK {
		t.Fatalf("exits %d/%d, stderr: %s", code1, code2, stderr)
	}
	if first != second {
		t.Fatalf("replay is not byte-deterministic:\n%s\nvs\n%s", first, second)
	}
}

func TestReplayPinsEveryRunVaryingMember(t *testing.T) {
	records := collectHealthy(t, stageHealthy(t))
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
	if begin["declaration"] != declarationDigest {
		t.Errorf("the declaration digest stays real under replay; got %v", begin["declaration"])
	}
	at := ofKind(records, "object")[0]["at"].(float64)
	if at != 1.0 {
		t.Errorf("the first object's `at` is the reference constant 1.0; got %v", at)
	}
}

// The whole point of giving the WALK a seam. A replayed run must enumerate the
// captured tree and nothing else: without this the collector would list the
// cgroups of whichever machine is replaying and then hand them captured
// contents, which is the seam escape that once put a workstation's filesystem
// into committed facts — invisible to every other check, because the stream
// would still be well-formed.
func TestTheWalkReplaysTheCapturedTreeAndNotTheReplayingMachines(t *testing.T) {
	records := collectHealthy(t, stageHealthy(t))
	names := objectsByName(records)
	want := map[string]bool{
		"-.slice": true, "user.slice": true, "user@1000.service": true,
		"system.slice": true, "nginx.service": true,
		"system-getty.slice": true, "init.scope": true,
	}
	for name := range want {
		if _, ok := names[name]; !ok {
			t.Errorf("the captured tree holds %s and the stream does not", name)
		}
	}
	for name := range names {
		if !want[name] {
			t.Errorf("row %q is in no captured listing — this run read a tree "+
				"nobody staged", name)
		}
	}
}

// The shallowest occurrence of a duplicated unit name wins, and the deep one's
// readings are discarded rather than merged. A user manager runs its own
// init.scope inside user@<uid>.service and the name collides with the system
// manager's; merging by name lets whichever the walk reached last decide,
// which is a coin toss over whose consumption a row reports. Here the DEEP one
// is walked first, so a port that simply kept the last write would publish the
// user manager's numbers under the host's init.scope.
func TestTheShallowestOccurrenceOfADuplicatedUnitNameWins(t *testing.T) {
	facts := objectsByName(collectHealthy(t, stageHealthy(t)))["init.scope"]
	if facts == nil {
		t.Fatal("init.scope has no row")
	}
	if depth := facts["Depth"].(float64); depth != 1 {
		t.Fatalf("init.scope is published at depth %v: the deep occurrence, "+
			"inside user@1000.service, won a collision it must lose", depth)
	}
	if parent := facts["Parent"]; parent != "-.slice" {
		t.Fatalf("init.scope's parent is %v, not the root slice", parent)
	}
}

// A cgroup below a DELEGATED unit belongs to another manager: user@1000.service
// runs a whole second systemd, and the units inside it are that manager's. The
// delegating unit's own row carries their aggregate and says so.
func TestADelegatedSubtreeGetsNoRowsAndTheDelegatorSaysSo(t *testing.T) {
	facts := objectsByName(collectHealthy(t, stageHealthy(t)))
	if facts["user@1000.service"]["Delegated"] != true {
		t.Error("user@1000.service owns a subtree and must be marked Delegated")
	}
	if _, ok := facts["system.slice"]["Delegated"]; ok {
		t.Error("a slice's members are rows here, so a slice is never marked Delegated")
	}
}

// Absent and zero are different answers, and the difference is load-bearing:
// the root cgroup has no memory.current by kernel design, and rendering that
// as 0 would report a workload consuming nothing — a measurement nobody took.
func TestAPathThatWasNotThereYieldsNoFactRatherThanAZero(t *testing.T) {
	omit := map[string]bool{"/sys/fs/cgroup/memory.current": true}
	dir := stageTree(t, healthyListings, healthyReads(nil, omit))
	facts := objectsByName(collectHealthy(t, dir))["-.slice"]
	if value, ok := facts["MemoryCurrentBytes"]; ok {
		t.Fatalf("a path the capture recorded as absent published %v", value)
	}
	if _, ok := facts["MemoryPeakBytes"]; !ok {
		t.Fatal("the neighbouring file was present and its fact must still be there")
	}
}

// The three attribution states, each stated positively. A slice reporting a
// stall says which member accounts for it, or that every member was read and
// none does — never silence, because silence is what a reader would have to
// infer the interesting case from.
func TestASlicesStallIsAttributedToTheMemberThatAccountsForIt(t *testing.T) {
	stalls := map[string]string{
		"/sys/fs/cgroup/system.slice":               "40.00",
		"/sys/fs/cgroup/system.slice/nginx.service": "55.00",
	}
	dir := stageTree(t, healthyListings, healthyReads(stalls, nil))
	facts := objectsByName(collectHealthy(t, dir))["system.slice"]
	explained, ok := facts[factExplainedBy].(map[string]any)
	if !ok {
		t.Fatalf("system.slice reports a stall and attributes it to nobody: %v", facts)
	}
	if explained["PsiIoFullAvg60"] != "nginx.service" {
		t.Fatalf("the member reading 55.00 under a slice reading 40.00 is what "+
			"accounts for it; got %v", explained)
	}
}

func TestASliceNoMemberAccountsForIsStatedUnexplainedRatherThanLeftSilent(t *testing.T) {
	stalls := map[string]string{"/sys/fs/cgroup/system.slice": "40.00"}
	dir := stageTree(t, healthyListings, healthyReads(stalls, nil))
	facts := objectsByName(collectHealthy(t, dir))["system.slice"]
	if _, ok := facts[factExplainedBy]; ok {
		t.Fatalf("no member reads anywhere near 40.00 and one was named: %v", facts)
	}
	unexplained, ok := facts[factUnexplained].(map[string]any)
	if !ok {
		t.Fatalf("a stall no member explains must SAY so: %v", facts)
	}
	// The member NAMED is the maximum of the (reading, name, depth) tuples the
	// reference takes a max over, so on a tie at 0.0 the highest name wins —
	// which is `system-getty.slice`, not the alphabetically first member. Bound
	// to that exact spelling because a port that broke the tie the other way
	// would still produce a plausible sentence about a different workload.
	statement, _ := unexplained["PsiIoFullAvg60"].(string)
	for _, want := range []string{"every member cgroup", "system-getty.slice at 0.0%", "40.0%"} {
		if !strings.Contains(statement, want) {
			t.Errorf("the unexplained statement does not carry %q: %s", want, statement)
		}
	}
}

// A member that could not be read is not a member that is quiet. Counting it
// as quiet would turn "we did not see it" into "nothing inside explains this"
// — the most interesting finding here, manufactured out of a gap in the
// reading.
func TestAMemberThatWouldNotReadMakesTheAttributionUnobservableNotUnexplained(t *testing.T) {
	stalls := map[string]string{"/sys/fs/cgroup/system.slice": "40.00"}
	omit := map[string]bool{"/sys/fs/cgroup/system.slice/nginx.service/io.pressure": true}
	dir := stageTree(t, healthyListings, healthyReads(stalls, omit))
	facts := objectsByName(collectHealthy(t, dir))["system.slice"]
	if _, ok := facts[factUnexplained]; ok {
		t.Fatalf("a member nobody could read was counted as quiet: %v", facts)
	}
	unobservable, ok := facts[factUnobservable].(map[string]any)
	if !ok {
		t.Fatalf("an unread member must be stated as a gap in the reading: %v", facts)
	}
	statement, _ := unobservable["PsiIoFullAvg60"].(string)
	if !strings.Contains(statement, "no I/O pressure reading for 1 of the 2 member cgroups") {
		t.Errorf("the unobservable statement does not name the gap: %s", statement)
	}
}

// The host denominator, and the two rules that decide what it is: steal is not
// busy, and a bare-metal host that has lost none carries no stolen fact at all
// rather than a standing zero for a condition it cannot have.
func TestTheRootRowCarriesTheHostTotalAndOmitsStolenTimeWhereThereIsNone(t *testing.T) {
	facts := objectsByName(collectHealthy(t, stageHealthy(t)))["-.slice"]
	// 10000 user + 10000 nice + 10000 system + 5000 irq + 5000 softirq
	// = 40000 ticks at 100 Hz = 400_000_000 microseconds.
	if busy := facts["HostCpuBusyUsec"].(float64); busy != 400000000 {
		t.Errorf("HostCpuBusyUsec is %v: idle, iowait and steal are not work this host did", busy)
	}
	if value, ok := facts["HostCpuStolenUsec"]; ok {
		t.Errorf("a host that lost no time to a hypervisor carries no stolen fact; got %v", value)
	}
	// Everything the host spent that is inside none of the top-level cgroups.
	// The sum is taken from the same staging the walk was built from, so the
	// expectation moves with the fixture rather than being a number to keep in
	// step by hand.
	if left := facts["UnattributedCpuUsec"].(float64); left != 400000000-stagedDepthOneUsage() {
		t.Errorf("UnattributedCpuUsec is %v, and the subtraction is against the "+
			"top-level cgroups rather than the root's own cpu.stat", left)
	}
}

func TestStolenTimeIsPublishedWhereTheHypervisorTookSome(t *testing.T) {
	reads := healthyReads(nil, nil)
	stat := "cpu  10000 10000 10000 900000 500 5000 5000 218 0 0\n"
	reads[procStat] = &stat
	dir := stageTree(t, healthyListings, reads)
	facts := objectsByName(collectHealthy(t, dir))["-.slice"]
	if stolen := facts["HostCpuStolenUsec"].(float64); stolen != 2180000 {
		t.Errorf("HostCpuStolenUsec is %v, want 218 ticks at 100 Hz", stolen)
	}
	if busy := facts["HostCpuBusyUsec"].(float64); busy != 400000000 {
		t.Errorf("stolen time leaked into HostCpuBusyUsec: %v", busy)
	}
}

// A variant that staged no tree at all is a host with no unified hierarchy:
// absent, which is authoritative-empty and therefore commits, so a host that
// HAD a v2 hierarchy and lost it has its workload rows retired rather than
// served stale forever.
func TestAnEmptyReplayDirectoryDeclinesAbsentAndCommitsZero(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect workloads:5\n",
		map[string]string{"SE_REPLAY_DIR": t.TempDir()})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["reason"] != "absent" {
		t.Fatalf("expected one absent decline, got %v", declines)
	}
	if declines[0]["detail"] != declineNoCgroupV2.detail {
		t.Fatalf("the decline detail is the shared constant, not a second spelling: %v", declines[0]["detail"])
	}
	commits := ofKind(records, "commit")
	if len(commits) != 1 || commits[0]["objects"].(float64) != 0 {
		t.Fatalf("absent commits zero and must commit: %v", commits)
	}
}

// The reading has one spelling, reached by both paths. The storage collector
// answered exactly this question two opposite ways for as long as it existed —
// live `unsupported`, replay `absent` — and nothing caught it, because replay
// exercises only the replay half.
func TestTheInterfaceMissingReadingIsOneConstantForBothPaths(t *testing.T) {
	if declineNoCgroupV2.reason != "absent" {
		t.Fatalf("the missing-hierarchy reading is %q: absent is the one decline that retires", declineNoCgroupV2.reason)
	}
	// The live path reaches the same value, so there is nowhere for a second
	// spelling to live: this asserts the identity rather than the string.
	live := &liveSource{}
	_, err := live.walk("/no/such/hierarchy/for/this/test")
	if err == nil {
		t.Fatal("a hierarchy that is not there must not walk")
	}
	var refused *declined
	if !errors.As(err, &refused) || *refused != declineNoCgroupV2 {
		t.Fatalf("the live path reached %v, not the shared constant", err)
	}
}

// A path the capture did not record is a broken transcription, never a fall
// back to the kernel of the machine replaying, and never a decline — a decline
// states something about a machine and this run observed none.
func TestAnUncapturedPathFailsTheBatchRatherThanReadingTheLiveKernel(t *testing.T) {
	reads := healthyReads(nil, nil)
	delete(reads, "/sys/fs/cgroup/system.slice/cpu.stat")
	dir := stageTree(t, healthyListings, reads)
	code, stdout, stderr := runWith(t, "collect workloads:5\n",
		map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitRuntime {
		t.Fatalf("exit %d: an uncaptured path is 'I could not run'\n%s", code, stdout)
	}
	if !strings.Contains(stderr, "not captured") {
		t.Fatalf("stderr does not name the uncaptured path: %s", stderr)
	}
}

// slug is the payload seam's addressing and it must match the reference's
// character for character, or the port reads a directory the shim wrote and
// finds nothing in it.
func TestSlugMatchesTheReferencesAddressing(t *testing.T) {
	cases := map[string]string{
		"/sys/fs/cgroup":                                   "sys-fs-cgroup",
		"/proc/stat":                                       "proc-stat",
		"/sys/fs/cgroup/system.slice/cpu.stat":             "sys-fs-cgroup-system.slice-cpu.stat",
		"/sys/fs/cgroup/user.slice/user@1000.service/x":    "sys-fs-cgroup-user.slice-user-1000.service-x",
		`/sys/fs/cgroup/system.slice/a\x2db.slice/io.stat`: "sys-fs-cgroup-system.slice-a-x2db.slice-io.stat",
	}
	for path, want := range cases {
		if got := slug(path); got != want {
			t.Errorf("slug(%q) = %q, want %q", path, got, want)
		}
	}
}
