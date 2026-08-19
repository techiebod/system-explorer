package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One shut-off domain on a libvirt-managed network: the smallest document
// that reaches every fact the row carries, and the shape the committed
// corpus holds.
const stagedDomains = `[{
  "name": "lab", "uuid": "5cb00000-0000-4000-8000-000000000001",
  "state": "shutoff", "memory_mib": 256, "max_memory_mib": 512, "vcpus": 1,
  "autostart": false, "persistent": true,
  "xml": "<domain type='qemu'><name>lab</name><devices><interface type='network'><mac address='02:00:00:00:00:01'/><source network='default'/></interface></devices></domain>",
  "ips_by_mac": {}, "ip_note": null
}]`

// The same host with the guest up and answering, on a bridge this time, so
// the two conditionally-emitted members are both reached.
const stagedRunning = `[{
  "name": "lab", "uuid": "5cb00000-0000-4000-8000-000000000001",
  "state": "running", "memory_mib": 2048, "max_memory_mib": 2048, "vcpus": 2,
  "autostart": true, "persistent": true,
  "xml": "<domain type='qemu'><name>lab</name><devices><interface type='bridge'><mac address='02:00:00:00:00:01'/><source bridge='br0'/><target dev='vnet7'/></interface><interface type='bridge'><mac address='02:00:00:00:00:02'/><source bridge='br0'/><target dev='vnet3'/></interface></devices></domain>",
  "ips_by_mac": {"02:00:00:00:00:02": ["192.168.122.9"], "02:00:00:00:00:01": ["192.168.122.10", "192.168.122.9"]},
  "ip_note": null
}]`

// stageReplayDir lays out the one document the replay seam reads. An empty
// string stages no file, which is a host with no libvirt.
func stageReplayDir(t *testing.T, domains string) string {
	t.Helper()
	dir := t.TempDir()
	if domains == "" {
		return dir
	}
	if err := os.WriteFile(filepath.Join(dir, "domains.json"), []byte(domains), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func replayEnv(dir string) map[string]string {
	return map[string]string{"SE_REPLAY_DIR": dir}
}

func TestReplayIsByteDeterministicAcrossTwoRuns(t *testing.T) {
	env := replayEnv(stageReplayDir(t, stagedRunning))
	code1, first, stderr := runWith(t, "collect domains:412\n", env)
	code2, second, _ := runWith(t, "collect domains:412\n", env)
	if code1 != exitOK || code2 != exitOK {
		t.Fatalf("exits %d/%d, stderr: %s", code1, code2, stderr)
	}
	if first != second {
		t.Fatalf("replay is not byte-deterministic:\n%s\nvs\n%s", first, second)
	}
}

func TestReplayPinsEveryRunVaryingMember(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect domains:412\n", replayEnv(stageReplayDir(t, stagedDomains)))
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
	// rather than byte-compared (DESIGN 19), so this collector publishes its
	// own identity instead of copying the one the committed half carries.
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

// The row is the summary subset, and the whole of it: a shut-off guest gets
// six facts and neither address member, because it has no address BECAUSE IT
// IS OFF and that is inapplicability rather than emptiness.
func TestAStoppedDomainOmitsTheAddressFactsEntirely(t *testing.T) {
	_, stdout, _ := runWith(t, "collect domains:412\n", replayEnv(stageReplayDir(t, stagedDomains)))
	records := parseRecords(t, stdout)
	object := ofKind(records, "object")[0]
	if object["name"] != "lab" {
		t.Errorf("the row is named by the domain's own name; got %v", object["name"])
	}
	facts := object["facts"].(map[string]any)
	for _, absent := range []string{"IPAddresses", "IPAddressesUnobservable"} {
		if _, present := facts[absent]; present {
			t.Errorf("%s reached a stopped guest's row: it has no address because "+
				"it is off, which is not the same statement as [] or as null", absent)
		}
	}
	if len(facts) != 6 {
		t.Errorf("the row carries %d facts; the summary subset is six for a "+
			"stopped guest: %v", len(facts), facts)
	}
	// Typed, not merely valued: `true` is not `1` and 256 is not 256.0, and a
	// consumer in a typed language sees the difference the reference's dynamic
	// one does not.
	if facts["Autostart"] != false || facts["Persistent"] != true {
		t.Errorf("the two flags are booleans; got %T/%T", facts["Autostart"], facts["Persistent"])
	}
	if !strings.Contains(stdout, `"MemoryMiB":256`) || !strings.Contains(stdout, `"VCPUs":1`) {
		t.Errorf("the two figures travel as the integers the document spelled:\n%s", stdout)
	}
	// max_memory_mib is 512 here and the row must not carry it: the row is the
	// summary, and a port that published the whole fact set would ship a
	// member with no sentence and no disclosure class.
	if strings.Contains(stdout, "512") {
		t.Errorf("the maximum memory is not a row fact:\n%s", stdout)
	}
	if len(ofKind(records, "unobservable")) != 0 {
		t.Error("a stopped guest's address is inapplicable, and inapplicable " +
			"opens no channel at all")
	}
	commit := ofKind(records, "commit")[0]
	if commit["objects"] != 1.0 || commit["assertions"] != 0.0 || commit["unobservable"] != 0.0 {
		t.Errorf("all three counts, always, zero when zero; got %v", commit)
	}
}

// A running guest with addresses: sorted, deduplicated across interfaces, and
// taken from ips_by_mac rather than from the definition — the definition
// records what the guest was given, never what it answered on.
func TestARunningDomainCarriesTheAddressesLibvirtSaw(t *testing.T) {
	_, stdout, stderr := runWith(t, "collect domains:412\n", replayEnv(stageReplayDir(t, stagedRunning)))
	records := parseRecords(t, stdout)
	if len(records) == 0 {
		t.Fatalf("no stream, stderr: %s", stderr)
	}
	facts := ofKind(records, "object")[0]["facts"].(map[string]any)
	addresses := facts["IPAddresses"].([]any)
	if len(addresses) != 2 || addresses[0] != "192.168.122.10" || addresses[1] != "192.168.122.9" {
		t.Errorf("IPAddresses %v: one sorted set across every interface — the "+
			"duplicate appears once, and the order is the reference's sorted()", addresses)
	}
	taps := facts["HostTaps"].([]any)
	if len(taps) != 2 || taps[0] != "vnet3" || taps[1] != "vnet7" {
		t.Errorf("HostTaps %v: every <target dev=…/> in the definition, sorted, "+
			"which is the only authoritative answer to who owns vnet3", taps)
	}
	if len(ofKind(records, "unobservable")) != 0 {
		t.Error("an address that was observed opens no unobservable channel")
	}
}

// The third arm, and the one that is ORDINARY rather than exotic: a bridged
// guest whose address no source could answer for. The reference publishes a
// null value with a reason beside it; a null fact value is refused by the
// contract at any depth and by the judge that grades this binary, so the same
// statement travels on the channel DESIGN 19 gives it.
// A running guest nobody could get an address for. The null IPAddresses fact
// is dropped — a null is refused at any depth — and the REASON is published as
// an ordinary string fact, matching the reference.
//
// This asserted an unobservable RECORD until 2026-08-19. The live comparator
// disagreed with the reference on the first running guest either had seen, and
// the record lost the argument for a reason that is not about elegance:
// rules/vms.py reads IPAddressesUnobservable as a FACT to decide whether a
// blank address column is a gap or an answer, and rules do not see the record
// channel. Moving it there deletes the opinion.
func TestARunningDomainWithNoAnswerSaysSoAsAFact(t *testing.T) {
	silent := strings.Replace(stagedRunning,
		`"ips_by_mac": {"02:00:00:00:00:02": ["192.168.122.9"], "02:00:00:00:00:01": ["192.168.122.10", "192.168.122.9"]}`,
		`"ips_by_mac": {}`, 1)
	_, stdout, stderr := runWith(t, "collect domains:412\n", replayEnv(stageReplayDir(t, silent)))
	records := parseRecords(t, stdout)
	if len(records) == 0 {
		t.Fatalf("no stream, stderr: %s", stderr)
	}
	facts := ofKind(records, "object")[0]["facts"].(map[string]any)
	if _, present := facts["IPAddresses"]; present {
		t.Errorf("a value nobody could read is not a fact value: %v", facts["IPAddresses"])
	}
	// Not merely absent from the parse: the BYTES must carry no null in any
	// fact, at any depth, because that is what the judge and the collator
	// both refuse — and `instance` in begin is the one null the contract
	// requires, so the check is scoped to the row.
	for _, object := range ofKind(records, "object") {
		if encoded, err := json.Marshal(object["facts"]); err != nil || strings.Contains(string(encoded), "null") {
			t.Errorf("a fact is null: %s (%v)", encoded, err)
		}
	}
	if facts["IPAddressesUnobservable"] != addressUnobservable {
		t.Fatalf("the reason is a fact and it is the constant, never the "+
			"payload's own note; got %v", facts["IPAddressesUnobservable"])
	}
	if missing := ofKind(records, "unobservable"); len(missing) != 0 {
		t.Errorf("the reason travels as a fact, so no record is emitted: %v", missing)
	}
	if ofKind(records, "commit")[0]["unobservable"] != 0.0 {
		t.Error("no unobservable record, so the count is zero")
	}
}

// No payload at all is a host with no libvirt: absent is authoritative-empty,
// so it declines AND commits zero, which is what lets it retire the domains a
// previous batch published.
func TestNoInterfacePayloadDeclinesAbsentAndCommitsZero(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect domains:77\n", replayEnv(stageReplayDir(t, "")))
	if code != exitOK {
		t.Fatalf("an honest absence exits zero; got %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declines := ofKind(records, "decline")
	if len(declines) != 1 || declines[0]["reason"] != "absent" || declines[0]["detail"] != declineNoLibvirt.detail {
		t.Fatalf("expected the absent decline; got %v", declines)
	}
	commits := ofKind(records, "commit")
	if len(commits) != 1 || commits[0]["objects"] != 0.0 || commits[0]["generation"] != 77.0 {
		t.Fatalf("absent commits zero under the issued generation; got %v", commits)
	}
	if len(ofKind(records, "object")) != 0 {
		t.Fatal("a declined collection carries no records of any kind")
	}
}

// A staged document this seam cannot read is a broken capture, not a
// statement about any machine — and never a fall-back to the live libvirt of
// the workstation replaying the corpus.
func TestAnUnreadablePayloadRefusesToRun(t *testing.T) {
	for label, staged := range map[string]string{
		"not a document":  "{",
		"not a list":      `{"pools": {}}`,
		"no definition":   `[{"name": "lab", "state": "shutoff"}]`,
		"addresses wrong": `[{"name": "lab", "state": "running", "xml": "<domain/>", "ips_by_mac": {"02:00:00:00:00:01": "192.168.122.9"}}]`,
	} {
		code, stdout, stderr := runWith(t, "collect domains:5\n", replayEnv(stageReplayDir(t, staged)))
		if code != exitRuntime {
			t.Errorf("%s: exit %d, want %d (stdout %q)", label, code, exitRuntime, stdout)
		}
		if strings.TrimSpace(stderr) == "" {
			t.Errorf("%s: a refusal with no stderr line is indistinguishable from a crash", label)
		}
		if strings.Contains(stdout, `"record":"object"`) {
			t.Errorf("%s: a batch that could not run publishes no object", label)
		}
	}
}

// `at` is one counter across the whole batch, in emission order, and domains
// are emitted in the order libvirt walked them — nothing sorts them.
func TestAtAdvancesAcrossEveryEmittedObjectInWalkOrder(t *testing.T) {
	two := strings.Replace(stagedDomains, `"name": "lab"`, `"name": "zeta"`, 1) +
		"" // one domain renamed, then a second appended below
	two = strings.TrimSuffix(strings.TrimSpace(two), "]") + "," +
		strings.TrimPrefix(strings.TrimSpace(stagedDomains), "[")
	_, stdout, stderr := runWith(t, "collect domains:4\n", replayEnv(stageReplayDir(t, two)))
	objects := ofKind(parseRecords(t, stdout), "object")
	if len(objects) != 2 {
		t.Fatalf("expected two objects, got %d (stderr %s)", len(objects), stderr)
	}
	if objects[0]["name"] != "zeta" || objects[1]["name"] != "lab" {
		t.Errorf("domains are emitted in the order the walk returned them; got %v then %v",
			objects[0]["name"], objects[1]["name"])
	}
	if objects[0]["at"] != 1.0 || objects[1]["at"] != 1.001 {
		t.Errorf("at: %v then %v", objects[0]["at"], objects[1]["at"])
	}
}

func TestACollectionThisCollectorNeverDeclaredIsDeclinedUnsupported(t *testing.T) {
	env := replayEnv(stageReplayDir(t, stagedDomains))
	code, stdout, _ := runWith(t, "collect networks:11 domains:12\n", env)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	records := parseRecords(t, stdout)
	var refused map[string]any
	for _, record := range ofKind(records, "decline") {
		if record["collection"] == "networks" {
			refused = record
		}
	}
	if refused == nil || refused["reason"] != "unsupported" {
		t.Fatalf("a name this collector did not publish is declined, not sanitised; got %v", refused)
	}
	for _, commit := range ofKind(records, "commit") {
		if commit["collection"] == "networks" {
			t.Fatal("an unsupported decline established nothing and must not commit")
		}
	}
	if len(ofKind(records, "object")) != 1 {
		t.Error("domains must still be served alongside the declined collection")
	}
}

func TestProbeAnswersWithAVerdictNotAnExitCode(t *testing.T) {
	ready := replayEnv(stageReplayDir(t, stagedDomains))
	code, stdout, _ := runWith(t, "probe\n", ready)
	if code != exitOK || !strings.Contains(stdout, `"verdict":"yes"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	// A no is still exit zero: the verdict is the answer, and a non-zero exit
	// would read as a crash (DESIGN 18).
	bare := replayEnv(stageReplayDir(t, ""))
	code, stdout, _ = runWith(t, "probe\n", bare)
	if code != exitOK || !strings.Contains(stdout, `"verdict":"no"`) {
		t.Fatalf("exit %d, stdout %q", code, stdout)
	}
	if record := parseRecords(t, stdout)[0]; record["reason"] == "" || record["reason"] == nil {
		t.Fatal("a verdict without its why is not actionable")
	}
}

// Law 1: the UUID travels as a NAME, not only as a fact the summary drops.
//
// It was read, used and published nowhere until 2026-08-19, so the collator
// keyed a domain on its NAME alone and `virsh domrename` retired the guest
// and minted a new object carrying none of its history. The declaration
// test pins the declared half; this pins the emitted half, and the two
// together are what stop a family being declared that the stream never
// carries — a join key nobody may join on.
func TestTheDomainUUIDTravelsAsAName(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect domains:412\n", replayEnv(stageReplayDir(t, stagedDomains)))
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	object := ofKind(parseRecords(t, stdout), "object")[0]
	names, ok := object["names"].(map[string]any)
	if !ok {
		t.Fatalf("the row carries no names block: %v", object["names"])
	}
	stable, ok := names["stable"].(map[string]any)
	if !ok {
		t.Fatalf("a UUID is a STABLE name — it survives the rename the row's own name does not: %v", names)
	}
	if stable["uuid"] != "5cb00000-0000-4000-8000-000000000001" {
		t.Errorf("the uuid family carries the document's own value; got %v", stable["uuid"])
	}
	if len(names) != 1 || len(stable) != 1 {
		t.Errorf("exactly the declared family, and no other: %v", names)
	}
}

// A document with no uuid publishes no names block at all, rather than an
// empty family: a names block whose family is missing is a join key nobody
// may join on, which is the rule the declaration test's old pin defended.
func TestADomainWithNoUUIDPublishesNoNames(t *testing.T) {
	document := strings.Replace(stagedDomains,
		`"uuid": "5cb00000-0000-4000-8000-000000000001",`, "", 1)
	code, stdout, stderr := runWith(t, "collect domains:412\n", replayEnv(stageReplayDir(t, document)))
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	object := ofKind(parseRecords(t, stdout), "object")[0]
	if _, present := object["names"]; present {
		t.Errorf("an absent uuid publishes no names block: %v", object["names"])
	}
}
