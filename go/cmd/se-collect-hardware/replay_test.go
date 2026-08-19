package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The committed capture, replayed from its own directory. Reading the real
// corpus rather than a hand-written stand-in is the point: the pair on disk is
// what the Python judge grades this binary against, so a fixture here that
// drifted from it would prove agreement with nothing.
func corpusPayloads(t *testing.T) string {
	t.Helper()
	// cmd/se-collect-hardware -> cmd -> go -> the repository root.
	return filepath.Join("..", "..", "..", "corpus", "hardware", "qemu-guest", "payloads")
}

func stageCorpus(t *testing.T) string {
	t.Helper()
	source := corpusPayloads(t)
	entries, err := os.ReadDir(source)
	if err != nil {
		t.Skipf("no committed hardware capture to replay: %v", err)
	}
	dir := t.TempDir()
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(source, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, entry.Name()), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A directory with no tree document at all: the absent-interface variant, and
// the only shape that declines.
func stageEmpty(t *testing.T) string {
	t.Helper()
	return t.TempDir()
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

func objectsIn(records []map[string]any, collection string) []map[string]any {
	var out []map[string]any
	for _, record := range records {
		if record["record"] == "object" && record["collection"] == collection {
			out = append(out, record)
		}
	}
	return out
}

const allFive = "collect nvme:197 pci:214 platform:231 scsi:248 usb:265\n"

func TestTheCommittedCaptureReplaysToTheStagedTruths(t *testing.T) {
	code, stdout, stderr := runWith(t, allFive, map[string]string{
		"SE_REPLAY_DIR": stageCorpus(t),
		"SE_REPLAY_NOW": "2026-08-19T11:00:00Z",
	})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)

	// The anchors corpus/hardware/qemu-guest/meta.json plants, asserted here
	// too. Not duplication: the Python judge holds the SHIM to them and this
	// holds the BINARY to them, and a port that satisfied one and not the
	// other is exactly what the two tiers exist to tell apart.
	counts := map[string]int{"platform": 1, "pci": 21, "usb": 4, "scsi": 2, "nvme": 0}
	for collection, want := range counts {
		if got := len(objectsIn(records, collection)); got != want {
			t.Errorf("%s: %d objects, staging asserted %d", collection, got, want)
		}
	}

	scsi := objectsIn(records, "scsi")
	if len(scsi) == 0 {
		t.Fatal("no scsi rows")
	}
	facts, _ := scsi[0]["facts"].(map[string]any)
	// The three facts that exist ONLY because the link resolution is captured:
	// host0's sysfs link lands in an ata1 path, which is the whole of the SATA
	// derivation, and the deepest PCI function on it is what the hardware
	// database is then asked about. Unpinned, realpath answers about the
	// machine running this test and all three go missing.
	for fact, want := range map[string]any{
		"Transport":  "SATA",
		"PCIAddress": "0000:00:01.1",
		"Model":      "82371SB PIIX3 IDE [Natoma/Triton II] (Qemu virtual machine)",
	} {
		if facts[fact] != want {
			t.Errorf("scsi host0 %s = %v, staging asserted %v", fact, facts[fact], want)
		}
	}
	if _, present := facts["FirmwareVersion"]; present {
		t.Error("scsi host0 carries FirmwareVersion; all six HBA attribute names read null on this guest and a fact value is never null")
	}
}

// A fact's value is never null at any depth (DESIGN 19): the three statements
// each have their own channel and null names none of them. Held over the whole
// stream rather than over a list of keys, because the nulls this collector can
// produce come from a dozen sysfs reads and an enumeration would be the subset
// guard again.
func TestNoFactValueIsEverNull(t *testing.T) {
	_, stdout, _ := runWith(t, allFive, map[string]string{
		"SE_REPLAY_DIR": stageCorpus(t),
		"SE_REPLAY_NOW": "2026-08-19T11:00:00Z",
	})
	var walk func(path string, value any)
	walk = func(path string, value any) {
		switch typed := value.(type) {
		case nil:
			t.Errorf("%s is null", path)
		case map[string]any:
			for key, inner := range typed {
				walk(path+"/"+key, inner)
			}
		case []any:
			for i, inner := range typed {
				walk(path+"["+string(rune('0'+i))+"]", inner)
			}
		}
	}
	for _, record := range parseRecords(t, stdout) {
		if record["record"] != "object" {
			continue
		}
		walk(record["collection"].(string)+"/"+record["name"].(string),
			record["facts"])
	}
}

// The interface-is-not-here reading, reached by BOTH paths through ONE
// constant. The storage collector answered exactly this question two opposite
// ways for as long as it existed — live said `unsupported`, replay said
// `absent` — and nothing caught it, because replay exercises only the replay
// half. This asserts the constant IS what the replay path emits, and
// TestTheLiveAndReplayPathsCannotSpellAbsenceDifferently asserts the live path
// reaches the same one.
func TestNoTreeDocumentDeclinesAbsentAndCommitsZero(t *testing.T) {
	code, stdout, stderr := runWith(t, allFive,
		map[string]string{"SE_REPLAY_DIR": stageEmpty(t)})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	declined := map[string]bool{}
	committed := map[string]bool{}
	for _, record := range records {
		switch record["record"] {
		case "decline":
			if record["reason"] != declineNoSysfs.reason {
				t.Fatalf("reason %v, want %q", record["reason"], declineNoSysfs.reason)
			}
			if record["detail"] != declineNoSysfs.detail {
				t.Fatalf("detail %v, want %q", record["detail"], declineNoSysfs.detail)
			}
			declined[record["collection"].(string)] = true
		case "commit":
			if record["objects"].(float64) != 0 {
				t.Fatalf("%v committed objects on a host with no sysfs", record["collection"])
			}
			committed[record["collection"].(string)] = true
		case "object":
			t.Fatalf("an object was emitted with nothing staged: %v", record)
		}
	}
	for _, collection := range []string{"platform", "pci", "usb", "scsi", "nvme"} {
		if !declined[collection] || !committed[collection] {
			t.Errorf("%s: declined=%v committed=%v — absent is authoritative-empty and must retire what a previous batch published",
				collection, declined[collection], committed[collection])
		}
	}
}

// Both sources route the same condition through the same constant. Without
// this, the two halves could drift into two spellings of one reading and only
// the replay half would ever be exercised — which is precisely how the storage
// collector shipped `unsupported` live and `absent` under replay for its whole
// life.
func TestTheLiveAndReplayPathsCannotSpellAbsenceDifferently(t *testing.T) {
	replay := newSource(func(key string) string {
		if key == "SE_REPLAY_DIR" {
			return stageEmpty(t)
		}
		return ""
	})
	if err := sysfsPresent(replay); err == nil {
		t.Fatal("a replay with no tree document must reach the absent reading")
	} else if err.Error() != declineNoSysfs.Error() {
		t.Fatalf("replay reached %q, the shared constant is %q", err, declineNoSysfs.Error())
	}

	// The live half, on a machine FORCED into the same condition. Pointing the
	// tree list at an empty directory is what makes this falsifiable
	// everywhere: read as it stands, a Linux developer's machine has sysfs and
	// the live arm returns nil, so a second spelling could be introduced and
	// nothing here would go red — which is precisely how storage's two
	// spellings survived. On macOS the arm fires anyway; this makes it fire on
	// the deploy target too.
	trees := sysfsTrees
	sysfsTrees = []string{filepath.Join(t.TempDir(), "no-sysfs-here")}
	defer func() { sysfsTrees = trees }()

	live := newSource(func(string) string { return "" })
	err := sysfsPresent(live)
	if err == nil {
		t.Fatal("a live source with no device tree must reach the absent reading")
	}
	if err.Error() != declineNoSysfs.Error() {
		t.Fatalf("live reached %q, the shared constant is %q", err, declineNoSysfs.Error())
	}
}

// A path the capture does not hold is "I could not run" — never a decline, and
// never a fall back to the tree of the machine replaying, which is the seam
// escape that once put a replaying workstation's filesystem into committed
// facts.
func TestAnUncapturedPathFailsTheBatchRatherThanDeclining(t *testing.T) {
	dir := stageCorpus(t)
	// A listing that names a scsi host the read document knows nothing about:
	// the walk will ask for its proc_name and the seam must refuse.
	raw, err := os.ReadFile(filepath.Join(dir, "listdir.json"))
	if err != nil {
		t.Fatal(err)
	}
	var listings map[string]map[string][]string
	if err := json.Unmarshal(raw, &listings); err != nil {
		t.Fatal(err)
	}
	listings["/sys/class"]["scsi_host"] = append(listings["/sys/class"]["scsi_host"], "host9")
	edited, _ := json.Marshal(listings)
	if err := os.WriteFile(filepath.Join(dir, "listdir.json"), edited, 0o644); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := runWith(t, "collect scsi:248\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitRuntime {
		t.Fatalf("exit %d, want %d — an uncaptured read is an inability to run", code, exitRuntime)
	}
	if !strings.Contains(stderr, "not captured") {
		t.Fatalf("stderr does not name the uncaptured path: %q", stderr)
	}
}

// One transport verdict turns on PRESENCE rather than content, so the probe is
// a captured reading like any other. This stages a host that publishes a SAS
// address — no such file exists on the machine running this test — and asserts
// the row says SAS. An implementation that answered the probe off its own
// filesystem would say SATA here, which is what makes the pin falsifiable on a
// machine that has no SAS host at all: without a staged true, the guest's own
// false and the test machine's own false agree by accident and the seam could
// be removed with nothing going red.
func TestTheExistsProbeIsAnsweredFromTheCaptureAndNotTheLocalTree(t *testing.T) {
	dir := stageCorpus(t)
	raw, err := os.ReadFile(filepath.Join(dir, "exists.json"))
	if err != nil {
		t.Fatal(err)
	}
	var probes map[string]map[string]bool
	if err := json.Unmarshal(raw, &probes); err != nil {
		t.Fatal(err)
	}
	probes["/sys/class/scsi_host/host0"]["host_sas_address"] = true
	edited, _ := json.Marshal(probes)
	if err := os.WriteFile(filepath.Join(dir, "exists.json"), edited, 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runWith(t, "collect scsi:248\n", map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	rows := objectsIn(parseRecords(t, stdout), "scsi")
	if len(rows) == 0 {
		t.Fatal("no scsi rows")
	}
	facts, _ := rows[0]["facts"].(map[string]any)
	if facts["Transport"] != "SAS" {
		t.Fatalf("Transport = %v, want SAS — the staged probe was not consulted", facts["Transport"])
	}
	// The unedited host must stay SATA, so the reading is per-path rather than
	// a switch the whole walk flipped.
	other, _ := rows[1]["facts"].(map[string]any)
	if other["Transport"] != "SATA" {
		t.Fatalf("host1 Transport = %v, want SATA", other["Transport"])
	}
}

// The pin is what stops a corpus rotting on the shelf: one fact here is
// derived against wall-clock now, and under replay it must be a function of
// the capture rather than of the day the test runs.
func TestTheReplayClockIsPinnedBySEReplayNow(t *testing.T) {
	src := newSource(func(key string) string {
		switch key {
		case "SE_REPLAY_DIR":
			return stageEmpty(t)
		case "SE_REPLAY_NOW":
			return "2026-08-19T11:00:00Z"
		}
		return ""
	})
	if got := src.now(); got != 1787137200 {
		t.Fatalf("pinned clock reads %v, want the capture's own moment", got)
	}
}
