package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Everything here is a derivation the committed capture cannot reach: the lab
// guest's disks are virtio-blk, so it has no scsi device, no NVMe controller,
// no enclosure and no hwmon sensor, and corpus.NAMED_RESIDUALS says so. These
// are unit tests and not a second corpus — they pin the arithmetic and the
// parse, and the venue that owns the READING is the live comparator on a host
// with disks.

// posix realpath's non-strict form: follow every link, leave a component that
// does not exist exactly as written. The second half is what the scsi walk
// depends on — it reads topology out of the answer — and a resolver that
// errored instead would publish a host with no transport and no PCI function,
// which is a wrong answer wearing a complete one's clothes.
func TestResolveFollowsLinksAndLeavesMissingComponentsAlone(t *testing.T) {
	root := t.TempDir()
	// The tempdir's OWN path may run through a link — on macOS /var is one —
	// and resolving it is the correct answer, so the expectations are written
	// against the resolved root rather than the one the toolkit handed back.
	resolvedRoot := resolve(root)
	deep := filepath.Join(resolvedRoot, "devices", "pci0000:00", "0000:00:01.1", "ata1", "host0")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(resolvedRoot, "class", "scsi_host"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(resolvedRoot, "class", "scsi_host", "host0")
	if err := os.Symlink(deep, link); err != nil {
		t.Fatal(err)
	}
	if got := resolve(link); got != deep {
		t.Errorf("resolve(%s) = %s, want %s", link, got, deep)
	}
	// The missing-component half, and the one that matters: an attribute the
	// walk asks about on a host that does not publish it.
	missing := filepath.Join(link, "host_sas_address")
	if got := resolve(missing); got != filepath.Join(deep, "host_sas_address") {
		t.Errorf("resolve of a missing leaf = %s, want the link resolved and the leaf kept", got)
	}
	// A relative link, which is how sysfs spells nearly all of its own.
	if err := os.Symlink("../../devices/pci0000:00", filepath.Join(resolvedRoot, "class", "scsi_host", "up")); err != nil {
		t.Fatal(err)
	}
	if got := resolve(filepath.Join(resolvedRoot, "class", "scsi_host", "up")); got != filepath.Join(resolvedRoot, "devices", "pci0000:00") {
		t.Errorf("a relative link resolved to %s", got)
	}
}

// udisks reports temperatures in KELVIN, and 0 means unknown. Whole kelvin in,
// whole degrees out: subtracting 273.15 from an integer always lands on .85, so
// rounding to one decimal made every udisks reading end in .9 — a digit the
// sensor never measured.
func TestKelvinToCelsiusInventsNoPrecision(t *testing.T) {
	cases := []struct {
		raw  string
		want any
		ok   bool
	}{
		{"300", int64(27), true},
		{"273", int64(0), true},
		{"310.5", 37.4, true},
		{"0", nil, false},
		{"-5", nil, false},
	}
	for _, c := range cases {
		got, ok := kelvinToCelsius(variant{Type: "d", Data: json.RawMessage(c.raw)})
		if ok != c.ok {
			t.Errorf("%s: ok=%v want %v", c.raw, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("%s K -> %v (%T), want %v (%T)", c.raw, got, got, c.want, c.want)
		}
	}
}

// The PCIe conversion is EXACT LABELS ONLY. A generation the table has not met
// must produce silence rather than a plausible wrong number, so there is no
// parsing of the leading float and no interpolation — which is the difference
// between a fact a rule may cite and a guess.
func TestPCIeBandwidthIsExactLabelsOnly(t *testing.T) {
	if got, ok := pcieBandwidth("8.0 GT/s PCIe", true, 4, true); !ok || got != 3938461536 {
		t.Errorf("gen3 x4 = %v (%v), want 3938461536", got, ok)
	}
	for _, label := range []string{"8.0 GT/s", "128.0 GT/s PCIe", "8 GT/s PCIe", ""} {
		if _, ok := pcieBandwidth(label, true, 4, true); ok {
			t.Errorf("%q produced a bandwidth; an unmet label must be silent", label)
		}
	}
	if _, ok := pcieBandwidth("8.0 GT/s PCIe", true, 0, false); ok {
		t.Error("a link with no lane count produced a bandwidth")
	}
}

// A controller with SEVERAL namespaces has several wwids and no single one of
// its own, so it SAYS so rather than picking the first — the same shape the
// adapter uses for a SMART reading it cannot take.
func TestNVMeWWNSaysWhenThereIsNoSingleOne(t *testing.T) {
	src := &fakeTree{reads: map[string]string{
		"/sys/block/nvme0n1/wwid": "eui.0011223344556677",
		"/sys/block/nvme0n2/wwid": "eui.8899aabbccddeeff",
	}}
	one := map[string]any{}
	nvmeWWN(src, one, []string{"nvme0n1"})
	if one["WWN"] != "eui.0011223344556677" {
		t.Errorf("one namespace: WWN = %v", one["WWN"])
	}
	several := map[string]any{}
	nvmeWWN(src, several, []string{"nvme0n1", "nvme0n2"})
	if _, published := several["WWN"]; published {
		t.Error("two distinct namespace wwids published one WWN, which identifies nothing")
	}
	if reason, _ := several["WWNUnobservable"].(string); !strings.Contains(reason, "2 namespaces") {
		t.Errorf("WWNUnobservable does not say why: %v", several["WWNUnobservable"])
	}
}

// The health merge, over systemd's own JSON rendering of the D-Bus reply. Two
// passes, because the SMART properties hang off a Drive and the kernel name
// every other collection joins on hangs off a Block that points at it.
func TestDriveHealthByBlockJoinsTheDriveToItsKernelName(t *testing.T) {
	document := map[string]map[string]map[string]variant{
		"/org/freedesktop/UDisks2/drives/D": {
			"org.freedesktop.UDisks2.Drive": {
				"Serial":   {Type: "s", Data: json.RawMessage(`"S3RIAL"`)},
				"Vendor":   {Type: "s", Data: json.RawMessage(`""`)},
				"Revision": {Type: "s", Data: json.RawMessage(`"FW01"`)},
			},
			"org.freedesktop.UDisks2.Drive.Ata": {
				"SmartSupported":      {Type: "b", Data: json.RawMessage(`true`)},
				"SmartFailing":        {Type: "b", Data: json.RawMessage(`false`)},
				"SmartNumBadSectors":  {Type: "t", Data: json.RawMessage(`0`)},
				"SmartSelftestStatus": {Type: "s", Data: json.RawMessage(`"success"`)},
				"SmartTemperature":    {Type: "d", Data: json.RawMessage(`309`)},
				"SmartPowerOnSeconds": {Type: "t", Data: json.RawMessage(`36000`)},
			},
		},
		"/org/freedesktop/UDisks2/block_devices/sda": {
			"org.freedesktop.UDisks2.Block": {
				// `ay`, NUL-terminated, which is how udisks spells every path.
				"Device": {Type: "ay", Data: json.RawMessage(`[47,100,101,118,47,115,100,97,0]`)},
				"Drive":  {Type: "o", Data: json.RawMessage(`"/org/freedesktop/UDisks2/drives/D"`)},
			},
		},
		// A block device with no drive behind it — a loop mount — must join to
		// nothing rather than to whatever came back last.
		"/org/freedesktop/UDisks2/block_devices/loop0": {
			"org.freedesktop.UDisks2.Block": {
				"Device": {Type: "ay", Data: json.RawMessage(`[47,100,101,118,47,108,111,111,112,48,0]`)},
				"Drive":  {Type: "o", Data: json.RawMessage(`"/"`)},
			},
		},
	}
	health := driveHealthByBlock(document)
	if len(health) != 1 {
		t.Fatalf("joined %d block devices, want 1: %v", len(health), health)
	}
	facts := health["sda"]
	for name, want := range map[string]any{
		"Serial":              "S3RIAL",
		"Firmware":            "FW01",
		"SmartFailing":        false,
		"SmartSelftestStatus": "success",
		"SmartTemperatureC":   int64(36),
		"SmartPowerOnHours":   int64(10),
	} {
		if facts[name] != want {
			t.Errorf("sda %s = %v (%T), want %v (%T)", name, facts[name], facts[name], want, want)
		}
	}
	// An empty string is not a value: the drive published no vendor, and a
	// fact whose value is "" asserts an identity and carries none.
	if _, published := facts["Vendor"]; published {
		t.Error("an empty Vendor was published as a fact")
	}
	// Zero bad sectors IS a reading and must be published; only the u64
	// sentinel is an absence.
	if facts["SmartBadSectors"] != uint64(0) {
		t.Errorf("SmartBadSectors = %v, want 0 published as a reading", facts["SmartBadSectors"])
	}
}

// smartctl's numbers reach the wire spelled exactly as the tool wrote them:
// `12` and `12.0` are different answers to a typed reader (DESIGN 19), and a
// round trip through any Go numeric type would respell them.
func TestSmartDocumentNumbersKeepTheirWireSpelling(t *testing.T) {
	document := map[string]json.RawMessage{
		"temperature":   json.RawMessage(`{"current": 31}`),
		"power_on_time": json.RawMessage(`{"hours": 21474836470}`),
		"smart_status":  json.RawMessage(`{"passed": true}`),
		"nvme_smart_health_information_log": json.RawMessage(
			`{"percentage_used": 3, "available_spare": 100, "media_errors": 0}`),
	}
	info := map[string]any{}
	mergeSmartDocument(info, document)
	encoded, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"SmartTemperatureC":31`,
		`"SmartPowerOnHours":21474836470`,
		`"SmartOverallPassed":true`,
		`"SmartPercentUsed":3`,
		`"SmartMediaErrors":0`,
	} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("%s missing from %s", want, encoded)
		}
	}
	// A member the document spells as null is a reading smartctl did not take,
	// and a fact value is never null.
	nulled := map[string]json.RawMessage{"temperature": json.RawMessage(`{"current": null}`)}
	empty := map[string]any{}
	mergeSmartDocument(empty, nulled)
	if len(empty) != 0 {
		t.Errorf("a null member became a fact: %v", empty)
	}
}

// Order matters: smartctl's own words beat any inference. A drive whose
// snapshot was garbage-collected for carrying no reading has no
// SmartSnapshotAt at all, so without checking the recorded reason first this
// would blame grantDiskAccess on a host whose collector is working correctly.
func TestNoReadingReasonPrefersSmartctlsOwnWords(t *testing.T) {
	if got := noReadingReason(map[string]any{
		"SmartSnapshotReason": "Device is in STANDBY mode",
	}); !strings.Contains(got, "STANDBY") {
		t.Errorf("the recorded reason was not used: %s", got)
	}
	if got := noReadingReason(map[string]any{
		"SmartSnapshotAt": "2026-08-19T11:00:00Z",
	}); !strings.Contains(got, "carried no reading") {
		t.Errorf("a snapshot with no reading was not named: %s", got)
	}
	if got := noReadingReason(map[string]any{}); !strings.Contains(got, "grantDiskAccess") {
		t.Errorf("the no-snapshot case did not name the grant: %s", got)
	}
}

// A row that yielded no health reading says so, so a rule can decline to vouch
// for it. Snapshot age and timestamp do NOT count as a reading — they say the
// collector RAN, not that it read anything, and conflating the two is how five
// raidz1 members displayed a vouched-for "ok" while their snapshots held
// nothing but an smartctl error.
func TestUnobservableIsStatedUnlessSomethingWasActuallyMeasured(t *testing.T) {
	ran := map[string]any{"SmartSnapshotAt": "x", "SmartSnapshotAgeSeconds": int64(4)}
	applyUnobservable("scsi", "disk", ran)
	if _, said := ran["SmartUnobservable"]; !said {
		t.Error("a row with only a snapshot timestamp claimed a reading")
	}
	measured := map[string]any{"SmartTemperatureC": 31}
	applyUnobservable("scsi", "disk", measured)
	if _, said := measured["SmartUnobservable"]; said {
		t.Error("a row with a real temperature was marked unobservable")
	}
	// A host adapter is topology and not a health subject, so it makes no
	// health claim either way.
	host := map[string]any{}
	applyUnobservable("scsi", "scsi-host", host)
	if len(host) != 0 {
		t.Errorf("a scsi host was given a health statement: %v", host)
	}
}

// The reason text is bounded and scrubbed before it can travel: it reaches a
// hub and goes out over MCP, and one of this estate's planned upstreams
// accepts its API key only as a query parameter.
func TestReasonTextIsBoundedAndStrippedOfQueryStrings(t *testing.T) {
	if got := boundedReason("  two   lines\nhere  "); got != "two lines here" {
		t.Errorf("collapse = %q", got)
	}
	if got := boundedReason("failed https://host/api?apikey=s3cret"); strings.Contains(got, "s3cret") {
		t.Errorf("a query string survived: %q", got)
	}
	if got := boundedReason("failed https://user:pw@host/api"); strings.Contains(got, "user:pw") {
		t.Errorf("userinfo survived: %q", got)
	}
	long := boundedReason(strings.Repeat("word ", 200))
	if len(long) > reasonLimit+20 || !strings.HasSuffix(long, "(truncated)") {
		t.Errorf("bound not applied: %d chars, %q", len(long), long[max(0, len(long)-30):])
	}
}

// The natural sort the attachment tree is walked in: 2:0:10:0 after 2:0:9:0,
// host10 after host9. Plain string order puts host10 before host2, which
// reorders every row on a machine with ten adapters.
func TestNaturalOrderComparesDigitsAsNumbers(t *testing.T) {
	names := []string{"host10", "host2", "host9", "2:0:10:0", "2:0:9:0"}
	sortNatural(names)
	want := []string{"2:0:9:0", "2:0:10:0", "host2", "host9", "host10"}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("sorted %v, want %v", names, want)
		}
	}
}

// fakeTree is a source whose only real members are the tree reads a unit test
// needs. Every other method answers as an empty machine would, so a test that
// reached one by accident gets nothing rather than the developer's own /sys.
type fakeTree struct {
	reads map[string]string
	lists map[string][]string
}

func (f *fakeTree) read(p string) (string, bool) {
	value, ok := f.reads[p]
	return value, ok && value != ""
}
func (f *fakeTree) listdir(p string) []string            { return f.lists[p] }
func (*fakeTree) readBytes(string) ([]byte, bool)        { return nil, false }
func (*fakeTree) exists(string) bool                     { return false }
func (*fakeTree) realpath(p string) string               { return p }
func (*fakeTree) udev(string) map[string]string          { return map[string]string{} }
func (*fakeTree) lscpu() (map[string]string, error)      { return map[string]string{}, nil }
func (*fakeTree) bootID() (string, error)                { return replayBootID, nil }
func (*fakeTree) timens() int64                          { return 0 }
func (*fakeTree) batch() (string, error)                 { return "test", nil }
func (*fakeTree) declaration() string                    { return declarationDigest }
func (*fakeTree) beginCollection() error                 { return nil }
func (*fakeTree) stamp(int) float64                      { return 1 }
func (*fakeTree) costs() (float64, float64)              { return 0, 0 }
func (*fakeTree) hostname() string                       { return "test" }
func (*fakeTree) now() float64                           { return 0 }
func (*fakeTree) sysfsAbsent() bool                      { return false }
func (*fakeTree) failure() error                         { return nil }
func (*fakeTree) smartctlUsable(string) bool             { return false }
func (*fakeTree) drives() (map[string]driveHealth, bool) { return nil, false }
func (*fakeTree) drivesRaw() (map[string]map[string]map[string]variant, bool) {
	return nil, false
}
func (*fakeTree) smartReason(string) (string, bool) { return "", false }
func (*fakeTree) smartSnapshot(string) (map[string]json.RawMessage, float64, bool) {
	return nil, 0, false
}
func (*fakeTree) smartctlJSON(string) (map[string]json.RawMessage, error) {
	return map[string]json.RawMessage{}, nil
}
