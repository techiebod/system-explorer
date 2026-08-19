package main

import (
	"reflect"
	"testing"
)

func names(rows []pkgRow) []string {
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.native)
	}
	return out
}

// dpkg keeps a row for a package that was removed but kept its configuration,
// and half a package is not an installed one. Every row of every committed
// capture is `installed`, so replay equivalence cannot see this filter at all
// — which is why it is asserted here and minted by a mutation operator there.
func TestOnlyInstalledDpkgRowsAreInstalled(t *testing.T) {
	rows := inventory(reading{manager: managerDpkg, rows: [][]string{
		{"adduser", "3.153ubuntu1", "all", "installed"},
		{"ifupdown", "0.8.41", "amd64", "config-files"},
		{"zstd", "1.5.7+dfsg-3", "amd64", "installed"},
	}})
	if got := names(rows); !reflect.DeepEqual(got, []string{"adduser", "zstd"}) {
		t.Fatalf("the removed-but-configured row was published: %v", got)
	}
}

// rpm reports only what is installed, so its rows have no status field to
// filter on — and a three-field row must not be read as a fourth field that
// happens to be missing and therefore not-installed.
func TestEveryRPMRowIsPublished(t *testing.T) {
	rows := inventory(reading{manager: managerRPM, rows: [][]string{
		{"bash", "5.2.26-1.fc44", "x86_64"},
		{"filesystem", "3.18-24.fc44", "x86_64"},
	}})
	if got := names(rows); !reflect.DeepEqual(got, []string{"bash", "filesystem"}) {
		t.Fatalf("an rpm row went missing: %v", got)
	}
}

// Codepoint order, which is what the reference's sort gives: a digit precedes
// every letter and an uppercase letter precedes every lowercase one. A port
// sorting case-insensitively or by locale would move both edges.
func TestRowsAreOrderedByCodepointNotByLocale(t *testing.T) {
	rows := inventory(reading{manager: managerDpkg, rows: [][]string{
		{"adduser", "1", "all", "installed"},
		{"Zulu", "1", "all", "installed"},
		{"3cpio", "1", "amd64", "installed"},
		{"zstd", "1", "amd64", "installed"},
	}})
	if got := names(rows); !reflect.DeepEqual(got, []string{"3cpio", "Zulu", "adduser", "zstd"}) {
		t.Fatalf("order is %v", got)
	}
}

// A multi-arch install is one name twice, so the two rows tie on both members
// of the sort key. Stable order keeps them as the interface listed them; an
// unstable sort would swap them between runs and make the pair
// non-deterministic for no reading of the machine at all.
func TestATiedPairKeepsTheOrderTheInterfaceListedThemIn(t *testing.T) {
	rows := inventory(reading{manager: managerDpkg, rows: [][]string{
		{"libz1", "1.3-1", "amd64", "installed"},
		{"libz1", "1.3-1", "i386", "installed"},
	}})
	if len(rows) != 2 || rows[0].facts["Architecture"] != "amd64" || rows[1].facts["Architecture"] != "i386" {
		t.Fatalf("the tied pair was reordered: %v", rows)
	}
}

// The divergence from the Python reference, asserted so it cannot be undone
// by accident: `version or None` puts a JSON null on the wire, and a fact
// value is never null (DESIGN 19) — the stream rules refuse one at any depth.
// A field the manager did not report goes on the absent channel, which is the
// statement that was meant.
func TestAFieldTheManagerDidNotReportIsAbsentAndNeverNullOrBlank(t *testing.T) {
	rows := inventory(reading{manager: managerDpkg, rows: [][]string{
		{"halfrow", "", "", "installed"},
	}})
	if len(rows) != 1 {
		t.Fatalf("rows: %v", rows)
	}
	if _, carried := rows[0].facts["Version"]; carried {
		t.Error("an unreported version was published as a fact value")
	}
	if !reflect.DeepEqual(rows[0].absent, []string{"Version", "Architecture"}) {
		t.Errorf("absent is %v", rows[0].absent)
	}
}

// A short row is missing fields, not a parse failure: the reference pads every
// row to its format string's field count before unpacking it, and the count is
// a contract only because the format is this collector's own.
func TestAShortRowIsPaddedRatherThanDropped(t *testing.T) {
	rows := inventory(reading{manager: managerDpkg, rows: [][]string{{"lonely"}}})
	if len(rows) != 1 || rows[0].native != "lonely" {
		t.Fatalf("rows: %v", rows)
	}
	if rows[0].facts["Manager"] != managerDpkg {
		t.Fatalf("facts: %v", rows[0].facts)
	}
}

// The store publishes one token and the split has to find the version inside
// it. Non-greedy at the FIRST hyphen followed by a digit, so a package whose
// own name carries a version-looking segment keeps it.
func TestNixNameVersionSplitsAtTheFirstDigitLedComponent(t *testing.T) {
	store := map[string]string{
		"hello-2.12.1":            "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-2.12.1",
		"python3.11-numpy-1.26.4": "/nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-python3.11-numpy-1.26.4",
		"system-path":             "/nix/store/cccccccccccccccccccccccccccccccc-system-path",
	}
	byNative := map[string]pkgRow{}
	for _, row := range inventory(reading{manager: managerNix, store: store}) {
		byNative[row.native] = row
	}
	for native, want := range map[string][2]string{
		"hello-2.12.1":            {"hello", "2.12.1"},
		"python3.11-numpy-1.26.4": {"python3.11-numpy", "1.26.4"},
	} {
		row := byNative[native]
		if row.facts["Name"] != want[0] || row.facts["Version"] != want[1] {
			t.Errorf("%s split to %q/%q, want %q/%q", native, row.facts["Name"], row.facts["Version"], want[0], want[1])
		}
		if row.facts["StorePath"] != store[native] {
			t.Errorf("%s lost its store path", native)
		}
	}
	// A store name with no version at all is the reachable half of the null
	// defect: on any NixOS host `system-path` and its siblings carry none.
	unversioned := byNative["system-path"]
	if unversioned.facts["Name"] != "system-path" {
		t.Errorf("an unversioned name must fall back to the whole token, got %q", unversioned.facts["Name"])
	}
	if !reflect.DeepEqual(unversioned.absent, []string{"Version"}) {
		t.Errorf("an unversioned package declares Version absent, got %v", unversioned.absent)
	}
}

// Architecture and StorePath are not two spellings of the same slot: a fact a
// manager has no concept of is not "absent", which means we read a document
// that could have carried it and it did not.
func TestAManagerPublishesOnlyTheFactsItsInterfaceIsAbout(t *testing.T) {
	dpkg := inventory(reading{manager: managerDpkg, rows: [][]string{
		{"adduser", "3.153ubuntu1", "all", "installed"}}})[0]
	if _, carried := dpkg.facts["StorePath"]; carried {
		t.Error("a dpkg row carries no store path")
	}
	for _, name := range dpkg.absent {
		if name == "StorePath" {
			t.Error("dpkg has no store, so StorePath is not something we looked for and missed")
		}
	}

	nix := inventory(reading{manager: managerNix, store: map[string]string{
		"hello-2.12.1": "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-hello-2.12.1"}})[0]
	if _, carried := nix.facts["Architecture"]; carried {
		t.Error("the Nix store reports no architecture")
	}
	for _, name := range nix.absent {
		if name == "Architecture" {
			t.Error("the store has no architecture field, so it is not absent from one")
		}
	}
}
