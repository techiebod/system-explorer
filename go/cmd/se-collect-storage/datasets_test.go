// The dataset rows' own disciplines, staged to the shapes the corpus cannot
// reach: the ProtectSystem mask (which needs a sandboxed reader, so no
// unsandboxed capture produces it — corpus.NAMED_RESIDUALS names this file
// as the venue), the property helpers' None-vs-empty edges, and the decline
// on a host with no zfs.
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func stageDatasets(t *testing.T, document string) map[string]string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "zfs-list.json"),
		[]byte(document), 0o644); err != nil {
		t.Fatal(err)
	}
	return replayEnv(dir)
}

// The 2026-08-10 audit's shape: libzfs derives readonly from the QUERYING
// process's mount table, so under ProtectSystem=strict a mounted dataset
// reports on/temporary while PID 1's table says rw. The sandbox's value is
// not the dataset's: the fact is masked onto the unobservable channel, never
// published and never nulled.
func TestATemporaryReadonlySourceMasksTheFact(t *testing.T) {
	env := stageDatasets(t, `{"datasets": {"tank/data": {
		"name": "tank/data", "type": "FILESYSTEM",
		"properties": {
			"used": {"value": "1024", "source": {"type": "NONE", "data": "-"}},
			"available": {"value": "1024", "source": {"type": "NONE", "data": "-"}},
			"usedbysnapshots": {"value": "0", "source": {"type": "NONE", "data": "-"}},
			"mountpoint": {"value": "/tank/data", "source": {"type": "DEFAULT", "data": "-"}},
			"canmount": {"value": "on", "source": {"type": "DEFAULT", "data": "-"}},
			"readonly": {"value": "on", "source": {"type": "TEMPORARY", "data": "-"}},
			"mounted": {"value": "yes", "source": {"type": "NONE", "data": "-"}}
		}}}}`)
	code, stdout, stderr := runWith(t, "collect datasets:7\n", env)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	object := ofKind(records, "object")[0]
	facts := object["facts"].(map[string]any)
	if _, published := facts["ReadOnly"]; published {
		t.Fatal("a masked ReadOnly must not publish the sandbox's value as the dataset's")
	}
	if facts["ReadOnlyUnobservable"] == nil || facts["ReadOnlySource"] != "temporary" {
		t.Fatalf("the mask states itself in facts: %+v", facts)
	}
	unobservables := ofKind(records, "unobservable")
	if len(unobservables) != 1 || unobservables[0]["fact"] != "ReadOnly" ||
		unobservables[0]["reason"] != "unavailable" {
		t.Fatalf("the masked fact rides its own channel: %+v", unobservables)
	}
	commit := ofKind(records, "commit")[0]
	if commit["unobservable"] != float64(1) {
		t.Fatalf("the commit counts what the channel carried: %+v", commit)
	}
	// UsePercent at the half boundary: 1024 of 2048 is 50 exactly — a
	// reading, not a mask casualty.
	if facts["UsePercent"] != float64(50) {
		t.Fatalf("%v", facts["UsePercent"])
	}
	// The wire's type is lowercase by schema; zfs spells it FILESYSTEM.
	if object["type"] != "filesystem" {
		t.Fatalf("type %v", object["type"])
	}
}

// The property helpers' edges: an empty value is absent (`or None`), a NONE
// source is no statement, an INHERITED one names its ancestor.
func TestPropertyEdgesMatchTheReference(t *testing.T) {
	env := stageDatasets(t, `{"datasets": {"tank": {
		"name": "tank", "type": "FILESYSTEM",
		"properties": {
			"used": {"value": "", "source": {"type": "NONE", "data": "-"}},
			"available": {"value": "10", "source": {"type": "NONE", "data": "-"}},
			"usedbysnapshots": {"value": "0", "source": {"type": "NONE", "data": "-"}},
			"mountpoint": {"value": "/tank", "source": {"type": "INHERITED", "data": "up/stream"}},
			"canmount": {"value": "on", "source": {"type": "LOCAL", "data": "-"}},
			"readonly": {"value": "off", "source": {"type": "NONE", "data": "-"}},
			"mounted": {"value": "yes", "source": {"type": "NONE", "data": "-"}}
		}}}}`)
	code, stdout, stderr := runWith(t, "collect datasets:9\n", env)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	object := ofKind(records, "object")[0]
	facts := object["facts"].(map[string]any)
	if facts["MountpointSource"] != "inherited from up/stream" ||
		facts["CanMountSource"] != "local" {
		t.Fatalf("%+v", facts)
	}
	if _, present := facts["ReadOnlySource"]; present {
		t.Fatal("a NONE source is no statement, not the word none")
	}
	// An empty used value is absent, and the derivation that needs it is
	// absent with it — never a zero invented from a blank.
	absent := object["absent"].([]any)
	wantAbsent := map[string]bool{"UsedBytes": true, "UsePercent": true}
	for _, name := range absent {
		delete(wantAbsent, name.(string))
	}
	if len(wantAbsent) != 0 {
		t.Fatalf("absent %v missing %v", absent, wantAbsent)
	}
	if facts["SnapshotUsedBytes"] != float64(0) {
		t.Fatal("a zero reading is a reading, never absence")
	}
}

// A payload directory with no zfs-list document is a host with no zfs:
// absent, authoritative-empty, committing zero — the zpool seam's own
// reading through the same constant.
func TestNoZfsDeclinesAbsentAndCommitsZero(t *testing.T) {
	dir := t.TempDir()
	code, stdout, stderr := runWith(t, "collect datasets:3\n", replayEnv(dir))
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	decline := ofKind(records, "decline")[0]
	if decline["reason"] != "absent" {
		t.Fatalf("%+v", decline)
	}
	commit := ofKind(records, "commit")[0]
	if commit["collection"] != "datasets" || commit["objects"] != float64(0) {
		t.Fatalf("absent retires: %+v", commit)
	}
}
