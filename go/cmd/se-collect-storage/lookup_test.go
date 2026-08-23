// The lookup verb, against a document taken from the lab pool the datasets
// variant stages — real zfs output, so the shapes are the tool's own.
package main

import (
	"os"
	"path/filepath"
	"testing"
)

const labSnapshots = `{"output_version": {"command": "zfs list", "vers_major": 0, "vers_minor": 1},
 "datasets": {
  "brimful/data@seed": {"name": "brimful/data@seed", "type": "SNAPSHOT",
   "pool": "brimful", "dataset": "brimful/data", "snapshot_name": "seed",
   "properties": {
    "used": {"value": "8408064", "source": {"type": "NONE", "data": "-"}},
    "creation": {"value": "1787466976", "source": {"type": "NONE", "data": "-"}},
    "referenced": {"value": "8543232", "source": {"type": "NONE", "data": "-"}}}},
  "brimful/data#mark": {"name": "brimful/data#mark", "type": "BOOKMARK",
   "pool": "brimful", "dataset": "brimful/data",
   "properties": {
    "used": {"value": "-", "source": {"type": "NONE", "data": "-"}},
    "creation": {"value": "1787467000", "source": {"type": "NONE", "data": "-"}},
    "referenced": {"value": "-", "source": {"type": "NONE", "data": "-"}}}}
 }}`

func stageLookup(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "zfs-snapshots-brimful-data.json"),
		[]byte(labSnapshots), 0o644); err != nil {
		t.Fatal(err)
	}
	return replayEnv(dir)
}

func TestLookupAnswersOneObjectAndItsEdge(t *testing.T) {
	code, stdout, stderr := runWith(t, "lookup snapshots-of brimful/data\n", stageLookup(t))
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	object := ofKind(records, "object")[0]
	if object["collection"] != "lookups" || object["name"] != "snapshots-of/brimful/data" ||
		object["type"] != "lookup-result" {
		t.Fatalf("%+v", object)
	}
	facts := object["facts"].(map[string]any)
	if facts["Count"] != float64(2) || facts["Dataset"] != "brimful/data" ||
		facts["Recursive"] != false {
		t.Fatalf("%+v", facts)
	}
	newest := facts["Newest"].([]any)
	// Newest first: the bookmark's creation is later than the snapshot's.
	first := newest[0].(map[string]any)
	if first["Name"] != "#mark" || first["Type"] != "bookmark" {
		t.Fatalf("newest-first ordering: %+v", first)
	}
	second := newest[1].(map[string]any)
	if second["Name"] != "@seed" || second["UsedBytes"] != float64(8408064) ||
		second["Created"] != "2026-08-23T06:36:16Z" {
		t.Fatalf("%+v", second)
	}
	// A bookmark's dash-valued used is absent from the entry, never zero:
	// zfs answers "-" for a property a bookmark does not carry.
	if _, present := first["UsedBytes"]; present {
		t.Fatalf("a dash is not a byte count: %+v", first)
	}
	// TotalUsedBytes sums what was measured.
	if facts["TotalUsedBytes"] != float64(8408064) {
		t.Fatalf("%v", facts["TotalUsedBytes"])
	}
	// The dataset edge, so the answer joins the row it is about.
	edge := ofKind(records, "relation_assertion")[0]
	if edge["type"] != "member-of" ||
		edge["target"].(map[string]any)["name"] != "brimful/data" {
		t.Fatalf("%+v", edge)
	}
	if terminator := ofKind(records, "verb_end")[0]; terminator["verb"] != "lookup" {
		t.Fatalf("%+v", terminator)
	}
}

func TestLookupRefusesWhatItCannotAskSafely(t *testing.T) {
	env := stageLookup(t)
	// An unknown palette name declines as data.
	code, stdout, _ := runWith(t, "lookup route-get 1.1.1.1\n", env)
	if code != exitOK {
		t.Fatalf("%d", code)
	}
	if decline := ofKind(parseRecords(t, stdout), "decline")[0]; decline["reason"] != "unsupported" {
		t.Fatalf("%+v", decline)
	}
	// A token the argv gate refuses declines as data — never sanitised,
	// never interpolated.
	code, stdout, _ = runWith(t, "lookup snapshots-of -oops\n", env)
	if code != exitOK {
		t.Fatalf("%d", code)
	}
	if decline := ofKind(parseRecords(t, stdout), "decline")[0]; decline["reason"] != "unsupported" {
		t.Fatalf("%+v", decline)
	}
	// The wrong token count is refused whole.
	code, _, _ = runWith(t, "lookup snapshots-of\n", env)
	if code != exitRequest {
		t.Fatalf("%d", code)
	}
}
