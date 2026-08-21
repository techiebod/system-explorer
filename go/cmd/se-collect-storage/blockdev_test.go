// The flatten's hardest-won rule, on the shape the lab cannot stage: an md
// array is listed under EVERY member it is assembled from, and emitting a
// row per appearance once put the same object id in one page twice. First
// appearance wins the position, every parent is kept, and the Parents fact
// says how many there really are.
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const mdTree = `{"blockdevices": [
  {"name": "sda", "type": "disk", "size": "1T", "fstype": null,
   "mountpoints": [null], "model": "X", "serial": "S1", "rota": true,
   "rm": false, "tran": "sata", "children": [
     {"name": "md126", "type": "raid1", "size": "1T",
      "fstype": "ext4", "mountpoints": ["/data"], "model": null,
      "serial": null, "rota": true, "rm": false, "tran": null}]},
  {"name": "sdb", "type": "disk", "size": "1T", "fstype": null,
   "mountpoints": [null], "model": "X", "serial": "S2", "rota": true,
   "rm": false, "tran": "sata", "children": [
     {"name": "md126", "type": "raid1", "size": "1T",
      "fstype": "ext4", "mountpoints": ["/data"], "model": null,
      "serial": null, "rota": true, "rm": false, "tran": null}]}
]}`

func TestAMultiParentDeviceIsOneRowCarryingEveryParent(t *testing.T) {
	doc, err := decodeDocument([]byte(mdTree))
	if err != nil {
		t.Fatal(err)
	}
	devices := flattenDevices(doc.get("blockdevices"))
	names := []string{}
	for _, device := range devices {
		names = append(names, device.node.get("name").text)
	}
	if len(names) != 3 || names[0] != "sda" || names[1] != "md126" || names[2] != "sdb" {
		t.Fatalf("first appearance wins the position, once: %v", names)
	}
	md := devices[1]
	if len(md.parents) != 2 || md.parents[0] != "sda" || md.parents[1] != "sdb" {
		t.Fatalf("every parent is kept, in encounter order: %v", md.parents)
	}
}

func TestNullMembersLandOnTheAbsentListNotInTheFacts(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lsblk.json"), []byte(mdTree), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runWith(t, "collect block-devices:3\n",
		map[string]string{"SE_REPLAY_DIR": dir})
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := ofKind(parseRecords(t, stdout), "object")
	first := records[0]
	if first["type"] != "disk" || first["name"] != "sda" {
		t.Fatalf("%+v", first)
	}
	facts := first["facts"].(map[string]any)
	if _, present := facts["FsType"]; present {
		t.Fatalf("null fstype must be absent, not a fact: %+v", facts)
	}
	var listed []string
	for _, name := range first["absent"].([]any) {
		listed = append(listed, name.(string))
	}
	if len(listed) != 1 || listed[0] != "FsType" {
		t.Fatalf("%v", listed)
	}
	// The padded null mountpoint is dropped, and the empty list is a value.
	if points, _ := json.Marshal(facts["Mountpoints"]); string(points) != "[]" {
		t.Fatalf("%s", points)
	}
	if md := records[1]; md["type"] != "raid1" {
		t.Fatalf("the row's kind is lsblk's own word: %+v", md)
	}
}
