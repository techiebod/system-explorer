package main

import (
	"errors"
	"fmt"
)

// volumeRows is adapters/docker.py `_volume_items()`: one row per entry of the
// /volumes document's `Volumes` member, in the order dockerd listed them. The
// member is `raw.get("Volumes") or []`, so a document whose Volumes is null —
// which is what a daemon with no volumes at all can answer — is a reading of
// zero volumes rather than a failure.
func volumeRows(document *value) ([]row, error) {
	if document == nil || document.kind != jsonObject {
		return nil, errors.New("the staged volumes payload is not a document")
	}
	list := document.get("Volumes")
	if !list.stated() {
		return nil, nil
	}
	if list.kind != jsonArray {
		return nil, errors.New("the volumes document's Volumes member is not a list")
	}
	rows := make([]row, 0, len(list.items))
	for i, volume := range list.items {
		name := volume.get("Name")
		if !name.isString() {
			// Indexed directly by the reference, which raises without one.
			return nil, fmt.Errorf("volume %d has no name", i)
		}
		facts := newObject()
		facts.set("Driver", volume.get("Driver"))
		facts.set("Mountpoint", volume.get("Mountpoint"))
		facts.set("ComposeProject", volume.dig("Labels", composeProject))
		rows = append(rows, row{name: name.text, facts: facts})
	}
	return rows, nil
}
