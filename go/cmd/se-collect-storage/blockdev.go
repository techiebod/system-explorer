package main

// The block-devices collection (register row 9, R3b): every block device
// on the host, one row per DEVICE and not per appearance, ported from the
// reference's _block_items with its hardest-won rule intact. lsblk's tree
// is containment and containment is not a tree — an md array is listed
// under every member it is assembled from — so first appearance wins the
// position and every parent is kept: the applied order is a real path to
// each device, and the Parents fact is the truth a single tree coordinate
// cannot state.
//
// Facts travel verbatim from the document — lsblk's own booleans, its own
// human-readable sizes — and a JSON null is the absent list's statement,
// never a null fact: a partition has no MODEL, a virtual device no TRAN,
// and the source says so with a null the stream refuses to carry.

import (
	"errors"
	"fmt"
	"io"
)

// blockFacts maps the emitted fact names to lsblk's member names, in the
// declared order.
var blockFacts = [...]struct{ fact, member string }{
	{"Type", "type"},
	{"Size", "size"},
	{"FsType", "fstype"},
	{"Model", "model"},
	{"Serial", "serial"},
	{"Rotational", "rota"},
	{"Removable", "rm"},
	{"Transport", "tran"},
}

type flatDevice struct {
	node    *value
	parents []string
}

// flattenDevices walks the lsblk tree: first appearance wins the position,
// every parent is kept, insertion order preserved.
func flattenDevices(nodes *value) []*flatDevice {
	seen := map[string]*flatDevice{}
	order := []string{}
	var walk func(children *value, parent string)
	walk = func(children *value, parent string) {
		if children == nil {
			return
		}
		for _, node := range children.items {
			name := node.get("name")
			if !name.isString() {
				continue
			}
			entry := seen[name.text]
			if entry == nil {
				entry = &flatDevice{node: node}
				if parent != "" {
					entry.parents = []string{parent}
				}
				seen[name.text] = entry
				order = append(order, name.text)
			} else if parent != "" && !contains(entry.parents, parent) {
				entry.parents = append(entry.parents, parent)
			}
			walk(node.get("children"), name.text)
		}
	}
	walk(nodes, "")
	out := make([]*flatDevice, 0, len(order))
	for _, name := range order {
		out = append(out, seen[name])
	}
	return out
}

func contains(list []string, want string) bool {
	for _, item := range list {
		if item == want {
			return true
		}
	}
	return false
}

func collectBlockDevices(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	at, err := src.stamp(*objects)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	doc, err := src.lsblk()
	if err != nil {
		if errors.Is(err, errUncaptured) {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		// Present but not answering — a host without lsblk still HAS block
		// devices, so absence of the tool must not retire them.
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: "unavailable", Detail: "lsblk did not answer on this host"})
		fmt.Fprintln(stderr, "lsblk:", err)
		return exitOK
	}

	emitted := 0
	for _, device := range flattenDevices(doc.get("blockdevices")) {
		name := device.node.get("name").text
		facts := newFactSet()
		for _, mapping := range blockFacts {
			member := device.node.get(mapping.member)
			if isNone(member) {
				facts.put(mapping.fact, nil)
			} else {
				facts.put(mapping.fact, member)
			}
		}
		// Mountpoints drops the null and empty members exactly as the
		// reference does: an unmounted filesystem contributes nothing to
		// the answer "where is this mounted".
		mountpoints := newArray()
		if raw := device.node.get("mountpoints"); raw != nil {
			for _, m := range raw.items {
				if m.isString() && m.text != "" {
					mountpoints.append(m)
				}
			}
		}
		facts.put("Mountpoints", mountpoints)
		parents := newArray()
		for _, parent := range device.parents {
			parents.append(&value{kind: jsonString, text: parent})
		}
		facts.put("Parents", parents)

		factValues, absent := facts.split()
		kind := "disk"
		if t := device.node.get("type"); t.isString() && t.text != "" {
			kind = t.text
		}
		out.emit(objectRecord{
			Record:     "object",
			Collection: collection,
			Name:       name,
			Type:       kind,
			Facts:      factValues.encode(),
			Absent:     absent,
			At:         at,
		})
		emitted++
		*objects++
	}
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    emitted,
	})
	return exitOK
}
