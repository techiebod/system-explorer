package main

// arrays: /sys/block/*/md, one row per md array — the walk the reference's
// _md_scrape makes, over the transcribed tree, with the same disciplines: a
// member attribute sysfs did not yield is left off the member rather than
// carried as null, and Status is the state an operator MEANS — the sync
// action while one runs, else the array state, because array_state stays
// "clean" during a resync and only tracks superblock dirtiness.

import (
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"strconv"
	"strings"
)

// mdActiveSync is the rulebook's own vocabulary for a sync in progress.
var mdActiveSync = map[string]bool{
	"resync": true, "recover": true, "check": true, "repair": true,
	"reshape": true,
}

func collectArrays(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	tree, err := src.mdTree()
	var refused *declined
	if errors.As(err, &refused) {
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     refused.reason,
			Detail:     refused.detail,
		})
		if refused.reason == "absent" {
			out.emit(commitRecord{Record: "commit", Collection: collection, Generation: generation})
		}
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	emitted := 0
	for _, name := range tree.listdir("/sys/block") {
		md := "/sys/block/" + name + "/md"
		// The listing is the probe: a device with no md directory lists
		// nothing, and an md directory is never empty.
		entries := tree.listdir(md)
		if len(entries) == 0 {
			continue
		}
		at, err := src.stamp(*objects)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}

		facts := newObject()
		var absent []string
		keep := func(fact, text string, ok bool) {
			if ok {
				facts.set(fact, stringValue(text))
			} else {
				absent = append(absent, fact)
			}
		}
		read := func(member string) (string, bool) { return tree.read(md + "/" + member) }

		level, haveLevel := read("level")
		arrayState, haveState := read("array_state")
		action, haveAction := read("sync_action")
		// Status is the state an operator means: the sync action while one
		// runs, else the array state.
		status, haveStatus := arrayState, haveState
		if haveAction && mdActiveSync[action] {
			status, haveStatus = action, true
		}
		keep("Status", status, haveStatus)
		keep("Level", level, haveLevel)
		keep("ArrayState", arrayState, haveState)
		keepIntFile := func(fact, member string) (int64, bool) {
			text, ok := read(member)
			if !ok {
				absent = append(absent, fact)
				return 0, false
			}
			n, err := strconv.ParseInt(text, 10, 64)
			if err != nil {
				absent = append(absent, fact)
				return 0, false
			}
			facts.set(fact, intValue(n))
			return n, true
		}
		keepIntFile("Degraded", "degraded")
		keepIntFile("RaidDisks", "raid_disks")
		metadata, haveMetadata := read("metadata_version")
		keep("MetadataVersion", metadata, haveMetadata)
		uuid, haveUUID := read("uuid")
		keep("UUID", uuid, haveUUID)
		keep("SyncAction", action, haveAction)
		// sync_completed spells "done / total" sectors mid-sync and a bare
		// word otherwise; the percentage keeps Python's one-decimal
		// half-even rounding.
		completed, haveCompleted := read("sync_completed")
		percentSet := false
		if haveCompleted && strings.Contains(completed, "/") {
			parts := strings.SplitN(completed, "/", 2)
			done, doneErr := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
			total, totalErr := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
			if doneErr == nil && totalErr == nil && total != 0 {
				percent := math.RoundToEven(float64(done)*100/float64(total)*10) / 10
				facts.set("SyncPercent", floatValue(percent))
				percentSet = true
			}
		}
		if !percentSet {
			absent = append(absent, "SyncPercent")
		}
		if sectors, ok := tree.read("/sys/block/" + name + "/size"); ok {
			if n, err := strconv.ParseInt(sectors, 10, 64); err == nil {
				facts.set("SizeBytes", intValue(n*512))
			} else {
				absent = append(absent, "SizeBytes")
			}
		} else {
			absent = append(absent, "SizeBytes")
		}

		// Members, in the listing's order; each attribute sysfs did not
		// yield is left off the member — the rulebook reads members with
		// .get() and treats the gap as no statement.
		members := newArray()
		erroring := newArray()
		for _, entry := range entries {
			if !strings.HasPrefix(entry, "dev-") {
				continue
			}
			dev := md + "/" + entry
			kname := path.Base(tree.realpath(dev + "/block"))
			member := newObject()
			member.set("Device", stringValue("block-device:"+kname))
			if state, ok := tree.read(dev + "/state"); ok {
				member.set("State", stringValue(state))
			}
			if slot, ok := tree.read(dev + "/slot"); ok {
				member.set("Slot", stringValue(slot))
			}
			if text, ok := tree.read(dev + "/errors"); ok {
				if n, err := strconv.ParseInt(text, 10, 64); err == nil {
					member.set("Errors", intValue(n))
					if n != 0 {
						erroring.append(stringValue("block-device:" + kname))
					}
				}
			}
			members.append(member)
		}
		facts.set("Members", members)
		// Minted because the rule vocabulary names one fact and a literal:
		// "a member with a non-zero error counter" is a predicate inside a
		// list of objects, which no closed condition can say — the same
		// reasoning as hardware's derived judgement facts.
		facts.set("MembersWithErrors", erroring)

		record := objectRecord{
			Record:     "object",
			Collection: collection,
			Name:       name,
			Type:       levelOr(level, haveLevel),
			Facts:      facts.encode(),
			Absent:     sortedStrings(absent),
			At:         at,
		}
		// The md NUMBER moves — md126 today can assemble as md0 next boot —
		// and the uuid does not, so the uuid is the family a collator keys
		// rename survival on (register row 6's audit).
		if haveUUID && uuid != "" {
			names := newObject()
			stable := newObject()
			stable.set("uuid", stringValue(uuid))
			names.set("stable", stable)
			record.Names = names.encode()
		}
		out.emit(record)
		*objects++
		emitted++
	}
	out.emit(commitRecord{
		Record: "commit", Collection: collection, Generation: generation,
		Objects: emitted,
	})
	return exitOK
}

// levelOr is the reference's `arr["level"] or "md-array"`: the row's type is
// the raid level where sysfs reports one.
func levelOr(level string, have bool) string {
	if have && level != "" {
		return level
	}
	return "md-array"
}
