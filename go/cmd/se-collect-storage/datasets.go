package main

// datasets: `zfs list -j -p`, one row per dataset — the level protection
// joins against, and the level quotas and snapshots live at. The capacity
// gauge carries the same semantics the mounts carry: share of what this
// dataset could grow into, quota- or pool-bounded.

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
)

// datasetProp is the reference's _prop_value: the property's value member,
// with the empty string degraded to absent — `or None` in the original, so
// "" and a missing member are one statement.
func datasetProp(properties *value, key string) (string, bool) {
	entry := properties.get(key)
	if isNone(entry) {
		return "", false
	}
	text := pyStr(entry.get("value"))
	return text, text != ""
}

// datasetPropSource is the reference's _prop_source: NONE and absent are no
// statement, INHERITED names its ancestor, and everything else is the
// type's own word lowercased — `local`, `default`, `temporary`, `received`.
func datasetPropSource(properties *value, key string) (string, bool) {
	entry := properties.get(key)
	if isNone(entry) {
		return "", false
	}
	source := entry.get("source")
	if isNone(source) {
		return "", false
	}
	sourceType := pyStr(source.get("type"))
	switch sourceType {
	case "", "NONE":
		return "", false
	case "INHERITED":
		return "inherited from " + pyStr(source.get("data")), true
	}
	return asciiLower(sourceType), true
}

func asciiLower(s string) string {
	out := []rune(s)
	for i, r := range out {
		if 'A' <= r && r <= 'Z' {
			out[i] = r + ('a' - 'A')
		}
	}
	return string(out)
}

func datasetInt(properties *value, key string) (int64, bool) {
	text, ok := datasetProp(properties, key)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// maskReason is the ProtectSystem trap, verbatim from the reference: libzfs
// derives readonly from the QUERYING process's mount table, so under
// ProtectSystem=strict every mounted dataset reported ReadOnly=on/temporary
// while PID 1's table said rw — 21 rows across two hosts, every one wrong
// (2026-08-10 audit). The sandbox's value is not the dataset's: a temporary
// source masks the fact onto the unobservable channel — never a null
// standing where a fact should be — while the reason stays a string fact,
// because consumers cite it in place.
const readOnlyMaskReason = "masked by a temporary mount-option override in " +
	"the agent's own mount namespace (ProtectSystem=strict): zfs reads " +
	"/proc/self/mounts, not PID 1's. This dataset's mount row carries the " +
	"host's live read-only state."

func collectDatasets(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	doc, err := src.zfsList()
	var refused *declined
	if errors.As(err, &refused) {
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     refused.reason,
			Detail:     refused.detail,
		})
		// absent is authoritative-empty and the only decline reason that
		// commits: it must be able to retire datasets a previous batch
		// published.
		if refused.reason == "absent" {
			out.emit(commitRecord{Record: "commit", Collection: collection, Generation: generation})
		}
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	datasets := doc.get("datasets").object()
	emitted, unobservable := 0, 0
	for _, name := range keysOf(datasets) {
		at, err := src.stamp(*objects)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		entry := datasets.byKey[name]
		properties := entry.get("properties")

		facts := newObject()
		var absent []string
		keep := func(fact, text string, ok bool) {
			if ok {
				facts.set(fact, stringValue(text))
			} else {
				absent = append(absent, fact)
			}
		}
		keepInt := func(fact string, n int64, ok bool) {
			if ok {
				facts.set(fact, intValue(n))
			} else {
				absent = append(absent, fact)
			}
		}

		used, haveUsed := datasetInt(properties, "used")
		avail, haveAvail := datasetInt(properties, "available")
		keepInt("UsedBytes", used, haveUsed)
		keepInt("AvailBytes", avail, haveAvail)
		// Share of what this dataset could grow into — the same gauge the
		// mounts carry, under the half-even rounding both implementations
		// share (Python's round; math.RoundToEven here).
		if haveUsed && haveAvail && used+avail != 0 {
			facts.set("UsePercent", intValue(int64(
				math.RoundToEven(float64(used)*100/float64(used+avail)))))
		} else {
			absent = append(absent, "UsePercent")
		}
		snapshots, haveSnapshots := datasetInt(properties, "usedbysnapshots")
		keepInt("SnapshotUsedBytes", snapshots, haveSnapshots)
		// A door, not a datum: the UI routes lookup: ids to this
		// subsystem's lookups collection.
		facts.set("SnapshotsLookup", stringValue("lookup:snapshots-of/"+name))
		mountpoint, haveMountpoint := datasetProp(properties, "mountpoint")
		keep("Mountpoint", mountpoint, haveMountpoint)
		mountpointSource, haveMPSource := datasetPropSource(properties, "mountpoint")
		keep("MountpointSource", mountpointSource, haveMPSource)
		canMount, haveCanMount := datasetProp(properties, "canmount")
		keep("CanMount", canMount, haveCanMount)
		canMountSource, haveCMSource := datasetPropSource(properties, "canmount")
		keep("CanMountSource", canMountSource, haveCMSource)
		mounted, haveMounted := datasetProp(properties, "mounted")
		keep("Mounted", mounted, haveMounted)

		readonlySource, haveROSource := datasetPropSource(properties, "readonly")
		masked := haveROSource && readonlySource == "temporary"
		if masked {
			facts.set("ReadOnlyUnobservable", stringValue(readOnlyMaskReason))
		} else {
			readOnly, haveReadOnly := datasetProp(properties, "readonly")
			keep("ReadOnly", readOnly, haveReadOnly)
		}
		keep("ReadOnlySource", readonlySource, haveROSource)

		datasetType := pyStr(entry.get("type"))
		if datasetType == "" {
			datasetType = "filesystem"
		}
		out.emit(objectRecord{
			Record:     "object",
			Collection: collection,
			Name:       name,
			Type:       asciiLower(datasetType),
			Facts:      facts.encode(),
			Absent:     sortedStrings(absent),
			At:         at,
		})
		*objects++
		emitted++
		if masked {
			out.emit(unobservableRecord{
				Record: "unobservable", Collection: collection, Name: name,
				Fact: "ReadOnly", Reason: "unavailable", Detail: readOnlyMaskReason,
			})
			unobservable++
		}
	}
	out.emit(commitRecord{
		Record: "commit", Collection: collection, Generation: generation,
		Objects: emitted, Unobservable: unobservable,
	})
	return exitOK
}
