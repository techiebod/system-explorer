package main

// The mounts collection (register row 9, R3b): PID 1's mount table in the
// tree order findmnt reports it, ported from the reference's _mount_items.
// The applied order IS the mount hierarchy walked depth-first, and a
// pseudo-filesystem's missing size is the absent list's statement — findmnt
// says null, and null is no channel at all.

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var mountFacts = [...]struct{ fact, member string }{
	{"Source", "source"},
	{"FsType", "fstype"},
	{"Options", "options"},
	{"SizeBytes", "size"},
	{"UsedBytes", "used"},
	{"AvailBytes", "avail"},
}

func collectMounts(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	at, err := src.stamp(*objects)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	doc, fellBack, err := src.findmnt()
	if err != nil {
		if errors.Is(err, errUncaptured) {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: "unavailable", Detail: "findmnt did not answer on this host"})
		fmt.Fprintln(stderr, "findmnt:", err)
		return exitOK
	}
	if fellBack {
		// The sandbox view, not the host's: said where a person debugging
		// reads, never invented into the stream. The provenance channel
		// proper is the evidence verb's, at R3c.
		fmt.Fprintln(stderr, "findmnt: PID 1's namespace was not readable; "+
			"serving this process's own mount view")
	}

	emitted := 0
	var walk func(nodes *value) int
	walk = func(nodes *value) int {
		if nodes == nil {
			return exitOK
		}
		for _, node := range nodes.items {
			target := node.get("target")
			if !target.isString() {
				continue
			}
			facts := newFactSet()
			for _, mapping := range mountFacts {
				member := node.get(mapping.member)
				if isNone(member) {
					facts.put(mapping.fact, nil)
				} else {
					facts.put(mapping.fact, member)
				}
			}
			facts.put("UsePercent", usePercentValue(node.get("use%")))
			factValues, absent := facts.split()
			out.emit(objectRecord{
				Record:     "object",
				Collection: collection,
				Name:       target.text,
				Type:       "mount",
				Facts:      factValues.encode(),
				Absent:     absent,
				At:         at,
			})
			emitted++
			*objects++
			walk(node.get("children"))
		}
		return exitOK
	}
	walk(doc.get("filesystems"))

	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    emitted,
	})
	return exitOK
}

// usePercentValue parses findmnt's "42%" into the integer the capacity
// rules judge; nil (the absent statement) where the member is null or not
// a percentage — the reference's own tolerance.
func usePercentValue(raw *value) *value {
	if isNone(raw) {
		return nil
	}
	text := raw.text
	if raw.kind != jsonString {
		return nil
	}
	parsed, err := strconv.Atoi(strings.TrimSuffix(text, "%"))
	if err != nil {
		return nil
	}
	return &value{kind: jsonNumber, text: strconv.Itoa(parsed)}
}
