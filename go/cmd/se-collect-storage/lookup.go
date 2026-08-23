package main

// The lookup verb: a parameterised read-only question (DESIGN 18), answered
// as one object record — collection `lookups`, named `<name>/<input>` — then
// the terminator. This collector's palette holds one question, snapshots-of:
// a dataset's snapshots run to thousands, so they are a lookup scoped to one
// dataset rather than a collection the UI would re-poll. The newest rows
// render; the rest is a stated count, never a silent cap.

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// datasetArg is the safety gate for the argv token, not full zfs-name
// validation: alnum start (no leading dash), the zfs name charset, optional
// trailing /* marker handled by the caller.
var datasetArg = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:%/-]{0,254}$`)

const snapshotDisplayCap = 100

// verbEndRecord arrives with this collector's first request-shaped verb;
// object and evidence will share it when the fleet rollout reaches here.
type verbEndRecord struct {
	Record    string `json:"record"`
	Verb      string `json:"verb"`
	Truncated bool   `json:"truncated"`
}

func verbExit(out *emitter, stderr io.Writer) int {
	if out.err != nil {
		fmt.Fprintln(stderr, "writing the response:", out.err)
		return exitRuntime
	}
	return exitOK
}

func serveLookup(stdout, stderr io.Writer, src source, name, input string) int {
	out := newEmitter(stdout)
	if name != "snapshots-of" {
		out.emit(declineRecord{Record: "decline", Collection: "lookups",
			Reason: "unsupported",
			Detail: "this collector's lookup palette holds snapshots-of only"})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "lookup"})
		return verbExit(out, stderr)
	}
	recursive := strings.HasSuffix(input, "/*")
	dataset := strings.TrimSuffix(input, "/*")
	if !datasetArg.MatchString(dataset) {
		// The collator is the validating party; this side still refuses a
		// token it could not pass safely, as data rather than a crash.
		out.emit(declineRecord{Record: "decline", Collection: "lookups",
			Reason: "unsupported",
			Detail: "not a plausible dataset name"})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "lookup"})
		return verbExit(out, stderr)
	}

	doc, err := src.snapshots(dataset, recursive)
	var refused *declined
	if errors.As(err, &refused) {
		out.emit(declineRecord{Record: "decline", Collection: "lookups",
			Reason: refused.reason, Detail: refused.detail})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "lookup"})
		return verbExit(out, stderr)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	type entry struct {
		name, of, kind, created string
		used, referenced        int64
		haveUsed, haveRef       bool
	}
	var entries []entry
	datasets := doc.get("datasets").object()
	for _, fullName := range keysOf(datasets) {
		snap := datasets.byKey[fullName]
		properties := snap.get("properties")
		sep := "#"
		if strings.Contains(fullName, "@") {
			sep = "@"
		}
		short, of := fullName, ""
		if i := strings.Index(fullName, sep); i >= 0 {
			short = sep + fullName[i+1:]
			of = fullName[:i]
		}
		one := entry{name: short, of: of,
			kind: asciiLower(pyStr(snap.get("type")))}
		one.used, one.haveUsed = datasetInt(properties, "used")
		one.referenced, one.haveRef = datasetInt(properties, "referenced")
		if seconds, ok := datasetInt(properties, "creation"); ok {
			one.created = time.Unix(seconds, 0).UTC().Format("2006-01-02T15:04:05Z")
		}
		entries = append(entries, one)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].created > entries[j].created
	})

	newest := newArray()
	var totalUsed int64
	for i, one := range entries {
		if one.haveUsed {
			totalUsed += one.used
		}
		if i >= snapshotDisplayCap {
			continue
		}
		item := newObject()
		item.set("Name", stringValue(one.name))
		if recursive && one.of != "" {
			item.set("Of", stringValue(one.of))
		}
		if one.kind != "" {
			item.set("Type", stringValue(one.kind))
		}
		if one.haveUsed {
			item.set("UsedBytes", intValue(one.used))
		}
		if one.haveRef {
			item.set("ReferencedBytes", intValue(one.referenced))
		}
		if one.created != "" {
			item.set("Created", stringValue(one.created))
		}
		newest.append(item)
	}

	facts := newObject()
	facts.set("Dataset", stringValue(dataset))
	facts.set("Recursive", &value{kind: jsonBool, boolean: recursive})
	facts.set("Count", intValue(int64(len(entries))))
	facts.set("TotalUsedBytes", intValue(totalUsed))
	facts.set("Newest", newest)
	if len(entries) > snapshotDisplayCap {
		facts.set("Omitted", stringValue(
			strconv.Itoa(len(entries)-snapshotDisplayCap)+
				" older entries not shown; evidence has all of them"))
	}
	at, err := src.stamp(0)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	out.emit(objectRecord{
		Record:     "object",
		Collection: "lookups",
		Name:       name + "/" + input,
		Type:       "lookup-result",
		Facts:      facts.encode(),
		At:         at,
	})
	out.emit(relationAssertionRecord{
		Record: "relation_assertion", Collection: "lookups",
		Name: name + "/" + input, Vantage: "lookups", Type: "member-of",
		Target: assertionTarget{Kind: "dataset", Name: dataset},
	})
	out.emit(verbEndRecord{Record: "verb_end", Verb: "lookup"})
	return verbExit(out, stderr)
}
