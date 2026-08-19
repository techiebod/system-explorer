package main

import (
	"fmt"
	"strconv"
	"time"
)

// The journald fields this collection publishes, and the fact each becomes.
// Order is the reference's own (adapters/logs.py FACT_FIELDS) and is kept for
// one reason only: a fact map written in a stable order makes two runs of one
// payload byte-identical, which is what the determinism check asks for. The
// judge compares facts member-wise, so order is never a claim.
//
// This slice is a CLOSED SET and the differential guard reads it as one: a
// walk whose fields are an enum over the ones its author had met is the
// family-enum defect wearing a journal's clothes, and two of these ten
// (CONTAINER_NAME, _SYSTEMD_USER_UNIT) appear in no committed capture at all —
// a container's stderr and a user manager's own log are shapes the lab guest
// does not stage, so replay equivalence cannot see them going missing.
var factFields = []struct{ field, fact string }{
	{"MESSAGE", "Message"},
	// The emitter's own catalog id for a message TYPE, so entries differing
	// only in interpolated values (a PID, a path) share it. Absent from plenty
	// of emitters, which is why repetition falls back to the text.
	{"MESSAGE_ID", "MessageId"},
	{"PRIORITY", "Priority"},
	{"SYSLOG_IDENTIFIER", "SyslogIdentifier"},
	// Which stream the entry arrived on. A container's stderr is mapped to
	// priority err by the journald log driver, so this is what distinguishes
	// "the application said this is an error" from "the application wrote to
	// stderr" — the single biggest source of misleading err entries.
	{"_TRANSPORT", "Transport"},
	{"_SYSTEMD_UNIT", "SystemdUnit"},
	{"_SYSTEMD_USER_UNIT", "SystemdUserUnit"},
	{"CONTAINER_NAME", "Container"},
	{"_COMM", "Command"},
	{"_PID", "PID"},
}

// The journal's own cursor: the entry's name, and the only thing that
// addresses one entry again afterwards.
const cursorField = "__CURSOR"

// systemd's unset u64. usec_to_iso refuses it and zero alike, because both
// mean "no time was recorded" rather than the epoch.
const unsetU64 uint64 = 1<<64 - 1

// entryFacts derives one entry's facts from its journal record.
//
// Every value but two is copied verbatim from the document, which is what
// keeps a binary MESSAGE (journalctl renders one as an array of byte values)
// and a PID (journald spells every field as a string, and this collection
// republishes _PID as one) reading the same on both sides. The two exceptions
// are the reference's own: PRIORITY is parsed to an integer because the
// rulebook compares it numerically, and __REALTIME_TIMESTAMP becomes an ISO
// instant.
func entryFacts(record *value) (*value, error) {
	facts := newObject()
	for _, mapping := range factFields {
		if !record.has(mapping.field) {
			continue
		}
		// A member present and JSON-null is dropped rather than republished.
		// The reference copies it and publishes a null fact value, which the
		// stream rules and the contract's recursive fact_value both refuse —
		// so the two cannot be faithful and lawful at once, and this takes the
		// lawful half (DESIGN 19; the null-fact family in the adjudication
		// queue). No journalctl output reaches it: journald has no null.
		member := record.get(mapping.field)
		if member.kind == jsonNull {
			continue
		}
		facts.set(mapping.fact, member)
	}

	if record.has("__REALTIME_TIMESTAMP") {
		usec, err := asUsec(record.get("__REALTIME_TIMESTAMP"))
		if err != nil {
			// The reference's int() raises here and the shim reports "I could
			// not run"; a timestamp that is not a number is a broken document,
			// never a statement about the machine.
			return nil, fmt.Errorf("__REALTIME_TIMESTAMP: %v", err)
		}
		// Omitted rather than published as null when the reading is 0 or the
		// unset u64 — the same lawful half as above. envelope.usec_to_iso
		// returns None for both and logs.py assigns it unconditionally, so the
		// reference emits `"Timestamp": null` there.
		if iso := usecToISO(usec); iso != "" {
			facts.set("Timestamp", stringValue(iso))
		}
	}

	// Parsed only when the document spelled it as a string, exactly as the
	// reference's isinstance check does: a document already carrying a number
	// is left as the number it was, and never routed through a float.
	if priority := facts.get("Priority"); priority.isString() {
		parsed, err := strconv.ParseInt(priority.text, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("PRIORITY %q is not an integer", priority.text)
		}
		facts.members.byKey["Priority"] = numberValue(parsed)
	}
	return facts, nil
}

// asUsec reads a microsecond reading spelled either way. journald writes every
// field as a string, so that is the path that runs; a number is accepted
// because the reference's int() accepts one, and both are read as an integer
// rather than through a float64 — a u64 microsecond stamp is above 2^53 and a
// float round trip would move it.
func asUsec(member *value) (uint64, error) {
	switch member.kind {
	case jsonString, jsonNumber:
		parsed, err := strconv.ParseUint(member.text, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%q is not a microsecond reading", member.text)
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("a microsecond reading is a number or a digit string")
	}
}

// usecToISO renders a systemd realtime stamp, or "" where there is no time to
// render. Second resolution, UTC, the reference's own strftime.
//
// Integer division rather than the reference's usec/1e6 float: the float path
// is exact for every value journald can produce (a double's spacing at epoch
// scale is ~2e-7s, and fromtimestamp rounds microseconds back out), so the two
// agree — this way simply cannot stop agreeing as the epoch grows.
func usecToISO(usec uint64) string {
	if usec == 0 || usec == unsetU64 {
		return ""
	}
	return time.Unix(int64(usec/1_000_000), 0).UTC().Format("2006-01-02T15:04:05Z")
}

// repeatIdentity is what "the same message" means for repetition counting.
//
// MESSAGE_ID first, because it names a message TYPE: two entries differing
// only in an interpolated PID share it, and counting them apart would report a
// pattern as a run of unrelated events. The fallback is the text itself, and
// the `msg:`/`id:` prefixes are what stop a message that happens to read like
// a catalog id from colliding with one.
func repeatIdentity(record *value) string {
	if id := record.get("MESSAGE_ID"); id.isString() && id.text != "" {
		return "id:" + id.text
	}
	message := record.get("MESSAGE")
	if message.isString() {
		return "msg:" + message.text
	}
	// Not a string — a binary MESSAGE, or none at all. The reference keys
	// those on repr(), whose Python spelling this cannot reproduce and does
	// not need to: what the key must do is tell two different values apart and
	// hold one value equal to itself, and the encoded JSON does both. A
	// difference here changes RepeatCount only if one page mixes several
	// non-string messages, which no capture stages — named in the report
	// rather than left as an unstated divergence.
	return "msg:" + string(message.encode())
}

// row is one published entry: the cursor it is named by, and its facts.
type row struct {
	name  string
	facts *value
}

// entryRows turns one page of journal records into the collection's rows.
//
// The repeat counts are PAGE-SCOPED and that is the whole of what they mean:
// they answer "is this line spam", which no single record can, and the window
// is the number of entries this read returned. Counted over the whole page
// before any row is built, because a count that grew as the page was walked
// would report the first occurrence as unique and the last as frequent.
func entryRows(records []*value) ([]row, error) {
	repeats := map[string]int64{}
	for _, record := range records {
		repeats[repeatIdentity(record)]++
	}
	window := int64(len(records))

	rows := make([]row, 0, len(records))
	for _, record := range records {
		cursor := record.get(cursorField)
		if !cursor.isString() || cursor.text == "" {
			// The reference indexes record["__CURSOR"] and raises without it.
			// An entry with no cursor cannot be named, and a row that cannot
			// be named cannot be re-read, so this is a broken document rather
			// than a reading.
			return nil, fmt.Errorf("a journal entry carries no %s, so nothing names it", cursorField)
		}
		facts, err := entryFacts(record)
		if err != nil {
			return nil, err
		}
		facts.set("RepeatCount", numberValue(repeats[repeatIdentity(record)]))
		facts.set("RepeatWindow", numberValue(window))
		rows = append(rows, row{name: cursor.text, facts: facts})
	}
	return rows, nil
}
