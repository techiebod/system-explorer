package main

import (
	"encoding/json"
	"testing"
)

func entry(t *testing.T, document string) *value {
	t.Helper()
	decoded, err := decodeDocument([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func factsJSON(t *testing.T, record *value) map[string]any {
	t.Helper()
	facts, err := entryFacts(record)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(facts.encode(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The payload the replay seam addresses is named by the ARGUMENT the reference
// dispatches on, run through se-reference-collector's slug(). Pinned by value
// as well as derived, because "derived from the same inputs" is worth nothing
// if the derivation is wrong: a name that is nearly right addresses no file,
// and the seam's refusal would read as "the interface was absent" — the one
// decline that retires objects.
func TestThePayloadNameIsTheSeamsOwnSlugOfTheArguments(t *testing.T) {
	if got := slugArgument([]string{"-r", "-n", "100"}); got != "r---n--100" {
		t.Fatalf("slug(['-r','-n','100']) is %q; the shim computes r---n--100", got)
	}
	if got := replayPayload(); got != "r---n--100.json" {
		t.Fatalf("the payload this binary looks for is %q, and the shim stages r---n--100.json", got)
	}
	// The other half: the name must MOVE with the bound. A constant somebody
	// remembered to edit is the failure this derivation exists to prevent.
	if got := slugArgument(pageArgs(40)); got != "r---n--40" {
		t.Fatalf("a different bound must produce a different payload name; got %q", got)
	}
	if got := slugArgument(nil); got != "root" {
		t.Fatalf("an argument that slugs to nothing is %q, and the shim answers root", got)
	}
}

// The live argv is the reference's fixed prefix plus the page arguments, and
// the page arguments are the ones the payload name is derived from. Held
// together here because the two lists are the same reading asked two ways.
func TestTheLiveArgvExtendsThePageArguments(t *testing.T) {
	argv := journalArgv(defaultLimit)
	want := []string{"-o", "json", "--no-pager", "-q", "-r", "-n", "100"}
	if len(argv) != len(want) {
		t.Fatalf("argv %v, want %v", argv, want)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Fatalf("argv %v, want %v", argv, want)
		}
	}
}

// The two type traps this collection carries, asserted together because they
// are one decision: journald spells every field as a string, the reference
// converts exactly one of them, and a port that converted both — or neither —
// would emit values a typed consumer reads differently while Python's == saw
// nothing (DESIGN 19, typed equality).
func TestPriorityBecomesAnIntegerAndPidStaysTheStringJournaldWrote(t *testing.T) {
	facts := factsJSON(t, entry(t, `{"PRIORITY":"3","_PID":"4321","MESSAGE":"x"}`))
	if priority, ok := facts["Priority"].(float64); !ok || priority != 3 {
		t.Errorf("Priority is %#v; the rulebook compares it numerically", facts["Priority"])
	}
	if pid, ok := facts["PID"].(string); !ok || pid != "4321" {
		t.Errorf("PID is %#v; it travels as journald spelled it", facts["PID"])
	}
}

// A member journald did not set is simply not a fact. It is NOT an absence
// claim: absent means "we read a document that could have carried it and it did
// not", and a kernel entry has no unit because no unit emitted it — which is
// inapplicability, and rule 7 omits those.
func TestAFieldTheEntryDoesNotCarryIsOmittedRatherThanAbsent(t *testing.T) {
	facts := factsJSON(t, entry(t, `{"MESSAGE":"audit: DENIED","PRIORITY":"4","_TRANSPORT":"kernel"}`))
	for _, fact := range []string{"SystemdUnit", "Command", "PID", "MessageId", "Container", "SystemdUserUnit"} {
		if _, present := facts[fact]; present {
			t.Errorf("%s is published for an entry that carries no such field", fact)
		}
	}
}

// A timestamp is derived, and the two readings that mean "no time was recorded"
// produce no fact at all. The reference publishes `"Timestamp": null` for both,
// which the stream rules and the contract's recursive fact_value refuse — so
// the reference cannot be reproduced faithfully and be lawful at once, and this
// takes the lawful half (the null-fact family, adjudication queue).
func TestATimestampWithNoTimeInItIsOmittedNeverNulled(t *testing.T) {
	present := factsJSON(t, entry(t, `{"__REALTIME_TIMESTAMP":"1787125570280809"}`))
	if present["Timestamp"] != "2026-08-19T07:46:10Z" {
		t.Errorf("Timestamp is %#v, want the UTC second the stamp names", present["Timestamp"])
	}
	for _, stamp := range []string{"0", "18446744073709551615"} {
		facts := factsJSON(t, entry(t, `{"__REALTIME_TIMESTAMP":"`+stamp+`"}`))
		if value, present := facts["Timestamp"]; present {
			t.Errorf("stamp %s published Timestamp %#v; a manufactured epoch is worse than an admitted absence, and a null is refused outright", stamp, value)
		}
	}
}

// Repetition is the signal priority cannot give, and it is keyed on the message
// TYPE where the emitter names one: two "Started session-N.scope." lines differ
// in their interpolated text and are the same message. A port that keyed on the
// text alone would report a pattern as a run of unrelated events — and would
// agree with this one on every entry whose emitter sets no MESSAGE_ID, which is
// most of them.
func TestRepetitionIsKeyedOnTheMessageTypeWhereTheEmitterNamesOne(t *testing.T) {
	same := []*value{
		entry(t, `{"__CURSOR":"a","MESSAGE_ID":"39f5","MESSAGE":"Started session-9.scope."}`),
		entry(t, `{"__CURSOR":"b","MESSAGE_ID":"39f5","MESSAGE":"Started session-8.scope."}`),
		entry(t, `{"__CURSOR":"c","MESSAGE":"Started session-7.scope."}`),
	}
	rows, err := entryRows(same)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]any{}
	for _, row := range rows {
		var facts map[string]any
		if err := json.Unmarshal(row.facts.encode(), &facts); err != nil {
			t.Fatal(err)
		}
		counts[row.name] = facts["RepeatCount"]
		if facts["RepeatWindow"] != float64(3) {
			t.Errorf("%s: RepeatWindow is %#v, and the page read 3 entries", row.name, facts["RepeatWindow"])
		}
	}
	if counts["a"] != float64(2) || counts["b"] != float64(2) {
		t.Errorf("the two entries sharing a MESSAGE_ID count %v/%v, want 2 each — the id names a message TYPE", counts["a"], counts["b"])
	}
	if counts["c"] != float64(1) {
		t.Errorf("the id-less entry counts %v, want 1 — its text matches neither of the others", counts["c"])
	}
}

// An identical message under two different catalogue ids is two identities, and
// an identical text with no id at all is one. Both directions, because a key
// that only ever prefers the id would also satisfy a port that ignored the text.
func TestTheRepeatIdentityDiscriminatesBothWays(t *testing.T) {
	cases := []struct {
		label      string
		a, b       string
		wantEquals bool
	}{
		{"same id, different text", `{"MESSAGE_ID":"aa","MESSAGE":"x"}`, `{"MESSAGE_ID":"aa","MESSAGE":"y"}`, true},
		{"different id, same text", `{"MESSAGE_ID":"aa","MESSAGE":"x"}`, `{"MESSAGE_ID":"bb","MESSAGE":"x"}`, false},
		{"no id, same text", `{"MESSAGE":"x"}`, `{"MESSAGE":"x"}`, true},
		{"no id, different text", `{"MESSAGE":"x"}`, `{"MESSAGE":"y"}`, false},
		{"empty id falls back to the text", `{"MESSAGE_ID":"","MESSAGE":"x"}`, `{"MESSAGE":"x"}`, true},
	}
	for _, c := range cases {
		got := repeatIdentity(entry(t, c.a)) == repeatIdentity(entry(t, c.b))
		if got != c.wantEquals {
			t.Errorf("%s: identities equal=%v, want %v", c.label, got, c.wantEquals)
		}
	}
}

// journalctl renders an entry whose bytes are not valid UTF-8 as an array of
// byte values, and the reference copies whatever it found onto the row. A port
// that decoded through map[string]any and re-encoded would turn those integers
// into floats, which a typed consumer reads as a different answer.
func TestABinaryMessagePassesThroughAsTheArrayJournalctlWrote(t *testing.T) {
	facts := factsJSON(t, entry(t, `{"MESSAGE":[104,105,255],"PRIORITY":"6"}`))
	message, ok := facts["Message"].([]any)
	if !ok || len(message) != 3 {
		t.Fatalf("Message is %#v, want the three byte values the document carried", facts["Message"])
	}
	// The token, not the value: 255 must not come back 255.0 or 2.55e2.
	raw, err := entryFacts(entry(t, `{"MESSAGE":[104,105,255]}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw.encode()); got != `{"Message":[104,105,255]}` {
		t.Fatalf("re-encoded as %s; a pass-through number keeps the wire's token", got)
	}
}

// An entry with no cursor cannot be named, and a row that cannot be named
// cannot be re-read. That is a broken document, so the batch reports "I could
// not run" rather than inventing a name or dropping the row silently.
func TestAnEntryWithNoCursorFailsTheBatch(t *testing.T) {
	if _, err := entryRows([]*value{entry(t, `{"MESSAGE":"x"}`)}); err == nil {
		t.Fatal("an entry with no __CURSOR was accepted, and nothing names it")
	}
}

// The field set is a CLOSED list and the collection publishes exactly it. A
// walk whose fields are an enum over the ones its author had met is the
// family-enum defect in a journal's clothes — and two of these ten appear in no
// capture the lab guest can produce, so this is the only place that says they
// are read at all.
func TestEveryDeclaredJournalFieldIsPublished(t *testing.T) {
	document := `{"__CURSOR":"c","MESSAGE":"m","MESSAGE_ID":"i","PRIORITY":"3",` +
		`"SYSLOG_IDENTIFIER":"s","_TRANSPORT":"journal","_SYSTEMD_UNIT":"u.service",` +
		`"_SYSTEMD_USER_UNIT":"init.scope","CONTAINER_NAME":"paperless","_COMM":"c","_PID":"9"}`
	facts := factsJSON(t, entry(t, document))
	for _, mapping := range factFields {
		if _, present := facts[mapping.fact]; !present {
			t.Errorf("%s is in the document and %s is not on the row", mapping.field, mapping.fact)
		}
	}
	if facts["Container"] != "paperless" || facts["SystemdUserUnit"] != "init.scope" {
		t.Errorf("the two fields no lab capture stages came back %#v/%#v", facts["Container"], facts["SystemdUserUnit"])
	}
}
