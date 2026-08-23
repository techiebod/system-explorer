package main

import (
	"sort"
	"strings"
	"testing"
)

// emittableFacts is every fact this derivation can set, built from the tables
// it is driven by rather than retyped — a list a test spelled itself would
// drift into agreement with whatever the code happened to do.
func emittableFacts() []string {
	facts := []string{}
	for _, pair := range inventoryMembers {
		facts = append(facts, pair.fact)
	}
	facts = append(facts, factPngxVersion)
	for _, pair := range storageMembers {
		facts = append(facts, pair.fact)
	}
	facts = append(facts, "StorageUsedPercent")
	facts = append(facts, factDatabaseStatus, factDatabaseError)
	for _, component := range taskComponents {
		facts = append(facts, component.statusFact, component.errorFact)
	}
	return append(facts, factStatusUnobservable)
}

func factNames(facts map[string]any) []string {
	names := make([]string, 0, len(facts))
	for name := range facts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// The committed capture's row, whole. Fourteen facts and no more, which is the
// count a reader can check against corpus/paperless/healthy/expected.jsonl by
// eye.
func TestTheCommittedDocumentsYieldTheCommittedRow(t *testing.T) {
	facts := rowFacts(t, healthyStatistics, healthyStatus)
	want := map[string]any{
		factDocumentCount:         3.0,
		factInboxCount:            1.0,
		factTagCount:              2.0,
		factCorrespondentCount:    1.0,
		factDocumentTypeCount:     1.0,
		factPngxVersion:           "3.0.5",
		factStorageTotalBytes:     63195054080.0,
		factStorageAvailableBytes: 54911987712.0,
		// (63195054080-54911987712)*100/63195054080 = 13.106…, half-even
		// to 13 on both implementations.
		"StorageUsedPercent": 13.0,
		factDatabaseStatus:   "OK",
		factRedisStatus:      "OK",
		factCeleryStatus:     "OK",
		factIndexStatus:      "OK",
		factClassifierStatus: "WARNING",
		factClassifierError:  "No classifier training tasks found",
	}
	for name, value := range want {
		if facts[name] != value {
			t.Errorf("%s = %v, want %v", name, facts[name], value)
		}
	}
	if len(facts) != len(want) {
		t.Errorf("the row carries %v; the capture states %d facts", factNames(facts), len(want))
	}
}

// The five counts are five DIFFERENT numbers on purpose. A port that transposed
// two of them would satisfy an anchor set where every count was 1, and this
// collection's whole value is that the numbers are right — documents_total and
// documents_inbox in particular sit adjacent in the document.
func TestTheInventoryMembersAreNotTransposed(t *testing.T) {
	statistics := `{"documents_total": 11, "documents_inbox": 22, "tag_count": 33,
	                "correspondent_count": 44, "document_type_count": 55}`
	facts := rowFacts(t, statistics, healthyStatus)
	for fact, want := range map[string]float64{
		factDocumentCount:      11,
		factInboxCount:         22,
		factTagCount:           33,
		factCorrespondentCount: 44,
		factDocumentTypeCount:  55,
	} {
		if facts[fact] != want {
			t.Errorf("%s = %v, want %v — the members are transposed", fact, facts[fact], want)
		}
	}
}

// The four `*_error` members are SPELLED in the healthy document and hold JSON
// null. The reference publishes an error fact only where the value is truthy,
// so a port that emitted a fact whenever the key existed produces four facts of
// null — which the contract's fact_value refuses. ClassifierError is asserted
// present in the same test, because a port blind to the whole error channel
// passes the four absences and fails this one.
func TestTheNullErrorMembersPublishNoFactAndTheOneWithTextDoes(t *testing.T) {
	facts := rowFacts(t, healthyStatistics, healthyStatus)
	for _, fact := range []string{factDatabaseError, factRedisError, factCeleryError, factIndexError} {
		if value, present := facts[fact]; present {
			t.Errorf("%s is on the row holding %v, and the document holds null there", fact, value)
		}
	}
	if facts[factClassifierError] != "No classifier training tasks found" {
		t.Errorf("%s = %v: the one populated error member must reach the row", factClassifierError, facts[factClassifierError])
	}
}

// `sanity_check_status` and `llmindex_status` are present in the payload, both
// carry a status word, and the reference publishes NEITHER — its tuple names
// redis, celery, index and classifier and no others. A port that turned every
// `*_status` member into a fact passes every anchor the corpus plants and ships
// two facts nothing declares.
func TestTheStatusMembersOutsideTheTupleReachNoRow(t *testing.T) {
	facts := rowFacts(t, healthyStatistics, healthyStatus)
	emittable := map[string]bool{}
	for _, name := range emittableFacts() {
		emittable[name] = true
	}
	for name := range facts {
		if !emittable[name] {
			t.Errorf("%s is on the row and this collection cannot publish it", name)
		}
		for _, unpublished := range []string{"Sanity", "Llm", "LLM"} {
			if strings.Contains(name, unpublished) {
				t.Errorf("%s reached the row: the component tuple is closed at four", name)
			}
		}
	}
	// The same rule stated over the CLOSED tuple rather than over one payload,
	// so a fifth component added to the table without a declaration fails here.
	if len(taskComponents) != 4 {
		t.Errorf("the component tuple names %d members; the reference names four", len(taskComponents))
	}
}

// A count is lifted only where json.loads made a Python int of it. A fraction,
// an exponent, a quoted number and a null are all NOT ints, so the fact is
// omitted — which is rule 7's omission and the same rule that keeps a paperless
// too old to carry a member from publishing anything.
func TestOnlyAnIntegerLiteralIsACount(t *testing.T) {
	statistics := `{"documents_total": 3.0, "documents_inbox": "1", "tag_count": null,
	                "correspondent_count": 2e0, "document_type_count": 7}`
	facts := rowFacts(t, statistics, healthyStatus)
	for _, fact := range []string{factDocumentCount, factInboxCount, factTagCount, factCorrespondentCount} {
		if value, present := facts[fact]; present {
			t.Errorf("%s = %v: only an integer literal states a count", fact, value)
		}
	}
	if facts[factDocumentTypeCount] != 7.0 {
		t.Errorf("%s = %v, want 7 — the positive control failed and the absences above prove nothing",
			factDocumentTypeCount, facts[factDocumentTypeCount])
	}
}

// json.loads makes a Python bool of `true`, and bool SUBCLASSES int, so
// isinstance(value, int) passes and the reference publishes the fact holding
// True. Reproduced rather than corrected: this port's job is to say what the
// reference says about the same bytes, and a paperless spelling a count as a
// boolean is a bug for the estate to see rather than one to hide here.
func TestABooleanCountIsLiftedBecausePythonBoolIsAnInt(t *testing.T) {
	facts := rowFacts(t, `{"documents_total": true, "documents_inbox": false}`, healthyStatus)
	if facts[factDocumentCount] != true {
		t.Errorf("%s = %v, want true", factDocumentCount, facts[factDocumentCount])
	}
	if facts[factInboxCount] != false {
		t.Errorf("%s = %v, want false", factInboxCount, facts[factInboxCount])
	}
}

// The two byte counts are the largest values in the capture and both exceed
// 2^32. They are pass-through tokens rather than parsed numbers, so a value
// past the point where a float64 stops being exact travels with its own digits
// — a port that decoded them through a float would print something that still
// looks like about 63 GB.
func TestByteCountsTravelAsTheirOwnDigits(t *testing.T) {
	const beyondFloat64 = "9007199254740993" // 2^53 + 1: the first integer a float64 cannot hold
	status := `{"storage": {"total": ` + beyondFloat64 + `, "available": 54911987712}}`
	code, stdout, stderr := runWith(t, "collect instance:12\n",
		map[string]string{"SE_REPLAY_DIR": stageInstance(t, healthyStatistics, status)})
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, `"StorageTotalBytes":`+beyondFloat64) {
		t.Fatalf("the byte count did not travel verbatim:\n%s", stdout)
	}
}

// Truthiness is the gate on every status word and on the version, so a member
// the app spelled as an empty string publishes no fact rather than one holding
// nothing — and its error member is not consulted at all, because the reference
// reads the error inside the `if`.
func TestAFalsyStatusWordPublishesNeitherTheStatusNorItsError(t *testing.T) {
	status := `{"pngx_version": "",
	            "database": {"status": "", "error": "ignored"},
	            "tasks": {"redis_status": null, "redis_error": "ignored",
	                      "celery_status": "OK", "celery_error": "the worker did not answer"}}`
	facts := rowFacts(t, healthyStatistics, status)
	for _, fact := range []string{factPngxVersion, factDatabaseStatus, factDatabaseError, factRedisStatus, factRedisError} {
		if value, present := facts[fact]; present {
			t.Errorf("%s = %v: a falsy member states nothing", fact, value)
		}
	}
	if facts[factCeleryStatus] != "OK" || facts[factCeleryError] != "the worker did not answer" {
		t.Errorf("the positive control failed: %v", facts)
	}
}

// A sub-document that is truthy and not a mapping has no `.get` in the
// reference at all: status_facts raises, its LOCAL dict is discarded, and the
// caller records the whole component half as unobservable. So the version the
// fold had already lifted goes with it, and every inventory count stays.
func TestATruthyNonMappingCostsTheWholeComponentHalfAndNoCounts(t *testing.T) {
	for label, status := range map[string]string{
		"storage is a list":  `{"pngx_version": "3.0.5", "storage": [1, 2], "database": {"status": "OK"}}`,
		"database is a word": `{"pngx_version": "3.0.5", "database": "OK"}`,
		"tasks is a number":  `{"pngx_version": "3.0.5", "tasks": 4}`,
		"the whole document": `["not", "a", "mapping"]`,
	} {
		facts := rowFacts(t, healthyStatistics, status)
		if facts[factStatusUnobservable] != detailUnreadable(statusPath) {
			t.Errorf("%s: StatusUnobservable = %v, want %q", label, facts[factStatusUnobservable], detailUnreadable(statusPath))
		}
		if value, present := facts[factPngxVersion]; present {
			t.Errorf("%s: %s = %v survived a fold that raised; the reference discards its local dict whole",
				label, factPngxVersion, value)
		}
		if facts[factDocumentCount] != 3.0 {
			t.Errorf("%s: the inventory must stand — a dark component half narrows the row, it does not empty it", label)
		}
	}
}

// A sub-document that is FALSY is `or {}` and yields no facts, which is a
// reading rather than a failure: absent and unreadable must not render the
// same, so nothing here says the component half could not be read.
func TestAFalsySubDocumentIsAReadingAndNotAnUnobservability(t *testing.T) {
	facts := rowFacts(t, healthyStatistics, `{"pngx_version": "3.0.5", "storage": {}, "database": null, "tasks": {}}`)
	if value, present := facts[factStatusUnobservable]; present {
		t.Errorf("%s = %v: an empty sub-document was read, not missed", factStatusUnobservable, value)
	}
	if facts[factPngxVersion] != "3.0.5" {
		t.Errorf("%s = %v: the version was stated and must stand", factPngxVersion, facts[factPngxVersion])
	}
	if len(facts) != 6 {
		t.Errorf("five counts and one version; got %v", factNames(facts))
	}
}

// The inventory is required and its failure is not a quiet row. Publishing a
// row without DocumentCount would be the healthy-looking wrapper over a broken
// archive that this subsystem exists to refuse, so a document that cannot be
// folded fails the batch instead.
func TestAnUnfoldableInventoryFailsTheBatchRatherThanPublishingARow(t *testing.T) {
	code, stdout, stderr := runWith(t, "collect instance:13\n",
		map[string]string{"SE_REPLAY_DIR": stageInstance(t, `["not", "a", "mapping"]`, healthyStatus)})
	if code != exitRuntime || stderr == "" {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	records := parseRecords(t, stdout)
	if len(ofKind(records, "object")) != 0 || len(ofKind(records, "commit")) != 0 {
		t.Fatalf("an unreadable inventory must publish nothing and commit nothing: %v", records)
	}
}

// An error member is Python TEXT: str() of whatever the document held, then
// bounded on a word boundary and stripped of the two credential shapes a URL
// carries. paperless's database check names the DSN it could not reach, which
// on a Postgres deployment is the credential itself.
func TestAnErrorMemberIsPythonTextBoundedAndScrubbed(t *testing.T) {
	status := `{"database": {"status": "ERROR",
	                         "error": "could not connect to postgresql://paperless:hunter2@db:5432/paperless?sslmode=require"},
	            "tasks": {"redis_status": "ERROR", "redis_error": 42,
	                      "index_status": "ERROR", "index_error": ["a", "b"]}}`
	facts := rowFacts(t, healthyStatistics, status)

	database, _ := facts[factDatabaseError].(string)
	if strings.Contains(database, "hunter2") || strings.Contains(database, "sslmode") {
		t.Errorf("%s carried a credential out of the app's own prose: %q", factDatabaseError, database)
	}
	if !strings.Contains(database, "[userinfo-stripped]@") || !strings.Contains(database, "?[query-stripped]") {
		t.Errorf("%s = %q: a redaction that hides its own existence inverts the provenance contract", factDatabaseError, database)
	}
	// str() of a number is its digits and str() of a list is its Python repr —
	// the reference interpolates through the same two spellings.
	if facts[factRedisError] != "42" {
		t.Errorf("%s = %v, want \"42\"", factRedisError, facts[factRedisError])
	}
	if facts[factIndexError] != "['a', 'b']" {
		t.Errorf("%s = %v, want \"['a', 'b']\"", factIndexError, facts[factIndexError])
	}
}

func TestAnOverlongErrorIsBoundedOnAWordBoundary(t *testing.T) {
	long := strings.TrimSpace(strings.Repeat("connection refused ", 40))
	status := `{"tasks": {"celery_status": "ERROR", "celery_error": "` + long + `"}}`
	facts := rowFacts(t, healthyStatistics, status)
	bounded, _ := facts[factCeleryError].(string)
	if !strings.HasSuffix(bounded, " … (truncated)") {
		t.Fatalf("%s = %q: an unbounded blob reached a fact", factCeleryError, bounded)
	}
	if len([]rune(bounded)) > maxReasonLength+len([]rune(" … (truncated)")) {
		t.Fatalf("%s is %d runes; the bound is %d plus its marker", factCeleryError, len([]rune(bounded)), maxReasonLength)
	}
	if strings.Contains(bounded, "connectio ") {
		t.Fatalf("%s was cut mid-word: %q", factCeleryError, bounded)
	}
}

// The error member's name is derived from the status member's, exactly as the
// reference derives it. A component whose error member were misspelt would
// publish its status and silently lose the sentence saying what went wrong.
func TestTheErrorMemberIsTheReferencesSpelling(t *testing.T) {
	for _, component := range taskComponents {
		want := strings.TrimSuffix(component.member, "_status") + "_error"
		if got := errorMember(component.member); got != want {
			t.Errorf("errorMember(%q) = %q, want %q", component.member, got, want)
		}
		if !strings.HasSuffix(component.member, "_status") {
			t.Errorf("%q is not a status member, and the derivation assumes it is", component.member)
		}
	}
}

// A repeated member keeps the FIRST position and the LAST value, which is what
// json.loads does — so a document that states a count twice publishes the value
// the interface ended on rather than the one it started with.
func TestARepeatedMemberKeepsTheLastValue(t *testing.T) {
	facts := rowFacts(t, `{"documents_total": 1, "documents_total": 9}`, healthyStatus)
	if facts[factDocumentCount] != 9.0 {
		t.Errorf("%s = %v, want 9", factDocumentCount, facts[factDocumentCount])
	}
}

// Zero documents is a VALUE and not an absence. It is the emptied-library shape
// the whole subsystem was built for, and a port that dropped a count for
// looking falsy would lose exactly the reading two incidents needed.
func TestZeroDocumentsIsAValueAndNotAnAbsence(t *testing.T) {
	facts := rowFacts(t, `{"documents_total": 0, "documents_inbox": 0}`, healthyStatus)
	if value, present := facts[factDocumentCount]; !present || value != 0.0 {
		t.Fatalf("%s = %v (present %v): zero is the reading this subsystem exists to publish",
			factDocumentCount, value, present)
	}
}
