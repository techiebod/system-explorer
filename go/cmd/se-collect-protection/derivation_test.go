package main

import (
	"strings"
	"testing"
)

// The shapes below are the ones the committed variant does not stage and a
// real estate does — an older checker, a job carrying two targets' hops, a
// second proof answering the first. Each is driven through the binary rather
// than through a helper, so what is asserted is what would reach a collator.

// rowsFrom stages one manifest and one verdict with whatever receipts are given
// and returns the parsed stream. Every registered job gets BOTH its receipt
// paths staged, defaulting to the file-was-not-there pair — because the seam is
// deny-by-default and a path the capture never recorded is a broken
// transcription rather than an absence. Staging the absence explicitly is what
// a capture of a host where those files do not exist actually looks like.
func rowsFrom(t *testing.T, hostname, manifest, status string, extra map[string]string) []map[string]any {
	t.Helper()
	documents := map[string]string{
		manifestPath: pair(manifest),
		statusPath:   pair(status),
	}
	verdict, err := decodeDocument([]byte(status))
	if err != nil {
		t.Fatalf("the staged verdict is not a document: %v", err)
	}
	for _, entry := range arrayItems(verdict.get("jobs")) {
		for _, suffix := range receiptSuffixes {
			documents[receiptPath(entry.get("job").pyStr(), suffix)] = absentFile
		}
	}
	for path, text := range extra {
		documents[path] = text
	}
	code, stdout, stderr := runWith(t, wholeBatch, replayEnv(stage(t, hostname, documents)))
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	return parseRecords(t, stdout)
}

const minimalManifest = `{"destinations":{},"targets":{}}`

// "none" is the checker's filler for a member it has no answer for, not a
// reading. Publishing it would put the word "none" on a row as though the
// checker had measured it.
func TestTheCheckersFillerIsOmittedRatherThanPublished(t *testing.T) {
	status := `{"checkedAt":1787146200,"jobs":[
      {"job":"filled","state":"none","basis":"none","ageSeconds":0,
       "maxAgeSeconds":10800,"lastResult":"none","target":null}]}`
	facts := objectIn(t, rowsFrom(t, "vault", minimalManifest, status, nil), "jobs", "filled")
	for _, fact := range []string{"State", "Basis", "LastResult"} {
		if _, present := facts[fact]; present {
			t.Errorf("%s is %v; \"none\" is the writer's filler and not an outcome", fact, facts[fact])
		}
	}
	// Zero IS a reading, and a falsy test would drop it: an age of zero seconds
	// is a job that has just succeeded.
	if facts["AgeSeconds"] != 0.0 {
		t.Errorf("AgeSeconds is %v; zero is a measurement, not an absence", facts["AgeSeconds"])
	}
}

// "unknown" is the receipt writer's filler on both members it can appear on,
// and the two behave differently: the result falls back to the checker's copy
// (which is what the fallback exists for), and the exit status has nothing to
// fall back to and is simply absent.
func TestTheReceiptsFillerFallsBackForTheResultAndIsAbsentForTheStatus(t *testing.T) {
	status := `{"checkedAt":1787146200,"jobs":[
      {"job":"filled","state":"ok","basis":"last-success","ageSeconds":60,
       "maxAgeSeconds":10800,"lastResult":"success","target":null}]}`
	receipts := map[string]string{
		receiptPath("filled", "last"): pair(`{"job":"filled","unit":"filled.service",
          "finishedAt":"2026-08-19T13:00:00Z","result":"unknown","exitStatus":"unknown"}`),
	}
	facts := objectIn(t, rowsFrom(t, "vault", minimalManifest, status, receipts), "jobs", "filled")
	if facts["LastResult"] != "success" {
		t.Errorf("LastResult is %v; an unknown result falls back to the checker's copy", facts["LastResult"])
	}
	if _, present := facts["ExitStatus"]; present {
		t.Errorf("ExitStatus is %v; \"unknown\" is filler and there is nothing to fall back to", facts["ExitStatus"])
	}
	// The finish time is still the receipt's, because the run did happen.
	if facts["LastFinishedAt"] != "2026-08-19T13:00:00Z" {
		t.Errorf("LastFinishedAt is %v", facts["LastFinishedAt"])
	}
}

// THREE answers, not two. A stated null is the declaration SAYING there is no
// single subject; the member being absent entirely is a checker that predates
// it, where the inference is all there is. Folding the middle into the last
// would report a stated answer as a failed join.
func TestAStatedNoSubjectIsNotAFailedJoin(t *testing.T) {
	status := `{"checkedAt":1787146200,"jobs":[
      {"job":"scrub","state":"ok","basis":"last-success","ageSeconds":60,
       "maxAgeSeconds":10800,"lastResult":"success","target":null},
      {"job":"older","state":"ok","basis":"last-success","ageSeconds":60,
       "maxAgeSeconds":10800,"lastResult":"success"}]}`
	records := rowsFrom(t, "vault", minimalManifest, status, nil)

	scoped := objectIn(t, records, "jobs", "scrub")
	if scoped["TargetNotScoped"] != true {
		t.Errorf("a stated null is a stated answer: %v", scoped)
	}
	if _, present := scoped["TargetClassUnjoined"]; present {
		t.Error("a declaration that answered the question was reported as a join that failed")
	}

	older := objectIn(t, records, "jobs", "older")
	if _, present := older["TargetNotScoped"]; present {
		t.Error("a checker that says nothing was read as saying there is no subject")
	}
	unjoined, _ := older["TargetClassUnjoined"].(string)
	if !strings.Contains(unjoined, "unknown") || !strings.Contains(unjoined, "irreplaceable") {
		t.Errorf("TargetClassUnjoined is %q; unknown is not \"replaceable\", and the row has to say so", unjoined)
	}
}

// A job may carry hops for more than one target, and it is graded by the WORST
// consequence it is responsible for: a join may sharpen a verdict, never soften
// one. The hops are listed in the order the declaration is walked — target,
// then destination — so two runs of one document agree.
func TestAJobCarryingTwoTargetsHopsTakesTheWorstClass(t *testing.T) {
	manifest := `{"destinations":{"offsite":{"kind":"restic-s3","independent":true}},
      "targets":{
        "zz-photos":{"class":"backup","ownerHost":"vault","destinations":["offsite"],
                     "implementedBy":{"offsite":"vault:mirror"}},
        "aa-scratch":{"class":"recreate","ownerHost":"vault","destinations":["offsite"],
                      "implementedBy":{"offsite":"vault:mirror"}}}}`
	status := `{"checkedAt":1787146200,"jobs":[
      {"job":"mirror","state":"ok","basis":"last-success","ageSeconds":60,
       "maxAgeSeconds":10800,"lastResult":"success","target":null}]}`
	facts := objectIn(t, rowsFrom(t, "vault", manifest, status, nil), "jobs", "mirror")
	if facts["TargetClass"] != "backup" {
		t.Errorf("TargetClass is %v; the job carries an irreplaceable target's hop and is graded by it", facts["TargetClass"])
	}
	hops, _ := facts["ImplementsHops"].([]any)
	if len(hops) != 2 {
		t.Fatalf("ImplementsHops is %v", facts["ImplementsHops"])
	}
	// Sorted by target name, which is the order the declaration is walked in.
	if first, _ := hops[0].(map[string]any); first["Target"] != "aa-scratch" {
		t.Errorf("the hops are in %v, and the walk is by target name", facts["ImplementsHops"])
	}
}

// An implementedBy reference that names NO host names no host, which is a
// different thing from naming this one. Assuming would let one host claim to
// implement another's hop — and it would import that hop's class onto a local
// job of the same name.
func TestAnUnqualifiedHopIsUnattributedRatherThanAssumedLocal(t *testing.T) {
	manifest := `{"destinations":{"offsite":{"kind":"restic-s3","independent":true}},
      "targets":{"photos":{"class":"backup","ownerHost":"vault","destinations":["offsite"],
                           "implementedBy":{"offsite":"mirror"}}}}`
	// No `target` member at all, so the hop route is the only one that could
	// have joined: with a stated null the row would say TargetNotScoped and
	// the failed join would be invisible.
	status := `{"checkedAt":1787146200,"jobs":[
      {"job":"mirror","state":"ok","basis":"last-success","ageSeconds":60,
       "maxAgeSeconds":10800,"lastResult":"success"}]}`
	records := rowsFrom(t, "vault", manifest, status, nil)

	hops, _ := objectIn(t, records, "targets", "photos")["HopImplementedBy"].([]any)
	if len(hops) != 1 {
		t.Fatal("the hop is still implemented — the declaration says so")
	}
	hop, _ := hops[0].(map[string]any)
	if _, present := hop["Host"]; present {
		t.Errorf("a reference naming no host was attributed to one: %v", hop)
	}
	if hop["Job"] != "mirror" {
		t.Errorf("the job name is %v", hop["Job"])
	}

	job := objectIn(t, records, "jobs", "mirror")
	if _, present := job["ImplementsHops"]; present {
		t.Errorf("an unattributed hop was claimed by this host: %v", job["ImplementsHops"])
	}
	if _, present := job["TargetClass"]; present {
		t.Errorf("an unattributed hop imported a class: %v", job["TargetClass"])
	}
	if _, present := job["TargetClassUnjoined"]; !present {
		t.Error("no class joined, and the row must say the join failed rather than say nothing")
	}
}

// A LATER pass on the same rung answers a failure; an earlier one does not.
// Both directions, because a port that ignored the dates satisfies one and
// fails the other whichever way it errs.
func TestALaterPassAnswersAFailureAndAnEarlierOneDoesNot(t *testing.T) {
	manifest := func(proven, proofs string) string {
		return `{"destinations":{"offsite":{"kind":"restic-s3","independent":true}},
          "targets":{"photos":{"class":"backup","ownerHost":"vault",
            "destinations":["offsite"],"implementedBy":{},
            "lastProvenAt":` + proven + `,"proofs":` + proofs + `}}}`
	}
	const status = `{"checkedAt":1787146200,"jobs":[]}`
	const failed = `{"rung":"offsite","at":"2026-06-11","result":"fail","record":"a.md"}`

	// A pass in July answers a failure in June.
	answered := manifest(`{"offsite":"2026-07-30"}`,
		`[`+failed+`,{"rung":"offsite","at":"2026-07-30","result":"pass","record":"a.md"}]`)
	facts := objectIn(t, rowsFrom(t, "vault", answered, status, nil), "targets", "photos")
	if _, present := facts["FailedProofRungs"]; present {
		t.Errorf("a later pass did not answer the failure: %v", facts["FailedProofRungs"])
	}

	// A pass in MAY does not: the artifact could not be read back after it.
	unanswered := manifest(`{"offsite":"2026-05-01"}`,
		`[`+failed+`,{"rung":"offsite","at":"2026-05-01","result":"pass","record":"a.md"}]`)
	facts = objectIn(t, rowsFrom(t, "vault", unanswered, status, nil), "targets", "photos")
	rungs, _ := facts["FailedProofRungs"].([]any)
	if len(rungs) != 1 || rungs[0] != "offsite" {
		t.Errorf("an earlier pass answered a later failure: %v", facts["FailedProofRungs"])
	}
	// And the rung still counts as proven, because a pass did happen there —
	// the two facts are about different questions and neither cancels the
	// other.
	proven, _ := facts["ProvenRungs"].([]any)
	if len(proven) != 1 || proven[0] != "offsite" {
		t.Errorf("ProvenRungs is %v", facts["ProvenRungs"])
	}
}

// A rung a proof cites and the manifest never declares counts when proven and
// is not invented as a gap when it is not: the source host's own snapshot
// history is the rung an operator reaches for first, and it is not a
// destination.
func TestAProvenRungNeedNotBeADeclaredDestination(t *testing.T) {
	manifest := `{"destinations":{"offsite":{"kind":"restic-s3","independent":true}},
      "targets":{"photos":{"class":"backup","ownerHost":"vault",
        "destinations":["offsite"],"implementedBy":{},
        "lastProvenAt":{"local-snapshots":"2026-07-30"},
        "proofs":[{"rung":"local-snapshots","at":"2026-07-30","result":"pass",
                   "scope":"one file","comparedAgainst":"the live dataset","record":"a.md"}]}}}`
	facts := objectIn(t, rowsFrom(t, "vault", manifest, `{"checkedAt":1787146200,"jobs":[]}`, nil), "targets", "photos")
	proven, _ := facts["ProvenRungs"].([]any)
	if len(proven) != 1 || proven[0] != "local-snapshots" {
		t.Errorf("ProvenRungs is %v; a rung the manifest does not declare still counts when proven", facts["ProvenRungs"])
	}
	unproven, _ := facts["UnprovenRungs"].([]any)
	if len(unproven) != 1 || unproven[0] != "offsite" {
		t.Errorf("UnprovenRungs is %v; it is the declared destinations with no passing restore, not the complement", facts["UnprovenRungs"])
	}
	// The caveat travels with the date, prefixed by the rung it belongs to,
	// because a sampled restore must not read as a full one.
	scopes, _ := facts["ProofScope"].([]any)
	if len(scopes) != 1 || !strings.HasPrefix(scopes[0].(string), "local-snapshots 2026-07-30: ") {
		t.Errorf("ProofScope is %v", facts["ProofScope"])
	}
}

// One record collapses to the string itself and several carry the list — the
// one shape of this fact a consumer switching on the declared type will not be
// expecting, which is why the declaration says so.
func TestProofRecordCollapsesForOneAndListsForSeveral(t *testing.T) {
	manifest := func(second string) string {
		return `{"destinations":{},"targets":{"photos":{"class":"backup","ownerHost":"vault",
          "destinations":[],"implementedBy":{},"lastProvenAt":{},
          "proofs":[{"rung":"a","at":"2026-01-01","result":"pass","record":"docs/proofs.md"},
                    {"rung":"b","at":"2026-02-01","result":"pass","record":"` + second + `"}]}}}`
	}
	const status = `{"checkedAt":1787146200,"jobs":[]}`

	same := objectIn(t, rowsFrom(t, "vault", manifest("docs/proofs.md"), status, nil), "targets", "photos")
	if same["ProofRecord"] != "docs/proofs.md" {
		t.Errorf("ProofRecord is %v; one distinct record is the string itself", same["ProofRecord"])
	}
	two := objectIn(t, rowsFrom(t, "vault", manifest("docs/other.md"), status, nil), "targets", "photos")
	records, ok := two["ProofRecord"].([]any)
	if !ok || len(records) != 2 || records[0] != "docs/other.md" {
		t.Errorf("ProofRecord is %v; two distinct records are carried as a sorted list", two["ProofRecord"])
	}
}

// A receipt that opened, parsed, and is not a receipt is still a fault in the
// EVIDENCE rather than evidence that no run happened — and the reason names
// what it turned out to be, so somebody can go and look at the file.
func TestAReceiptThatIsNotAnObjectIsAFaultAndNotASilence(t *testing.T) {
	status := `{"checkedAt":1787146200,"jobs":[
      {"job":"odd","state":"ok","basis":"last-success","ageSeconds":60,
       "maxAgeSeconds":10800,"lastResult":"success","target":null}]}`
	receipts := map[string]string{
		receiptPath("odd", "last"):         pair(`["not","a","receipt"]`),
		receiptPath("odd", "last-success"): pair(`42`),
	}
	facts := objectIn(t, rowsFrom(t, "vault", minimalManifest, status, receipts), "jobs", "odd")
	text, _ := facts["ReceiptsUnobservable"].(string)
	if !strings.Contains(text, "odd.last.json: the receipt parsed as list, not an object") {
		t.Errorf("ReceiptsUnobservable is %q", text)
	}
	if !strings.Contains(text, "odd.last-success.json: the receipt parsed as int, not an object") {
		t.Errorf("ReceiptsUnobservable is %q", text)
	}
	// Sorted by file name and joined, so two runs of one payload agree on the
	// text. `-` sorts before `.`, so the last-success receipt leads — the
	// order is the byte order of the names and not the order they were read.
	if !strings.Contains(text, "; ") || strings.Index(text, "odd.last-success.json") > strings.Index(text, "odd.last.json:") {
		t.Errorf("the faults are joined in file-name order: %q", text)
	}
}

// A target that declares no destinations at all carries neither a hop list nor
// a gap: rule 7's omission, not a zero. It is the row an estate has for
// something it has decided not to protect, and inventing an UnimplementedHops
// of [] would make it read as a promise nobody kept.
func TestATargetWithNoDeclaredDestinationsCarriesNoHopFacts(t *testing.T) {
	manifest := `{"destinations":{},"targets":{"scratch":{"class":"recreate","kind":"dataset",
      "ownerHost":"vault","cadence":"none","retention":"derived","source":"dataset:tank/scratch",
      "destinations":[],"implementedBy":{},"lastProvenAt":{},"proofs":[]}}}`
	facts := objectIn(t, rowsFrom(t, "vault", manifest, `{"checkedAt":1787146200,"jobs":[]}`, nil), "targets", "scratch")
	for _, fact := range []string{
		"Destinations", "IndependentDestinations", "ImplementedHops",
		"HopImplementedBy", "UnimplementedHops", "ProvenRungs", "UnprovenRungs",
		"LastProvenAt", "FailedProofRungs", "ProofRecord",
	} {
		if _, present := facts[fact]; present {
			t.Errorf("%s is %v on a target that declares nothing", fact, facts[fact])
		}
	}
	// A cadence of "none" is a WORD the declaration wrote, not an absence, so
	// it is published: the estate said this target is not on a schedule.
	if facts["Cadence"] != "none" {
		t.Errorf("Cadence is %v; \"none\" here is the declaration's own word", facts["Cadence"])
	}
	if facts["Class"] != "recreate" || facts["OwnerHost"] != "vault" {
		t.Errorf("the declared members are %v", facts)
	}
}

// An entry that is not an object is no object at all — the same predicate the
// evidence document is checked against, so an id this collection publishes is
// one the object verb could open.
func TestAnEntryThatIsNotAMappingMintsNoRow(t *testing.T) {
	manifest := `{"destinations":{"real":{"kind":"zfs-recv","independent":false},"bogus":"a string"},
      "targets":{"real":{"class":"backup","ownerHost":"vault"},"bogus":[1,2,3]}}`
	records := rowsFrom(t, "vault", manifest, `{"checkedAt":1787146200,"jobs":[]}`, nil)
	for _, record := range ofKind(records, "object") {
		if record["name"] == "bogus" {
			t.Fatalf("a %s entry that is not a mapping minted a row", record["collection"])
		}
	}
	for _, commit := range ofKind(records, "commit") {
		if commit["collection"] != "jobs" && commit["objects"] != 1.0 {
			t.Errorf("%v commits %v objects, want the one real entry", commit["collection"], commit["objects"])
		}
	}
}
