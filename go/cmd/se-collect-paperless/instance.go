package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// The one collection, and the row's native name. One process fronts one
// paperless, so the name is a constant rather than anything read out of a
// document: the collator mints `instance:paperless` from the declared prefix
// and this name, which is the id the shipping adapter mints too. paperless
// publishes no identifier that survives a rename, so the row carries no name
// family at all and law 1 has nothing here to hold.
const (
	collectionInstance = "instance"
	instanceName       = "paperless"
)

// The facts this collection can publish, spelled once. Nineteen: five
// inventory counts, the release, two byte counts, five component status words,
// their four error sentences, and the one fact that says the component half
// could not be read at all.
const (
	factDocumentCount         = "DocumentCount"
	factInboxCount            = "InboxCount"
	factTagCount              = "TagCount"
	factCorrespondentCount    = "CorrespondentCount"
	factDocumentTypeCount     = "DocumentTypeCount"
	factPngxVersion           = "PngxVersion"
	factStorageTotalBytes     = "StorageTotalBytes"
	factStorageAvailableBytes = "StorageAvailableBytes"
	factDatabaseStatus        = "DatabaseStatus"
	factDatabaseError         = "DatabaseError"
	factRedisStatus           = "RedisStatus"
	factRedisError            = "RedisError"
	factCeleryStatus          = "CeleryStatus"
	factCeleryError           = "CeleryError"
	factIndexStatus           = "IndexStatus"
	factIndexError            = "IndexError"
	factClassifierStatus      = "ClassifierStatus"
	factClassifierError       = "ClassifierError"
	factStatusUnobservable    = "StatusUnobservable"
)

// The archive's inventory, and the fact each member becomes, in the
// REFERENCE'S order. Five members, five DIFFERENT numbers on the committed
// capture — 3, 1, 2, 1, 1 — precisely so a port that transposed two of them
// prints red; the two most transposable, documents_total and documents_inbox,
// sit adjacent in the document.
var inventoryMembers = [...]struct{ fact, member string }{
	{factDocumentCount, "documents_total"},
	{factInboxCount, "documents_inbox"},
	{factTagCount, "tag_count"},
	{factCorrespondentCount, "correspondent_count"},
	{factDocumentTypeCount, "document_type_count"},
}

// The media volume as the app sees it from inside its own mount, which can
// differ from any host row when a bind has diverged.
var storageMembers = [...]struct{ fact, member string }{
	{factStorageTotalBytes, "total"},
	{factStorageAvailableBytes, "available"},
}

// The components under `tasks`, and this tuple is a CLOSED set rather than a
// pattern. The status document also carries `sanity_check_status` and
// `llmindex_status`, both holding a status word, and the reference publishes
// NEITHER: a port that turned every `*_status` member into a fact would emit
// two facts nothing declares and nothing renders. DESIGN 15 is the reason —
// a fact must be cited by an opinion, used in identity or a relation, or be
// part of the declared answer — and the rulebook cites exactly these four
// beside the database.
var taskComponents = [...]struct{ statusFact, errorFact, member string }{
	{factRedisStatus, factRedisError, "redis_status"},
	{factCeleryStatus, factCeleryError, "celery_status"},
	{factIndexStatus, factIndexError, "index_status"},
	{factClassifierStatus, factClassifierError, "classifier_status"},
}

// errorMember is the reference's own `member.replace("_status", "_error")`,
// derived rather than tabulated so the two spellings cannot drift apart in a
// later edit — a component whose error member were misspelt here would publish
// its status and silently lose the sentence that says what went wrong.
func errorMember(statusMember string) string {
	return strings.ReplaceAll(statusMember, "_status", "_error")
}

// statisticsFacts folds the inventory document onto the row, and reports
// whether the document had a shape it could be folded from.
//
// False is the reference's AttributeError arm — `raw.get(member)` on a
// document that is not a mapping — and it is NOT caught anywhere: the
// inventory is what this collection is FOR, so an instance that cannot state
// it is an acquisition failure rather than a quiet row. Two incidents in one
// week wanted DocumentCount on the attention surface, and a row published
// without it would be the healthy-looking wrapper both incidents already had.
func statisticsFacts(doc jsonValue, facts *factRow) bool {
	if !doc.isObject() {
		return false
	}
	for _, pair := range inventoryMembers {
		if value := doc.get(pair.member); isPythonInt(value) {
			facts.setValue(pair.fact, value)
		}
	}
	return true
}

// statusFacts folds the app's own health checks, native status words kept.
//
// It builds its own row and hands it back whole, which is not a style choice:
// the reference builds a local dict and `facts.update()`s it, so a document
// that raises partway through contributes NOTHING — not even the version it
// had already lifted. The second return is that raise, and every one of its
// three sites is a sub-document that is truthy and not a mapping.
//
// A component's error rides only where the value is TRUTHY, and that is the
// half the corpus anchors hardest. The committed status document PRESENTS
// database.error, redis_error, celery_error and index_error, all four holding
// JSON null; a port that published a fact whenever the key existed emits four
// facts of null, which the contract's fact_value refuses. ClassifierError is
// anchored as a value beside those four absences precisely because it IS
// populated, which separates a port that omits error keys correctly from one
// that omits them always.
func statusFacts(doc jsonValue) (*factRow, bool) {
	if !doc.isObject() {
		return nil, false
	}
	facts := newFactRow()
	if version := doc.get("pngx_version"); version.truthy() {
		facts.setValue(factPngxVersion, version)
	}

	storage, ok := mapping(doc.get("storage"))
	if !ok {
		return nil, false
	}
	for _, pair := range storageMembers {
		if value := storage.get(pair.member); isPythonInt(value) {
			facts.setValue(pair.fact, value)
		}
	}

	database, ok := mapping(doc.get("database"))
	if !ok {
		return nil, false
	}
	if status := database.get("status"); status.truthy() {
		facts.setValue(factDatabaseStatus, status)
		if failure := database.get("error"); failure.truthy() {
			facts.setString(factDatabaseError, reasonText(pythonStr(failure)))
		}
	}

	tasks, ok := mapping(doc.get("tasks"))
	if !ok {
		return nil, false
	}
	for _, component := range taskComponents {
		status := tasks.get(component.member)
		if !status.truthy() {
			continue
		}
		facts.setValue(component.statusFact, status)
		if failure := tasks.get(errorMember(component.member)); failure.truthy() {
			facts.setString(component.errorFact, reasonText(pythonStr(failure)))
		}
	}
	return facts, true
}

// instanceRow is the whole derivation: what this collector could establish
// about the archive, as one row.
//
// ONE row, from TWO documents, and that is the shape a port is most likely to
// get wrong: `/api/statistics/` and `/api/status/` are separate requests
// feeding a single object, so a collector that published a row per document
// would satisfy every fact anchor and commit two objects instead of one.
//
// The two halves are also not equal. The inventory is required and its failure
// is an error the caller turns into "I could not run"; the component checks are
// optional by design, because `/api/status/` is admin-only and a token without
// that grant narrows this observation to the inventory numbers rather than
// breaking it (rule 7).
func instanceRow(got reading) (*factRow, error) {
	facts := newFactRow()
	if !statisticsFacts(got.statistics, facts) {
		return nil, errors.New("the paperless API answered " + statisticsPath +
			" with a document this collector cannot read; the inventory is this" +
			" collection's answer rather than an enrichment, so there is no row" +
			" to publish without it")
	}
	if !got.statusRead {
		facts.setString(factStatusUnobservable, got.unobservable)
		return facts, nil
	}
	component, ok := statusFacts(got.status)
	if !ok {
		facts.setString(factStatusUnobservable, detailUnreadable(statusPath))
		return facts, nil
	}
	facts.merge(component)
	return facts, nil
}

// collectInstance serves the one collection this collector answers for.
func collectInstance(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	got, err := src.instance()
	var refused *declined
	if errors.As(err, &refused) {
		if err.Error() != refused.Error() {
			// The record carries the constant, because decline detail travels
			// to a hub and out over MCP — and this collector's URL is
			// deployment configuration that may carry userinfo. Whatever the
			// seam wrapped around it stays here on stderr, where a person
			// debugging can read it and no redaction path has to be reviewed
			// for it. Printed only when there IS something wrapped, so an
			// ordinary absence does not restate itself into the journal on
			// every sweep.
			fmt.Fprintln(stderr, "instance:", err)
		}
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     refused.reason,
			Detail:     refused.detail,
		})
		// absent is authoritative-empty: it must be able to retire the instance
		// a previous batch published, so it declines AND commits zero. No other
		// reason commits — an archive this deployment cannot open is still
		// there, and retiring its row over a credential slip would delete
		// exactly the numbers this subsystem exists to keep watch on.
		if refused.reason == "absent" {
			out.emit(commitRecord{Record: "commit", Collection: collection, Generation: generation})
		}
		return exitOK
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	row, err := instanceRow(got)
	if err != nil {
		fmt.Fprintln(stderr, "instance:", err)
		return exitRuntime
	}
	out.emit(objectRecord{
		Record:     "object",
		Collection: collection,
		Name:       instanceName,
		Facts:      row.encode(),
		At:         src.stamp(*objects),
	})
	*objects++
	// One row, no relations, and no unobservable RECORD — StatusUnobservable is
	// a fact the reference publishes on the row, not a per-fact could-not-read
	// statement, and turning it into one here would be a second implementation
	// rather than the port of this one. The two zeroes below are therefore the
	// statement rather than a placeholder.
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    1,
	})
	return exitOK
}
