package main

// The object and evidence verbs (DESIGN 18) — the fleet rollout of what R3c
// landed on the champions (register rows 1–2).
//
// servarr has no density behind its rows, so an object response is the row
// the collection publishes, addressed by name — built by the SAME row
// builders collect uses, so the two cannot disagree about one app. The
// EVIDENCE payloads follow the reference (adapters/servarr.py get_evidence):
// an app serves its status and health documents; a health item its matching
// entries; a queue item its raw record; a history event serves the PAGE it
// was minted from, with the credential half of every embedded URL withheld
// (_redact_history_urls) — a grab's downloadUrl is where indexer credentials
// live, on a route that requires no authentication. apps, health and queue
// evidence passes through raw, on the reviewed ground the per-collection
// exemption entries carry: the API key travels only in the request header
// this collector sends and appears in none of those three document families.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
)

type verbEndRecord struct {
	Record    string `json:"record"`
	Verb      string `json:"verb"`
	Truncated bool   `json:"truncated"`
}

type evidenceDocumentRecord struct {
	Record    string `json:"record"`
	MediaType string `json:"media_type"`
	Digest    string `json:"digest"`
	Canon     string `json:"canon,omitempty"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
}

// The declared bounds, pinned against declaration.json by test: a bound only
// in the declaration is a promise, one only here is undeclared authority.
const (
	objectVerbBytes   = 262144
	evidenceVerbBytes = 1048576
)

const noSuchObject = "this collector publishes no object of that name in this collection"

// redactedMarker is env.REDACTED's spelling — the visible stand-in every
// withheld credential half leaves behind.
const redactedMarker = "«redacted»"

func verbDecline(out *emitter, stderr io.Writer, verb, collection, reason, detail string) int {
	out.emit(declineRecord{Record: "decline", Collection: collection,
		Reason: reason, Detail: detail})
	out.emit(verbEndRecord{Record: "verb_end", Verb: verb})
	return verbExit(out, stderr)
}

// verbFleet is the shared configuration gate: both verbs address one
// instance out of the same fleet collect walks, and the whole-fleet
// configuration decline routes the same way.
func verbFleet(out *emitter, stderr io.Writer, src source, verb, collection string) ([]instance, bool, int) {
	apps, err := src.fleet()
	var refused *declined
	if errors.As(err, &refused) {
		return nil, false, verbDecline(out, stderr, verb, collection,
			refused.reason, refused.detail)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return nil, false, exitRuntime
	}
	return apps, true, exitOK
}

// instanceNamed finds one configured instance. The requested name for the
// fan-out collections is `<instance>/<native>`, cut at the FIRST slash —
// the reference's rest.partition("/") — because instance names cannot carry
// one and native ids can.
func instanceNamed(apps []instance, name string) (instance, bool) {
	for _, app := range apps {
		if app.name == name {
			return app, true
		}
	}
	return instance{}, false
}

func serveObject(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	spec, serves := served[collection]
	if !serves {
		decline := unsupportedFor(collection)
		return verbDecline(out, stderr, "object", collection, decline.Reason, decline.Detail)
	}
	apps, ok, code := verbFleet(out, stderr, src, "object", collection)
	if !ok {
		return code
	}
	if err := src.beginCollection(); err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	var built []row
	var err error
	if spec.fanout {
		instanceName, _, _ := strings.Cut(name, "/")
		app, found := instanceNamed(apps, instanceName)
		if !found || !app.ready() {
			return verbDecline(out, stderr, "object", collection, "unavailable", noSuchObject)
		}
		built, err = spec.rows(src, app)
		if detail, narrowed := narrowing(err); narrowed {
			// The instance did not answer; for a request addressed to it,
			// that IS the answer — the same fault its apps row carries.
			return verbDecline(out, stderr, "object", collection, "unavailable", detail)
		}
	} else {
		built, err = appRows(src, apps)
	}
	if err != nil {
		fmt.Fprintln(stderr, collection+":", err)
		return exitRuntime
	}
	for _, one := range built {
		if one.name != name {
			continue
		}
		out.emit(objectRecord{
			Record:     "object",
			Type:       collectionTypes[collection],
			Collection: collection,
			Name:       one.name,
			Facts:      one.facts.encode(),
			At:         src.stamp(0),
		})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
		return verbExit(out, stderr)
	}
	return verbDecline(out, stderr, "object", collection, "unavailable", noSuchObject)
}

// ── evidence ────────────────────────────────────────────────────────────

// embeddedURL is the reference's _EMBEDDED_URL: every http(s) URL anywhere
// in a string, because torrent history wraps URLs in prose and tracker
// errors embed announce URLs with passkeys — a whole-value gate let every
// one of those ride out with the credential intact.
var embeddedURL = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)

// keepSchemeHost cuts one matched URL back to its diagnostic half — the
// reference's _keep_scheme_host. A value the parser refuses is withheld
// whole (scheme://«redacted»), never skipped: a refusal is not a clearance.
// One stated divergence: Python keeps the host when only the PORT is
// uncastable, where Go's parser refuses the whole URL and this side
// withholds it whole — more withheld, never less.
func keepSchemeHost(matched string) string {
	parts, err := url.Parse(matched)
	if err != nil || parts.Hostname() == "" {
		scheme, _, _ := strings.Cut(matched, "://")
		if err != nil {
			return strings.ToLower(scheme) + "://" + redactedMarker
		}
		return matched
	}
	if (parts.Path == "" || parts.Path == "/") && parts.RawQuery == "" &&
		parts.Fragment == "" && parts.User == nil {
		return matched // bare scheme+host: nothing after the host to withhold
	}
	host := strings.ToLower(parts.Hostname())
	if port := parts.Port(); port != "" {
		host += ":" + port
	}
	return strings.ToLower(parts.Scheme) + "://" + host + "/" + redactedMarker
}

// redactHistoryPage is the reference's _redact_history_urls, applied to a
// freshly fetched page nothing else holds: every string member of every
// record's data map, matched on value shape wherever a URL appears —
// deny-by-default over every occurrence, not a member-name list.
func redactHistoryPage(page *value) {
	records := page.get("records")
	if records == nil || records.kind != jsonArray {
		return
	}
	for _, record := range records.items {
		if record == nil || record.kind != jsonObject {
			continue
		}
		data := record.get("data")
		if data == nil || data.kind != jsonObject {
			continue
		}
		for _, key := range data.members.keys {
			member := data.members.byKey[key]
			if member == nil || !member.isString() {
				continue
			}
			if replaced := embeddedURL.ReplaceAllStringFunc(member.text, keepSchemeHost); replaced != member.text {
				data.set(key, stringValue(replaced))
			}
		}
	}
}

// evidenceCanonical is the payload bytes for one object, and whether the
// name is among what the same documents publish. Membership is checked in
// the documents the payload is cut from — fetched once — so an app that
// churned between two fetches cannot ship evidence that denies its object.
func evidenceCanonical(stderr io.Writer, src source, apps []instance, collection, name string) ([]byte, bool, error) {
	instanceName, native, _ := strings.Cut(name, "/")
	if collection == "apps" {
		instanceName = name
	}
	app, found := instanceNamed(apps, instanceName)
	if !found {
		return nil, false, nil
	}
	if !app.ready() {
		// The apps ROW for this instance exists, so its evidence must not
		// deny it — the honest answer is the stated fault (the reference's
		// RuntimeError, as a decline detail here).
		return nil, false, &unreadable{"instance has no complete receipts, so there is nothing to ask it: " +
			strings.Join(sortedMissing(app.missing), ", ")}
	}
	switch collection {
	case "apps":
		status, err := src.document(app, pathStatus, nil)
		if err != nil {
			return nil, false, err
		}
		health, err := src.document(app, pathHealth, nil)
		if err != nil {
			return nil, false, err
		}
		// The top level is assembled here (Go marshals map keys sorted,
		// which is the canon the digest names); each document inside keeps
		// the app's own member order and number spellings.
		canonical, err := json.Marshal(map[string]json.RawMessage{
			"system_status": status.encode(),
			"health":        health.encode(),
		})
		return canonical, true, err
	case "health":
		document, err := src.document(app, pathHealth, nil)
		if err != nil {
			return nil, false, err
		}
		if document == nil || document.kind != jsonArray {
			return nil, false, &unreadable{app.name + "'s health answer is not a list of items"}
		}
		matching := &value{kind: jsonArray}
		for _, raw := range document.items {
			if raw == nil || raw.kind != jsonObject {
				continue
			}
			source := raw.get("source").stringOr("unknown")
			if source == "" {
				source = "unknown"
			}
			if source == native {
				matching.items = append(matching.items, raw)
			}
		}
		if len(matching.items) == 0 {
			return nil, false, nil
		}
		if len(matching.items) == 1 {
			return matching.items[0].encode(), true, nil
		}
		return matching.encode(), true, nil
	case "queue":
		raw, found, err := queueRecordNamed(src, app, native)
		if err != nil || !found {
			return nil, found, err
		}
		return raw.encode(), true, nil
	case "history":
		status, err := src.document(app, pathStatus, nil)
		if err != nil {
			return nil, false, err
		}
		if status.get("appName").stringOr("") == indexerProxyAppName {
			// prowlarr's /api/v1/history is indexer grabs, not media events:
			// the row walk publishes nothing for it and its evidence must
			// not invent anything either.
			return nil, false, nil
		}
		page, err := src.document(app, pathHistory, historyQuery())
		if err != nil {
			return nil, false, err
		}
		if page == nil || page.kind != jsonObject {
			return nil, false, &unreadable{app.name + "'s history answer is not a document"}
		}
		records := page.get("records")
		known := false
		if records != nil && records.kind == jsonArray {
			for index, raw := range records.items {
				if raw == nil || raw.kind != jsonObject {
					continue
				}
				// Membership through the SAME minting the rows use
				// (historyNative), so an index-N row's evidence cannot deny
				// the record its page plainly contains.
				if historyNative(raw, index) == native {
					known = true
					break
				}
			}
		}
		if !known {
			return nil, false, nil
		}
		redactHistoryPage(page)
		return page.encode(), true, nil
	}
	return nil, false, nil
}

// queueRecordNamed mirrors queueRows' page walk (queue.go) for one record:
// the same pagination, the same 404-on-page-one silence, the same stated-id
// matching the reference's evidence arm uses — an index-N queue row has no
// id to ask for, exactly as in the reference.
func queueRecordNamed(src source, app instance, native string) (*value, bool, error) {
	got := 0
	for page := 1; page <= queueMaxPages; page++ {
		document, err := src.document(app, pathQueue, queueQuery(page))
		if err != nil {
			if errors.Is(err, errNotFound) && page == 1 {
				return nil, false, nil
			}
			return nil, false, err
		}
		if document == nil || document.kind != jsonObject {
			return nil, false, &unreadable{app.name + "'s queue answer is not a document"}
		}
		records := document.get("records")
		if records == nil || records.kind != jsonArray || len(records.items) == 0 {
			return nil, false, nil
		}
		for _, raw := range records.items {
			got++
			if raw == nil || raw.kind != jsonObject {
				continue
			}
			if raw.get("id").stated() && pythonStr(raw.get("id")) == native {
				return raw, true, nil
			}
		}
		if total, ok := document.get("totalRecords").integer(); ok && int64(got) >= total {
			return nil, false, nil
		}
	}
	return nil, false, nil
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if _, serves := served[collection]; !serves {
		decline := unsupportedFor(collection)
		return verbDecline(out, stderr, "evidence", collection, decline.Reason, decline.Detail)
	}
	apps, ok, code := verbFleet(out, stderr, src, "evidence", collection)
	if !ok {
		return code
	}
	if err := src.beginCollection(); err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	canonical, found, err := evidenceCanonical(stderr, src, apps, collection, name)
	if detail, narrowed := narrowing(err); narrowed {
		return verbDecline(out, stderr, "evidence", collection, "unavailable", detail)
	}
	if err != nil {
		fmt.Fprintln(stderr, collection+":", err)
		return exitRuntime
	}
	if !found {
		return verbDecline(out, stderr, "evidence", collection, "unavailable", noSuchObject)
	}
	truncated := false
	if len(canonical) > evidenceVerbBytes {
		// A truncated document marked truncated is still evidence; an
		// unmarked one is a lie about the system (DESIGN 19). The digest is
		// over the bytes AS SERVED, so it stays checkable.
		canonical = canonical[:evidenceVerbBytes]
		truncated = true
	}
	sum := sha256.Sum256(canonical)
	out.emit(evidenceDocumentRecord{
		Record:    "evidence_document",
		MediaType: "application/json",
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		Canon:     "jcs/1",
		Bytes:     len(canonical),
		Truncated: truncated,
	})
	if out.err == nil {
		if _, err := stdout.Write(append([]byte(canonical), '\n')); err != nil {
			out.err = err
		}
	}
	out.emit(verbEndRecord{Record: "verb_end", Verb: "evidence", Truncated: truncated})
	return verbExit(out, stderr)
}

func verbExit(out *emitter, stderr io.Writer) int {
	if out.err != nil {
		fmt.Fprintln(stderr, "writing the response:", out.err)
		return exitRuntime
	}
	return exitOK
}
