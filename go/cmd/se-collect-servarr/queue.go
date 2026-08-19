package main

import (
	"errors"
	"strconv"
	"strings"
)

// queueRows is adapters/servarr.py `_queue_rows()`: one row per download the
// app is tracking, walked page by page.
//
// The rows carry the app's OWN verdict on each transfer — trackedDownloadStatus
// and trackedDownloadState — because the shape that goes unnoticed is the one
// that completed and will not import, and only the app can say so. Every fetch
// asks for the include-unknown variants of all four apps: the ORPHANED download
// the app cannot map to a series, movie, artist or author is the stuck one, and
// every app hides it from the queue by default while still counting it in
// totalCount. Absence reading as health, in the collection written against it.
func queueRows(src source, app instance) ([]row, error) {
	var rows []row
	seen := map[string]bool{}
	index := 0
	for page := 1; page <= queueMaxPages; page++ {
		document, err := src.document(app, pathQueue, queueQuery(page))
		if err != nil {
			if errors.Is(err, errNotFound) && page == 1 {
				// prowlarr: no queue endpoint at all, which is silence by
				// design and not an empty queue. A 404 on any LATER page is
				// the interface changing under the walk, and that is a real
				// failure rather than a shorter queue.
				return nil, nil
			}
			return nil, err
		}
		if document == nil || document.kind != jsonObject {
			return nil, &unreadable{app.name + "'s queue answer is not a document"}
		}
		records := document.get("records")
		if !records.stated() {
			// The reference's `body.get("records") or []`: an absent or null
			// member is a page with nothing on it, which ends the walk.
			return rows, nil
		}
		if records.kind != jsonArray {
			return nil, &unreadable{app.name + "'s queue records are not a list"}
		}
		for _, raw := range records.items {
			if raw == nil || raw.kind != jsonObject {
				return nil, &unreadable{app.name + " listed a queue record that is not an object"}
			}
			// The app's own id where it states one, index-N where it does not:
			// a record with no id is still a download in flight, and dropping
			// it would hide exactly the orphan this walk asks for.
			native := pythonStr(raw.get("id"))
			if !raw.get("id").stated() {
				native = "index-" + strconv.Itoa(index)
			}
			index++
			name := app.name + "/" + native
			if seen[name] {
				continue
			}
			seen[name] = true
			rows = append(rows, row{name: name, facts: queueFacts(app, raw)})
		}
		total, ok := document.get("totalRecords").integer()
		if len(records.items) == 0 || !ok || int64(page)*queuePageSize >= total {
			return rows, nil
		}
	}
	// The runaway guard fired: ten thousand tracked downloads is far past any
	// real queue, so the walk stops with the rows already gathered rather than
	// looping on a lying totalRecords.
	return rows, nil
}

func queueFacts(app instance, raw *value) *value {
	facts := newObject()
	facts.set("App", stringValue(app.name))
	facts.set("Title", raw.get("title"))
	facts.set("Status", raw.get("status"))
	facts.set("TrackedDownloadStatus", raw.get("trackedDownloadStatus"))
	facts.set("TrackedDownloadState", raw.get("trackedDownloadState"))
	for _, pair := range []struct{ fact, member string }{
		{"DownloadClient", "downloadClient"},
		{"Indexer", "indexer"},
		{"Protocol", "protocol"},
		{"DownloadId", "downloadId"},
	} {
		// The reference's `if raw.get(member)` is TRUTHY, so an empty string
		// is a member the app did not fill in rather than a value.
		if truthy(raw.get(pair.member)) {
			facts.set(pair.fact, raw.get(pair.member))
		}
	}
	// sizeleft is `is not None`, not truthy: zero bytes remaining beside a
	// warning verdict IS the stuck-import shape, and dropping the zero would
	// delete the reading the collection exists for.
	facts.set("SizeLeftBytes", statedNumber(raw.get("sizeleft")))
	if truthy(raw.get("errorMessage")) {
		facts.set("ErrorMessage", boundedReason(raw.get("errorMessage")))
	}
	if lines := statusMessages(raw.get("statusMessages")); lines != "" {
		facts.set("StatusMessages", stringValue(reasonText(lines)))
	}
	return facts
}

// statusMessages folds the app's per-item status lines into one bounded line.
// The document nests them — a list of {title, messages: [...]} — and the
// reference takes the MESSAGES and not the titles, joined with "; ", which is
// what makes a row's explanation readable beside its verdict.
func statusMessages(member *value) string {
	if member == nil || member.kind != jsonArray {
		return ""
	}
	var lines []string
	for _, entry := range member.items {
		if entry == nil || entry.kind != jsonObject {
			continue
		}
		messages := entry.get("messages")
		if messages == nil || messages.kind != jsonArray {
			continue
		}
		for _, text := range messages.items {
			lines = append(lines, pythonStr(text))
		}
	}
	return strings.Join(lines, "; ")
}

// truthy is Python's truth test for the members this collector reads: a string
// is truthy when non-empty, a number when non-zero, and null and false never
// are. It exists because the reference draws the line between `if x` and
// `x is not None` deliberately and differently per member, and a port that
// used one rule for both would either drop a real zero or publish an empty
// string as an answer.
func truthy(member *value) bool {
	switch {
	case member == nil:
		return false
	case member.kind == jsonNull:
		return false
	case member.kind == jsonBool:
		return member.boolean
	case member.kind == jsonString:
		return member.text != ""
	case member.kind == jsonNumber:
		n, ok := member.integer()
		if ok {
			return n != 0
		}
		return member.text != "0"
	case member.kind == jsonArray:
		return len(member.items) > 0
	case member.kind == jsonObject:
		return len(member.members.keys) > 0
	}
	return false
}

// pythonStr renders a scalar the way `str()` renders it, because the reference
// stringifies two things a document decides the type of: a record's id, which
// becomes half an object's name, and a status line, which is folded into a
// fact. The bound worth stating: a number is rendered from the token the wire
// carried, so a document spelling `1e3` where Python would print `1000.0` would
// put the two implementations in disagreement — no app has ever emitted one,
// and the corpus would show it if one did.
func pythonStr(member *value) string {
	switch {
	case member == nil || member.kind == jsonNull:
		return "None"
	case member.kind == jsonBool:
		if member.boolean {
			return "True"
		}
		return "False"
	case member.kind == jsonString:
		return member.text
	case member.kind == jsonNumber:
		return member.text
	}
	return ""
}
