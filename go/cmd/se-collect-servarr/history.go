package main

import "strconv"

// The app's own statement of what it is, and the one instance whose trail this
// collection does not serve. prowlarr excludes itself by THIS member and never
// by the operator-chosen instance name: its /api/v1/history is indexer
// telemetry — releaseGrabbed, indexerQuery, indexerRss, indexerAuth,
// indexerInfo, records carrying no source title, quality or download client —
// a search audit rather than an acquisition trail, and the grabs it does file
// are the same events the asking apps' own histories state in full.
const indexerProxyAppName = "Prowlarr"

// historyRows is adapters/servarr.py `_history_rows()`: the newest page of one
// app's own event log, date-descending, and nothing older.
//
// A bounded recent tail is the answer to "what arrived lately", which is a
// different question from "everything that ever did" — and the second would be
// paid for on every sweep. Events are not current health: a row makes no
// severity claim at all, because a grab from yesterday is not this hour's
// standing.
func historyRows(src source, app instance) ([]row, error) {
	status, err := src.document(app, pathStatus, nil)
	if err != nil {
		return nil, err
	}
	if status.get("appName").stringOr("") == indexerProxyAppName {
		return nil, nil
	}
	document, err := src.document(app, pathHistory, historyQuery())
	if err != nil {
		return nil, err
	}
	records := document.get("records")
	if !records.stated() || records.kind != jsonArray {
		// A page that is not a document, or one carrying no records member at
		// all, holds no events. The reference reaches the same answer through
		// `page.get("records") if isinstance(page, dict) else None`.
		return nil, nil
	}
	var rows []row
	seen := map[string]bool{}
	// Every record's native id, minted ONE way for the whole page: the app's
	// own id where it states one, index-N — the record's POSITION IN THE PAGE
	// — where it does not. The enumeration counts non-object entries too, so
	// two implementations of this numbering cannot drift apart over a page
	// with a stray null in it.
	for index, raw := range records.items {
		if raw == nil || raw.kind != jsonObject {
			continue
		}
		name := app.name + "/" + historyNative(raw, index)
		if seen[name] {
			continue
		}
		seen[name] = true
		rows = append(rows, row{name: name, facts: historyFacts(app, raw)})
	}
	return rows, nil
}

// historyNative is the page's one minting rule, shared by the row walk above
// and the evidence verb's membership so the two cannot drift: the app's own
// id where it states one, index-N — the record's position in the page —
// where it does not.
func historyNative(raw *value, index int) string {
	if raw.get("id").stated() {
		return pythonStr(raw.get("id"))
	}
	return "index-" + strconv.Itoa(index)
}

// historyFacts is one event's stated members, the app's vocabulary verbatim:
// eventType rides exactly as the app spells it — grabbed,
// downloadFolderImported, downloadFailed, trackFileImported and kin — never
// translated, because a vocabulary this product invented would be it re-grading
// events the app already named. An absent member is an absent fact, never a
// guess (rule 7).
func historyFacts(app instance, raw *value) *value {
	data := raw.get("data")
	if data == nil || data.kind != jsonObject {
		data = newObject()
	}
	facts := newObject()
	facts.set("App", stringValue(app.name))
	for _, pair := range []struct {
		fact   string
		member *value
	}{
		{"EventType", raw.get("eventType")},
		{"Title", raw.get("sourceTitle")},
		// The indexer is a GRAB-event member: an import names its client and
		// its download id, and its indexer lives on the grab that preceded it
		// — which the bounded tail may no longer hold.
		{"Indexer", data.get("indexer")},
		{"DownloadClient", data.get("downloadClient")},
		{"DownloadId", raw.get("downloadId")},
		{"Date", raw.get("date")},
	} {
		if truthy(pair.member) {
			facts.set(pair.fact, pair.member)
		}
	}
	if name := raw.dig("quality", "quality", "name"); truthy(name) {
		facts.set("Quality", name)
	}
	return facts
}
