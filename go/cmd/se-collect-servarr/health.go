package main

// healthRows is adapters/servarr.py `_health_rows()`: one row per item the app
// itself raised, in the order it listed them.
//
// The severity is MIRRORED and never invented — the app graded its own check
// and this product repeats the grade — so the row carries `Type` verbatim and
// makes no judgement of its own. What this collector adds is the namespacing:
// the row's name is <instance>/<check>, so two apps raising the same check are
// two rows rather than one that overwrites the other.
func healthRows(src source, app instance) ([]row, error) {
	document, err := src.document(app, pathHealth, nil)
	if err != nil {
		return nil, err
	}
	if document == nil || document.kind != jsonArray {
		return nil, &unreadable{app.name + "'s health answer is not a list of items"}
	}
	rows := make([]row, 0, len(document.items))
	for _, item := range document.items {
		if item == nil || item.kind != jsonObject {
			return nil, &unreadable{app.name + " listed a health item that is not an object"}
		}
		// The app's own name for the check that fired, and `unknown` where it
		// states none: the row must still exist, because an item with no
		// source is still the app saying something is wrong.
		source := item.get("source").stringOr("")
		if source == "" {
			source = "unknown"
		}
		facts := newObject()
		facts.set("App", stringValue(app.name))
		facts.set("Source", item.get("source"))
		facts.set("Type", item.get("type"))
		facts.set("Message", boundedReason(item.get("message")))
		facts.set("WikiUrl", statedString(item.get("wikiUrl")))
		rows = append(rows, row{name: app.name + "/" + source, facts: facts})
	}
	return rows, nil
}

// boundedReason is env.reason() applied to a member the app wrote: one line,
// bounded on a word boundary, with the two credential shapes a URL carries
// stripped. An absent member yields no fact at all rather than a null.
func boundedReason(member *value) *value {
	if !member.isString() || member.text == "" {
		return nil
	}
	return stringValue(reasonText(member.text))
}
