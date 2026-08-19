package main

import (
	"errors"
	"net/url"
	"strconv"
)

// row is one object record's publishable half: the native name the collator
// addresses it by, and the facts.
type row struct {
	name  string
	facts *value
}

// appRows is adapters/servarr.py `_app_items()`: one row per CONFIGURED
// instance, in configuration order, including the ones that cannot be observed
// at all.
//
// That inclusion is the collection's whole point. An instance named in
// SE_SERVARR_INSTANCES with no receipts, or one that has stopped answering, is
// a statement about the estate the apps themselves cannot make — so it is a
// row carrying the fault, never a silent skip. The fan-out collections below
// serve only the instances that answered; this one serves every instance that
// was named.
func appRows(src source, apps []instance) ([]row, error) {
	rows := make([]row, 0, len(apps))
	for _, app := range apps {
		built, err := appRow(src, app)
		if err != nil {
			return nil, err
		}
		rows = append(rows, built)
	}
	return rows, nil
}

func appRow(src source, app instance) (row, error) {
	facts := newObject()
	facts.set("App", stringValue(app.name))
	facts.set("ApiFamily", stringValue(app.api))
	if len(app.duplicates) > 0 {
		facts.set("ConfigDuplicate", stringArray(app.duplicates))
	}
	if len(app.missing) > 0 {
		// The receipts decide this row on their own: nothing is asked of an
		// instance this process cannot address, so there is no reading to
		// narrow and no endpoint to blame.
		facts.set("ConfigMissing", stringArray(sortedMissing(app.missing)))
		return row{name: app.name, facts: facts}, nil
	}

	// The reference's try block, in its order, because the order is visible on
	// the row: /system/status lands its two facts BEFORE /health is asked, so
	// an app that answered what it is and then failed to answer what is wrong
	// with it publishes its version beside the reason — a partial reading
	// stated rather than discarded.
	err := func() error {
		status, err := src.document(app, pathStatus, nil)
		if err != nil {
			return err
		}
		if status == nil || status.kind != jsonObject {
			return &unreadable{app.name + "'s status answer is not a document"}
		}
		facts.set("Version", statedString(status.get("version")))
		facts.set("AppName", statedString(status.get("appName")))
		health, err := src.document(app, pathHealth, nil)
		if err != nil {
			return err
		}
		errorCount, warnCount, err := healthCounts(app, health)
		if err != nil {
			return err
		}
		facts.set("HealthErrors", numberValue(errorCount))
		facts.set("HealthWarnings", numberValue(warnCount))
		return nil
	}()
	if err != nil {
		detail, narrowed := narrowing(err)
		if !narrowed {
			return row{}, err
		}
		// A dark manager is an observation. The row stays — a configured
		// manager that does not answer is a statement rather than a gap — and
		// the queue is not asked, because the app that could not say what it
		// is cannot be asked what it is downloading either.
		facts.set("StatusUnobservable", stringValue(reasonText(detail)))
		return row{name: app.name, facts: facts}, nil
	}

	queue, err := src.document(app, pathQueueStatus, nil)
	switch {
	case err == nil:
		// Verbatim, and only when stated: totalCount is the app's own figure
		// and passes through as the token it spelled, so a count above 2^53
		// keeps every digit and a zero stays an integer zero.
		facts.set("QueueTotal", statedNumber(queue.get("totalCount")))
	case errors.Is(err, errNotFound):
		// prowlarr: no queue endpoint at all. Silence by design — the row
		// carries neither the figure nor a reason it could not be read, and
		// the difference between those two is what the corpus anchors.
	default:
		detail, narrowed := narrowing(err)
		if !narrowed {
			return row{}, err
		}
		facts.set("QueueUnobservable", stringValue(reasonText(detail)))
	}
	return row{name: app.name, facts: facts}, nil
}

// healthCounts grades the app's own health items through the SAME rules the
// health collection's rows are graded by (rules/servarr.py health_opinions), so
// the fleet number and the rows cannot disagree about what deserves attention.
//
// It is a count of GRADES and not of items: an `ok` item is a passing check
// with nothing to mirror, a `notice` is below attention by the apps' own
// definition, an `error` is critical and everything else — including a grade
// this code has never heard of, which is still the app raising its hand — is a
// warning. An item with no type or no message states nothing gradeable.
// A health document that is not a list of objects narrows this instance
// exactly as a dark one does — the reference reaches the same row through an
// exception on the same line — rather than ending the batch.
func healthCounts(app instance, document *value) (errorCount, warnCount int, err error) {
	if document == nil || document.kind != jsonArray {
		return 0, 0, &unreadable{app.name + "'s health answer is not a list of items"}
	}
	for _, item := range document.items {
		if item == nil || item.kind != jsonObject {
			return 0, 0, &unreadable{app.name + " listed a health item that is not an object"}
		}
		kind := item.get("type").stringOr("")
		if kind == "" || item.get("message").stringOr("") == "" {
			continue
		}
		switch kind {
		case "ok", "notice":
			// ok mirrors nothing; notice mirrors as info, which is below the
			// two levels this row counts.
		case "error":
			errorCount++
		default:
			warnCount++
		}
	}
	return errorCount, warnCount, nil
}

// narrowing splits the errors that narrow ONE instance's observation from the
// ones that mean this collector could not run at all. A live app that did not
// answer is the first; an uncaptured payload is the second, and it must never
// become a fact — a capture that forgot a document is not a machine anybody
// observed, and "not captured in this variant" on a row is a harness artefact
// wearing an observation's clothes.
func narrowing(err error) (string, bool) {
	var narrowed *unreadable
	if errors.As(err, &narrowed) {
		return narrowed.detail, true
	}
	return "", false
}

// statedString is a member the reference publishes only when TRUTHY: its
// `if raw.get("version")` skips an empty string as well as an absent member,
// and an empty version is a member the app failed to fill in rather than a
// value.
func statedString(member *value) *value {
	if !member.isString() || member.text == "" {
		return nil
	}
	return member
}

// statedNumber is `x is not None`: a member the app stated, whatever it says.
// A zero is a reading — the queue really is empty — and dropping it as
// uninteresting is how a figure somebody is watching goes missing.
func statedNumber(member *value) *value {
	if !member.stated() {
		return nil
	}
	return member
}

func numberValue(n int) *value {
	return &value{kind: jsonNumber, text: strconv.Itoa(n)}
}

// query is the parameter set a path takes, built once per call site so the
// two that have one cannot drift from the reference's constants.
func queueQuery(page int) url.Values {
	values := url.Values{}
	values.Set("page", strconv.Itoa(page))
	values.Set("pageSize", strconv.Itoa(queuePageSize))
	// Every app's include-unknown flag, sent together on every queue call:
	// ASP.NET Core binds only the parameter the app declares and ignores the
	// rest, and the default (false, all four apps) hides exactly the orphaned
	// records whose verdicts this collection exists to surface.
	values.Set("includeUnknownSeriesItems", "true")
	values.Set("includeUnknownMovieItems", "true")
	values.Set("includeUnknownArtistItems", "true")
	values.Set("includeUnknownAuthorItems", "true")
	return values
}

func historyQuery() url.Values {
	values := url.Values{}
	values.Set("page", "1")
	values.Set("pageSize", strconv.Itoa(historyPage))
	values.Set("sortKey", "date")
	values.Set("sortDirection", "descending")
	return values
}
