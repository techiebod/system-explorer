// The collection page: one table, columns from the producer's `answer`.
//
// **The four empty states, which is what this page is really for.** A
// table with no rows can mean four different things and §28 says they
// must not render alike. Below the collector they were collapsed twice
// and each was fixed at the tier that owned it; here is where the
// difference finally reaches a person:
//
//	declined  — the collection does not apply, or could not be read. The
//	            page states its reason INSTEAD of showing an empty table,
//	            because an empty table is an answer and a decline is not.
//	absent    — the interface is not on this host. It COMMITS, so it is
//	            not stale and holds no objects; without the decline being
//	            served this row is byte-identical to the next one.
//	empty     — the interface is here, was read, and holds nothing.
//	never read — a generation was issued and nothing has ever applied. A
//	            baseline that does not exist is not an empty baseline.
//
// **Staleness belongs to the collection, not to the cell.** A stale
// collection renders its values with the age prominent and the reason if
// one is known — repeating "stale" into every cell would say that each
// fact independently went stale, which is not what happened and buries
// the one statement that matters.
package collate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/techiebod/system-explorer/go/internal/store"
)

func collectionPage(st *store.Store, name string, now func() float64,
	bootID string) (string, int, error) {
	states, err := st.Collections()
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	var self *store.CollectionState
	for i := range states {
		if states[i].Name == name {
			self = &states[i]
		}
	}
	if self == nil {
		return "", http.StatusNotFound, nil
	}

	document, err := st.DeclarationFor(name)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	render, err := RenderFor(document, name)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}

	var body strings.Builder
	body.WriteString(fmt.Sprintf(
		`<p class="dim"><a href="/">← this host</a></p><h1>%s</h1>`, esc(name)))
	if render != nil && render.Question != "" {
		// The page states its own purpose. A table whose reason for
		// existing is only in the producer's head is a table a reader
		// has to reverse-engineer.
		body.WriteString(fmt.Sprintf(`<p class="question">%s</p>`,
			esc(render.Question)))
	}

	// The decline comes FIRST and replaces the table. Rendering a decline
	// as an empty table is the collapse this page exists to undo.
	if self.Decline != nil && self.Decline.Reason != "" {
		body.WriteString(declinePanel(self.Decline))
		if self.Decline.Reason != "absent" {
			// The three non-absent declines leave PRIOR objects standing,
			// marked stale — they established nothing, so what was true
			// before is still the last thing known.
			body.WriteString(`<p class="dim">What follows is the last reading ` +
				`that did apply, which this decline did not replace.</p>`)
		}
	}

	if self.Generation == 0 {
		body.WriteString(`<section class="panel empty-state"><h2>Never read</h2>` +
			`<p>A generation was issued for this collection and nothing has ` +
			`ever applied. That is not an empty answer — there is no ` +
			`baseline here to compare against, and diffing against nothing ` +
			`would report every object as newly added.</p></section>`)
		return wrap(name+" · never read", body.String()), http.StatusOK, nil
	}

	rows, err := st.Objects(name)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	unobs, err := st.Unobservables(name)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	// object id → fact → the reason it could not be read.
	could := map[string]map[string]store.Unobserved{}
	for _, u := range unobs {
		if could[u.Object] == nil {
			could[u.Object] = map[string]store.Unobserved{}
		}
		could[u.Object][u.Fact] = u
	}

	if len(rows) == 0 && (self.Decline == nil || self.Decline.Reason == "") {
		body.WriteString(`<section class="panel empty-state"><h2>Nothing here</h2>` +
			`<p>This collection was read and holds no objects. The interface ` +
			`answered; it had nothing to report. That is a measured emptiness, ` +
			`not a collection that could not be reached.</p></section>`)
		return wrap(name, body.String()), http.StatusOK, nil
	}

	body.WriteString(freshnessNote(self, now, bootID))
	body.WriteString(objectsTable(name, render, rows, could))
	return wrap(name, body.String()), http.StatusOK, nil
}

func declinePanel(d *store.Decline) string {
	// Each reason says a different thing about the host, so each gets its
	// own sentence rather than one template with the word swapped in.
	says := map[string]string{
		"absent": "This interface is not on this host. Nothing is wrong: the " +
			"question does not apply here, which is different from a question " +
			"whose answer happens to be empty.",
		"unauthorised": "The collector was refused permission to read this. " +
			"The host may well have plenty to report; nobody here can see it.",
		"unavailable": "The interface is on this host and did not answer. " +
			"This is an incident, not a configuration.",
		"unsupported": "The interface exists but this collector cannot read " +
			"this shape of it.",
	}
	sentence := says[d.Reason]
	if sentence == "" {
		sentence = "The collection declined to answer."
	}
	detail := ""
	if d.Detail != "" {
		// The reason says which of four kinds this is; the detail says
		// what to do about it.
		detail = fmt.Sprintf(`<p class="detail">%s</p>`, esc(d.Detail))
	}
	when := ""
	if d.At != "" {
		when = fmt.Sprintf(`<p class="faint">Stated at %s.</p>`, esc(d.At))
	}
	return fmt.Sprintf(
		`<section class="panel declined"><h2>Declined: %s</h2><p>%s</p>%s%s</section>`,
		esc(d.Reason), esc(sentence), detail, when)
}

func freshnessNote(cs *store.CollectionState, now func() float64, bootID string) string {
	if cs.Stale {
		reason := ""
		if cs.StaleReason != nil {
			reason = " — " + *cs.StaleReason
		}
		// Prominent, and over the table rather than in it.
		return fmt.Sprintf(
			`<p class="stale-banner">These values are stale%s. They are the `+
				`last reading that applied, shown because the last thing known `+
				`is more useful than a blank page — but nothing here has been `+
				`confirmed since.</p>`, esc(reason))
	}
	if cs.TimensSkew != nil && *cs.TimensSkew != 0 {
		return `<p class="stale-banner">The collector's clock domain differs ` +
			`from this collator's, so no age can be stated for these readings. ` +
			`The values stand; their age does not.</p>`
	}
	if cs.OldestAt == nil {
		return ""
	}
	if cs.BootID == nil || !strings.EqualFold(*cs.BootID, bootID) {
		return `<p class="dim">Read during another boot, so no age can be ` +
			`stated: a monotonic reading means nothing outside the boot that ` +
			`produced it.</p>`
	}
	if age := now() - *cs.OldestAt; age >= 0 {
		return fmt.Sprintf(
			`<p class="dim">Oldest contributing reading: <span class="num">%.0fs`+
				`</span> ago.</p>`, age)
	}
	return `<p class="dim">The arithmetic on these stamps is impossible on ` +
		`this boot, so no age is stated rather than a negative one shown.</p>`
}

func objectsTable(collection string, render *CollectionRender,
	rows []store.ObjectRow, could map[string]map[string]store.Unobserved) string {
	// Columns come from the producer's `answer`, in the producer's order.
	var columns []string
	if render != nil {
		columns = render.Answer
	}
	if len(columns) == 0 {
		// No answer declared: every fact present, stated as a fallback so
		// nobody reads a wide table as a deliberate one.
		seen := map[string]bool{}
		for _, row := range rows {
			var facts map[string]any
			if json.Unmarshal(row.Facts, &facts) == nil {
				for k := range facts {
					seen[k] = true
				}
			}
		}
		for k := range seen {
			columns = append(columns, k)
		}
		sortStrings(columns)
	}

	var b strings.Builder
	b.WriteString(`<section class="panel"><div class="scroll"><table>`)
	b.WriteString(`<thead><tr><th>object</th>`)
	for _, name := range columns {
		title := ""
		if render != nil {
			if decl, ok := render.Facts[name]; ok && decl.Sentence != "" {
				// The sentence comes from the declaration. A glossary in
				// this file would be a fourth copy of what the producer
				// already said.
				title = fmt.Sprintf(` title="%s"`, esc(decl.Sentence))
			}
		}
		b.WriteString(fmt.Sprintf(`<th%s>%s</th>`, title, esc(name)))
	}
	b.WriteString(`</tr></thead><tbody>`)

	for _, row := range rows {
		var facts map[string]any
		if json.Unmarshal(row.Facts, &facts) != nil {
			facts = map[string]any{}
		}
		absent := map[string]bool{}
		for _, name := range row.Absent {
			absent[name] = true
		}
		b.WriteString(`<tr>`)
		b.WriteString(fmt.Sprintf(
			`<td class="ident"><a href="/collections/%s/objects/%s">%s</a>%s</td>`,
			esc(collection), esc(row.Name), esc(row.Name), scopeMark(row.Scope)))
		for _, name := range columns {
			b.WriteString("<td>" + cellFor(render, name, facts, absent,
				could[row.ID], false) + "</td>")
		}
		b.WriteString(`</tr>`)
	}
	b.WriteString(`</tbody></table></div></section>`)
	return b.String()
}

// cellFor decides which of §28's states a fact is in and renders it.
// The ORDER of these questions is the whole of the logic: a fact the
// collector could not read is unobservable even though it is also
// missing from the facts map, and a fact it looked for and did not find
// is absent rather than unknown.
func cellFor(render *CollectionRender, name string, facts map[string]any,
	absent map[string]bool, could map[string]store.Unobserved, object bool) string {
	var sib Siblings
	sib.Values = facts
	if render != nil {
		sib.Decls = render.Facts
	}
	if u, ok := could[name]; ok {
		detail := u.Detail
		if detail == "" {
			detail = u.Reason
		}
		return Cell(FactDecl{}, nil, StateUnobservable, detail, sib, object)
	}
	if absent[name] {
		return Cell(FactDecl{}, nil, StateAbsent, "", sib, object)
	}
	value, present := facts[name]
	if render == nil {
		if !present {
			return Cell(FactDecl{}, nil, StateAbsent, "", sib, object)
		}
		return Undeclared(value)
	}
	decl, declared := render.Facts[name]
	if !declared {
		if !present {
			return Cell(FactDecl{}, nil, StateAbsent, "", sib, object)
		}
		return Undeclared(value)
	}
	if !present {
		// Declared, not absent, not unobservable, and not sent. Stated as
		// unknown by Cell rather than rendered blank.
		return Cell(decl, nil, StateValue, "", sib, object)
	}
	return Cell(decl, value, StateValue, "", sib, object)
}

func scopeMark(scope string) string {
	if scope == store.HostNative {
		return ""
	}
	// Two instances mint the same id, so a row without its instance is
	// indistinguishable from its sibling.
	return fmt.Sprintf(` <span class="chip instance">%s</span>`, esc(scope))
}

func sortStrings(in []string) {
	for i := 1; i < len(in); i++ {
		for j := i; j > 0 && in[j] < in[j-1]; j-- {
			in[j], in[j-1] = in[j-1], in[j]
		}
	}
}

func wrap(title, body string) string {
	return "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">" +
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
		"<title>" + esc(title) + "</title><style>" + tokensCSS +
		"</style></head><body><main>" + body + "</main></body></html>\n"
}
