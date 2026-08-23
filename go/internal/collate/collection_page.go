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
	"sort"
	"strings"

	"github.com/techiebod/system-explorer/go/internal/store"
)

func collectionPage(st *store.Store, name, sortBy, facet string,
	now func() float64, bootID string) (string, int, error) {
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

	groups, err := HideGroupsFor(document, name)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	// The worst opinion per object, needed BEFORE the table is drawn
	// because invariant 2 — a critical row is never suppressed — is
	// enforced at assignment rather than inside any group's condition.
	worst := worstPerObject(st, document, name, rows)

	// The nesting relation, and the rows' parents, from the producer's own
	// assertions. A collection asserting none renders a flat table, which
	// is what most of them are.
	parentOf, nestedBy := parentsFrom(st, name)

	body.WriteString(freshnessNote(self, now, bootID))
	body.WriteString(objectsTable(name, render, rows, could, groups, worst,
		parentOf, nestedBy, sortBy, facet))
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

// Unjudged is the verdict of a collection whose rule table could not be
// read. It is NOT the same as a clean verdict and must never render as
// one: SPEC §8 — "a UI that renders absence as neutrality re-asserts the
// judgement the agent withheld". Nothing formed an opinion here, which
// is a statement about the declaration; every rule ran and none fired is
// a statement about the object.
const Unjudged = "unjudged"

// worstPerObject is the rulebook's verdict per object, which drives both
// the row's severity mark and the critical exemption. Read from the
// declared rules rather than from anything this file decides — a
// severity table here would be the fourth copy §27 records.
func worstPerObject(st *store.Store, document, collection string,
	rows []store.ObjectRow) map[string]string {
	out := map[string]string{}
	rules, err := RulesFor(document, collection)
	if err != nil || rules == nil {
		// No rule table. Every row is UNJUDGED, stated as such — the
		// earlier spelling returned an empty map, which made "nothing
		// could judge this" and "everything was judged and is fine"
		// the same value one layer below the mark that exists to keep
		// them apart.
		//
		// Nothing is known to be critical either, so nothing is exempt
		// and every hide group applies as declared. The alternative —
		// treat unjudged as critical and hide nothing — would let an
		// unreadable declaration silently disable the whole mechanism.
		for _, row := range rows {
			out[row.ID] = Unjudged
		}
		return out
	}
	secrets, err := SecretFacts(document, collection)
	if err != nil {
		secrets = map[string]bool{}
	}
	rank := map[string]int{"critical": 0, "warn": 1, "info": 2}
	for _, row := range rows {
		var facts map[string]any
		if json.Unmarshal(row.Facts, &facts) != nil {
			continue
		}
		for name := range secrets {
			delete(facts, name)
		}
		var instance *string
		if row.Scope != store.HostNative {
			scope := row.Scope
			instance = &scope
		}
		for _, o := range JudgeShaped(rules, row.ID, instance, row.Type, facts) {
			if held, seen := out[row.ID]; !seen || rank[o.Level] < rank[held] {
				out[row.ID] = o.Level
			}
		}
	}
	return out
}

// parentsFrom reads the nesting edges a collection asserted: child name
// → parent name, and the relation type that produced them.
//
// `member-of` and `enslaved-to` are the two the acceptance item names —
// the units slice tree and the links bridge tree — and they are read
// from the RELATIONS the producer asserted rather than from any shape
// declared here. A collection that asserts neither nests nothing.
func parentsFrom(st *store.Store, collection string) (map[string]string, string) {
	all, err := st.Relations(collection)
	if err != nil {
		return nil, ""
	}
	for _, nesting := range []string{"member-of", "enslaved-to"} {
		parents := map[string]string{}
		for _, rel := range all {
			if rel.Type == nesting {
				parents[rel.SourceName] = rel.TargetName
			}
		}
		if len(parents) > 0 {
			return parents, nesting
		}
	}
	return nil, ""
}

func objectsTable(collection string, render *CollectionRender,
	rows []store.ObjectRow, could map[string]map[string]store.Unobserved,
	groups []HideGroup, worst map[string]string,
	parentOf map[string]string, nestedBy, sortBy, facet string) string {
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

	// Assign first, so the chips can be rendered ABOVE the table with
	// counts that describe what each group holds.
	assigned := make([]string, len(rows))
	for i, row := range rows {
		var facts map[string]any
		if json.Unmarshal(row.Facts, &facts) != nil {
			facts = map[string]any{}
		}
		assigned[i] = assign(groups, facts, worst[row.ID])
	}

	// The display order, and the depth each row is drawn at.
	//
	// INDENTATION IS DISABLED UNDER SORT. Indentation claims a parent is
	// directly above its child; once the rows are reordered that claim is
	// false, and a tree drawn over a reordered list tells the reader
	// something the data does not say. So a sorted table is flat, and the
	// page says why rather than silently dropping the shape.
	order := make([]int, len(rows))
	for i := range rows {
		order[i] = i
	}
	depth := map[int]int{}
	cyclic := false
	sorted := sortBy != ""
	if sorted {
		order = sortedOrder(rows, render, sortBy)
	} else if nestedBy != "" && len(parentOf) > 0 {
		order, depth, cyclic = nest(rows, parentOf)
	}

	var b strings.Builder
	b.WriteString(`<section class="panel">`)
	if nestedBy != "" && len(parentOf) > 0 {
		if sorted {
			b.WriteString(fmt.Sprintf(
				`<p class="dim">Sorted by %s, so the <code>%s</code> tree is `+
					`not drawn: indentation would claim a parent sits directly `+
					`above its child, which a reordered list does not say.</p>`,
				esc(sortBy), esc(nestedBy)))
		} else {
			b.WriteString(fmt.Sprintf(
				`<p class="dim">Nested by <code>%s</code>, as this collection `+
					`asserted it.</p>`, esc(nestedBy)))
		}
	}
	if cyclic {
		b.WriteString(`<p class="stale-banner">Some rows form a cycle in the ` +
			`nesting relation and are drawn at the top level. They are shown ` +
			`rather than dropped: a row omitted because its shape surprised ` +
			`the renderer is a row nobody can find.</p>`)
	}
	b.WriteString(facetControls(collection, rows, order, facet, sortBy))
	// Applied AFTER the counts are taken, so a facet chip's number keeps
	// answering "what this facet holds" rather than "what is showing" —
	// the same invariant the hide-group chips carry.
	if facet != "" {
		var kept []int
		for _, i := range order {
			if rows[i].Type == facet {
				kept = append(kept, i)
			}
		}
		order = kept
	}
	b.WriteString(hideControls(Chips(groups, assigned)))
	b.WriteString(`<div class="scroll"><table>`)
	b.WriteString(`<thead><tr><th></th><th>object</th>`)
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
		// Sorting is a link that RE-ASKS, not a reordering in the
		// browser: pattern 2 of §28's table — if the control needs
		// something the page does not hold, it re-asks. The server's
		// answer is the answer.
		b.WriteString(fmt.Sprintf(
			`<th%s><a class="sort" href="/collections/%s?sort=%s">%s</a></th>`,
			title, esc(collection), esc(name), esc(name)))
	}
	b.WriteString(`</tr></thead><tbody>`)

	for _, i := range order {
		row := rows[i]
		var facts map[string]any
		if json.Unmarshal(row.Facts, &facts) != nil {
			facts = map[string]any{}
		}
		absent := map[string]bool{}
		for _, name := range row.Absent {
			absent[name] = true
		}
		if group := assigned[i]; group != "" {
			// The row is IN THE MARKUP whatever its group — hidden by a
			// selector, never omitted. A row the server left out is a row
			// `curl` and §29's consumer without eyes never receive, and
			// the page stops being a complete answer.
			b.WriteString(fmt.Sprintf(`<tr data-group="%s">`, esc(group)))
		} else {
			b.WriteString(`<tr>`)
		}
		// Depth is a style property because it is DATA — how deep this
		// row sits is a fact of the producer's edges, not a class this
		// file chose from a fixed set.
		indent := ""
		if d := depth[i]; d > 0 {
			indent = fmt.Sprintf(` style="--depth:%d"`, d)
		}
		b.WriteString("<td>" + severityMark(worst[row.ID]) + "</td>")
		b.WriteString(fmt.Sprintf(
			`<td class="ident"%s><a href="/collections/%s/objects/%s">%s</a>%s</td>`,
			indent, esc(collection), esc(row.Name), esc(row.Name),
			scopeMark(row.Scope)))
		for _, name := range columns {
			b.WriteString("<td>" + cellFor(render, name, facts, absent,
				could[row.ID], false) + "</td>")
		}
		b.WriteString(`</tr>`)
	}
	b.WriteString(`</tbody></table></div>`)
	// Narrowed to nothing, and WHICH control did it. app.js records the
	// case: pick a facet, then hide the group that holds all of its rows,
	// and "nothing matches" is a misleading answer — the rows are there,
	// two controls are hiding them. Because both are computed here, one
	// place knows which.
	if len(order) == 0 {
		switch {
		case facet != "":
			b.WriteString(fmt.Sprintf(
				`<p class="dim">No object of type <code>%s</code> is on this `+
					`page. The collection is not empty — this facet is.</p>`,
				esc(facet)))
		default:
			b.WriteString(`<p class="dim">Every row on this page is held by a ` +
				`hide group. Reveal one above to see them: they are in the ` +
				`page, not missing from it.</p>`)
		}
	}
	b.WriteString(`</section>`)
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

// sortedOrder ranks rows by one fact's rendered VALUE.
//
// Ordering on the value the producer sent, compared as text unless both
// sides are numbers — never on the formatted string, which would sort
// "1 GiB" before "512 B" and present a wrong answer confidently.
func sortedOrder(rows []store.ObjectRow, render *CollectionRender, by string) []int {
	order := make([]int, len(rows))
	values := make([]any, len(rows))
	for i, row := range rows {
		order[i] = i
		var facts map[string]any
		if json.Unmarshal(row.Facts, &facts) == nil {
			values[i] = facts[by]
		}
	}
	sort.SliceStable(order, func(a, b int) bool {
		x, y := values[order[a]], values[order[b]]
		if x == nil {
			// A row with no value sorts last whichever way the column
			// goes: it is not the smallest, it is unanswered.
			return false
		}
		if y == nil {
			return true
		}
		if nx, ok := number(x); ok {
			if ny, ok := number(y); ok {
				return nx < ny
			}
		}
		return scalar(x) < scalar(y)
	})
	return order
}

// severityMark is the row's verdict, and its whole job is that ABSENCE OF
// A VERDICT DOES NOT RENDER AS A GOOD ONE.
//
// SPEC §8: "a UI that renders absence as neutrality re-asserts the
// judgement the agent withheld." Three states, three marks:
//
//	critical/warn/info — a rule fired, and the chip carries its level
//	clean              — every declared rule ran and none fired
//	unjudged           — no rule table could be read, so nothing formed
//	                     an opinion at all
//
// The last two are the pair that must not collapse. A blank cell for
// both is the neutrality SPEC §8 forbids, and it is the same defect as
// the blank cell for `absent` one density down.
func severityMark(level string) string {
	switch level {
	case "critical", "warn", "info":
		return chip(level, level)
	case Unjudged:
		return `<span class="mark-unjudged" title="no rule table could be ` +
			`read for this collection, so nothing has judged this object — ` +
			`a statement about the declaration, not about the object">?</span>`
	}
	return `<span class="mark-clean" title="every rule this collection ` +
		`declares was evaluated against this object and none fired">ok</span>`
}

// facetControls renders the type facet as LINKS carrying the facet in
// the query — the second form §28's interaction table permits, and the
// one chosen deliberately over the radio group.
//
// **Why not the selector form.** A facet drawn with `:checked ~` has to
// hide rows with `display:none`, and the hide-group reveal rule un-hides
// with `display:table-row`. The two cannot compose without a rule for
// every (group × facet) pair, and a page that gets that wrong either
// shows a row the reader asked to hide or hides one they asked to see —
// which is worse than a round trip. `app.js` already recorded the shape
// of this: a facet whose every row is held back by a hide group, "pick
// mount, then hide mounts", where "nothing matches" is a misleading
// answer. Computing both on the server means one place decides, and it
// can say WHICH of the two narrowed the page to nothing.
//
// **"All" is first and is the default**, so a page arrives showing
// everything. A facet that arrived pre-narrowed would be the renderer
// hiding rows nobody asked it to hide.
//
// The axis is the object's declared TYPE, which the producer minted. A
// facet derived from fact values would be this file deciding what groups
// things.
func facetControls(collection string, rows []store.ObjectRow, order []int,
	chosen, sortBy string) string {
	counts := map[string]int{}
	var types []string
	for _, i := range order {
		if kind := rows[i].Type; kind != "" {
			if counts[kind] == 0 {
				types = append(types, kind)
			}
			counts[kind]++
		}
	}
	if len(types) < 2 && chosen == "" {
		// One type, or none, is not a facet — it is a control that does
		// nothing, and a control that does nothing still costs a reader
		// the moment they spend deciding it is not for them.
		return ""
	}
	sortStrings(types)
	keep := func(facet string) string {
		q := "?"
		if facet != "" {
			q += "facet=" + facet
		}
		if sortBy != "" {
			if q != "?" {
				q += "&"
			}
			q += "sort=" + sortBy
		}
		if q == "?" {
			q = ""
		}
		return "/collections/" + collection + q
	}
	var b strings.Builder
	b.WriteString(`<div class="facets">`)
	b.WriteString(facetChip(keep(""), "all", len(order), chosen == ""))
	for _, kind := range types {
		b.WriteString(facetChip(keep(kind), kind, counts[kind], chosen == kind))
	}
	b.WriteString(`</div>`)
	return b.String()
}

func facetChip(href, label string, count int, current bool) string {
	class := "chip facet-chip"
	aria := ""
	if current {
		class += " current"
		// The current facet is announced, not merely coloured: a reader
		// who cannot see the styling still needs to know which one they
		// are looking at.
		aria = ` aria-current="true"`
	}
	return fmt.Sprintf(
		`<a class="%s" href="%s"%s>%s <span class="count">%d</span></a>`,
		class, esc(href), aria, esc(label), count)
}
