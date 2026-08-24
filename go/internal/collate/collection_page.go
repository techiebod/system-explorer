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
	"net/url"
	"sort"
	"strings"

	"github.com/techiebod/system-explorer/go/internal/store"
)

func collectionPage(st *store.Store, name, sortBy, facet, attention string,
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

	// EVERYTHING IS READ BEFORE ANYTHING IS SAID.
	//
	// The first version of this function wrote the decline's prose, then
	// discovered whether anything had ever applied, then wrote about that
	// too — so a collection that declined and had NEVER applied rendered
	// "What follows is the last reading that did apply" immediately above
	// a panel headed "Never read". Two branches each narrating the same
	// question, and the page contradicted itself on 18 of 52 collections.
	// Found by a person clicking a link, which no assertion here had done.
	//
	// The rule that prevents the shape recurring: gather the state, decide
	// ONCE what this collection's situation is, then write one statement.
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

	declined := self.Decline != nil && self.Decline.Reason != ""
	everApplied := self.Generation > 0
	if declined {
		body.WriteString(declinePanel(self.Decline, everApplied, len(rows)))
	}

	switch {
	case !everApplied:
		// Never read. A DECLINE ALREADY SAYS THIS, so no second panel is
		// emitted when one is present: the first draft printed both and
		// told the reader "nothing has ever applied" three times over two
		// panels. One situation, one statement — the decline panel
		// carries the baseline consequence itself.
		if !declined {
			body.WriteString(neverReadPanel())
		}
		return wrapWithNav(name+" · never read", navRail(st, states, name), body.String()), http.StatusOK, nil
	case len(rows) == 0 && !declined:
		body.WriteString(`<section class="panel empty-state"><h2>Nothing here</h2>` +
			`<p>This collection was read and holds no objects. The interface ` +
			`answered; it had nothing to report. That is a measured emptiness, ` +
			`not a collection that could not be reached.</p></section>`)
		return wrapWithNav(name, navRail(st, states, name), body.String()), http.StatusOK, nil
	case len(rows) == 0 && declined:
		// Declined, and nothing stands behind it. Said explicitly: the
		// alternative is a page that ends after the decline panel, and a
		// reader cannot tell that from a page whose table failed to render.
		body.WriteString(`<section class="panel empty-state"><h2>Nothing to ` +
			`fall back on</h2><p>No earlier reading of this collection is held, ` +
			`so there is nothing to show beneath the decline. What was true ` +
			`before is not known here — which is different from knowing it was ` +
			`empty.</p></section>`)
		return wrapWithNav(name, navRail(st, states, name), body.String()), http.StatusOK, nil
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
	// Which rules cannot be decided from the row's own facts. Computed
	// once, stated on every clean mark, rather than a claim the page
	// cannot support.
	var undecidable []string
	if rules, err := RulesFor(document, name); err == nil && rules != nil {
		undecidable = undecidableAtRowDensity(rules, render)
	}
	body.WriteString(objectsTable(name, render, rows, could, groups, worst,
		parentOf, nestedBy, sortBy, facet, attention, undecidable))
	// The script rides only where there are rows to narrow.
	return wrapWith(name, navRail(st, states, name), body.String(), true),
		http.StatusOK, nil
}

// neverReadPanel is for a collection that has never applied AND has not
// said why. Where a decline says why, that panel carries this and this
// one is not emitted.
func neverReadPanel() string {
	return `<section class="panel empty-state"><h2>Never read</h2>` +
		`<p>A generation was issued for this collection and nothing has ` +
		`ever applied, and no decline says why — so this is a collection ` +
		`that was asked for and has not answered either way. That is not ` +
		`an empty answer: there is no baseline here to compare against, ` +
		`and diffing against nothing would report every object as newly ` +
		`added.</p></section>`
}

func declinePanel(d *store.Decline, everApplied bool, rows int) string {
	// Each reason says a different thing about the host, so each gets its
	// own sentence rather than one template with the word swapped in.
	// Each sentence says WHAT THE REASON MEANS and stops there. The
	// detail beneath says what happened, and this must not contradict it.
	//
	// `unavailable` read "This is an incident, not a configuration" — and
	// DESIGN §2256 rules the exact opposite: a configuration gap declines
	// `unavailable`, never `absent`, because "`unavailable` already means
	// could-not-read, which is exactly what 'nobody told this process
	// where to look' is". A fifth reason `unconfigured` was considered
	// and rejected. So the page asserted an incident directly above the
	// collector's own words "no servarr api configured for this process",
	// diagnosing past a closed vocabulary and contradicting a ruling. That
	// is §27's forbidden move — a renderer deciding what something means
	// — committed in prose rather than in code, which is the form it is
	// hardest to notice.
	says := map[string]string{
		"absent": "This interface is not on this host. Nothing is wrong: the " +
			"question does not apply here, which is different from a question " +
			"whose answer happens to be empty.",
		"unauthorised": "The collector was refused permission to read this. " +
			"The host may well have plenty to report; nobody here can see it — " +
			"which is a deployment problem, not a fault in what is being read.",
		"unavailable": "The collector could not get a reading. That covers a " +
			"service that did not answer AND one nobody told this collector " +
			"how to reach — the detail below says which, and this page does " +
			"not guess.",
		"unsupported": "The interface is here and this collector cannot read " +
			"this shape of it, which usually means the interface has moved on. " +
			"That is for whoever maintains the collector.",
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
	// What STANDS behind the decline, said here because this is where the
	// reader asks it. The three non-absent declines establish nothing, so
	// whatever applied before is still the last thing known — but only if
	// something did. Saying "what follows is the last reading that did
	// apply" above a page that has never had one is the contradiction this
	// argument exists to prevent, and it shipped.
	stands := ""
	if d.Reason != "absent" {
		switch {
		case !everApplied:
			// This carries the never-read panel's whole meaning, including
			// the baseline consequence, so that panel is not also emitted.
			stands = `<p class="dim">Nothing has ever applied for this ` +
				`collection, so there is no earlier reading standing behind ` +
				`this decline — and no baseline for change tracking: a ` +
				`question reaching before the first reading has no answer ` +
				`here rather than an empty one.</p>`
		case rows > 0:
			stands = `<p class="dim">The rows below are the last reading that ` +
				`did apply. This decline did not replace them, so they are the ` +
				`last thing known — not the current state.</p>`
		default:
			stands = `<p class="dim">An earlier reading applied but holds no ` +
				`objects, so there is nothing to show beneath this decline.</p>`
		}
	}
	return fmt.Sprintf(
		`<section class="panel declined"><h2>Declined: %s</h2><p>%s</p>%s%s%s</section>`,
		esc(d.Reason), esc(sentence), detail, stands, when)
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

// query builds a collection URL from the parameters that survive a click.
//
// ONE builder, used by every control on the page. The facet links carried
// the sort forward and the sort links did not carry the facet, so
// choosing a column silently un-narrowed the page — which is precisely
// what happens when two places each assemble the same URL. A control that
// discards another control's state is worse than no control, because the
// reader cannot see what they lost.
//
// Values are URL-escaped: a fact name and an object type are producer
// text, and a `&` in either would rewrite the query somebody clicked.
func query(collection string, params ...string) string {
	var kept []string
	for _, p := range params {
		if p != "" {
			kept = append(kept, p)
		}
	}
	base := "/collections/" + url.PathEscape(collection)
	if len(kept) == 0 {
		return base
	}
	return base + "?" + strings.Join(kept, "&")
}

func facetParam(facet string) string {
	if facet == "" {
		return ""
	}
	return "facet=" + url.QueryEscape(facet)
}

func sortParam(sortBy string) string {
	if sortBy == "" {
		return ""
	}
	return "sort=" + url.QueryEscape(sortBy)
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
	parentOf map[string]string, nestedBy, sortBy, facet, attention string,
	undecidable []string) string {
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
		assigned[i] = assignTyped(groups, facts, row.Type, worst[row.ID])
	}

	// The display order, and the depth each row is drawn at.
	//
	// INDENTATION IS DISABLED UNDER SORT **AND UNDER A FACET**. Indentation
	// claims a parent is directly above its child. Reordering makes that
	// false, which the sort branch always handled — but FILTERING makes it
	// false in a worse way, and that shipped: a facet removes rows without
	// touching the depths computed over the whole set, so a child stayed
	// indented under a parent the facet had just deleted. The page then
	// draws a hierarchy whose parent is not on it, which is a stronger
	// false claim than a reordered tree: the reader looks for the row
	// above and it is not there.
	//
	// Both are the same rule — a tree may only be drawn over the set it
	// was computed for — so they share one condition rather than two that
	// can drift apart.
	order := make([]int, len(rows))
	for i := range rows {
		order[i] = i
	}
	depth := map[int]int{}
	cyclic := false
	sorted := sortBy != ""
	narrowed := facet != ""
	if sorted {
		order = sortedOrder(rows, render, sortBy)
	} else if !narrowed && nestedBy != "" && len(parentOf) > 0 {
		order, depth, cyclic = nest(rows, parentOf)
	}

	var b strings.Builder
	b.WriteString(`<section class="panel">`)
	if nestedBy != "" && len(parentOf) > 0 {
		switch {
		case sorted:
			b.WriteString(fmt.Sprintf(
				`<p class="dim">Sorted by %s, so the <code>%s</code> tree is `+
					`not drawn: indentation would claim a parent sits directly `+
					`above its child, which a reordered list does not say.</p>`,
				esc(sortBy), esc(nestedBy)))
		case narrowed:
			b.WriteString(fmt.Sprintf(
				`<p class="dim">Narrowed to <code>%s</code>, so the <code>%s</code> `+
					`tree is not drawn: this page no longer holds every parent, `+
					`and indenting a row under one that is not here would draw a `+
					`hierarchy you cannot follow.</p>`,
				esc(facet), esc(nestedBy)))
		default:
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
	// THE VERDICT FACET. The levels come from the rulebook via
	// worstPerObject, which this page has already computed before drawing
	// anything — so this narrows by what the PRODUCER judged, and decides
	// nothing itself. It is the one control a person reaches for on a
	// 300-row table: show me the rows something is wrong with.
	b.WriteString(attentionControls(collection, rows, order, worst, attention,
		facet, sortBy))
	if attention != "" {
		rank := map[string]int{"critical": 0, "warn": 1, "info": 2}
		want, known := rank[attention]
		var kept []int
		for _, i := range order {
			if got, fired := rank[worst[rows[i].ID]]; known && fired && got <= want {
				kept = append(kept, i)
			}
		}
		order = kept
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
	// The typed filter's control, rendered HIDDEN. The script's first act
	// is to reveal it, so a client without script is never shown a dead
	// input and the unfiltered page stays the whole answer.
	if len(order) > 12 {
		b.WriteString(`<div id="narrow-shell" class="narrow" hidden>` +
			`<label for="narrow">narrow</label>` +
			`<input id="narrow" type="search" autocomplete="off" ` +
			`placeholder="type to narrow these rows (press /)">` +
			`<span id="narrow-status" class="dim" role="status" ` +
			`aria-live="polite"></span></div>`)
	}
	b.WriteString(hideControls(Chips(groups, assigned)))
	b.WriteString(`<div class="scroll"><table>`)
	// The verdict column had an EMPTY <th>. A screen reader announces
	// "blank" for the column that carries every row's severity, and a
	// sighted reader gets no clue what the marks mean either.
	b.WriteString(`<thead><tr><th><span class="visually-hidden">verdict` +
		`</span></th><th>object</th>`)
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
		//
		// It CARRIES THE FACET. The facet links already carried the sort,
		// and this side did not, so choosing a column silently threw the
		// reader's narrowing away and returned them to all 508 rows. A
		// control that discards another control's state is worse than no
		// control: the reader does not know what they lost.
		//
		// The CURRENT column is marked and its link CLEARS the sort, which
		// is also the only way back to the tree — before this, a sorted
		// page told the reader its tree was not drawn and offered no route
		// to the page where it is.
		current := name == sortBy
		mark, cls, target := "", "sort", "sort="+name
		if current {
			mark = ` <span class="sorted-mark" aria-hidden="true">▾</span>`
			cls = "sort current"
			target = ""
		}
		aria := ""
		if current {
			aria = ` aria-sort="ascending"`
		}
		// The column's DECLARED type rides on the cell, so the stylesheet
		// can size a state column narrow and let prose take the slack.
		// The renderer is not deciding anything: it is passing through
		// what the producer said this fact is.
		kind := ""
		if render != nil {
			if decl, ok := render.Facts[name]; ok && decl.Type != "" {
				kind = " t-" + decl.Type
			}
		}
		b.WriteString(fmt.Sprintf(
			`<th%s%s class="%s"><a class="%s" href="%s">%s%s</a></th>`,
			title, aria, strings.TrimSpace(kind), cls,
			esc(query(collection, target, facetParam(facet))), esc(name), mark))
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
		// Depth is a style property because it is DATA — how deep this
		// row sits is a fact of the producer's edges, not a class this
		// file chose from a fixed set.
		//
		// It also carries `aria-level`, because the CSS custom property
		// was the ONLY encoding of the nesting: with the stylesheet
		// unavailable the asserted hierarchy vanished entirely and the
		// tree became a flat list with no indication it had ever been
		// one. §28 requires a page to be a complete answer without
		// script; a structure that exists only in a stylesheet fails the
		// same test one layer over.
		indent := ""
		if d := depth[i]; d > 0 {
			indent = fmt.Sprintf(` style="--depth:%d" aria-level="%d"`, d, d+1)
		} else if nestedBy != "" && len(parentOf) > 0 && !sorted && !narrowed {
			indent = ` aria-level="1"`
		}
		b.WriteString("<td>" + severityMarkWith(worst[row.ID], undecidable) +
			"</td>")
		b.WriteString(fmt.Sprintf(
			`<td class="ident"%s><a href="%s">%s</a>%s</td>`,
			indent, objectHref(collection, row.Name), esc(row.Name),
			scopeMark(row.Scope)))
		for _, name := range columns {
			kind := ""
			if render != nil {
				if decl, ok := render.Facts[name]; ok && decl.Type != "" {
					kind = ` class="t-` + esc(decl.Type) + `"`
				}
			}
			b.WriteString("<td" + kind + ">" + cellFor(render, name, facts,
				absent, could[row.ID], false) + "</td>")
		}
		b.WriteString(`</tr>`)
	}
	b.WriteString(`</tbody></table></div>`)

	// A column the producer stated for NO row is called out once, beneath
	// the table, rather than left as N identical cells.
	//
	// `units` renders MissingRequirements — which is in its `answer`, so
	// it is a column on every row — and the collector emits it only where
	// non-empty and never declares it absent. 300 of 300 cells read "not
	// stated": the table's only dependency column, carrying no
	// information at all, and a reader scans it 300 times before
	// concluding it never says anything.
	//
	// The cells STAY. Each one is the truth for its row, and removing the
	// column would hide a fact the producer's own `answer` list asks for.
	// What is added is the summary a reader would otherwise derive by
	// scrolling.
	if declarationMismatch(render, rows) {
		b.WriteString(`<p class="stale-banner">The declaration this page is ` +
			`drawn from does not describe these objects: not one fact they ` +
			`carry appears in it. Three collection names are claimed by two ` +
			`collectors each, and a store keyed by name keeps one ` +
			`declaration — so the columns above are another collector's ` +
			`questions asked of this one's answers. The objects are real; ` +
			`the columns are not theirs.</p>`)
	} else if unstated := uniformlyUnstated(columns, render, rows, could); len(unstated) > 0 {
		b.WriteString(fmt.Sprintf(
			`<p class="dim">The producer stated no value for %s on any of `+
				`these %d rows, and did not declare it absent either — so the `+
				`column is empty of information rather than empty of things. `+
				`It is here because the producer's own answer list asks for `+
				`it.</p>`,
			esc(strings.Join(unstated, ", ")), len(rows)))
	}
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
	return wrapWithNav(title, "", body)
}

// wrapWithNav puts the rail on every page.
//
// The rail comes FIRST in source order, behind a skip link. That costs
// `curl` a prelude and buys correct keyboard order — and the MCP
// consumer does not read this surface at all, it reads /v1, so the curl
// cost is the only one.
func wrapWithNav(title, rail, body string) string {
	return wrapWith(title, rail, body, false)
}

// wrapWith puts the rail on every page, and the one script on the pages
// that have rows to narrow.
//
// The script goes LAST and deferred: the page is a complete answer
// before it runs, which is what `curl` and §29's consumer without eyes
// receive, and is why granting the exception costs nothing.
func wrapWith(title, rail, body string, script bool) string {
	tail := ""
	if script {
		tail = "<script>" + narrowJS + "</script>"
	}
	return "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">" +
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
		"<title>" + esc(title) + "</title><style>" + tokensCSS +
		"</style></head><body>" + rail + "<main id=\"main\">" + body +
		"</main>" + tail + "</body></html>\n"
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
// undecidableAtRowDensity names the declared rules that CANNOT be
// evaluated from the facts a row carries, because they test a fact the
// producer deliberately kept off the row.
//
// `units` is the worked example: restart-churn tests NRestarts, and the
// declaration says NRestarts is "deliberately not a row fact — fetching
// it for every unit would turn one bus call into hundreds". So at row
// density that rule is UNDECIDABLE, `match` reports its missing fact as
// false, and nothing fires. The producer is right; the page was wrong to
// then claim every rule had been evaluated.
func undecidableAtRowDensity(rules []Rule, render *CollectionRender) []string {
	if render == nil || len(render.Answer) == 0 {
		return nil
	}
	onRow := map[string]bool{}
	for _, name := range render.Answer {
		onRow[name] = true
	}
	var out []string
	for _, rule := range rules {
		for _, fact := range ConditionFacts(rule.When) {
			if !onRow[fact] {
				out = append(out, rule.Key)
				break
			}
		}
	}
	return out
}

// severityMark is the row's verdict, and its whole job is that ABSENCE OF
// A VERDICT DOES NOT RENDER AS A GOOD ONE.
//
// `held` names the rules that could not be evaluated at this density. The
// clean mark USED TO SAY "every rule this collection declares was
// evaluated against this object and none fired" — 302 times on the units
// page, where restart-churn structurally cannot run. A page asserting a
// check it never made is the same defect as absence rendering as health,
// one level up: the reader is told the rulebook cleared this row.
func severityMarkWith(level string, held []string) string {
	if level == "critical" || level == "warn" || level == "info" {
		return chip(level, level)
	}
	if level == Unjudged {
		return severityMark(level)
	}
	if len(held) == 0 {
		return severityMark(level)
	}
	return fmt.Sprintf(
		`<span class="mark-clean partial" title="the rules that could be `+
			`evaluated from this row ran, and none fired. %d could not: %s — `+
			`each tests a fact the producer keeps off the row, so it is `+
			`undecidable here and is judged on the object page">ok*</span>`,
		len(held), esc(strings.Join(held, ", ")))
}

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
	keep := func(chosen string) string {
		return query(collection, facetParam(chosen), sortParam(sortBy))
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

// uniformlyUnstated names the columns for which the producer stated
// nothing on any row — neither a value nor an absence nor an
// unobservable.
//
// A column with SOME values is not listed: the subject is a column that
// cannot inform, not one that is merely sparse, and lowering the bar
// would start summarising away real sparseness a reader should see.
func uniformlyUnstated(columns []string, render *CollectionRender,
	rows []store.ObjectRow, could map[string]map[string]store.Unobserved) []string {
	if render == nil || len(rows) == 0 {
		return nil
	}
	var out []string
	for _, name := range columns {
		if _, declared := render.Facts[name]; !declared {
			continue
		}
		stated := false
		for _, row := range rows {
			var facts map[string]any
			if json.Unmarshal(row.Facts, &facts) == nil {
				if _, has := facts[name]; has {
					stated = true
				}
			}
			for _, absent := range row.Absent {
				if absent == name {
					stated = true
				}
			}
			if _, unobserved := could[row.ID][name]; unobserved {
				stated = true
			}
			if stated {
				break
			}
		}
		if !stated {
			out = append(out, name)
		}
	}
	return out
}

// attentionControls narrows to rows the rulebook judged at a level or
// worse. `worst` is the producer's verdict per object, already computed.
//
// The counts describe what each level HOLDS, exactly as the facet and
// hide-group counts do, so they do not move when one is chosen.
func attentionControls(collection string, rows []store.ObjectRow, order []int,
	worst map[string]string, chosen, facet, sortBy string) string {
	held := map[string]int{}
	for _, i := range order {
		switch worst[rows[i].ID] {
		case "critical":
			held["critical"]++
			held["warn"]++
			held["info"]++
		case "warn":
			held["warn"]++
			held["info"]++
		case "info":
			held["info"]++
		}
	}
	if held["info"] == 0 && chosen == "" {
		// Nothing fired anywhere: a control that can only ever return
		// everything is a control that does nothing, and it still costs a
		// reader the moment they spend deciding it is not for them.
		return ""
	}
	link := func(level string) string {
		return query(collection, attentionParam(level), facetParam(facet),
			sortParam(sortBy))
	}
	var b strings.Builder
	b.WriteString(`<div class="facets attention">`)
	b.WriteString(facetChip(link(""), "everything", len(order), chosen == ""))
	for _, level := range []string{"critical", "warn", "info"} {
		if held[level] == 0 {
			continue
		}
		label := level + " or worse"
		if level == "critical" {
			label = "critical"
		}
		b.WriteString(facetChip(link(level), label, held[level], chosen == level))
	}
	b.WriteString(`</div>`)
	return b.String()
}

func attentionParam(level string) string {
	if level == "" {
		return ""
	}
	return "attention=" + url.QueryEscape(level)
}

// declarationMismatch reports when a collection's DECLARATION does not
// describe the objects it holds.
//
// Three collection NAMES are claimed by two collectors each — `overview`
// by system and traefik, `daemon` by kea and unbound, `instance` by
// bazarr and paperless — and the store keys a collection by name, so the
// declaration is whichever collector issued generations last while the
// objects are whoever applied. Measured on a live host 2026-08-24:
// `overview` held one object carrying BootedAt, CpuCount, LoadAvg1 and
// twenty more, under traefik's five columns — Version, RoutersTotal,
// ServicesTotal — every one of them "not stated". The host's headline
// page, rendering another collector's questions over this one's answers.
//
// The renderer cannot pick the right declaration: it has one, and no
// grounds to prefer another. What it CAN do is notice that the
// declaration and the data do not describe the same thing, and say so —
// rather than reporting the producer "stated no value", which blames the
// wrong party and reads as a gap in collection instead of a collision in
// naming.
func declarationMismatch(render *CollectionRender, rows []store.ObjectRow) bool {
	if render == nil || len(render.Answer) == 0 || len(rows) == 0 {
		return false
	}
	described, undescribed := 0, 0
	for _, row := range rows {
		var facts map[string]any
		if json.Unmarshal(row.Facts, &facts) != nil {
			continue
		}
		for name := range facts {
			if _, known := render.Facts[name]; known {
				described++
			} else {
				undescribed++
			}
		}
	}
	// NOTHING the objects carry is described, and they do carry
	// something. A collection whose producer simply omitted a few facts
	// has some overlap; none at all means these are not the same
	// collection's facts.
	return described == 0 && undescribed > 0
}
