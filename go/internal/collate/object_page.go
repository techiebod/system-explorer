// The object page: full density. §27 — "this is where somebody arrives
// having decided this row is the interesting one." Every fact, every
// opinion including the informational ones, and the relations with their
// observability.
//
// **An asserted relation must never look like a confirmed one.** §28
// calls that "the founding failure re-entering through layer 6 after five
// other layers went to considerable trouble to prevent it", and the
// sentence it names — *"pushes to repository:offsite-vault — the far end
// has never been read"* — is the one that would have prevented an
// incident. So the three states are visually distinct AND each carries
// its own words on the row: not a tooltip, not a footnote.
//
// **Every section is a <details>.** §28's interaction table gives
// expansion to the platform, so opening a section runs no script and
// works with script disabled — which is what makes the page a complete
// answer rather than a shell that fills itself in.
package collate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/techiebod/system-explorer/go/internal/store"
)

func objectPage(st *store.Store, collection, object string, now func() float64,
	bootID string) (string, int, error) {
	rows, err := st.Objects(collection)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	var self *store.ObjectRow
	for i := range rows {
		if rows[i].Name == object {
			self = &rows[i]
			break
		}
	}
	if self == nil {
		return "", http.StatusNotFound, nil
	}

	document, err := st.DeclarationFor(collection)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	render, err := RenderFor(document, collection)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	unobs, err := st.Unobservables(collection)
	if err != nil {
		return "", http.StatusInternalServerError, err
	}
	could := map[string]store.Unobserved{}
	for _, u := range unobs {
		if u.Object == self.ID {
			could[u.Fact] = u
		}
	}

	var facts map[string]any
	if json.Unmarshal(self.Facts, &facts) != nil {
		facts = map[string]any{}
	}
	absent := map[string]bool{}
	for _, name := range self.Absent {
		absent[name] = true
	}

	var body strings.Builder
	body.WriteString(fmt.Sprintf(
		`<p class="dim"><a href="/">this host</a> · `+
			`<a href="/collections/%s">%s</a></p><h1>%s</h1>`,
		esc(collection), esc(collection), esc(self.Name)))
	if self.Type != "" {
		body.WriteString(fmt.Sprintf(`<p class="dim">%s%s</p>`,
			chip(self.Type, "type"), scopeMark(self.Scope)))
	}

	body.WriteString(factsSection(render, facts, absent, could))
	body.WriteString(opinionsSection(st, document, collection, self, facts))
	body.WriteString(relationsSection(st, collection, self))
	body.WriteString(evidenceSection(collection, self.Name))

	return wrap(self.Name+" · "+collection, body.String()), http.StatusOK, nil
}

func factsSection(render *CollectionRender, facts map[string]any,
	absent map[string]bool, could map[string]store.Unobserved) string {
	// EVERY declared fact, plus every absent one, plus every fact the
	// collector could not read, plus anything undeclared that arrived.
	// A fact missing from all four lists is a fact nobody can ask about.
	names := map[string]bool{}
	if render != nil {
		for name := range render.Facts {
			names[name] = true
		}
	}
	for name := range facts {
		names[name] = true
	}
	for name := range absent {
		names[name] = true
	}
	for name := range could {
		names[name] = true
	}
	var ordered []string
	for name := range names {
		ordered = append(ordered, name)
	}
	sort.Strings(ordered)

	var b strings.Builder
	b.WriteString(`<details open class="panel"><summary><h2>Facts</h2></summary>` +
		`<div class="scroll"><table><tbody>`)
	for _, name := range ordered {
		sentence := ""
		if render != nil {
			if decl, ok := render.Facts[name]; ok && decl.Sentence != "" {
				sentence = fmt.Sprintf(`<div class="sentence">%s</div>`,
					esc(decl.Sentence))
			}
		}
		b.WriteString(fmt.Sprintf(
			`<tr><th class="factname">%s</th><td>%s%s</td></tr>`,
			esc(name), cellFor(render, name, facts, absent, could, true), sentence))
	}
	b.WriteString(`</tbody></table></div></details>`)
	return b.String()
}

func opinionsSection(st *store.Store, document, collection string,
	row *store.ObjectRow, facts map[string]any) string {
	rules, err := RulesFor(document, collection)
	if err != nil || rules == nil {
		// Unjudged, never "clean". A collection whose rule table cannot
		// be read has had no opinion formed about it, and saying nothing
		// fired would be reporting absence as health.
		return `<details class="panel"><summary><h2>Opinions</h2></summary>` +
			`<p class="faint">No rule table could be read for this ` +
			`collection, so nothing has judged this object. That is a ` +
			`statement about the declaration, not about the object.</p></details>`
	}
	secrets, err := SecretFacts(document, collection)
	if err != nil {
		secrets = map[string]bool{}
	}
	judged := map[string]any{}
	for k, v := range facts {
		if !secrets[k] {
			judged[k] = v
		}
	}
	var instance *string
	if row.Scope != store.HostNative {
		scope := row.Scope
		instance = &scope
	}
	// EVERY opinion including the informational ones: §27 gives the
	// object density "every opinion", and info is where an explanation
	// usually lives.
	fired := JudgeShaped(rules, row.ID, instance, row.Type, judged)
	if len(fired) == 0 {
		return `<details class="panel"><summary><h2>Opinions</h2></summary>` +
			`<p class="dim">Every rule this collection declares was ` +
			`evaluated against this object and none fired.</p></details>`
	}
	order := map[string]int{"critical": 0, "warn": 1, "info": 2}
	sort.SliceStable(fired, func(i, j int) bool {
		return order[fired[i].Level] < order[fired[j].Level]
	})
	var b strings.Builder
	b.WriteString(`<details open class="panel"><summary><h2>Opinions</h2></summary>` +
		`<div class="scroll"><table><thead><tr><th>level</th><th>grounds</th>` +
		`<th>says</th><th>cites</th></tr></thead><tbody>`)
	for _, o := range fired {
		b.WriteString(fmt.Sprintf(
			`<tr><td>%s</td><td><span class="grounds %s">%s</span></td>`+
				`<td>%s</td><td class="faint">%s</td></tr>`,
			chip(o.Level, o.Level), esc(o.Grounds), esc(o.Grounds),
			esc(o.Sentence), esc(strings.Join(o.Cites, ", "))))
	}
	b.WriteString(`</tbody></table></div></details>`)
	return b.String()
}

func relationsSection(st *store.Store, collection string, row *store.ObjectRow) string {
	all, err := st.Relations(collection)
	if err != nil {
		return `<details class="panel"><summary><h2>Relations</h2></summary>` +
			`<p class="faint">The relation store could not be read, so no ` +
			`claim is made about this object's edges either way.</p></details>`
	}
	var mine []store.Relation
	for _, rel := range all {
		if rel.SourceID == row.ID || rel.SourceName == row.Name {
			mine = append(mine, rel)
		}
	}
	if len(mine) == 0 {
		return `<details class="panel"><summary><h2>Relations</h2></summary>` +
			`<p class="dim">This object asserts no relations.</p></details>`
	}
	var b strings.Builder
	b.WriteString(`<details open class="panel"><summary><h2>Relations</h2></summary>` +
		`<ul class="relations">`)
	for _, rel := range mine {
		b.WriteString(relationItem(collection, rel))
	}
	b.WriteString(`</ul></details>`)
	return b.String()
}

// relationItem draws one edge. The three states of §13 are distinct here
// in CLASS and in WORDS, because a class alone is a stylesheet away from
// being nothing at all — and this is the exact rendering whose collapse
// §28 calls the founding failure re-entering through layer 6.
func relationItem(collection string, rel store.Relation) string {
	target := rel.TargetName
	link := target
	if rel.Resolved && rel.TargetID != "" {
		// The link is minted from the resolution the COLLATOR made, never
		// from a prefix table in the renderer — §27's first rotted copy
		// was such a table, 31 prefixes deep, with the whole application
		// tier missing so every app-tier link rendered as dead text.
		link = fmt.Sprintf(`<a href="/collections/%s/objects/%s">%s</a>`,
			esc(collection), esc(target), esc(target))
	} else {
		link = esc(target)
	}
	switch rel.Observability {
	case store.Confirmed:
		return fmt.Sprintf(
			`<li class="rel confirmed"><span class="rel-type">%s</span> %s:%s `+
				`<span class="rel-state">both ends read</span></li>`,
			esc(rel.Type), esc(rel.TargetKind), link)
	case store.Contradicted:
		// Both ends shown, disagreeing, with each vantage named.
		return fmt.Sprintf(
			`<li class="rel contradicted"><span class="rel-type">%s</span> %s:%s `+
				`<span class="rel-state">the two ends disagree — read from %s</span>`+
				`</li>`,
			esc(rel.Type), esc(rel.TargetKind), link, esc(rel.Vantage))
	default:
		// Asserted. NOT a degraded confirmed: it carries a positive claim
		// about what was not looked at, and the sentence says so.
		return fmt.Sprintf(
			`<li class="rel asserted"><span class="rel-type">%s</span> %s:%s `+
				`<span class="rel-state">the far end has never been read — `+
				`claimed from %s alone</span></li>`,
			esc(rel.Type), esc(rel.TargetKind), link, esc(rel.Vantage))
	}
}

func evidenceSection(collection, object string) string {
	// Evidence is one step from any fact, and it is a LINK: captured
	// fresh on request, stored nowhere. The page does not embed it,
	// because embedding would mean capturing it on every page load.
	return fmt.Sprintf(
		`<details class="panel"><summary><h2>Evidence</h2></summary>`+
			`<p>The raw native document this object's facts were read from, `+
			`captured fresh when you ask for it and stored nowhere: `+
			`<a href="/v1/collections/%s/objects/%s/evidence">fetch it</a>.</p>`+
			`<p class="faint">Evidence is checkable, not infallible. It is `+
			`captured now, so it may show a system that has changed since the `+
			`fact was read; it can be truncated by a limit; and it inherits `+
			`whatever the source itself gets wrong. What it offers is that it `+
			`is the only thing here that is not our interpretation.</p></details>`,
		esc(collection), esc(object))
}
