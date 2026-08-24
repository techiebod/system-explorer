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
// expansion to the platform because the platform does it well, not
// because script is rationed: the browser maintains open/closed state,
// keyboard access and the accessibility tree here, and a hand-rolled
// version would be this repository maintaining all three. The page is a
// complete answer before anything runs, which is what `curl` and §29's
// consumer without eyes receive.
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
			`<a href="%s">%s</a></p><h1>%s</h1>`,
		collectionHref(collection), esc(collection), esc(self.Name)))
	if self.Type != "" {
		body.WriteString(fmt.Sprintf(`<p class="dim">%s%s</p>`,
			chip(self.Type, "type"), scopeMark(self.Scope)))
	}

	var families map[string][]string
	if len(self.Names) > 0 {
		// A malformed name map is not treated as "no names": the identity
		// chain would then silently show one name, which is the state it
		// exists to prevent.
		if json.Unmarshal(self.Names, &families) != nil {
			families = nil
		}
	}
	body.WriteString(nameFamilies(families))
	body.WriteString(factsSection(render, facts, absent, could))
	body.WriteString(opinionsSection(st, document, collection, self, facts))
	body.WriteString(relationsSection(st, collection, self))
	body.WriteString(evidenceSection(collection, self.Name))

	states, err := st.Collections()
	if err != nil {
		states = nil
	}
	return wrapWithNav(self.Name+" · "+collection,
		navRail(st, states, collection), body.String()), http.StatusOK, nil
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
	// THREE states, not two. This tested `err != nil || rules == nil` and
	// reported both as "no rule table could be read" — the same
	// conflation the host page carried, and just as wrong here: a
	// collection that declares no rules has a perfectly readable
	// declaration, and telling a reader otherwise sends them to debug it.
	//
	// Unjudged is never "clean" in either case: saying nothing fired
	// would be reporting absence as health.
	switch {
	case err != nil || document == "":
		return `<details class="panel"><summary><h2>Opinions</h2></summary>` +
			`<p class="faint">No rule table could be read for this ` +
			`collection, so nothing has judged this object. That is a ` +
			`statement about the declaration, not about the object.</p></details>`
	case rules == nil:
		return `<details class="panel"><summary><h2>Opinions</h2></summary>` +
			`<p class="faint">This collection declares no rules, so nothing ` +
			`was ever going to be said about this object either way. Its ` +
			`producer has published facts and no judgement of them.</p></details>`
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
	// A contested prefix returns an error and no index, so every target
	// degrades to a stated non-link rather than to a guess.
	owner, err := collectionOfPrefix(st)
	if err != nil {
		owner = map[string]string{}
	}
	// BOTH DIRECTIONS, ACROSS EVERY COLLECTION.
	//
	// This read Relations(collection) and matched only the SOURCE, so an
	// edge was visible from one end and one collection only. An md
	// array's page read "This object asserts no relations" while every
	// member device asserted `member-of` pointing at it, and a disk's
	// `backs` edge lives in block-devices where the arrays page could
	// never see it. The owner's words were "most relationships don't
	// appear to be shown"; they were all there and reachable from one
	// side.
	//
	// The two are kept apart rather than merged, because they answer
	// different questions: outbound is "what is this made of", inbound is
	// "what depends on this" — and the second is the one you want before
	// unplugging anything.
	out, in, err := st.RelationsTouching(row.ID, row.Name)
	if err != nil {
		return `<details class="panel"><summary><h2>Relations</h2></summary>` +
			`<p class="faint">The relation store could not be read, so no ` +
			`claim is made about this object's edges either way.</p></details>`
	}
	if len(out) == 0 && len(in) == 0 {
		return `<details class="panel"><summary><h2>Relations</h2></summary>` +
			`<p class="dim">Nothing asserts an edge to or from this object. ` +
			`That is a statement about what the collectors declared, not ` +
			`about what the system does.</p></details>`
	}
	var b strings.Builder
	b.WriteString(`<details open class="panel"><summary><h2>Relations</h2></summary>`)
	if len(out) > 0 {
		b.WriteString(`<p class="dim">This object asserts:</p><ul class="relations">`)
		for _, rel := range out {
			b.WriteString(relationItem(owner, rel))
		}
		b.WriteString(`</ul>`)
	}
	if len(in) > 0 {
		b.WriteString(`<p class="dim">Asserted about this object, from ` +
			`elsewhere:</p><ul class="relations">`)
		for _, rel := range in {
			b.WriteString(inboundItem(owner, rel))
		}
		b.WriteString(`</ul>`)
	}
	b.WriteString(`</details>`)
	return b.String()
}

// relationItem draws one edge. The three states of §13 are distinct here
// in CLASS and in WORDS, because a class alone is a stylesheet away from
// being nothing at all — and this is the exact rendering whose collapse
// §28 calls the founding failure re-entering through layer 6.
func relationItem(owner map[string]string, rel store.Relation) string {
	// CROSS-SUBSYSTEM, which is an acceptance item: a zpool device links
	// through to its hardware disk, a veth to its container. The target
	// almost never lives in the source's own collection, so the link is
	// resolved through the prefix index assembled from every declaration
	// this host holds — the producers' knowledge, read, not copied.
	link := targetLink(owner, rel)
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
			`<a href="/v1%s/objects/%s/evidence">fetch it</a>.</p>`+
			`<p class="faint">Evidence is checkable, not infallible. It is `+
			`captured now, so it may show a system that has changed since the `+
			`fact was read; it can be truncated by a limit; and it inherits `+
			`whatever the source itself gets wrong. What it offers is that it `+
			`is the only thing here that is not our interpretation.</p></details>`,
		collectionHref(collection), esc(url.PathEscape(object)))
}
