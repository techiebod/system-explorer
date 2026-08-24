// Trees derived from relations, and the cross-collection link.
//
// **A tree is DERIVED, never declared as a shape.** The units page's
// slice tree and the links page's bridge tree are the same mechanism
// reading different edges: a collection declares which relation type
// nests it, and the rows arrange themselves. §27's rule holds — the
// nesting is the producer's `member-of`/`enslaved-to` assertion, and
// this file only draws it.
//
// **Indentation is disabled under sort or filter**, which is an
// acceptance item and not a nicety. Indentation claims a parent is
// directly above its child; once the rows are reordered that claim is
// false, and a tree drawn over a reordered list tells the reader
// something the data does not say.
//
// **Where a target lives is resolved from the PRODUCERS' declarations**,
// never from a table here. §27's first rotted copy was exactly such a
// table — 31 id prefixes in the browser, missing the whole application
// tier, so every app-tier link rendered as dead text and nothing in the
// browser could have noticed, because nothing in the browser mints ids.
// The prefix index is already assembled from every declaration this host
// holds; this reads the same source.
package collate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/techiebod/system-explorer/go/internal/store"
	"github.com/techiebod/system-explorer/go/internal/wire"
)

// collectionOfPrefix maps an object-id prefix to the collection that
// declared it, and names any prefix that is contested.
//
// **A CONTESTED PREFIX COSTS ITS OWN KIND AND NOTHING ELSE.** This used
// `store.PrefixIndex`, which refuses the WHOLE INDEX when any prefix is
// declared twice — and the estate's own declarations contain such a
// clash: `units` and `workloads` both declare `unit`. So on every host
// running both collectors, EVERY relation target on EVERY object page
// rendered as dead text, and the page blamed a prefix that was very
// often not the one in question.
//
// It is the same defect the apply path had, fixed there on 2026-08-23
// with the same words — one bad thing must not cost the host its other
// facts — and left here. `prefixIndexTolerant` is that fix; this now
// calls it rather than keeping a second, stricter opinion.
//
// DESIGN's rule is unchanged: two collections declaring one prefix
// resolve to NEITHER, never to whichever was read last. What changes is
// that the other forty-odd prefixes keep working.
func collectionOfPrefix(st *store.Store) (map[string]string, map[string][]string, error) {
	documents, err := st.DeclarationDocuments()
	if err != nil {
		return nil, nil, err
	}
	prefixes := map[string]string{}
	for _, document := range documents {
		decl, _, err := wire.ParseDeclaration([]byte(document))
		if err != nil {
			continue
		}
		for _, c := range decl.Collections {
			prefixes[c.Name] = c.Prefix
		}
	}
	owner, contested, claimants := prefixIndexWithClaimants(prefixes)
	// Only the CONTESTED prefixes' claimants travel: an uncontested
	// prefix is already in `owner`, and carrying its single claimant too
	// would be two answers to one question.
	held := map[string][]string{}
	for _, prefix := range contested {
		held[prefix] = claimants[prefix]
	}
	return owner, held, nil
}

// targetLink mints the link to a relation's far end.
//
// An UNRESOLVED target is deliberately not a link. §13 says an asserted
// relation carries a positive claim about what was not looked at, and a
// link implies there is something at the other end to open — which is
// the claim the state exists to deny. The name is still shown: the
// reader needs to know what was asserted even when nothing confirms it.
func targetLink(owner map[string]string, contested map[string][]string,
	rel store.Relation) string {
	// A CONTESTED prefix offers every claimant rather than nothing.
	//
	// `units` and `workloads` both declare `unit`, and both are right —
	// one describes what a systemd unit is doing, the other what it is
	// consuming, about the same objects. The page said "resolves to
	// neither" and stopped, withholding two destinations it was holding
	// and blanking every relation on the host. Offering both decides
	// nothing: it hands the reader the claimants and lets them choose,
	// which is what this file is allowed to do.
	if holders := contested[rel.TargetKind]; len(holders) > 0 {
		var links []string
		for _, collection := range holders {
			links = append(links, fmt.Sprintf(`<a href="%s">%s</a>`,
				objectHref(collection, rel.TargetName), esc(collection)))
		}
		return fmt.Sprintf(
			`%s <span class="faint">(%s describe this name — `+
				`%s)</span>`,
			esc(rel.TargetName),
			esc(fmt.Sprintf("%d collections", len(holders))),
			strings.Join(links, ", "))
	}
	if !rel.Resolved || rel.TargetID == "" {
		// §13: an asserted relation carries a positive claim about what
		// was NOT looked at, and a link implies there is something to
		// open — the claim the state exists to deny.
		return esc(rel.TargetName)
	}
	collection, known := owner[rel.TargetKind]
	if !known {
		return fmt.Sprintf(
			`%s <span class="faint">(no collection on this host declares `+
				`the prefix %s)</span>`, esc(rel.TargetName), esc(rel.TargetKind))
	}
	return fmt.Sprintf(`<a href="%s">%s</a>`,
		objectHref(collection, rel.TargetName), esc(rel.TargetName))
}

// relationGroups renders edges grouped, because the state sentence is
// the same for every member and 181 copies of it is not information.
//
// A slice's page carried 181 inbound `member-of` edges, each its own
// list item repeating the same twelve words — "the far end has never
// been read, claimed from units alone". §28 is right that an asserted
// relation must carry its OWN WORDS and not a tooltip or a footnote, and
// the words describe a STATE, so the honest fix is to say them once on
// the container every member sits inside rather than to abbreviate them
// or drop them.
//
// **Nothing is elided.** Every target is present, as a link where the
// far end resolves. There is no "and 170 more": a page that cannot show
// its own data is not shorter, it is incomplete, and `curl` gets the
// whole document either way because <details> content is in the markup
// open or closed.
//
// The group key is (type, observability, vantage) within a direction.
// Observability is IN THE KEY so two states can never share a container
// — an asserted edge and a confirmed one must not sit under one heading
// whatever else they have in common.
func relationGroups(owner map[string]string, contested map[string][]string,
	rels []store.Relation, inbound bool) string {
	if len(rels) == 0 {
		return ""
	}
	type key struct{ relType, observability, vantage string }
	order := []key{}
	members := map[key][]store.Relation{}
	for _, rel := range rels {
		k := key{rel.Type, string(rel.Observability), rel.Vantage}
		if _, seen := members[k]; !seen {
			order = append(order, k)
		}
		members[k] = append(members[k], rel)
	}
	// Contradicted, then asserted, then confirmed — §13's own ordering of
	// how much each state should worry a reader, not a ranking invented
	// here.
	rank := map[string]int{
		string(store.Contradicted): 0,
		string(store.Asserted):     1,
		string(store.Confirmed):    2,
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if rank[a.observability] != rank[b.observability] {
			return rank[a.observability] < rank[b.observability]
		}
		return a.relType < b.relType
	})

	var b strings.Builder
	if inbound {
		b.WriteString(`<p class="dim">Asserted about this object, from elsewhere:</p>`)
	} else {
		b.WriteString(`<p class="dim">This object asserts:</p>`)
	}
	for _, k := range order {
		group := members[k]
		state, words := relationWords(store.Observability(k.observability),
			k.vantage, inbound)
		// The collection the far ends live in, named only when it is
		// uniform — a mixed group would be a claim the group cannot make.
		where := ""
		if uniform := uniformCollection(group, inbound); uniform != "" {
			where = ` in <span class="ident">` + esc(uniform) + `</span>`
		}
		// Open where a reader can take it in; closed above that, with the
		// count and the state visible in the summary either way.
		open := ""
		if len(group) <= 25 {
			open = " open"
		}
		verb := "assert"
		if !inbound {
			verb = "→"
		}
		b.WriteString(fmt.Sprintf(
			`<details%s class="rel-group %s"><summary><span class="num">%d</span> `+
				`<span class="rel-type">%s</span>%s <span class="rel-state">%s</span>`+
				`</summary>`,
			open, state, len(group), esc(k.relType), where, words))
		b.WriteString(relationBodies(owner, contested, group, inbound))
		b.WriteString(`</details>`)
		_ = verb
	}
	return b.String()
}

// relationWords is the state's sentence, in the direction being read.
func relationWords(o store.Observability, vantage string, inbound bool) (string, string) {
	switch o {
	case store.Confirmed:
		return "confirmed", "both ends read"
	case store.Contradicted:
		return "contradicted", "the two ends disagree — read from " + esc(vantage)
	}
	if inbound {
		return "asserted", "this end has never been read — claimed from " +
			esc(vantage) + " alone"
	}
	return "asserted", "the far end has never been read — claimed from " +
		esc(vantage) + " alone"
}

// uniformCollection is where every far end in a group lives, or "" when
// they differ. Named only when uniform: a mixed group naming one of them
// would be a claim about edges that do not hold it.
func uniformCollection(group []store.Relation, inbound bool) string {
	seen := ""
	for _, rel := range group {
		where := rel.TargetKind
		if inbound {
			where = rel.Collection
		}
		if seen == "" {
			seen = where
			continue
		}
		if seen != where {
			return ""
		}
	}
	return seen
}

// relationBodies renders a group's members: chips where the edge carries
// no facts, a table where it does.
//
// A relation type that CARRIES FACTS cannot collapse to a chip — the
// facts are the reason the edge was worth asserting — so those become a
// nested table, one row per edge, inside the same container.
func relationBodies(owner map[string]string, contested map[string][]string,
	group []store.Relation, inbound bool) string {
	carries := false
	for _, rel := range group {
		if len(rel.Facts) > 2 { // more than "{}"
			carries = true
			break
		}
	}
	var b strings.Builder
	if !carries {
		b.WriteString(`<div class="chips rel-members">`)
		for _, rel := range group {
			b.WriteString(`<span class="chip item">` +
				relationEnd(owner, contested, rel, inbound) + `</span>`)
		}
		b.WriteString(`</div>`)
		return b.String()
	}
	b.WriteString(`<div class="scroll"><table class="nested"><thead><tr>` +
		`<th>end</th><th>facts</th></tr></thead><tbody>`)
	for _, rel := range group {
		facts := ""
		if len(rel.Facts) > 2 {
			facts = esc(string(rel.Facts))
		}
		b.WriteString(`<tr><td>` + relationEnd(owner, contested, rel, inbound) +
			`</td><td class="faint">` + facts + `</td></tr>`)
	}
	b.WriteString(`</tbody></table></div>`)
	return b.String()
}

// relationEnd is the far end of one edge, as a link where it resolves.
func relationEnd(owner map[string]string, contested map[string][]string,
	rel store.Relation, inbound bool) string {
	if !inbound {
		return targetLink(owner, contested, rel)
	}
	if rel.Collection == "" || rel.SourceName == "" {
		return esc(rel.SourceName)
	}
	return fmt.Sprintf(`<a href="%s">%s</a>`,
		objectHref(rel.Collection, rel.SourceName), esc(rel.SourceName))
}

// inboundItem draws an edge pointing AT this object, from the far end's
// point of view: the SOURCE is what the reader wants to reach, and the
// wording is reversed so the sentence still reads outward from the page
// they are on.
//
// The observability states mean the same thing in this direction and are
// drawn the same way — an asserted inbound edge is still a positive
// claim about something nobody looked at, and must not be mistaken for a
// confirmed one just because it arrived from elsewhere.
func inboundItem(owner map[string]string, rel store.Relation) string {
	// The link goes to the SOURCE, which lives in the collection that
	// asserted the edge — not in this object's own.
	source := esc(rel.SourceName)
	if rel.Collection != "" && rel.SourceName != "" {
		source = fmt.Sprintf(`<a href="%s">%s</a>`,
			objectHref(rel.Collection, rel.SourceName), esc(rel.SourceName))
	}
	state, words := "asserted", "the far end has never been read — claimed "+
		"from "+esc(rel.Vantage)+" alone"
	switch rel.Observability {
	case store.Confirmed:
		state, words = "confirmed", "both ends read"
	case store.Contradicted:
		state, words = "contradicted", "the two ends disagree — read from "+
			esc(rel.Vantage)
	}
	return fmt.Sprintf(
		`<li class="rel %s">%s <span class="rel-type">%s</span> this `+
			`<span class="rel-state">%s</span></li>`,
		state, source, esc(rel.Type), words)
}

// nameFamilies renders every name a collector published for an object.
//
// The identity-chain acceptance item: one disk reachable from its
// /dev/disk/by-id path, its kernel name and its WWN — ONE object, ONE
// page, every name on it. The point is not decoration: an operator
// holding any one of those names must land on the same page, and a page
// that shows only the name it was reached by leaves them wondering
// whether they have the right disk.
func nameFamilies(names map[string][]string) string {
	if len(names) == 0 {
		return ""
	}
	var families []string
	for family := range names {
		families = append(families, family)
	}
	sortStrings(families)
	var b strings.Builder
	b.WriteString(`<details open class="panel"><summary><h2>Names</h2></summary>` +
		`<p class="dim">Every name this collector published for this object. ` +
		`Any of them denotes this page.</p><dl class="names">`)
	for _, family := range families {
		b.WriteString("<dt>" + esc(family) + "</dt><dd>")
		for _, name := range names[family] {
			b.WriteString(fmt.Sprintf(`<span class="chip item">%s</span> `, esc(name)))
		}
		b.WriteString("</dd>")
	}
	b.WriteString(`</dl></details>`)
	return b.String()
}

// nest arranges rows into parent/child order from a relation type.
//
// Returns the display order and each row's depth. A row whose parent is
// not on this page is a ROOT: nesting it under an absent parent would
// draw an edge to something the reader cannot see.
//
// A cycle is broken by treating the row that closes it as a root, and
// the caller says so on the page. Silently dropping it would lose a row;
// silently recursing would hang the request.
func nest(rows []store.ObjectRow, parentOf map[string]string) ([]int, map[int]int, bool) {
	index := map[string]int{}
	for i, row := range rows {
		index[row.Name] = i
	}
	children := map[int][]int{}
	var roots []int
	for i, row := range rows {
		parent, has := parentOf[row.Name]
		if j, on := index[parent]; has && on && j != i {
			children[j] = append(children[j], i)
			continue
		}
		roots = append(roots, i)
	}
	order := make([]int, 0, len(rows))
	depth := map[int]int{}
	seen := make([]bool, len(rows))
	var walk func(i, d int)
	walk = func(i, d int) {
		if seen[i] {
			return
		}
		seen[i] = true
		order = append(order, i)
		depth[i] = d
		for _, child := range children[i] {
			walk(child, d+1)
		}
	}
	for _, root := range roots {
		walk(root, 0)
	}
	broken := false
	for i := range rows {
		if !seen[i] {
			// In a cycle. Shown as a root, and the page says a cycle was
			// found rather than quietly presenting it as top-level.
			broken = true
			walk(i, 0)
		}
	}
	return order, depth, broken
}
