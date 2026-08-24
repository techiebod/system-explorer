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
func collectionOfPrefix(st *store.Store) (map[string]string, []string, error) {
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
	owner, contested := prefixIndexTolerant(prefixes)
	return owner, contested, nil
}

// targetLink mints the link to a relation's far end.
//
// An UNRESOLVED target is deliberately not a link. §13 says an asserted
// relation carries a positive claim about what was not looked at, and a
// link implies there is something at the other end to open — which is
// the claim the state exists to deny. The name is still shown: the
// reader needs to know what was asserted even when nothing confirms it.
func targetLink(owner map[string]string, contested []string,
	rel store.Relation) string {
	if !rel.Resolved || rel.TargetID == "" {
		return esc(rel.TargetName)
	}
	collection, known := owner[rel.TargetKind]
	if !known {
		// Stated rather than linked to a guess — and stated ACCURATELY.
		// The two reasons are different problems for different people:
		// nobody declaring the prefix is a gap, and two collections
		// declaring it is a collision somebody must break. Saying "no
		// collection declares it" about a prefix TWO collections declare
		// sends the reader looking for the wrong thing.
		for _, prefix := range contested {
			if prefix == rel.TargetKind {
				return fmt.Sprintf(
					`%s <span class="faint">(more than one collection declares `+
						`the prefix %s, so it resolves to neither)</span>`,
					esc(rel.TargetName), esc(rel.TargetKind))
			}
		}
		return fmt.Sprintf(
			`%s <span class="faint">(no collection on this host declares `+
				`the prefix %s)</span>`, esc(rel.TargetName), esc(rel.TargetKind))
	}
	return fmt.Sprintf(`<a href="%s">%s</a>`,
		objectHref(collection, rel.TargetName), esc(rel.TargetName))
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
