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
// declared it, from every declaration this host holds.
//
// The index itself is `store.PrefixIndex`, which the resolver already
// uses — ONE spelling of "which collection owns this prefix", not a
// second that can drift from it. It REFUSES a prefix two collections
// declare rather than picking one; a contested prefix therefore yields
// no index at all, and every link on the page degrades to a stated
// non-link. That is the right direction: the collator declines to decide
// which collection owns it, and a renderer quietly picking one would be
// re-deciding what the collator refused.
func collectionOfPrefix(st *store.Store) (map[string]string, error) {
	documents, err := st.DeclarationDocuments()
	if err != nil {
		return nil, err
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
	return store.PrefixIndex(prefixes)
}

// targetLink mints the link to a relation's far end.
//
// An UNRESOLVED target is deliberately not a link. §13 says an asserted
// relation carries a positive claim about what was not looked at, and a
// link implies there is something at the other end to open — which is
// the claim the state exists to deny. The name is still shown: the
// reader needs to know what was asserted even when nothing confirms it.
func targetLink(owner map[string]string, rel store.Relation) string {
	if !rel.Resolved || rel.TargetID == "" {
		return esc(rel.TargetName)
	}
	collection, known := owner[rel.TargetKind]
	if !known {
		// The kind names no prefix any declaration on this host claims,
		// or two claim it. Stated rather than linked to a guess: a dead
		// link is what the browser's routing table produced for the whole
		// application tier, and nobody noticed for as long as it existed.
		return fmt.Sprintf(
			`%s <span class="faint">(no collection on this host declares `+
				`the prefix %s)</span>`, esc(rel.TargetName), esc(rel.TargetKind))
	}
	return fmt.Sprintf(`<a href="%s">%s</a>`,
		objectHref(collection, rel.TargetName), esc(rel.TargetName))
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
