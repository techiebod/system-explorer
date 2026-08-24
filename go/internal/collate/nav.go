// The navigation rail: every collection this host has ever been asked
// for, grouped, on every page.
//
// **There was none.** Each page carried a breadcrumb and nothing else,
// and the only index was a 52-row table you had to go back to. The
// owner's words were "the left nav bar is lost".
//
// **The grouping is DERIVED, never a table here.** `app.js` held one —
// GROUPS and DOMAINS, hand-kept — and its own comment argues correctly
// that a collector is an acquisition boundary and so "the right way to
// organise adapters and no way at all to look for anything". That
// argument stands, and the answer is not to move the taxonomy into this
// file: it is to derive what can be derived, and let the operator supply
// the rest as data. Here we derive from the collector each collection
// was learned under, which the store already holds.
//
// **It works for a collection that has never been read**, which matters
// because 18 of 52 on a lab host are exactly that: `IssueGenerations`
// stamps the declaration digest when the generation is ISSUED, not when
// a batch applies, so a collection nothing ever answered for still knows
// which collector owns it. Verified on a live host: 52 of 52 carry one.
//
// **Nothing is ever hidden from it.** The old nav hid collections the
// roll-up called honestly empty, and the same file records what that
// produced — "a nav that shrank under the pointer". That is
// absence-as-health in the navigation itself. Every collection appears,
// in the same place, every time, wearing the state that made it empty.
package collate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/techiebod/system-explorer/go/internal/store"
	"github.com/techiebod/system-explorer/go/internal/wire"
)

// navGroup is one collector's collections, in the order that collector
// declared them.
type navGroup struct {
	Collector   string
	Collections []string
}

// navGroups reads the store's own collection→declaration join.
//
// Deliberately NOT a scan of "which collector declares a collection
// called X": `overview` is declared by both the system and traefik
// collectors, `daemon` by both kea and unbound, `instance` by both
// bazarr and paperless. A scan would have to tie-break and would
// therefore guess, where the store already knows which document THIS
// collection was learned under.
func navGroups(st *store.Store, states []store.CollectionState) []navGroup {
	// One read of every document this host holds, keyed by digest — the
	// store already selects exactly the ones some collection points at.
	documents, err := st.DeclarationDocuments()
	if err != nil {
		documents = map[string]string{}
	}
	// declaration digest → parsed collector name and its declared order.
	type parsed struct {
		collector string
		order     map[string]int
	}
	byDigest := map[string]parsed{}
	collectorOf := map[string]string{}
	orderOf := map[string]int{}

	for _, cs := range states {
		if cs.Declaration == nil {
			continue
		}
		digest := *cs.Declaration
		got, done := byDigest[digest]
		if !done {
			got = parsed{order: map[string]int{}}
			if decl, _, err := wire.ParseDeclaration(
				[]byte(documents[digest])); err == nil {
				got.collector = decl.Collector
				for i, c := range decl.Collections {
					got.order[c.Name] = i
				}
			}
			byDigest[digest] = got
		}
		if got.collector == "" {
			// The document could not be read or parsed. Its own group,
			// never a guess and never dropped — the same direction the
			// prefix index takes when a prefix is contested.
			collectorOf[cs.Name] = ""
			continue
		}
		collectorOf[cs.Name] = got.collector
		if i, ok := got.order[cs.Name]; ok {
			orderOf[cs.Name] = i
		}
	}

	members := map[string][]string{}
	for _, cs := range states {
		collector := collectorOf[cs.Name]
		members[collector] = append(members[collector], cs.Name)
	}
	var collectors []string
	for collector := range members {
		collectors = append(collectors, collector)
	}
	// Across groups: alphabetical. Stable, invents no ranking, and never
	// moves under load. An operator's own ordering is theirs to supply
	// as data; this file must not decide that storage matters more than
	// packages.
	sort.Strings(collectors)

	var out []navGroup
	for _, collector := range collectors {
		names := members[collector]
		// Within a group: the order the producer DECLARED them, which is
		// an argued order — network lists tailscale, port-exposure,
		// nft-tables, nft-chains, nft-rules, routes, listening,
		// resolver, links — and not an alphabet. The same principle as
		// `answer`, whose order this surface already preserves.
		sort.SliceStable(names, func(i, j int) bool {
			a, aok := orderOf[names[i]]
			b, bok := orderOf[names[j]]
			if aok && bok {
				return a < b
			}
			if aok != bok {
				return aok
			}
			return names[i] < names[j]
		})
		out = append(out, navGroup{Collector: collector, Collections: names})
	}
	return out
}

// navRail renders the rail. `current` is the collection being viewed, or
// "" on the host page.
func navRail(st *store.Store, states []store.CollectionState, current string) string {
	byName := map[string]store.CollectionState{}
	for _, cs := range states {
		byName[cs.Name] = cs
	}
	var b strings.Builder
	b.WriteString(`<nav class="rail" aria-label="Collections">`)
	b.WriteString(`<a class="skip" href="#main">Skip to content</a>`)
	b.WriteString(fmt.Sprintf(
		`<a class="rail-home%s" href="/">This host</a>`,
		map[bool]string{true: " current", false: ""}[current == ""]))

	for _, group := range navGroups(st, states) {
		heading := group.Collector
		if heading == "" {
			// Stated, not silently filed under a guess.
			heading = "collector not recorded"
		}
		b.WriteString(fmt.Sprintf(`<div class="rail-group"><h2>%s</h2><ul>`,
			esc(heading)))
		for _, name := range group.Collections {
			cs := byName[name]
			mark, count := railState(cs)
			aria := ""
			cls := "rail-item"
			if name == current {
				aria = ` aria-current="page"`
				cls += " current"
			}
			b.WriteString(fmt.Sprintf(
				`<li class="%s"><a href="%s"%s><span class="rail-name">%s</span>`+
					`<span class="rail-count">%s</span></a>%s</li>`,
				cls, collectionHref(name), aria, esc(name), count, mark))
		}
		b.WriteString(`</ul></div>`)
	}
	b.WriteString(`</nav>`)
	return b.String()
}

// railState is the entry's state mark and its count.
//
// It shares `freshnessChip` with the host page's table rather than
// deciding a second time: that decision has already been got wrong once
// — `current` applied as a default with downgrades after it, so a
// never-read collection read as healthy — and two copies is how it comes
// back.
//
// The conflation to keep out is `absent here` against `unavailable`. On
// a lab host all 18 never-read collections carry an `unavailable`
// decline whose detail reads "no servarr api configured for this
// process" — nobody told the collector where to look. That is a gap
// somebody can close. `absent` is the interface not being on the host at
// all, and nothing is wrong. They must not wear the same mark.
func railState(cs store.CollectionState) (mark, count string) {
	count = fmt.Sprintf(`<span class="num">%d</span>`, cs.ObjectCount)
	switch {
	case cs.Generation == 0:
		count = `<span class="rail-none">—</span>`
	case cs.ObjectCount == 0:
		count = `<span class="rail-none">0</span>`
	}
	return `<span class="rail-state">` + freshnessChip(cs) + `</span>`, count
}
