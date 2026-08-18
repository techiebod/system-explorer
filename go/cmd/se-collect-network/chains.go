package main

import "sort"

// The ruleset's shape: where the kernel enters it, and what runs what.
//
// Two of the facts on a chain row are not in the chain's own document and are
// the ones that make a large ruleset navigable — JumpedFrom, which needs
// every rule in every table read plus the elements of every named verdict map
// some rule consults, and Unreferenced, which falls out of it. Everything
// else is a copy.

// A chain is identified by all three of family, table and name. Never by the
// handle: one committed capture gives both `shared` chains handle 1 and both
// `input` chains handle 2, precisely so a handle-keyed walk collapses them.
type chainKey struct {
	family string
	table  string
	name   string
}

func (k chainKey) streamName() string {
	return k.family + " " + k.table + " " + k.name
}

// stringSet is a caller set. JumpedFrom is a SET of caller chains — a chain
// that jumps to the same target from two rules is one caller, and a
// single-valued map here is the defect the nft-second-caller operator exists
// to expose.
type stringSet map[string]struct{}

func (s stringSet) add(value string) { s[value] = struct{}{} }

func (s stringSet) sorted() []string {
	out := make([]string, 0, len(s))
	for value := range s {
		out = append(out, value)
	}
	// Python sorts strings by code point and Go compares UTF-8 bytes, which
	// is the same order for every valid string.
	sort.Strings(out)
	return out
}

// verdictTargets is every chain an expression tree can hand control to, in
// document order, each named once.
//
// The WHOLE tree, not the top-level statements. nftables nests verdicts
// inside expression bodies — a ct-state verdict map carries its jumps two
// levels down, in the map's data — and the distribution firewall this product
// most often reads opens its input chain with exactly that shape. A walk that
// iterated only the surface published the chain holding every inbound accept
// as Unreferenced.
//
// Both verbs, because both reach the chain: goto differs from jump in where
// control RETURNS, not in whether it ARRIVES, and reporting a goto-only chain
// as unreachable is the one answer here somebody acts on by deleting it.
func verdictTargets(node jsonValue) []string {
	var found []string
	var descend func(jsonValue)
	descend = func(n jsonValue) {
		switch n.kind {
		case jsonObject:
			// Fixed verb order, independent of the document's member order,
			// so the dedup below picks the same first occurrence either way.
			for _, verb := range [2]string{"jump", "goto"} {
				body, ok := n.member(verb)
				if !ok || !body.isObject() {
					continue
				}
				target := body.get("target")
				if !target.isString() || target.text == "" {
					continue
				}
				if !containsString(found, target.text) {
					found = append(found, target.text)
				}
			}
			for _, m := range n.members {
				descend(m.value)
			}
		case jsonArray:
			for _, element := range n.array {
				descend(element)
			}
		}
	}
	descend(node)
	return found
}

func containsString(haystack []string, needle string) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}
	return false
}

// mapReferences is every named set or map an expression tree consults, @
// stripped. "@name" is the one spelling libnftables-json has for such a
// reference wherever the grammar lets one appear — a vmap lookup holds it in
// "data", a match against a named set in "right" — so collecting @-strings
// generically covers the next expression that can consult a named object
// without foreseeing it. Names only: whether the named object is a set or a
// verdict map, and what its elements do, is the join below.
func mapReferences(node jsonValue) stringSet {
	found := stringSet{}
	var descend func(jsonValue)
	descend = func(n jsonValue) {
		switch n.kind {
		case jsonString:
			if len(n.text) > 0 && n.text[0] == '@' {
				found.add(n.text[1:])
			}
		case jsonObject:
			// Values only, never keys: a member NAMED "@x" is not a
			// reference to anything.
			for _, m := range n.members {
				descend(m.value)
			}
		case jsonArray:
			for _, element := range n.array {
				descend(element)
			}
		}
	}
	descend(node)
	return found
}

type chainRow struct {
	key   chainKey
	facts map[string]any
	edges []relationAssertionRecord
}

// nftChains derives one row per chain from the whole `nft -j list ruleset`
// document, in the document order of each key's FIRST chain entry.
func nftChains(doc jsonValue) []chainRow {
	var order []chainKey
	chains := map[chainKey]jsonValue{}
	ruleCounts := map[chainKey]int{}
	jumped := map[chainKey]stringSet{}
	var mapOrder []chainKey
	mapTargets := map[chainKey][]string{}
	mapUsers := map[chainKey]stringSet{}

	credit := func(into map[chainKey]stringSet, key chainKey, caller string) {
		set, ok := into[key]
		if !ok {
			set = stringSet{}
			into[key] = set
		}
		set.add(caller)
	}

	entries, _ := doc.member("nftables")
	for _, entry := range entries.array {
		switch {
		case entry.has("chain"):
			c := entry.get("chain")
			key := chainKey{c.stringMember("family"), c.stringMember("table"), c.stringMember("name")}
			// Last entry wins for the content, first sighting fixes the
			// position: a duplicate (family, table, name) is ONE chain, and
			// an append-only slice would publish it twice.
			if _, seen := chains[key]; !seen {
				order = append(order, key)
			}
			chains[key] = c

		case entry.has("rule"):
			r := entry.get("rule")
			family, table := r.stringMember("family"), r.stringMember("table")
			chain := r.stringMember("chain")
			ruleCounts[chainKey{family, table, chain}]++
			expr := r.get("expr")
			// A jump target is resolved inside the JUMPING rule's own family
			// and table, never by name alone: `ip asym input` jumping to
			// `shared` cannot credit `ip6 asym shared`.
			for _, target := range verdictTargets(expr) {
				credit(jumped, chainKey{family, table, target}, chain)
			}
			for ref := range mapReferences(expr) {
				credit(mapUsers, chainKey{family, table, ref}, chain)
			}

		case entry.has("map"):
			// A NAMED verdict map keeps its jumps HERE, in the top-level map
			// object's elem list — the rule dispatching through it carries
			// only the string "@dispatch" — so a derivation reading rule
			// expressions alone publishes a map-dispatched chain as
			// {RuleCount: 0, Unreferenced: true}. Maps only, by grammar: a
			// set object's elem list holds bare keys and verdict is not a key
			// type, so a set has nowhere for a jump to sit. The map's own
			// "map" member is deliberately NOT consulted — the reference runs
			// the same descent over any map entry's elem, and gating on
			// "verdict" here would disagree with it.
			m := entry.get("map")
			key := chainKey{m.stringMember("family"), m.stringMember("table"), m.stringMember("name")}
			if _, seen := mapTargets[key]; !seen {
				mapOrder = append(mapOrder, key)
			}
			mapTargets[key] = verdictTargets(m.get("elem"))
		}
	}

	// A map's targets count only where some rule consults the map: the kernel
	// never traverses a map no rule uses, so a jump inside an unused map is
	// latent, and counting it would retire Unreferenced from exactly the
	// chains it is telling the truth about. The callers recorded are the
	// CONSULTING rules' chains — control leaves that chain, goes through the
	// map, and lands on the target. Both halves are scoped by the map's own
	// family and table.
	for _, mkey := range mapOrder {
		users, ok := mapUsers[mkey]
		if !ok || len(users) == 0 {
			continue
		}
		for _, target := range mapTargets[mkey] {
			for caller := range users {
				credit(jumped, chainKey{mkey.family, mkey.table, target}, caller)
			}
		}
	}

	rows := make([]chainRow, 0, len(order))
	for _, key := range order {
		chain := chains[key]
		// A base chain is one the kernel calls, and `hook` is what says so.
		// Truthiness of the member, not its presence — which is a different
		// test from the one that decides whether Hook is emitted, and the two
		// are kept apart on purpose.
		base := chain.get("hook").truthy()
		facts := map[string]any{
			"Family":    key.family,
			"Table":     key.table,
			"Name":      key.name,
			"BaseChain": base,
		}
		// Absent members are omitted rather than nulled: a regular chain has
		// no policy, and a null one reads as "no policy set", which is a
		// different and much more alarming claim. Each pass-through carries
		// the document's own literal, so a handle stays the integer it was.
		for _, p := range [...]struct{ fact, member string }{
			{"Handle", "handle"}, {"Hook", "hook"}, {"Type", "type"},
			{"Priority", "prio"}, {"Policy", "policy"},
		} {
			if value, ok := chain.member(p.member); ok && !value.isNull() {
				facts[p.fact] = value
			}
		}
		// Zero is measured, not missing: an empty base chain runs its policy
		// on everything.
		facts["RuleCount"] = ruleCounts[key]

		callers := jumped[key].sorted()
		if len(callers) > 0 {
			facts["JumpedFrom"] = callers
		} else if !base {
			// Stated only when true, and only for a regular chain — nothing
			// jumps to an input hook and nothing needs to.
			facts["Unreferenced"] = true
		}
		// One assertion: the table this chain belongs to. Nothing this
		// collector serves publishes an nft-table object, so the target
		// resolves against nothing on this host and the collator mints the
		// relation `asserted` — the condition DESIGN 13 exists for, and not
		// a dangling pointer.
		//
		// Inbound dispatch is NOT asserted here even though JumpedFrom holds
		// it. A relation is directed because observation has a vantage, and
		// the vantage that saw a jump is the RULE that writes it; asserting
		// the same edge from this end would put two directed claims about
		// one edge on the wire from ONE reading of ONE document, which is
		// not the bilateral observation `confirmed` is supposed to mean.
		// JumpedFrom stays a derived fact, which is what it is.
		rows = append(rows, chainRow{
			key:   key,
			facts: facts,
			edges: []relationAssertionRecord{{
				Type:   "member-of",
				Target: assertionTarget{Kind: "nft-table", Name: key.family + " " + key.table},
			}},
		})
	}
	return rows
}
