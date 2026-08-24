// Hide groups: the default view narrowed, without the default view ever
// swallowing a failure.
//
// **The group definitions are DECLARED, not coded here.** `app.js` holds
// them as a hard-coded table of predicates — `facts.ActiveState ===
// "inactive"`, `item.type === type && facts.LoadState === "loaded"` —
// and that is a fifth copy of producer knowledge in a renderer, the
// exact shape §27 records rotting three times. So a group arrives in the
// declaration and is evaluated with `match()`, the SAME condition
// evaluator the rule tables use: one condition language, not two that
// drift.
//
// **No shipped declaration declares a group yet, and that is deliberate.**
// Adding the member to `units` would change that collector's declaration
// hash and every corpus pinning it, and this repository has no
// regeneration switch on purpose — "a corpus that regenerated itself
// silently would ratify a regression the first time it ran". That is a
// producer change with producer consequences and it does not belong
// inside a rendering wave. Until it lands, this mechanism renders no
// chips, which is why the units page shows every row.
//
// FOUR INVARIANTS, carried from `app.js` and each one load-bearing:
//
//  1. **A chip's count does not change when the chip is pressed.** The
//     number answers *what this group holds*, not *what is hidden right
//     now*. Server-rendered counts toggled by CSS cannot violate it —
//     nothing recomputes, so there is nothing to get wrong.
//  2. **A row the rulebook called critical is never suppressed**, whatever
//     a group matches on. Enforced ONCE, structurally, rather than
//     re-derived in every predicate anyone adds later: "the default view
//     never swallows a failure" is the promise the whole toggle rests on,
//     and a promise honoured by coincidence is one waiting to be broken
//     by an unrelated edit to the rulebook.
//  3. **Critical only, never warn.** The inactive group hides a unit
//     carrying a restart-churn warning today, and widening the exemption
//     to warn would quietly change what that group has always meant.
//     That is a separate call for whoever wants it, not a side effect.
//  4. **A hidden row's way back is legible.** The chip is the label of
//     the checkbox that reveals its group, so the control and the count
//     are one thing and there is no state to get out of step.
package collate

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// HideGroup is one declared group.
type HideGroup struct {
	Key   string          `json:"key"`
	Label string          `json:"label"`
	When  json.RawMessage `json:"when"`
	// ObjectType narrows the group to one declared object type, in
	// addition to `when`. It lives here rather than in the condition
	// vocabulary, which is closed on purpose and whose stated invariant
	// is that every leaf names a FACT — widening it would widen the
	// judging path too. A hide group is display only, so a narrowing
	// that lives on the group costs the rule tables nothing.
	ObjectType string `json:"object_type"`
}

// HideGroupsFor reads a collection's declared groups. A collection
// declaring none returns nil, which renders every row — the safe
// direction, since the failure mode of a missing group is a longer page
// and the failure mode of an invented one is a hidden fault.
func HideGroupsFor(document, collection string) ([]HideGroup, error) {
	var doc struct {
		Collections []struct {
			Name       string      `json:"name"`
			HideGroups []HideGroup `json:"hide_groups"`
		} `json:"collections"`
	}
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		return nil, fmt.Errorf("declaration: %w", err)
	}
	for _, c := range doc.Collections {
		if c.Name == collection {
			return c.HideGroups, nil
		}
	}
	return nil, nil
}

// assign decides which group holds a row, or "" if it stays on the page.
//
// The critical exemption is here and NOT in any predicate, which is
// invariant 2. `app.js` records why: the original single group got it for
// free, because nothing whose ActiveState is `inactive` is a failed unit,
// and a group matching on KIND has no such luck.
func assign(groups []HideGroup, facts map[string]any, worst string) string {
	return assignTyped(groups, facts, "", worst)
}

// assignTyped is assign with the object's declared TYPE available, which
// is what a kind group narrows on.
func assignTyped(groups []HideGroup, facts map[string]any,
	objectType, worst string) string {
	if worst == "critical" {
		return ""
	}
	for _, group := range groups {
		if group.ObjectType != "" && group.ObjectType != objectType {
			continue
		}
		if len(group.When) == 0 {
			continue
		}
		held, err := match(group.When, facts)
		if err != nil || !held {
			// An unevaluable condition leaves the row VISIBLE. A group
			// that cannot be evaluated hiding rows anyway would suppress
			// on the strength of a broken declaration.
			continue
		}
		return group.Key
	}
	return ""
}

// GroupCount is a chip: what the group holds, and the key that reveals it.
type GroupCount struct {
	Key   string
	Label string
	Count int
}

// Chips counts what assign() ASSIGNS rather than what a condition alone
// would claim, so a chip's number is exactly the set of rows toggling it
// reveals — critical rows, and rows an earlier group already took, are
// not counted twice or promised falsely. Groups holding nothing are
// omitted: a chip reading zero is a control that does nothing.
func Chips(groups []HideGroup, assigned []string) []GroupCount {
	held := map[string]int{}
	for _, key := range assigned {
		if key != "" {
			held[key]++
		}
	}
	var out []GroupCount
	for _, group := range groups {
		if n := held[group.Key]; n > 0 {
			out = append(out, GroupCount{Key: group.Key, Label: group.Label, Count: n})
		}
	}
	return out
}

// hideControls renders the chips and the CSS that acts on them.
//
// A checkbox and a `:checked ~` sibling selector, per §28's interaction
// table — the chip is its <label>. No script: the state is the browser's,
// and a mechanism the platform maintains beats one this repository does.
func hideControls(chips []GroupCount) string {
	if len(chips) == 0 {
		return ""
	}
	var b strings.Builder
	var rules []string
	b.WriteString(`<div class="hide-groups">`)
	for _, chip := range chips {
		id := "reveal-" + chip.Key
		// The checkbox precedes the table so `~` can reach it, and it is
		// visually hidden rather than absent — a control removed from the
		// accessibility tree is a control keyboard users do not have.
		b.WriteString(fmt.Sprintf(
			`<input type="checkbox" id="%s" class="reveal">`+
				`<label for="%s" class="chip hide-chip">%s `+
				`<span class="count">%d</span></label>`,
			esc(id), esc(id), esc(chip.Label), chip.Count))
		// The count is RENDERED, never recomputed — invariant 1 holds
		// because nothing here can change it.
		rules = append(rules, fmt.Sprintf(
			"#%s:checked ~ .scroll tr[data-group=\"%s\"]{display:table-row}",
			cssIdent(id), cssIdent(chip.Key)))
	}
	b.WriteString(`</div>`)
	if len(rules) > 0 {
		sort.Strings(rules)
		b.WriteString("<style>tr[data-group]{display:none}" +
			strings.Join(rules, "") + "</style>")
	}
	return b.String()
}

// cssIdent keeps a declared key from escaping into a selector. A group
// key is producer text, and a selector assembled from unescaped producer
// text is an injection into the one place a CSP cannot help — the
// stylesheet this page already permits.
func cssIdent(in string) string {
	var b strings.Builder
	for _, r := range in {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}
