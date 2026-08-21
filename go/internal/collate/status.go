// GET /v1/status — the attention surface (register row 10), carried over
// from the shipping agent's roll-up (agent/main.py, _status_rollup) onto
// this model's judgement: an opinion is a fired rule from the collection's
// own declared table (DESIGN 17), so a collection's severity derives from
// the opinions those rules fire over its applied rows — critical > warn >
// info, an object counted once at its worst level.
//
// Two claims the old shape could not make are load-bearing here:
//
//   - **judged is its own axis, never a quiet null.** A collection with no
//     rule table cannot say "nothing is wrong", and rendering that the same
//     as a judged-clean collection would be absence reported as health —
//     this estate's founding failure, arriving through the status route.
//     The unjudged list is repeated at the top level so a reader of the
//     roll-up alone cannot mistake silence for coverage.
//
//   - **the old vocabulary's "ok" does not exist here.** The shipping
//     roll-up counted positively-healthy rows; DESIGN 17's opinions state
//     what is wrong, and a judged row with no fired opinion carries the
//     absent-severity mark (DESIGN 27). worst=null with judged=true is
//     therefore the whole claim, not a degraded one.
//
// Secret facts are deleted before any rule reads them, exactly as the host
// page does: a credential deciding an opinion would put it in a sentence.
package collate

import (
	"encoding/json"
	"net/http"

	"github.com/techiebod/system-explorer/go/internal/store"
)

// statusEntry is one collection's roll-up. Worst is a raw message rather
// than a pointer, because the member has three honest states and a
// pointer under omitempty can only spell two: a judged collection serves
// its level or an EXPLICIT null ("nothing fired" is a claim, not a hole),
// and an unjudged collection serves no worst member at all, because it is
// not entitled to make the claim in either direction.
type statusEntry struct {
	Generation     uint64          `json:"generation"`
	Total          int             `json:"total"`
	Judged         bool            `json:"judged"`
	Worst          json.RawMessage `json:"worst,omitempty"`
	Counts         map[string]int  `json:"counts,omitempty"`
	Attention      int             `json:"attention"`
	UnjudgedReason string          `json:"unjudged_reason,omitempty"`
	Stale          bool            `json:"stale,omitempty"`
	StaleReason    *string         `json:"stale_reason,omitempty"`
}

type statusView struct {
	Worst       *string                `json:"worst"`
	Attention   int                    `json:"attention"`
	Unjudged    []string               `json:"unjudged"`
	Collections map[string]statusEntry `json:"collections"`
}

var levelRank = map[string]int{"info": 1, "warn": 2, "critical": 3}

func levelName(rank int) string {
	for level, r := range levelRank {
		if r == rank {
			return level
		}
	}
	return ""
}

// levelJSON spells a rank as the wire member: the quoted level, or the
// explicit null that says "judged, nothing fired".
func levelJSON(rank int) json.RawMessage {
	if rank == 0 {
		return json.RawMessage("null")
	}
	return json.RawMessage(`"` + levelName(rank) + `"`)
}

func registerStatus(mux *http.ServeMux, st *store.Store) {
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		states, err := st.Collections()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		view := statusView{
			// Empty lists, not nulls: "nothing needs attention" and
			// "nothing was judged" must be the same shape as their
			// occupied counterparts.
			Unjudged:    []string{},
			Collections: map[string]statusEntry{},
		}
		worstRank := 0
		for _, cs := range states {
			entry := statusEntry{
				Generation:  cs.Generation,
				Total:       cs.ObjectCount,
				Stale:       cs.Stale,
				StaleReason: cs.StaleReason,
			}
			switch reason, opinions, err := judgeCollection(st, cs); {
			case err != nil:
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			case reason != "":
				entry.UnjudgedReason = reason
				view.Unjudged = append(view.Unjudged, cs.Name)
			default:
				entry.Judged = true
				entry.Counts = map[string]int{}
				perObject := map[string]int{}
				for _, o := range opinions {
					key := o.Object
					if o.Instance != nil {
						key = *o.Instance + "\x00" + key
					}
					if levelRank[o.Level] > perObject[key] {
						perObject[key] = levelRank[o.Level]
					}
				}
				entryRank := 0
				for _, rank := range perObject {
					entry.Counts[levelName(rank)]++
					if rank > entryRank {
						entryRank = rank
					}
					if rank > worstRank {
						worstRank = rank
					}
				}
				entry.Attention = len(perObject)
				view.Attention += entry.Attention
				entry.Worst = levelJSON(entryRank)
			}
			view.Collections[cs.Name] = entry
		}
		if worstRank > 0 {
			l := levelName(worstRank)
			view.Worst = &l
		}
		writeJSON(w, view)
	})
}

// judgeCollection runs one collection's declared rules over its applied
// rows. Returns a non-empty reason when the collection cannot be judged —
// each reason distinct, because "nobody wrote rules", "nothing was ever
// applied" and "the declaration is unreadable" are three different states
// an operator acts on differently, and collapsing them was the old
// roll-up's capability-reason blur.
func judgeCollection(st *store.Store, cs store.CollectionState) (string, []Opinion, error) {
	if cs.Generation == 0 {
		return "declared; nothing has been applied yet", nil, nil
	}
	document, err := st.DeclarationFor(cs.Name)
	if err != nil {
		return "", nil, err
	}
	if document == "" {
		return "no declaration held for this collection", nil, nil
	}
	rules, err := RulesFor(document, cs.Name)
	if err != nil {
		return "the declaration could not be evaluated: " + err.Error(), nil, nil
	}
	if rules == nil {
		return "the declaration declares no rule table", nil, nil
	}
	rows, err := st.Objects(cs.Name)
	if err != nil {
		return "", nil, err
	}
	secrets, err := SecretFacts(document, cs.Name)
	if err != nil {
		return "", nil, err
	}
	var fired []Opinion
	for _, o := range rows {
		var facts map[string]any
		if json.Unmarshal(o.Facts, &facts) != nil {
			continue
		}
		for name := range secrets {
			delete(facts, name)
		}
		var instance *string
		if o.Scope != store.HostNative {
			scope := o.Scope
			instance = &scope
		}
		fired = append(fired, Judge(rules, o.ID, instance, facts)...)
	}
	return "", fired, nil
}
