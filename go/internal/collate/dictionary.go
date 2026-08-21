// The two declaration-derived read routes (register rows 13 and 14):
// GET /v1/capabilities, which says how to OPEN things — the id-prefix map
// that was a table in the old browser until 2026-08-14, drifted exactly as
// the fourth-copy rule predicts, and was pulled to the agent; and
// GET /v1/facts, which says what things MEAN — each fact's declared axes
// and sentence, served verbatim from the declaration so there is nothing
// here to drift from it.
//
// Both are assembled from the declarations the store already holds, never
// from anything this package knows: a plugin's collection appears in both
// answers the day its declaration is recorded, because nothing here names
// a first-party collection.
package collate

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/techiebod/system-explorer/go/internal/store"
)

type prefixHome struct {
	Collection string `json:"collection"`
	Route      string `json:"route"`
}

type capabilitiesView struct {
	// Per collection: the declared prefix and question. A collection whose
	// declaration the store does not hold is still listed — it exists and
	// a reader must see it — with neither member, which is the honest
	// "known, undescribed" rather than an invented description.
	Collections map[string]map[string]string `json:"collections"`
	// prefix → where an id wearing it opens. Narrowed to what this host's
	// store actually knows, so a chip built from this map never leads to a
	// 404 — the old rule, carried over: a chip that leads nowhere is worse
	// than one that stayed plain text.
	ObjectPrefixes map[string]prefixHome `json:"object_prefixes"`
	// A prefix two collections both declared resolves to neither: serving
	// either home would be a silent coin toss, and the wire path refuses
	// such a declaration anyway (ambiguous-prefix). Stated here because
	// the store can hold the state transiently, and a reader of this route
	// must see the contention rather than a winner nobody chose.
	AmbiguousPrefixes map[string][]string `json:"ambiguous_prefixes,omitempty"`
}

func registerDictionary(mux *http.ServeMux, st *store.Store) {
	mux.HandleFunc("GET /v1/capabilities", func(w http.ResponseWriter, r *http.Request) {
		perCollection, err := declaredCollections(st)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		view := capabilitiesView{
			Collections:    map[string]map[string]string{},
			ObjectPrefixes: map[string]prefixHome{},
		}
		homes := map[string][]string{}
		for name, declared := range perCollection {
			entry := map[string]string{}
			if declared != nil {
				if declared.Prefix != "" {
					entry["prefix"] = declared.Prefix
					homes[declared.Prefix] = append(homes[declared.Prefix], name)
				}
				if declared.Question != "" {
					entry["question"] = declared.Question
				}
			}
			view.Collections[name] = entry
		}
		for prefix, names := range homes {
			if len(names) > 1 {
				sort.Strings(names)
				if view.AmbiguousPrefixes == nil {
					view.AmbiguousPrefixes = map[string][]string{}
				}
				view.AmbiguousPrefixes[prefix] = names
				continue
			}
			view.ObjectPrefixes[prefix] = prefixHome{
				Collection: names[0],
				Route:      "/v1/collections/" + names[0] + "/objects",
			}
		}
		writeJSON(w, view)
	})

	mux.HandleFunc("GET /v1/facts", func(w http.ResponseWriter, r *http.Request) {
		perCollection, err := declaredCollections(st)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// The fact table VERBATIM: axes and sentence exactly as declared,
		// because a re-shaping here would be a second spelling of the
		// contract for every consumer to drift against. A fact declared
		// `discloses: secret` keeps its entry — the name, axes and sentence
		// are the public contract; it is the VALUE that never leaves, and
		// that is the objects route's withhold, not this one's.
		facts := map[string]map[string]json.RawMessage{}
		for name, declared := range perCollection {
			if declared != nil && len(declared.Facts) > 0 {
				facts[name] = declared.Facts
			}
		}
		writeJSON(w, map[string]any{"collections": facts})
	})
}

// declaredCollections resolves every collection the store knows to its
// declared shape, nil where no declaration is held.
func declaredCollections(st *store.Store) (map[string]*declaredCollection, error) {
	states, err := st.Collections()
	if err != nil {
		return nil, err
	}
	out := map[string]*declaredCollection{}
	for _, cs := range states {
		out[cs.Name] = nil
		document, err := st.DeclarationFor(cs.Name)
		if err != nil {
			return nil, err
		}
		if document == "" {
			continue
		}
		var doc declaredDocument
		if json.Unmarshal([]byte(document), &doc) != nil {
			continue
		}
		for i := range doc.Collections {
			if doc.Collections[i].Name == cs.Name {
				out[cs.Name] = &doc.Collections[i]
				break
			}
		}
	}
	return out, nil
}
