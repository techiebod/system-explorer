// The host-facing read API (DESIGN §06: the collator serves the host).
// Read-only is structural, not conventional: every route is registered
// with a GET pattern and no mutating route exists to misconfigure.
package collate

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/techiebod/system-explorer/go/internal/store"
)

// collectionView is one row of GET /v1/collections. age_s derives from
// the OLDEST at among the collection's objects against the collator's
// own boot clock — never from arrival time, so a six-second acquisition
// can never report itself fresher than its oldest contributing read
// (acceptance item 5) — and it is served only when the stored boot id is
// the collator's own: a monotonic reading means nothing outside the boot
// that produced it (DESIGN §09), so a mismatch is STATED, never
// subtracted through. cross_boot is that statement — a different clock
// domain, not staleness, which stays decline semantics.
// clock_domain_mismatch states the residual impossibility: same boot id,
// arithmetic still negative (a time namespace is the ordinary cause).
// Under either marker age_s is omitted; no route serves garbage.
type collectionView struct {
	Name                string   `json:"name"`
	Generation          uint64   `json:"generation"`
	AppliedAt           *string  `json:"applied_at"`
	OldestAt            *float64 `json:"oldest_at"`
	AgeS                *float64 `json:"age_s,omitempty"`
	CrossBoot           bool     `json:"cross_boot,omitempty"`
	ClockDomainMismatch bool     `json:"clock_domain_mismatch,omitempty"`
	ObjectCount         int      `json:"object_count"`
	Stale               bool     `json:"stale"`
	StaleReason         *string  `json:"stale_reason"`
}

type objectView struct {
	ID    string          `json:"id"`
	Name  string          `json:"name"`
	Facts json.RawMessage `json:"facts"`
	At    float64         `json:"at"`
}

// NewHandler builds the read API over one store. now is the boot-clock
// reading used for ages and bootID the domain that clock belongs to;
// tests inject both, the daemon passes BootNow and OwnBootID's answer.
// Injection here is what makes items 5 and the cross-boot statement
// assertable rather than merely intended.
func NewHandler(st *store.Store, now func() float64, bootID string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]bool{"ok": true})
	})

	mux.HandleFunc("GET /v1/collections", func(w http.ResponseWriter, r *http.Request) {
		states, err := st.Collections()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// An empty authority serves an empty list, not null: the shape of
		// "nothing yet" and the shape of "several" must be the same shape.
		views := make([]collectionView, 0, len(states))
		for _, cs := range states {
			v := collectionView{
				Name:        cs.Name,
				Generation:  cs.Generation,
				AppliedAt:   cs.AppliedAt,
				OldestAt:    cs.OldestAt,
				ObjectCount: cs.ObjectCount,
				Stale:       cs.Stale,
				StaleReason: cs.StaleReason,
			}
			if cs.OldestAt != nil {
				switch {
				// EqualFold: "UUID-shaped" is the ruling, not any one
				// platform's case (linux lowercases, darwin does not).
				case cs.BootID == nil || !strings.EqualFold(*cs.BootID, bootID):
					// A stored domain that is not provably this one (nil
					// cannot occur — apply always stamps — and is refused
					// rather than assumed). Stated, never subtracted.
					v.CrossBoot = true
				default:
					age := now() - *cs.OldestAt
					if age < 0 {
						// Same boot, impossible arithmetic: state it
						// rather than serving a negative age.
						v.ClockDomainMismatch = true
					} else {
						v.AgeS = &age
					}
				}
			}
			views = append(views, v)
		}
		writeJSON(w, views)
	})

	mux.HandleFunc("GET /v1/collections/{name}/objects", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		known, err := st.HasCollection(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !known {
			http.Error(w, "unknown collection", http.StatusNotFound)
			return
		}
		rows, err := st.Objects(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		views := make([]objectView, 0, len(rows))
		for _, o := range rows {
			views = append(views, objectView{ID: o.ID, Name: o.Name, Facts: o.Facts, At: o.At})
		}
		writeJSON(w, views)
	})

	// Relations are served on their own route rather than nested inside the
	// object, because the observability state is the thing a reader must be
	// able to act on and burying it in a sub-member of a row is how it stops
	// being visible (DESIGN 29: a relation renders its observability at
	// every density, never as a footnote).
	mux.HandleFunc("GET /v1/collections/{name}/relations", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		known, err := st.HasCollection(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !known {
			http.Error(w, "unknown collection", http.StatusNotFound)
			return
		}
		rows, err := st.Relations(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		views := make([]relationView, 0, len(rows))
		for _, rel := range rows {
			v := relationView{
				ID:            rel.Key,
				Source:        rel.SourceID,
				Type:          rel.Type,
				Vantage:       rel.Vantage,
				Observability: string(rel.Observability),
				Facts:         rel.Facts,
			}
			// The target always carries its name and whether it resolved.
			// An unresolved target renders as an edge into open space, and
			// a reader must be able to tell that from no edge at all
			// WITHOUT reading prose — so `resolved` is always present and
			// `id` appears only when there is one.
			v.Target.Kind = rel.TargetKind
			v.Target.Name = rel.TargetName
			v.Target.Resolved = rel.Resolved
			if rel.Resolved {
				v.Target.ID = rel.TargetID
			}
			views = append(views, v)
		}
		writeJSON(w, views)
	})

	return mux
}

// relationView is one assembled edge as the API serves it. Observability is
// a required member, never omitempty: `asserted` is not a degraded
// `confirmed` and a missing state would let a consumer default it to the
// wrong one, which is the founding failure arriving through the API.
type relationView struct {
	ID            string          `json:"id"`
	Source        string          `json:"source"`
	Type          string          `json:"type"`
	Vantage       string          `json:"vantage"`
	Observability string          `json:"observability"`
	Target        relationTarget  `json:"target"`
	Facts         json.RawMessage `json:"facts,omitempty"`
}

type relationTarget struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Resolved bool   `json:"resolved"`
	ID       string `json:"id,omitempty"`
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		// The header is gone; all that is left is not to lie with a 200
		// body that half-arrived. Nothing to do but drop the connection.
		return
	}
}
