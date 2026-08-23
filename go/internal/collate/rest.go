// The host-facing read API (DESIGN §06: the collator serves the host).
// Read-only is structural, not conventional: every route is registered
// with a GET pattern and no mutating route exists to misconfigure.
package collate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/techiebod/system-explorer/go/internal/store"
	"github.com/techiebod/system-explorer/go/internal/wire"
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
	// The collector's own account of the last committed acquisition,
	// omitted when none was ever reported. Advisory by construction
	// (DESIGN 19), and the member name says so — a reader must not take
	// a collector's self-report for the collator's accounting.
	AdvisoryCostCPUMs *float64 `json:"advisory_cost_cpu_ms,omitempty"`
}

// objectView is one applied object as the API serves it. Instance is a
// required member and never omitempty: two instances mint the same id,
// so a row without it is indistinguishable from its sibling — and
// letting an ABSENT member mean host-native would be the magic value the
// identity model refuses, readable only by somebody who already knows
// the convention. Null is the host-native reading, spelled out.
type objectView struct {
	ID       string  `json:"id"`
	Instance *string `json:"instance"`
	Name     string  `json:"name"`
	// Omitted when the object carries none: a homogeneous collection
	// genuinely has no type, and inventing one would be this tier
	// deciding something the producer did not say.
	Type  string          `json:"type,omitempty"`
	Facts json.RawMessage `json:"facts"`
	At    float64         `json:"at"`
}

// objectsPage is the objects route's envelope. Total counts the FILTERED
// set before pagination, and next_cursor is explicit — present or null,
// never omitted — so a client never has to infer truncation. applied_limit
// says what bound actually governed the page: the requested limit, the
// default, or the collection's own declared ceiling, whichever bit.
type objectsPage struct {
	Objects      []objectView `json:"objects"`
	Total        int          `json:"total"`
	AppliedLimit int          `json:"applied_limit"`
	NextCursor   *string      `json:"next_cursor"`
}

// NewHandler builds the read API over one store. now is the boot-clock
// reading used for ages and bootID the domain that clock belongs to;
// tests inject both, the daemon passes BootNow and OwnBootID's answer.
// Injection here is what makes items 5 and the cross-boot statement
// assertable rather than merely intended.
// Reverse is how the read API reaches a collector's own verbs (DESIGN
// §06). Injected rather than constructed here so the API stays testable
// without sockets, and nil where a deployment runs no collectors — a
// collator with only its read API is a valid daemon, and its verb routes
// then state that rather than dialling nothing.
type Reverse interface {
	Object(ctx context.Context, collection, name string, declared map[string]bool) ([]byte, error)
	Evidence(ctx context.Context, collection, name string, declared map[string]bool) ([]byte, error)
	Lookup(ctx context.Context, lookup, input string, declared map[string]bool) ([]byte, error)
}

func NewHandler(st *store.Store, now func() float64, bootID string) http.Handler {
	return NewHandlerWithReverse(st, now, bootID, nil)
}

// NewHandlerWithReverse adds the collector-facing half. Kept as a second
// constructor so every existing caller and test keeps the read-only
// handler it already had, and the reverse channel is a deployment's
// deliberate act.
func NewHandlerWithReverse(st *store.Store, now func() float64, bootID string,
	reverse map[string]Reverse) http.Handler {
	mux := http.NewServeMux()

	registerPage(mux, st, now, bootID)

	// The tier publishes its own route table, which is what lets an MCP
	// surface generate a tool per route without knowing at build time what
	// routes a tier has — and it is why a plugin's collection is reachable
	// the day it exists: the tools are per ROUTE, never per collection.
	mux.HandleFunc("GET /v1/routes", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{"routes": publishedRoutes})
	})

	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]bool{"ok": true})
	})

	registerStatus(mux, st)
	registerViews(mux)
	registerDictionary(mux, st)

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
				Name:              cs.Name,
				Generation:        cs.Generation,
				AppliedAt:         cs.AppliedAt,
				OldestAt:          cs.OldestAt,
				ObjectCount:       cs.ObjectCount,
				Stale:             cs.Stale,
				StaleReason:       cs.StaleReason,
				AdvisoryCostCPUMs: cs.CostCPUMs,
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
		filters, limit, cursor, refused := parsePage(r.URL.Query())
		if refused != nil {
			http.Error(w, refused.detail, refused.status)
			return
		}
		rows, err := st.Objects(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Withheld here as on every other channel. Found by the canary
		// sweep, which had been written against the page and the
		// checkpoint and not against this route — which is the whole
		// reason item 11 is worded "no output channel" rather than as a
		// list somebody maintains. Withheld BEFORE filtering, so a filter
		// can never probe a value this route refuses to print.
		document, err := st.DeclarationFor(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		secrets, err := SecretFacts(document, name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		served := make([]json.RawMessage, len(rows))
		facts := make([]map[string]json.RawMessage, len(rows))
		carried := map[string]bool{}
		for i, o := range rows {
			served[i] = o.Facts
			if len(secrets) > 0 {
				served[i] = withoutSecrets(o.Facts, secrets)
			}
			if json.Unmarshal(served[i], &facts[i]) != nil {
				facts[i] = map[string]json.RawMessage{}
			}
			for key := range facts[i] {
				carried[key] = true
			}
		}
		if len(rows) > 0 {
			carried["type"] = true
			if refused := checkNearMiss(filters, carried); refused != nil {
				http.Error(w, refused.detail, refused.status)
				return
			}
		}
		kept := make([]int, 0, len(rows))
		for i, o := range rows {
			matches := true
			for key, wanted := range filters {
				var text string
				var present bool
				if key == "type" {
					text, present = o.Type, o.Type != ""
				} else if raw, ok := facts[i][key]; ok {
					text, present = factText(raw), true
				}
				if !matchValue(text, present, wanted) {
					matches = false
					break
				}
			}
			if matches {
				kept = append(kept, i)
			}
		}
		offset, applied, next := paginate(len(kept), limit, cursor, ceilingFor(document, name))
		page := objectsPage{
			Objects:      make([]objectView, 0, applied),
			Total:        len(kept),
			AppliedLimit: applied,
			NextCursor:   next,
		}
		for _, i := range kept[offset:min(offset+applied, len(kept))] {
			o := rows[i]
			v := objectView{ID: o.ID, Name: o.Name, Type: o.Type, Facts: served[i], At: o.At}
			if o.Scope != store.HostNative {
				v.Instance = &o.Scope
			}
			page.Objects = append(page.Objects, v)
		}
		writeJSON(w, page)
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

	// What changed, at the tier that keeps the record (DESIGN 06). The
	// baseline is a stored snapshot with the measures already dropped —
	// so a collection whose counters advanced every sweep answers "no
	// change", which is the honest answer and the one the reference
	// could not give.
	mux.HandleFunc("GET /v1/collections/{name}/changes", func(w http.ResponseWriter, r *http.Request) {
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
		// The scope is a REQUEST parameter, not a constant.
		//
		// It was store.HostNative until 2026-08-23, and a collection
		// published only under a named instance was then unreachable:
		// applyCollection writes its snapshot under the instance scope,
		// and this route asked the host-native key and answered
		// "this collection has no stored reading yet" — a positive false
		// statement about a record that had begun, permanent and
		// undetectable from outside, with no parameter to reach the real
		// key. Unobservable rendering as healthy is the founding failure;
		// this was worse, because the answer was a confident assertion
		// rather than a null.
		scope := r.URL.Query().Get("instance")

		// No `since` means since the record BEGAN, and it is resolved
		// from the store rather than from the clock.
		//
		// This defaulted to now() for a few hours on 2026-08-23 and was
		// exactly wrong: SnapshotAtOrBefore(now) is the NEWEST reading,
		// so the route compared the live set against the snapshot taken
		// when it last changed and answered "nothing changed" for ever,
		// while the comment above it promised the opposite. It was
		// written that way to make the published-routes test — which
		// substitutes {name} and no query — answer 200 rather than 400,
		// which is a wrong answer bought to turn a test green.
		since := r.URL.Query().Get("since")
		if since == "" {
			began, err := st.RecordBegins(name, scope)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			// No record at all is not "no change": ChangesSince states
			// that as a gap, and an empty `since` reaches it.
			since = began
		}
		changes, err := ChangesSince(st, name, scope, since)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, changes)
	})

	// ── the reverse channel (DESIGN §06) ────────────────────────────
	//
	// The three verbs travel DOWN to the collector that serves the
	// collection, and the answer streams back untouched: evidence stays
	// captured-fresh and stored nowhere, so nothing here writes to the
	// store and there is deliberately no cache. A remembered evidence
	// document is a claim about a system as it was, served as though it
	// were now.
	//
	// The collection is resolved to its collector through the store's own
	// declaration record, so a plugin's collection is reachable the day
	// its declaration is recorded and nothing here names a first-party
	// one.
	serveVerb := func(verb string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			name := r.PathValue("name")
			token := r.PathValue("object")
			if verb == wire.VerbLookup {
				token = r.URL.Query().Get("input")
				if token == "" {
					http.Error(w, "a lookup carries its input: "+
						"?input=<value>", http.StatusBadRequest)
					return
				}
			}
			if len(reverse) == 0 {
				// Stated, never a 404: a collator with no collectors is a
				// valid daemon, and "this deployment runs none" is a
				// different answer from "no such object".
				writeJSON(w, map[string]any{
					"refused": "no-collectors",
					"detail": "this collator runs no collectors, so it has no " +
						"collector to ask; the verbs are answered by the " +
						"collector that serves the collection",
				})
				return
			}
			// The collection resolves to ITS collector, and a miss is a
			// stated refusal rather than a guess.
			//
			// This took `reverse[name]` and, on a miss, whatever the map
			// yielded first — and Go randomises map iteration, so the
			// same URL was answered by three different collectors across
			// thirty requests. A collector asked for a collection it does
			// not serve answers `decline`/`unsupported`, which is data
			// and reads exactly like the object not existing, so the
			// wrong-collector case was indistinguishable from an honest
			// absence. Found by review the day the channel landed.
			client, held := reverse[name]
			if !held {
				writeJSON(w, map[string]any{
					"refused": "no-collector-serves-it",
					"detail": "no collector on this host publishes " +
						strconv.Quote(name) + "; the reverse channel reaches " +
						"the collector that serves a collection, and asking " +
						"another one would get a decline that reads exactly " +
						"like the object not existing",
				})
				return
			}
			// The set §06 admits the request for. A LOOKUP name is not a
			// collection — the palette is a declaration-root member — so
			// the two are checked against different sets. Checking a
			// lookup against the collection list made /v1/lookups refuse
			// every request it could ever receive.
			declared := map[string]bool{name: true}
			var raw []byte
			var err error
			ctx := r.Context()
			switch verb {
			case wire.VerbObject:
				raw, err = client.Object(ctx, name, token, declared)
			case wire.VerbEvidence:
				raw, err = client.Evidence(ctx, name, token, declared)
			case wire.VerbLookup:
				raw, err = client.Lookup(ctx, name, token, declared)
			}
			var refused *wire.Refused
			if errors.As(err, &refused) {
				// §06: refused AND recorded. The refusal reaches the
				// caller and the rejections table both, because a refusal
				// nobody can see is one nobody can act on.
				_ = st.RecordRejection(name, "", "reverse-"+refused.Reason,
					refused.Detail)
				w.WriteHeader(http.StatusBadRequest)
				writeJSON(w, map[string]any{"refused": refused.Reason,
					"verb": refused.Verb, "detail": refused.Detail})
				return
			}
			if err != nil {
				// The type, never the message: an error's text is where a
				// path or a token reaches an unauthenticated channel.
				http.Error(w, verb+" failed", http.StatusBadGateway)
				return
			}
			// The collector's own NDJSON, byte for byte. Re-encoding it
			// here would make this tier a second interpreter of a stream
			// the contract already defines.
			w.Header().Set("Content-Type", "application/x-ndjson")
			_, _ = w.Write(raw)
		}
	}
	mux.HandleFunc("GET /v1/collections/{name}/objects/{object}",
		serveVerb(wire.VerbObject))
	mux.HandleFunc("GET /v1/collections/{name}/objects/{object}/evidence",
		serveVerb(wire.VerbEvidence))
	mux.HandleFunc("GET /v1/lookups/{name}", serveVerb(wire.VerbLookup))

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

// publishedRoutes is this tier's read surface, declared once and served
// so an MCP surface can become it. The warning a model needs about
// third-party text is the consumer's to attach — it is the same sentence
// at both scales, and duplicating it here would be a second copy of a
// thing the consumer already says.
//
// Every entry is a GET. No mutating route exists to misconfigure, which
// is read-only as a structural property rather than a policy.
var publishedRoutes = []map[string]any{
	{"path": "/v1/health", "tool": "host_health",
		"summary": "Whether this collator is answering at all.",
		"params":  []string{}},
	{"path": "/v1/status", "tool": "host_status",
		"summary": "The attention surface: per collection, the worst level " +
			"the declared rules fired and how many objects need attention — " +
			"and, separately, which collections carry no rule table at all. " +
			"An unjudged collection is its own state, never a quiet null: " +
			"absence of judgement must not read as health.",
		"params": []string{}},
	{"path": "/v1/capabilities", "tool": "host_capabilities",
		"summary": "How to open things here: each collection's declared " +
			"prefix and question, and the id-prefix map to the route where " +
			"an object wearing that prefix is served. Narrowed to what this " +
			"host's store knows, so a link built from it never dead-ends.",
		"params": []string{}},
	{"path": "/v1/facts", "tool": "fact_dictionary",
		"summary": "What each fact means: per collection, every declared " +
			"fact's axes and one-sentence meaning, verbatim from the " +
			"collector's own declaration. Fetch once and cache — it changes " +
			"only when a declaration does.",
		"params": []string{}},
	{"path": "/v1/collections", "tool": "list_collections",
		"summary": "Every collection this host holds, with its generation, its " +
			"object count, how fresh the applied state is, and what the last " +
			"acquisition cost by the collector's own advisory account. An age " +
			"is served only within the boot that produced it; across a reboot " +
			"the clock domain is stated rather than subtracted through.",
		"params": []string{}},
	{"path": "/v1/collections/{name}/objects", "tool": "get_collection",
		"summary": "One collection's applied objects, in applied order. Any " +
			"other query parameter is a fact filter matched against the " +
			"fact's JSON spelling ('type' matches the object's kind; a " +
			"leading ! negates, a trailing * prefix-matches); a near-miss " +
			"of a carried fact name is refused with the real name, and an " +
			"unknown one gets the honest empty page. limit and cursor page " +
			"the filtered set, bounded by the collection's declared " +
			"ceiling; next_cursor is explicit, so truncation is never " +
			"inferred. Reaches a plugin's collection the day it exists, " +
			"because nothing here names a first-party one.",
		"params": []string{"name", "limit", "cursor"}},
	{"path": "/v1/collections/{name}/changes", "tool": "what_changed",
		"summary": "What changed in one collection since a moment you name. " +
			"Facts whose declared temperament is counter or gauge do NOT " +
			"participate — a counter advances by definition, so a diff " +
			"carrying one reports change continuously and says nothing — and " +
			"the exclusion is read from the collection's own declaration, so " +
			"a plugin's counter is excluded the day it arrives. A question " +
			"reaching before the record begins is answered with a stated gap " +
			"rather than from an empty baseline: an unreachable baseline is " +
			"not an empty one, and diffing against nothing would report every " +
			"object as added. `instance` selects the scope a collection was " +
			"published under; omitted means the host-native one, and a " +
			"collection served only under a named instance is reached by " +
			"naming it.",
		"params": []string{"name", "since", "instance"}},
	{"path": "/v1/views", "tool": "get_views",
		"summary": "This deployment's operator-authored view documents " +
			"(se.views/1), read fresh from the deployed directory — the " +
			"operator edits a file and refreshes. Served by this tier as well " +
			"as by the hub, because a host with no hub keeps its own surface " +
			"in full. No directory means a deployment that made no views: an " +
			"empty list, not an error. A CONFIGURED directory that does not " +
			"exist is a deployment fault and is named in the envelope.",
		"params": []string{}},
	{"path": "/v1/collections/{name}/objects/{object}", "tool": "get_object",
		"summary": "One object in full, asked of the collector that serves it " +
			"over the reverse channel — every fact, not the row's declared " +
			"answer subset. Reaches a plugin's collection the day its " +
			"declaration is recorded.",
		"params": []string{"name", "object"}},
	{"path": "/v1/collections/{name}/objects/{object}/evidence", "tool": "get_evidence",
		"summary": "The raw native payload an object's facts were read from, " +
			"captured fresh on request and stored nowhere — the only thing in " +
			"the product that is not our interpretation. Carries its own " +
			"digest, so a claim can say whether the document it was made from " +
			"is still the document you are looking at.",
		"params": []string{"name", "object"}},
	{"path": "/v1/lookups/{name}", "tool": "lookup",
		"summary": "A parameterised read-only question a collector declares, " +
			"asked with ?input=<value>. The palette is the collector's own; " +
			"nothing here names a first-party lookup.",
		"params": []string{"name", "input"}},
	{"path": "/v1/collections/{name}/relations", "tool": "get_relations",
		"summary": "One collection's assembled relations, each carrying its " +
			"observability — asserted is NOT a degraded confirmed, and an " +
			"unresolved target renders as an edge into open space rather than " +
			"as no edge at all.",
		"params": []string{"name"}},
}
