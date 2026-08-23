// The host page, rendered by the collator (DESIGN 06, 27, 28).
//
// **The producer renders.** §27's rule — the renderer knows nothing the
// producer knows — is satisfied structurally when the two are one
// process, so there is no severity table here, no state table and no
// fact glossary. A level comes from the opinion the rule table produced;
// a sentence comes from the declaration. Anything this file decided for
// itself would be the fourth copy the estate has already shipped three of.
//
// **The collator keeps its own UI, and that is not optional.** Putting
// the hub in a container means that when that host's container engine is
// down the estate view is down — which is exactly when somebody wants it.
// The founding invariant survives only because each collator serves its
// own host in full and can be reached directly.
//
// **Everything interpolated is escaped.** Facts carry text this product
// did not write, and a page that trusted it would turn a read-only
// observer into a delivery mechanism.
//
// tokens.css is a COPY of src/system_explorer/surface/tokens.css, because
// the two renderers are in two languages and neither toolchain can read
// the other's tree. Drift between them is caught by a conformance test
// asserting the two files are byte-identical — which is the honest way to
// have two artifacts of one truth, and the coverage is stated here so
// nobody takes the copy for an independent decision.
package collate

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"sort"
	"strings"

	"github.com/techiebod/system-explorer/go/internal/store"
)

//go:embed tokens.css
var tokensCSS string

func esc(v any) string {
	if v == nil {
		return ""
	}
	return html.EscapeString(fmt.Sprintf("%v", v))
}

func chip(text, kind string) string {
	return fmt.Sprintf(`<span class="chip %s">%s</span>`, esc(kind), esc(text))
}

func hostPage(st *store.Store, now func() float64, bootID string) (string, error) {
	states, err := st.Collections()
	if err != nil {
		return "", err
	}
	var body strings.Builder
	body.WriteString("<h1>This host</h1>")

	body.WriteString(`<section class="panel"><h2>Collections</h2><div class="scroll"><table>` +
		"<thead><tr><th>collection</th><th>generation</th><th>objects</th>" +
		"<th>freshness</th><th>age</th></tr></thead><tbody>")
	for _, cs := range states {
		freshness := chip("current", "ok")
		if cs.Decline != nil && cs.Decline.Reason == "absent" {
			// Absent COMMITS, so it is neither stale nor an incident —
			// and with 0 objects its row was indistinguishable from a
			// collection that answered and holds nothing.
			freshness = chip("absent here", "muted")
		}
		if cs.Stale {
			reason := ""
			if cs.StaleReason != nil {
				reason = " · " + *cs.StaleReason
			}
			freshness = chip("stale"+reason, "warn")
		}
		age := `<span class="faint">—</span>`
		if cs.OldestAt != nil {
			if cs.BootID == nil || !strings.EqualFold(*cs.BootID, bootID) {
				// Stated, never subtracted through: a monotonic reading
				// means nothing outside the boot that produced it.
				age = `<span class="faint">another boot</span>`
			} else if d := now() - *cs.OldestAt; d >= 0 {
				age = fmt.Sprintf(`<span class="num">%.0fs</span>`, d)
			} else {
				age = `<span class="faint">clock domain mismatch</span>`
			}
		}
		// The drill starts here: row → collection → object → evidence,
		// every step an <a href> and no script anywhere in it.
		body.WriteString(fmt.Sprintf(
			`<tr><td class="ident"><a href="/collections/%s">%s</a></td>`+
				`<td class="num">%d</td><td class="num">%d</td>`+
				`<td>%s</td><td>%s</td></tr>`,
			esc(cs.Name), esc(cs.Name), cs.Generation, cs.ObjectCount, freshness, age))
	}
	body.WriteString("</tbody></table></div></section>")

	// Opinions, from each collection's declared rule table. A collection
	// whose declaration this store cannot produce is reported as
	// unjudged rather than as clean — unobservable and healthy must not
	// render the same.
	var fired []Opinion
	var unjudged []string
	for _, cs := range states {
		if cs.Generation == 0 {
			continue
		}
		document, err := st.DeclarationFor(cs.Name)
		if err != nil {
			return "", err
		}
		rules, err := RulesFor(document, cs.Name)
		if err != nil || rules == nil {
			unjudged = append(unjudged, cs.Name)
			continue
		}
		rows, err := st.Objects(cs.Name)
		if err != nil {
			return "", err
		}
		secrets, err := SecretFacts(document, cs.Name)
		if err != nil {
			return "", err
		}
		for _, o := range rows {
			var facts map[string]any
			if json.Unmarshal(o.Facts, &facts) != nil {
				continue
			}
			// Never on this page, and never into a rule either: a
			// credential deciding an opinion would put it in the sentence.
			for name := range secrets {
				delete(facts, name)
			}
			var instance *string
			if o.Scope != store.HostNative {
				scope := o.Scope
				instance = &scope
			}
			fired = append(fired, JudgeShaped(rules, o.ID, instance, o.Type, facts)...)
		}
	}
	order := map[string]int{"critical": 0, "warn": 1, "info": 2}
	sort.SliceStable(fired, func(i, j int) bool {
		return order[fired[i].Level] < order[fired[j].Level]
	})

	body.WriteString(`<section class="panel"><h2>Opinions</h2>`)
	if len(fired) == 0 {
		body.WriteString(`<p class="dim">No opinion fired on this host's own facts.</p>`)
	} else {
		body.WriteString(`<div class="scroll"><table><thead><tr><th>level</th>` +
			"<th>grounds</th><th>object</th><th>says</th><th>cites</th></tr></thead><tbody>")
		for _, o := range fired {
			body.WriteString(fmt.Sprintf(
				`<tr><td>%s</td><td><span class="grounds %s">%s</span></td>`+
					`<td class="ident">%s</td><td>%s</td><td class="faint">%s</td></tr>`,
				chip(o.Level, o.Level), esc(o.Grounds), esc(o.Grounds),
				esc(o.Object), esc(o.Sentence), esc(strings.Join(o.Cites, ", "))))
		}
		body.WriteString("</tbody></table></div>")
	}
	if len(unjudged) > 0 {
		body.WriteString(fmt.Sprintf(
			`<p class="faint">Not judged, because no rule table could be read for: %s. `+
				`That is a statement about the declaration, not about the host.</p>`,
			esc(strings.Join(unjudged, ", "))))
	}
	body.WriteString("</section>")

	body.WriteString(`<footer>Served by this host's own collator. It answers ` +
		`whether or not a hub is reachable, which is why it exists.</footer>`)

	return "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">" +
		"<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
		"<title>This host</title><style>" + tokensCSS + "</style></head><body><main>" +
		body.String() + "</main></body></html>\n", nil
}

func registerPage(mux *http.ServeMux, st *store.Store, now func() float64, bootID string) {
	mux.HandleFunc("GET /collections/{name}", func(w http.ResponseWriter, r *http.Request) {
		out, code, err := collectionPage(st, r.PathValue("name"),
			r.URL.Query().Get("sort"), r.URL.Query().Get("facet"), now, bootID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if code != http.StatusOK {
			http.NotFound(w, r)
			return
		}
		serveHTML(w, out)
	})
	mux.HandleFunc("GET /collections/{name}/objects/{object}",
		func(w http.ResponseWriter, r *http.Request) {
			out, code, err := objectPage(st, r.PathValue("name"),
				r.PathValue("object"), now, bootID)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if code != http.StatusOK {
				http.NotFound(w, r)
				return
			}
			serveHTML(w, out)
		})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		out, err := hostPage(st, now, bootID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		serveHTML(w, out)
	})
}

// serveHTML is the one place this tier's pages are sent, so the policy is
// a property of the SURFACE rather than of whoever remembered it.
//
// §28's ruling: the collator's host page keeps the absolute header and
// gets no typed filter. It is the page that must answer when everything
// else is down, and the property that it cannot execute anything is worth
// more there than incremental narrowing. A host page that needs a filter
// is a host page with too much on it.
func serveHTML(w http.ResponseWriter, out string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'")
	fmt.Fprint(w, out)
}
