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
	"net/url"
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

// collectionHref and objectHref are the ONLY places a link into this
// surface is built.
//
// **An object name is not a URL path segment.** `esc()` is HTML escaping
// and does nothing to a `/`, so a mount named `boot/efi` — and every ZFS
// dataset, `tank/photos` — minted
// `/collections/mounts/objects/boot/efi`, which Go's mux reads as two
// segments and answers 404. Every mount below the root and every nested
// dataset on the estate was unreachable from its own table, and the row
// linked confidently to nothing. Found by the owner clicking a mount.
//
// `url.PathEscape` turns the slash into %2F, which the mux decodes back
// to `boot/efi` in PathValue — verified against net/http rather than
// assumed. The HTML escape still wraps it, because the result lands in
// an attribute.
func collectionHref(collection string) string {
	return "/collections/" + esc(url.PathEscape(collection))
}

func objectHref(collection, object string) string {
	return collectionHref(collection) + "/objects/" + esc(url.PathEscape(object))
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
		// ONE decision, and `never read` dominates.
		//
		// This began as `current` with downgrades applied after, which is
		// absence rendering as health on the first page anyone opens: a
		// collection issued and never applied, carrying no decline, read
		// as `current`. And a never-read collection that HAD declined read
		// as `stale · unavailable` — stale means a reading older than its
		// declared freshness, and there has never been a reading. Both
		// were on the shipped index; the second was photographed.
		//
		// Generation 0 is the dominant fact because it changes what every
		// other column means: an object count of 0 is not a measurement,
		// and an age of — is not a fresh reading.
		var freshness string
		reason := ""
		if cs.StaleReason != nil {
			reason = " · " + *cs.StaleReason
		}
		switch {
		case cs.Generation == 0:
			// Not `current`, not `stale`, not `absent here`. Nothing was
			// ever read, and if a decline says why, the collection's own
			// page carries it.
			freshness = chip("never read", "muted")
		case cs.Decline != nil && cs.Decline.Reason == "absent":
			// Absent COMMITS, so it is neither stale nor an incident —
			// and with 0 objects its row was indistinguishable from a
			// collection that answered and holds nothing.
			freshness = chip("absent here", "muted")
		case cs.Stale:
			freshness = chip("stale"+reason, "warn")
		default:
			freshness = chip("current", "ok")
		}
		// The age column carried one em dash for three different things —
		// never read, read but carrying no stamp, and a clock this host
		// cannot subtract with. Each now says which, because "—" in a
		// freshness column is read as "fine, just quiet".
		age := `<span class="faint">no reading</span>`
		switch {
		case cs.Generation == 0:
			age = `<span class="faint">never read</span>`
		case cs.OldestAt == nil:
			age = `<span class="faint">applied, no stamp</span>`
		case cs.BootID == nil || !strings.EqualFold(*cs.BootID, bootID):
			// Stated, never subtracted through: a monotonic reading
			// means nothing outside the boot that produced it.
			age = `<span class="faint">another boot</span>`
		default:
			if d := now() - *cs.OldestAt; d >= 0 {
				age = fmt.Sprintf(`<span class="num">%.0fs</span>`, d)
			} else {
				age = `<span class="faint">clock domain mismatch</span>`
			}
		}
		// A never-read collection's object count is NOT a measurement, and
		// a bare 0 is byte-identical to a collection that was read and
		// genuinely holds nothing — two of the four empty states collapsed
		// on the index, one page above where the collection pages take
		// care to separate them.
		objects := fmt.Sprintf("%d", cs.ObjectCount)
		if cs.Generation == 0 {
			objects = `<span class="state-unstated">not counted</span>`
		}
		// The drill starts here: row → collection → object → evidence,
		// every step an <a href> and no script anywhere in it.
		body.WriteString(fmt.Sprintf(
			`<tr><td class="ident"><a href="%s">%s</a></td>`+
				`<td class="num">%d</td><td class="num">%s</td>`+
				`<td>%s</td><td>%s</td></tr>`,
			collectionHref(cs.Name), esc(cs.Name), cs.Generation, objects,
			freshness, age))
	}
	body.WriteString("</tbody></table></div></section>")

	// Opinions, from each collection's declared rule table. A collection
	// whose declaration this store cannot produce is reported as
	// unjudged rather than as clean — unobservable and healthy must not
	// render the same.
	var fired []Opinion
	var unjudged []string
	var unruled []string
	var neverRead []string
	for _, cs := range states {
		if cs.Generation == 0 {
			// NOT `continue`. Skipping these silently dropped 18 of 52
			// collections out of the roll-up — neither judged nor listed
			// as unjudged — and the section then read "No opinion fired on
			// this host's own facts", which is health asserted over an
			// estate a third of which had never been read. That is the
			// founding failure inside the summary whose whole job is to
			// prevent it.
			//
			// Kept separate from `unjudged`: no rule table readable is a
			// statement about the declaration, and never read is a
			// statement about the collection. Different problems, different
			// people to go and see.
			neverRead = append(neverRead, cs.Name)
			continue
		}
		document, err := st.DeclarationFor(cs.Name)
		if err != nil {
			return "", err
		}
		rules, err := RulesFor(document, cs.Name)
		switch {
		case err != nil || document == "":
			// The declaration could not be read. A real problem, and the
			// only case that belongs under "no rule table could be read".
			unjudged = append(unjudged, cs.Name)
			continue
		case rules == nil:
			// The declaration was read fine and this collection simply
			// DECLARES NO RULES — which is ordinary, and was reported as
			// "no rule table could be read for" on 14 collections whose
			// declarations are perfectly readable. That sends a reader to
			// debug a declaration that has nothing wrong with it, and it
			// buries the collections where the message is true.
			unruled = append(unruled, cs.Name)
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
		// QUALIFIED, always. "No opinion fired" is only good news over the
		// collections that were actually judged, and saying it plainly
		// while a third of the host was never read is the sentence this
		// product exists to refuse.
		// `unruled` collections ARE judged — by an empty rule table, which
		// is a complete judging. They are not subtracted here.
		judged := len(states) - len(unjudged) - len(neverRead)
		if len(unjudged)+len(neverRead) == 0 {
			body.WriteString(fmt.Sprintf(
				`<p class="dim">No opinion fired on this host's own facts, `+
					`across all %d collections.</p>`, judged))
		} else {
			body.WriteString(fmt.Sprintf(
				`<p class="dim">No opinion fired on the %d of %d collections `+
					`that were judged. That is not a verdict on the other %d — `+
					`see below.</p>`,
				judged, len(states), len(unjudged)+len(neverRead)))
		}
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
	if len(unruled) > 0 {
		body.WriteString(fmt.Sprintf(
			`<p class="faint">%d collections declare no rules at all, so `+
				`nothing was ever going to fire for them: %s. That is their `+
				`producer's choice, not a fault here — but it does mean this `+
				`page says nothing about them either way.</p>`,
			len(unruled), esc(strings.Join(unruled, ", "))))
	}
	if len(neverRead) > 0 {
		body.WriteString(fmt.Sprintf(
			`<p class="faint">Nothing has ever applied for %d of these `+
				`collections, so no opinion could be formed about them at all: `+
				`%s. Each one's own page says whether it declined and why.</p>`,
			len(neverRead), esc(strings.Join(neverRead, ", "))))
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
