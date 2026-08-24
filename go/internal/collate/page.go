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
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
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

//go:embed narrow.js
var narrowJS string

// narrowHash is the CSP source expression for the one script this
// surface serves, computed from the embedded bytes at start-up.
//
// The policy and the file cannot drift, because the policy IS the file's
// digest. `'self'` or `'unsafe-inline'` would admit whatever anybody
// later adds; a hash admits exactly one reviewed file, and §27's line is
// about what a script may KNOW, which only holds if somebody reads it.
var narrowHash = func() string {
	sum := sha256.Sum256([]byte(narrowJS))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()

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

// An object's name goes in a QUERY PARAMETER, not a path segment.
//
// Go's ServeMux refuses a segment that decodes to exactly "/" — verified
// against net/http — and the root mount is named "/". Percent-escaping
// gets `/boot/efi` through and cannot get `/` through at all, so the
// most important mount on every host was unreachable while its
// neighbours worked. A special case for that one name is the subset-
// guard shape: it fixes the instance and leaves the class.
//
// Object names are arbitrary producer text — mount points, dataset
// paths, unit names with @ and \x2d, container names — and arbitrary
// text belongs in a query parameter, which has no reserved structure to
// collide with. One form for every name, provably total, rather than a
// pretty form that works for most.
func objectHref(collection, object string) string {
	return collectionHref(collection) + "/object?name=" +
		esc(url.QueryEscape(object))
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

	// The collections table and the ATTENTION summary are built into
	// their own buffers so the summary can be assembled after it — it
	// needs the opinions — and rendered BEFORE it. A 52-row inventory
	// is not the answer to "what is wrong with this host", and at 3am
	// that is the question being asked.
	var table, attention strings.Builder

	table.WriteString(`<section class="panel"><h2>Collections</h2><div class="scroll"><table>` +
		"<thead><tr><th>collection</th><th>generation</th><th>objects</th>" +
		"<th>freshness</th><th>age</th></tr></thead><tbody>")
	promises := freshnessMap(st, states, now(), bootID)
	for _, cs := range states {
		freshness := freshnessChip(cs, promises[cs.Name])
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
		// every step an <a href>, because a link is what the platform
		// does best and a hand-rolled navigation would be this
		// repository maintaining what the browser already maintains.
		table.WriteString(fmt.Sprintf(
			`<tr><td class="ident"><a href="%s">%s</a></td>`+
				`<td class="num">%d</td><td class="num">%s</td>`+
				`<td>%s</td><td>%s</td></tr>`,
			collectionHref(cs.Name), esc(cs.Name), cs.Generation, objects,
			freshness, age))
	}
	table.WriteString("</tbody></table></div></section>")

	// Opinions, from each collection's declared rule table. A collection
	// whose declaration this store cannot produce is reported as
	// unjudged rather than as clean — unobservable and healthy must not
	// render the same.
	type opinionSource struct{ collection, object string }
	var from []opinionSource
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
			produced := JudgeShaped(rules, o.ID, instance, o.Type, facts)
			for range produced {
				// Which collection and object each opinion came from, so
				// the one list of problems on this page can be FOLLOWED.
				// It was dead text: a reader saw "unit:foo failed" and had
				// to go find it by hand, on the page whose whole job is to
				// say where to look.
				from = append(from, opinionSource{
					collection: cs.Name, object: o.Name})
			}
			fired = append(fired, produced...)
		}
	}
	// Sorted TOGETHER: `from` is parallel to `fired`, and sorting one
	// without the other would link every row to the wrong object — a
	// worse failure than not linking at all, because it is confident.
	order := map[string]int{"critical": 0, "warn": 1, "info": 2}
	rank := make([]int, len(fired))
	for i := range rank {
		rank[i] = i
	}
	sort.SliceStable(rank, func(i, j int) bool {
		return order[fired[rank[i]].Level] < order[fired[rank[j]].Level]
	})
	sortedFired := make([]Opinion, len(fired))
	sortedFrom := make([]opinionSource, len(from))
	for at, i := range rank {
		sortedFired[at] = fired[i]
		if i < len(from) {
			sortedFrom[at] = from[i]
		}
	}
	fired, from = sortedFired, sortedFrom

	attention.WriteString(`<section class="panel"><h2>Opinions</h2>`)
	if len(fired) == 0 {
		// QUALIFIED, always. "No opinion fired" is only good news over the
		// collections that were actually judged, and saying it plainly
		// while a third of the host was never read is the sentence this
		// product exists to refuse.
		// `unruled` collections ARE judged — by an empty rule table, which
		// is a complete judging. They are not subtracted here.
		judged := len(states) - len(unjudged) - len(neverRead)
		if len(unjudged)+len(neverRead) == 0 {
			attention.WriteString(fmt.Sprintf(
				`<p class="dim">No opinion fired on this host's own facts, `+
					`across all %d collections.</p>`, judged))
		} else {
			attention.WriteString(fmt.Sprintf(
				`<p class="dim">No opinion fired on the %d of %d collections `+
					`that were judged. That is not a verdict on the other %d — `+
					`see below.</p>`,
				judged, len(states), len(unjudged)+len(neverRead)))
		}
	} else {
		attention.WriteString(`<div class="scroll"><table><thead><tr><th>level</th>` +
			"<th>grounds</th><th>object</th><th>says</th><th>cites</th></tr></thead><tbody>")
		for i, o := range fired {
			object := esc(o.Object)
			if i < len(from) && from[i].collection != "" {
				object = fmt.Sprintf(`<a href="%s">%s</a>`,
					objectHref(from[i].collection, from[i].object), esc(o.Object))
			}
			attention.WriteString(fmt.Sprintf(
				`<tr><td>%s</td><td><span class="grounds %s">%s</span></td>`+
					`<td class="ident">%s</td><td>%s</td><td class="faint">%s</td></tr>`,
				chip(o.Level, o.Level), esc(o.Grounds), esc(o.Grounds),
				object, esc(o.Sentence), esc(strings.Join(o.Cites, ", "))))
		}
		attention.WriteString("</tbody></table></div>")
	}
	if len(unjudged) > 0 {
		attention.WriteString(fmt.Sprintf(
			`<p class="faint">Not judged, because no rule table could be read for: %s. `+
				`That is a statement about the declaration, not about the host.</p>`,
			esc(strings.Join(unjudged, ", "))))
	}
	if len(unruled) > 0 {
		attention.WriteString(fmt.Sprintf(
			`<p class="faint">%d collections declare no rules at all, so `+
				`nothing was ever going to fire for them: %s. That is their `+
				`producer's choice, not a fault here — but it does mean this `+
				`page says nothing about them either way.</p>`,
			len(unruled), esc(strings.Join(unruled, ", "))))
	}
	if len(neverRead) > 0 {
		attention.WriteString(fmt.Sprintf(
			`<p class="faint">Nothing has ever applied for %d of these `+
				`collections, so no opinion could be formed about them at all: `+
				`%s. Each one's own page says whether it declined and why.</p>`,
			len(neverRead), esc(strings.Join(neverRead, ", "))))
	}
	attention.WriteString("</section>")

	// Attention first, then the inventory.
	body.WriteString(attention.String())
	body.WriteString(table.String())
	body.WriteString(`<footer>Served by this host's own collator. It answers ` +
		`whether or not a hub is reachable, which is why it exists.</footer>`)

	return wrapWithNav("This host", navRail(st, states, "", promises), body.String()), nil
}

func registerPage(mux *http.ServeMux, st *store.Store, now func() float64, bootID string) {
	// The collection page is the one that carries the filter, so it is
	// the one whose policy names the script.
	mux.HandleFunc("GET /collections/{name}", func(w http.ResponseWriter, r *http.Request) {
		out, code, err := collectionPage(st, r.PathValue("name"),
			r.URL.Query().Get("sort"), r.URL.Query().Get("facet"),
			r.URL.Query().Get("attention"), r.URL.Query().Get("dir"),
			now, bootID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if code != http.StatusOK {
			http.NotFound(w, r)
			return
		}
		serveHTMLWith(w, out, true)
	})
	mux.HandleFunc("GET /collections/{name}/object",
		func(w http.ResponseWriter, r *http.Request) {
			out, code, err := objectPage(st, r.PathValue("name"),
				r.URL.Query().Get("name"), now, bootID)
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
// **This policy is a FACT about what the pages currently contain, not a
// ruling that they may never contain script.** These pages ship no
// script today, so the header says so exactly — a policy wider than the
// page needs is a policy that permits what nobody reviewed.
//
// The owner's ruling is to prefer modern HTML and CSS over hand-rolled
// JavaScript, and to have clear patterns; it is not a ban, and an
// earlier reading of §28 that made it one was wrong. When a script does
// earn its place here, this line widens deliberately with a `script-src`
// naming that file's hash — never `'self'` and never `'unsafe-inline'`,
// which admit whatever anybody later adds.
func serveHTML(w http.ResponseWriter, out string) {
	serveHTMLWith(w, out, false)
}

func serveHTMLWith(w http.ResponseWriter, out string, script bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	policy := "default-src 'none'; style-src 'unsafe-inline'"
	if script {
		policy += "; script-src " + narrowHash
	}
	w.Header().Set("Content-Security-Policy", policy)
	fmt.Fprint(w, out)
}

// freshnessChip is the ONE decision about what state a collection is in,
// shared by the host table and the navigation rail. Two copies is how
// it comes back: the first version applied downgrades after a `current`
// default, so a collection nothing had ever read rendered as healthy.
func freshnessChip(cs store.CollectionState, fv FreshnessVerdict) string {
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
	case fv.State == "overdue":
		// The founding failure's fix: a promise-breaking age must never
		// wear the current chip. The detail travels on the title so the
		// row stays scannable and the sentence is one hover away.
		freshness = fmt.Sprintf(
			`<span class="chip warn" title="%s">overdue</span>`, esc(fv.Detail))
	case fv.State == "unverifiable":
		// "Cannot check the promise" and "promise kept" must never share
		// a chip — unverifiable is its own state, muted not green.
		freshness = fmt.Sprintf(
			`<span class="chip muted" title="%s">unverifiable</span>`, esc(fv.Detail))
	default:
		freshness = chip("current", "ok")
	}
	return freshness
}
