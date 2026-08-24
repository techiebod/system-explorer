// The widget layer: DESIGN §28's table, implemented as a function of the
// DECLARATION rather than as a judgement made per screen.
//
// **This file may not decide what anything means.** It reads type, unit,
// temperament and kind off the producer's own declaration and renders
// accordingly. It holds no severity table, no id-to-route map and no
// unit guesser — the three copies §27 records as having rotted, each
// found only after it had been wrong for a long time. The unit guesser
// is the one this file most directly replaces: it inferred meaning from
// fact-name suffixes, did not know `Usec`, and so rendered every
// microsecond fact as a bare integer. Seven facts declare
// `unit: microseconds` and are formatted from that declaration here.
//
// TWO RULES OF §28 CANNOT BE DELIVERED FROM TODAY'S DECLARATIONS, and
// both are rendered honestly rather than approximated:
//
//   - **A counter's companion rate gauge does not exist.** §28 says a
//     counter renders as its declared companion rate and the raw counter
//     only on an object page. No declaration in the tree ships such a
//     member — 32 facts are counters, zero declare one. CORRECTED
//     2026-08-24: the contract DOES define `rate_companion`
//     (se.declaration.1.json) — a previous version of this comment said
//     the member existed only in prose. So the gap is twofold: no
//     collector declares it, and FactDecl below cannot read it — a
//     declared companion would be silently ignored. Register row 45.
//     So a counter renders as its raw value MARKED CUMULATIVE. The
//     renderer must not compute the rate: the window belongs to the
//     producer (§12), and a rate this file invented would be exactly the
//     fourth copy.
//   - **Twenty booleans declare no labels.** §28 requires a boolean's two
//     declared labels and forbids a tick and a cross, because a cross
//     reads as a failure and most booleans are not verdicts. Where labels
//     are missing the raw word is rendered, neutrally, and the fact is
//     marked under-declared — never a tick, never a cross, and never an
//     absence mark, since `absent` is a render state meaning something
//     else entirely.
package collate

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// FactDecl is the subset of a declared fact this layer renders from.
type FactDecl struct {
	Type        string   `json:"type"`
	Unit        string   `json:"unit"`
	Temperament string   `json:"temperament"`
	Kind        string   `json:"kind"`
	Values      []string `json:"values"`
	Labels      []string `json:"labels"`
	Denominator string   `json:"denominator"`
	Bound       string   `json:"bound"`
	Sentence    string   `json:"sentence"`
}

// FactState is which of §28's five states a cell is in. The collection
// level states (declined, stale) are not here: they are properties of the
// collection and are rendered once, over the table, rather than repeated
// into every cell as though each fact had independently gone stale.
type FactState int

const (
	// StateValue — we looked, and this is it.
	StateValue FactState = iota
	// StateAbsent — we looked; the thing genuinely has no such property.
	// An em dash, muted. Generated content, never an empty cell: a blank
	// reads as fine and a zero reads as measured.
	StateAbsent
	// StateUnobservable — we could not look, and here is why. The reason
	// goes ON THE ROW; never blank, never zero.
	StateUnobservable
)

// Cell renders one fact at one density.
//
// `sib` supplies the rest of the row — the sibling VALUES and their
// DECLARATIONS. A percentage's denominator and a gauge's bound are named
// by the declaration, so passing the row is what lets those rules be
// honoured without this file guessing which fact is which; and passing
// the sibling declarations too is what lets a denominator be formatted in
// ITS OWN unit rather than in the numerator's, which for a percentage is
// never right.
func Cell(decl FactDecl, value any, state FactState, detail string,
	sib Siblings, object bool) string {
	switch state {
	case StateAbsent:
		// The em dash is CONTENT, so it survives a stylesheet that did
		// not load. §28's founding rendering bug is collapsing a state
		// into a blank cell, and a CSS-generated dash is a blank cell
		// wearing a dash.
		return `<span class="state-absent" title="looked; no such property">—</span>`
	case StateUnobservable:
		why := detail
		if why == "" {
			why = "could not be read"
		}
		return fmt.Sprintf(
			`<span class="state-unobservable">could not read: %s</span>`, esc(why))
	}
	if value == nil {
		// Declared, and the producer sent no value AND did not say it was
		// absent. This is a sixth thing, and it gets its own mark rather
		// than borrowing `unobservable`'s: unobservable is the collector
		// saying "I could not look, and here is why", which is a positive
		// statement. This is the collector saying nothing at all, so
		// wearing that mark would put words in its mouth — a reader would
		// take it for a reported failure to read.
		//
		// It is a PRODUCER gap wherever it appears: a fact declared and
		// then omitted should be `absent` when the thing genuinely has no
		// such property, and unobservable when it could not be read.
		// Register row 34 is one such, found by this very rendering.
		return `<span class="state-unstated" title="declared by the ` +
			`collector and neither sent nor declared absent — the producer ` +
			`has not said which">not stated</span>`
	}
	rendered := widget(decl, value, sib, object)
	if decl.Kind == "declared" {
		// A reader forming a belief should know it rests on an assertion.
		rendered += ` <span class="mark-declared" title="declared, not observed">declared</span>`
	}
	return rendered
}

// Undeclared renders a fact no declaration describes (§26): shown, never
// dropped, never styled as understood.
func Undeclared(value any) string {
	return fmt.Sprintf(
		`<span class="undeclared" title="no declaration describes this fact; `+
			`shown raw">%s</span>`, esc(scalar(value)))
}

// Siblings is the rest of the row: the other facts' values, and their
// declarations. Both are needed and neither substitutes for the other —
// a value without its declaration cannot be formatted, and a declaration
// without its value has nothing to format.
type Siblings struct {
	Values map[string]any
	Decls  map[string]FactDecl
}

func widget(decl FactDecl, value any, sib Siblings, object bool) string {
	switch decl.Type {
	case "enum":
		// A chip, and DELIBERATELY UNCOLOURED. §28 allows colour only
		// where the vocabulary means the same thing everywhere the enum
		// appears — `down` is a fault on a NIC carrying addresses and
		// correct on an empty bridge — and nothing in a declaration says
		// whether a vocabulary is shared. Colouring from the value would
		// be this file deciding severity, which is the opinion layer's
		// and arrives as a verdict. An unknown member renders the same
		// way, never as an error.
		return fmt.Sprintf(`<span class="chip enum">%s</span>`, esc(scalar(value)))
	case "boolean":
		return boolean(decl, value)
	case "timestamp":
		return timestamp(value)
	case "list":
		return list(value, object)
	case "object":
		return nested(value)
	case "integer", "number":
		return numeric(decl, value, sib)
	case "duration":
		return fmt.Sprintf(`<span class="num">%s</span>`, esc(scalar(value)))
	}
	// string, and anything a newer declaration names that this renderer
	// does not know. VERBATIM AND WRAPPING, never clipped: the firewall
	// rule truncated at a column edge turned a rule confining sshd to one
	// interface into one admitting it from anywhere, which is the exact
	// inversion six layers go to trouble to prevent, reintroduced by CSS.
	return fmt.Sprintf(`<span class="prose">%s</span>`, esc(scalar(value)))
}

func boolean(decl FactDecl, value any) string {
	on, ok := value.(bool)
	if !ok {
		return fmt.Sprintf(`<span class="prose">%s</span>`, esc(scalar(value)))
	}
	if len(decl.Labels) == 2 {
		// Index 0 is the TRUE label. The declarations read
		// ["synthesised from the mount table", "declared in a unit file"]
		// with the first describing the true case.
		label := decl.Labels[1]
		if on {
			label = decl.Labels[0]
		}
		return fmt.Sprintf(`<span class="chip bool">%s</span>`, esc(label))
	}
	// Under-declared: the raw word, marked. Never a tick and never a
	// cross — a cross reads as a failure and most booleans are not
	// verdicts — and never an absence mark, which means something else.
	return fmt.Sprintf(
		`<span class="chip bool under-declared" title="no labels declared for `+
			`this boolean; the raw value is shown">%v</span>`, on)
}

func timestamp(value any) string {
	// **§28 asks for a relative age with the absolute on hover, and this
	// delivers NEITHER.** Saying so here rather than leaving the comment
	// describing a popover that was never written: the function had an
	// `object` parameter whose two branches returned identical markup —
	// dead code standing in for a promise, which reads as done.
	//
	// The AGE IS NOT COMPUTED HERE. A timestamp arrives as the producer's
	// own string and this file has no clock it can honestly subtract with
	// — the collection's own age is served beside the table, measured
	// against the reading's clock domain. Rendering "3 days ago" from a
	// stamp whose domain this file cannot check is the confident
	// arithmetic §09 refuses.
	// `datetime` so the value is machine-readable even though no age is
	// drawn from it, and the reader is told plainly that the absolute is
	// all there is rather than being left to wonder where the age went.
	text := esc(scalar(value))
	return fmt.Sprintf(
		`<time class="stamp" datetime="%s" title="absolute only: this tier `+
			`serves no relative age, because the clock domain a stamp `+
			`belongs to is stated beside the table rather than assumed `+
			`here">%s</time>`, text, text)
}

func list(value any, object bool) string {
	items, ok := value.([]any)
	if !ok {
		return fmt.Sprintf(`<span class="prose">%s</span>`, esc(scalar(value)))
	}
	if len(items) == 0 {
		// An empty list is a MEASURED emptiness — the producer looked and
		// found no members — which is not the same as absent and must not
		// borrow its em dash.
		return `<span class="empty-list">none</span>`
	}
	// A list of uniform objects earns structure: comma-joining it
	// destroys it.
	if uniform := uniformKeys(items); uniform != nil {
		return nestedTable(uniform, items)
	}
	var b strings.Builder
	b.WriteString(`<span class="chips">`)
	for _, item := range items {
		// Never truncated mid-item, which is enforced in the stylesheet
		// and stated here so the next reader knows the pair belongs.
		b.WriteString(fmt.Sprintf(`<span class="chip item">%s</span>`,
			esc(scalar(item))))
	}
	b.WriteString(`</span>`)
	return b.String()
}

func uniformKeys(items []any) []string {
	var keys []string
	for i, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			return nil
		}
		var these []string
		for k := range row {
			these = append(these, k)
		}
		sort.Strings(these)
		if i == 0 {
			keys = these
			continue
		}
		if strings.Join(keys, "\x00") != strings.Join(these, "\x00") {
			return nil
		}
	}
	return keys
}

func nestedTable(keys []string, items []any) string {
	var b strings.Builder
	b.WriteString(`<table class="nested"><thead><tr>`)
	for _, k := range keys {
		b.WriteString("<th>" + esc(k) + "</th>")
	}
	b.WriteString("</tr></thead><tbody>")
	for _, item := range items {
		row := item.(map[string]any)
		b.WriteString("<tr>")
		for _, k := range keys {
			b.WriteString("<td>" + esc(scalar(row[k])) + "</td>")
		}
		b.WriteString("</tr>")
	}
	b.WriteString("</tbody></table>")
	return b.String()
}

func nested(value any) string {
	row, ok := value.(map[string]any)
	if !ok {
		return fmt.Sprintf(`<span class="prose">%s</span>`, esc(scalar(value)))
	}
	var keys []string
	for k := range row {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(`<dl class="nested-object">`)
	for _, k := range keys {
		b.WriteString("<dt>" + esc(k) + "</dt><dd>" + esc(scalar(row[k])) + "</dd>")
	}
	b.WriteString("</dl>")
	return b.String()
}

func numeric(decl FactDecl, value any, sib Siblings) string {
	n, ok := number(value)
	if !ok {
		return fmt.Sprintf(`<span class="prose">%s</span>`, esc(scalar(value)))
	}
	figure := formatted(decl.Unit, n)

	if decl.Temperament == "counter" {
		// Marked cumulative, rate WITHHELD. See the file comment: no
		// declaration ships a companion rate gauge, and the window
		// belongs to the producer.
		return fmt.Sprintf(
			`<span class="num counter" title="cumulative since the producer's `+
				`own epoch; no rate is declared and this page does not compute one">`+
				`%s</span>`, figure)
	}

	// A DECLARED DENOMINATOR is what makes a figure a proportion, and it
	// is keyed on here rather than on `unit: percent`.
	//
	// This tested the unit alone, and three facts in the tree — including
	// MemUsedPercent and both UsePercents — declare a denominator and no
	// unit at all. They rendered as bare integers with the denominator
	// silently dropped, which §28 calls "a number pretending to be an
	// answer". Keying on the unit meant honouring only the declarations
	// that happened to be complete.
	//
	// The `%` is still added ONLY where the unit says percent: the name
	// ends in "Percent" and inferring from that is the unit guesser §27
	// records, which did not know `Usec` and is the reason this file
	// exists. So an underdeclared fact renders as "25 of 8 GiB" — the
	// figure in whatever unit was declared, beside what it is a
	// proportion OF — which is an answer, where a bare 25 is not.
	if decl.Unit == "percent" || decl.Denominator != "" {
		// The denominator is NAMED by the declaration, so this file looks
		// it up rather than guessing which sibling it is.
		if decl.Denominator != "" {
			if against, ok := number(sib.Values[decl.Denominator]); ok {
				// In the DENOMINATOR'S own unit, read off its own
				// declaration. Formatting it in the numerator's unit would
				// print a byte count as a percentage.
				return fmt.Sprintf(
					`<span class="num">%s</span> <span class="of">of %s</span>`,
					figure, esc(formatted(sib.Decls[decl.Denominator].Unit, against)))
			}
			return fmt.Sprintf(
				`<span class="num">%s</span> <span class="of faint">of %s, `+
					`not on this row</span>`, figure, esc(decl.Denominator))
		}
		return fmt.Sprintf(`<span class="num">%s</span>`, figure)
	}

	if decl.Temperament == "gauge" && decl.Bound != "" {
		// A bar only where the bound is KNOWN — an unbounded bar invents
		// a scale. The width is a style attribute rather than a class,
		// because the value is data.
		if bound, ok := number(sib.Values[decl.Bound]); ok && bound > 0 {
			pct := n / bound * 100
			if pct < 0 {
				pct = 0
			}
			if pct > 100 {
				pct = 100
			}
			return fmt.Sprintf(
				`<span class="num">%s</span><span class="bar" `+
					`style="--fill:%.1f%%" title="of %s"></span>`,
				figure, pct, esc(decl.Bound))
		}
	}
	return fmt.Sprintf(`<span class="num">%s</span>`, figure)
}

// formatted turns a number into text under its DECLARED unit. One ladder
// product-wide, and it is IEC: the disagreement between two tables is
// worse than either convention, so the choice is made once here.
func formatted(unit string, n float64) string {
	switch unit {
	case "bytes":
		return iec(n, "B")
	case "bytes_per_second":
		return iec(n, "B/s")
	case "percent":
		return trim(n) + "%"
	case "celsius":
		return trim(n) + " °C"
	case "seconds":
		return trim(n) + " s"
	case "microseconds":
		// The fact the guesser could not see. Declared, so rendered.
		return trim(n/1e6) + " s"
	}
	return trim(n)
}

func iec(n float64, suffix string) string {
	units := []string{"", "Ki", "Mi", "Gi", "Ti", "Pi"}
	i := 0
	for n >= 1024 && i < len(units)-1 {
		n /= 1024
		i++
	}
	return trim(n) + " " + units[i] + suffix
}

func trim(n float64) string {
	if n == float64(int64(n)) {
		return fmt.Sprintf("%d", int64(n))
	}
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", n), "0"), ".")
}

func number(value any) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case int64:
		return float64(v), true
	case int:
		return float64(v), true
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	}
	return 0, false
}

func scalar(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case float64:
		return trim(v)
	case bool:
		return fmt.Sprintf("%v", v)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(raw)
}
