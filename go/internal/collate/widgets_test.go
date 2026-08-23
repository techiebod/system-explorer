package collate

import (
	"regexp"
	"strings"
	"testing"
)

// visible is what a person reads: markup and attribute values removed, so
// an assertion cannot pass or fail on a class name or a title.
var tags = regexp.MustCompile(`<[^>]*>`)

func visible(html string) string {
	return strings.TrimSpace(tags.ReplaceAllString(html, " "))
}

var classAttr = regexp.MustCompile(`class="([^"]*)"`)

func classOf(html string) string {
	if m := classAttr.FindStringSubmatch(html); m != nil {
		return m[1]
	}
	return ""
}

// DESIGN §28's widget table, row by row. It is a SPECIFICATION, so each
// row is an assertion rather than a description.

func TestAnEnumIsAChipAndIsNeverColouredByThisFile(t *testing.T) {
	// §28 allows colour only where the vocabulary means the same thing
	// everywhere the enum appears — `down` is a fault on a NIC carrying
	// addresses and correct on an empty bridge. Nothing in a declaration
	// says whether a vocabulary is shared, so colouring from the value
	// would be this file deciding severity: the fourth copy §27 forbids.
	decl := FactDecl{Type: "enum", Values: []string{"active", "failed"}}
	// The PROPERTY, not a word list. The first spelling of this test
	// enumerated severity words — critical, warn, ok — and a plant that
	// styled the chip with the member's own name ("failed") sailed
	// through it, because "failed" was not on the list. What matters is
	// that the styling does not vary with the value at all; asserting
	// that directly cannot be evaded by choosing a different word.
	var classes []string
	for _, value := range []string{"failed", "active", "some-member-nobody-declared"} {
		out := Cell(decl, value, StateValue, "", nil, false)
		if !strings.Contains(out, "chip") || !strings.Contains(out, value) {
			t.Fatalf("%s: %s", value, out)
		}
		classes = append(classes, classOf(out))
	}
	for _, got := range classes[1:] {
		if got != classes[0] {
			t.Fatalf("the chip's styling varies with the member (%q vs %q), so "+
				"this file is deciding severity from a value — which the "+
				"opinion layer decides and delivers as a verdict",
				classes[0], got)
		}
	}
}

func TestABooleanRendersItsDeclaredLabelsAndNeverATickOrACross(t *testing.T) {
	// A cross reads as a failure and most booleans are not verdicts. And
	// absent is already a render state meaning "we looked and there is no
	// such property", so drawing false as absence collapses a measured
	// negative into an epistemic one — §28 calls that the founding error
	// in miniature.
	decl := FactDecl{Type: "boolean",
		Labels: []string{"synthesised from the mount table", "declared in a unit file"}}
	on := Cell(decl, true, StateValue, "", nil, false)
	off := Cell(decl, false, StateValue, "", nil, false)
	if !strings.Contains(on, "synthesised from the mount table") {
		t.Fatalf("true takes the first label: %s", on)
	}
	if !strings.Contains(off, "declared in a unit file") {
		t.Fatalf("false takes the second label: %s", off)
	}
	for _, out := range []string{on, off} {
		for _, glyph := range []string{"✓", "✔", "✗", "✘", "×", "—"} {
			if strings.Contains(out, glyph) {
				t.Fatalf("a boolean is not a verdict and not an absence: %s", out)
			}
		}
	}
}

func TestAnUnderDeclaredBooleanIsMarkedRatherThanGuessedAt(t *testing.T) {
	// Twenty booleans in the tree declare no labels. The raw word is
	// rendered and marked; inventing "yes"/"no" would be this file
	// supplying a vocabulary the producer never declared.
	out := Cell(FactDecl{Type: "boolean"}, true, StateValue, "", nil, false)
	if !strings.Contains(out, "under-declared") {
		t.Fatalf("an under-declared boolean says so: %s", out)
	}
	for _, glyph := range []string{"✓", "✗", "—"} {
		if strings.Contains(out, glyph) {
			t.Fatalf("still never a tick, a cross or an absence mark: %s", out)
		}
	}
}

func TestBytesUseOneLadderProductWide(t *testing.T) {
	// Pick IEC or SI once and never mix: the disagreement between two
	// tables is worse than either convention.
	decl := FactDecl{Type: "integer", Unit: "bytes"}
	for value, want := range map[float64]string{
		512: "512 B", 1024: "1 KiB", 1536: "1.5 KiB",
		1048576: "1 MiB", 1073741824: "1 GiB",
	} {
		out := Cell(decl, value, StateValue, "", nil, false)
		if !strings.Contains(out, want) {
			t.Fatalf("%v: want %q, got %s", value, want, out)
		}
	}
}

func TestTheMicrosecondFactTheUnitGuesserCouldNotSee(t *testing.T) {
	// §27 records the guesser: it inferred units from fact-name suffixes,
	// did not know `Usec`, and so rendered every microsecond fact as a
	// bare integer "to this day". Seven facts declare the unit, so this
	// renders from the declaration and the class of bug cannot recur.
	out := Cell(FactDecl{Type: "integer", Unit: "microseconds"},
		2_500_000.0, StateValue, "", nil, false)
	if !strings.Contains(out, "2.5 s") {
		t.Fatalf("a declared microsecond fact is not a bare integer: %s", out)
	}
}

func TestACounterIsMarkedCumulativeAndNoRateIsInvented(t *testing.T) {
	// §28 wants a counter's declared companion rate gauge. NO declaration
	// in the tree ships one, so the honest rendering is the raw value
	// marked cumulative. The window belongs to the producer (§12) and a
	// rate computed here would be the fourth copy.
	out := Cell(FactDecl{Type: "integer", Temperament: "counter", Unit: "count"},
		98765.0, StateValue, "", nil, false)
	if !strings.Contains(out, "counter") || !strings.Contains(out, "98765") {
		t.Fatalf("%s", out)
	}
	// Read the TEXT, not the attributes: the title says "no rate is
	// declared", which a naive substring check reads as a rate. Asserting
	// over markup rather than over what a person sees is how a guard ends
	// up policing its own prose.
	for _, invented := range []string{"/s", "per second", "rate"} {
		if strings.Contains(visible(out), invented) {
			t.Fatalf("the renderer computed a rate it was not given: %s", out)
		}
	}
}

func TestAPercentageCarriesItsDenominator(t *testing.T) {
	// A percentage with no denominator is a number pretending to be an
	// answer. The declaration NAMES the denominator, so it is looked up
	// rather than guessed at from the sibling names.
	decl := FactDecl{Type: "number", Unit: "percent", Denominator: "SizeBytes"}
	out := Cell(decl, 82.5, StateValue, "",
		map[string]any{"SizeBytes": 2199023255552.0}, false)
	if !strings.Contains(out, "82.5%") {
		t.Fatalf("%s", out)
	}
	if !strings.Contains(out, "of ") {
		t.Fatalf("the denominator must be beside the figure: %s", out)
	}
}

func TestAPercentageWhoseDenominatorIsNotOnTheRowSaysSo(t *testing.T) {
	// Stated, not silently dropped: a reader must be able to tell "no
	// denominator was declared" from "the declared one is not here".
	decl := FactDecl{Type: "number", Unit: "percent", Denominator: "SizeBytes"}
	out := Cell(decl, 82.5, StateValue, "", map[string]any{}, false)
	if !strings.Contains(out, "not on this row") {
		t.Fatalf("%s", out)
	}
}

func TestAGaugeGetsABarOnlyWhereItsBoundIsKnown(t *testing.T) {
	// An unbounded bar invents a scale.
	decl := FactDecl{Type: "integer", Unit: "bytes", Temperament: "gauge",
		Bound: "DiskTotalBytes"}
	bounded := Cell(decl, 250.0, StateValue, "",
		map[string]any{"DiskTotalBytes": 1000.0}, false)
	if !strings.Contains(bounded, "bar") || !strings.Contains(bounded, "--fill:25.0%") {
		t.Fatalf("%s", bounded)
	}
	unbounded := Cell(decl, 250.0, StateValue, "", map[string]any{}, false)
	if strings.Contains(unbounded, "bar") {
		t.Fatalf("no bound, no bar: %s", unbounded)
	}
	unboundedDecl := Cell(FactDecl{Type: "integer", Temperament: "gauge"},
		250.0, StateValue, "", nil, false)
	if strings.Contains(unboundedDecl, "bar") {
		t.Fatalf("a gauge declaring no bound gets no bar: %s", unboundedDecl)
	}
}

func TestAListOfScalarsIsChipsAndAListOfObjectsIsATable(t *testing.T) {
	// A structured value earns structure; comma-joining it destroys it.
	chips := Cell(FactDecl{Type: "list"},
		[]any{"one", "two", "three"}, StateValue, "", nil, false)
	if strings.Count(chips, "chip item") != 3 {
		t.Fatalf("%s", chips)
	}
	table := Cell(FactDecl{Type: "list"}, []any{
		map[string]any{"name": "a", "state": "up"},
		map[string]any{"name": "b", "state": "down"},
	}, StateValue, "", nil, false)
	if !strings.Contains(table, "<table class=\"nested\"") {
		t.Fatalf("a list of uniform objects is a nested table: %s", table)
	}
	if !strings.Contains(table, "<th>name</th>") || !strings.Contains(table, "<td>down</td>") {
		t.Fatalf("%s", table)
	}
}

func TestAnEmptyListIsMeasuredEmptinessNotAbsence(t *testing.T) {
	// The producer looked and found no members. Borrowing absent's em
	// dash would collapse a measured negative into an epistemic one.
	out := Cell(FactDecl{Type: "list"}, []any{}, StateValue, "", nil, false)
	if strings.Contains(out, "—") {
		t.Fatalf("an empty list is not an absent property: %s", out)
	}
	if !strings.Contains(out, "none") {
		t.Fatalf("%s", out)
	}
}

func TestProseIsVerbatimAndCarriesNoTruncation(t *testing.T) {
	// The shipped defect §28 records: a firewall rule truncated at the
	// column edge. `meta iifname tailscale0 tcp dport 22 counter accept`
	// clipped to `tcp dport 22 counter accept` is a rule confining sshd to
	// one interface rendered as one admitting it from anywhere.
	rule := "meta iifname tailscale0 tcp dport 22 counter accept"
	out := Cell(FactDecl{Type: "string"}, rule, StateValue, "", nil, false)
	if !strings.Contains(out, "iifname tailscale0") {
		t.Fatal("the interface clause is what the truncation destroyed")
	}
	if strings.Contains(out, "…") || strings.Contains(out, "...") {
		t.Fatalf("load-bearing text carries no ellipsis: %s", out)
	}
}

func TestTheFiveStatesDoNotRenderAlike(t *testing.T) {
	// "The most common rendering bug in this product's history is
	// collapsing these into a blank cell."
	decl := FactDecl{Type: "string"}
	value := Cell(decl, "running", StateValue, "", nil, false)
	absent := Cell(decl, nil, StateAbsent, "", nil, false)
	unobs := Cell(decl, nil, StateUnobservable, "EACCES on /proc/1/environ", nil, false)
	seen := map[string]string{"value": value, "absent": absent, "unobservable": unobs}
	for name, out := range seen {
		if strings.TrimSpace(out) == "" {
			t.Fatalf("%s rendered as a blank cell", name)
		}
		for other, against := range seen {
			if other != name && out == against {
				t.Fatalf("%s and %s render identically: %s", name, other, out)
			}
		}
	}
	if !strings.Contains(absent, "—") {
		t.Fatalf("absent is an em dash, muted: %s", absent)
	}
	if !strings.Contains(unobs, "EACCES on /proc/1/environ") {
		t.Fatal("unobservable carries THE REASON, on the row — never blank, " +
			"never zero")
	}
	if strings.Contains(unobs, ">0<") {
		t.Fatalf("never zero: %s", unobs)
	}
}

func TestTheAbsentDashIsContentNotAStylesheet(t *testing.T) {
	// A CSS-generated dash is a blank cell wearing a dash: a stylesheet
	// that did not load takes the state with it, and the founding
	// rendering bug returns through the door §28 shut.
	out := Cell(FactDecl{Type: "string"}, nil, StateAbsent, "", nil, false)
	if !strings.Contains(out, ">—<") {
		t.Fatalf("the dash must be in the markup: %s", out)
	}
}

func TestADeclaredFactIsMarkedWhereverItAppears(t *testing.T) {
	// A reader forming a belief should know it rests on an assertion.
	out := Cell(FactDecl{Type: "string", Kind: "declared"}, "offsite-vault",
		StateValue, "", nil, false)
	if !strings.Contains(out, "mark-declared") {
		t.Fatalf("%s", out)
	}
}

func TestAnUndeclaredFactIsShownRawWithItsCaveatVisible(t *testing.T) {
	// A fact from a newer collector than this renderer (§26) — shown,
	// never dropped, never styled as understood.
	out := Undeclared("something-new")
	if !strings.Contains(out, "something-new") {
		t.Fatalf("never dropped: %s", out)
	}
	if !strings.Contains(out, "undeclared") {
		t.Fatalf("the caveat is visible: %s", out)
	}
}

func TestEveryRenderedValueIsEscaped(t *testing.T) {
	// Facts carry text this product did not write, and a page that
	// trusted it would turn a read-only observer into a delivery
	// mechanism.
	hostile := `<script>alert(1)</script>`
	for _, out := range []string{
		Cell(FactDecl{Type: "string"}, hostile, StateValue, "", nil, false),
		Cell(FactDecl{Type: "enum"}, hostile, StateValue, "", nil, false),
		Cell(FactDecl{Type: "list"}, []any{hostile}, StateValue, "", nil, false),
		Cell(FactDecl{Type: "string"}, nil, StateUnobservable, hostile, nil, false),
		Undeclared(hostile),
	} {
		if strings.Contains(out, "<script>") {
			t.Fatalf("unescaped: %s", out)
		}
	}
}
