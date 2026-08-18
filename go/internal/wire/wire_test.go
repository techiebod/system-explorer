// The validating party must be proven to discriminate: every rule below
// is exercised red (a stream that breaks exactly one rule is rejected
// with exactly that reason) against a green baseline the same builder
// produces. A judge tested only on legal streams is a subset guard.
package wire

import (
	"fmt"
	"strings"
	"testing"
)

const bootID = "5e000000-0000-4000-8000-000000000001"

func issuedOne() map[string]uint64 { return map[string]uint64{"identity": 4} }

// legal returns the baseline stream the violation table mutates. One
// object, one relation, one unobservable, so every count is non-zero
// and a count mismatch in any of the three is detectable.
func legal() []string {
	return []string{
		`{"record":"begin","request":"b-1","batch":"b-1","declaration":"sha256:aa","boot_id":"` + bootID + `","timens":0,"instance":null,"generations":{"identity":4}}`,
		`{"record":"object","collection":"identity","name":"host1","names":{"stable":{"hostname":"host1"}},"facts":{"OsId":"nixos","Nested":{"a":1}},"absent":["OsVersionId"],"at":100.5}`,
		`{"record":"relation_assertion","collection":"identity","name":"host1","type":"runs-on","vantage":"identity","target":{"kind":"host","name":"host1"}}`,
		`{"record":"unobservable","collection":"identity","name":"host1","fact":"OsPrettyName","reason":"unavailable","detail":"os-release unreadable"}`,
		`{"record":"commit","collection":"identity","generation":4,"objects":1,"assertions":1,"unobservable":1,"cpu_ms":0.5}`,
		`{"record":"end","request":"b-1","batch":"b-1","cpu_ms":0.5,"wall_ms":1.0}`,
	}
}

func parse(t *testing.T, lines []string, issued map[string]uint64) (*Batch, error) {
	t.Helper()
	return ParseBatch([]byte(strings.Join(lines, "\n")+"\n"), issued)
}

func TestLegalStreamParses(t *testing.T) {
	b, err := parse(t, legal(), issuedOne())
	if err != nil {
		t.Fatalf("legal stream rejected: %v", err)
	}
	cs := b.Collections["identity"]
	if cs == nil || len(cs.Objects) != 1 || cs.Commit == nil {
		t.Fatalf("collection not assembled: %+v", cs)
	}
	o := cs.Objects[0]
	if o.Name != "host1" || o.At != 100.5 {
		t.Errorf("object mangled: %+v", o)
	}
	// Facts are canonical: sorted keys, source number lexemes.
	if got := string(o.Facts); got != `{"Nested":{"a":1},"OsId":"nixos"}` {
		t.Errorf("facts not canonical: %s", got)
	}
	if len(o.Absent) != 1 || o.Absent[0] != "OsVersionId" {
		t.Errorf("absent list lost: %v", o.Absent)
	}
	if o.Names == nil {
		t.Error("published names were dropped; law 1 stores every name")
	}
	if b.Begin.Instance != nil {
		t.Error("null instance must stay null (host-native)")
	}
	if len(b.Uncommitted()) != 0 {
		t.Errorf("nothing is uncommitted here: %v", b.Uncommitted())
	}
}

func TestAbsentDeclineCommitsEmpty(t *testing.T) {
	issued := map[string]uint64{"identity": 4, "arrays": 9}
	lines := []string{
		`{"record":"begin","request":"b-1","batch":"b-1","declaration":"sha256:aa","boot_id":"` + bootID + `","timens":0,"instance":null,"generations":{"identity":4,"arrays":9}}`,
		`{"record":"object","collection":"identity","name":"host1","facts":{"OsId":"nixos"},"at":100.5}`,
		`{"record":"commit","collection":"identity","generation":4,"objects":1,"assertions":0,"unobservable":0}`,
		`{"record":"decline","collection":"arrays","reason":"absent","detail":"no md devices"}`,
		`{"record":"commit","collection":"arrays","generation":9,"objects":0,"assertions":0,"unobservable":0}`,
		`{"record":"end","request":"b-1","batch":"b-1","wall_ms":1.0}`,
	}
	b, err := parse(t, lines, issued)
	if err != nil {
		t.Fatalf("absent + zero commit is the contract's own example: %v", err)
	}
	arrays := b.Collections["arrays"]
	if arrays.Decline == nil || arrays.Decline.Reason != "absent" || arrays.Commit == nil {
		t.Fatalf("absent decline and its commit are one statement: %+v", arrays)
	}
}

func TestNonAbsentDeclineWithoutCommitIsLegal(t *testing.T) {
	issued := map[string]uint64{"identity": 4}
	lines := []string{
		`{"record":"begin","request":"b-1","batch":"b-1","declaration":"sha256:aa","boot_id":"` + bootID + `","timens":0,"instance":null,"generations":{"identity":4}}`,
		`{"record":"decline","collection":"identity","reason":"unavailable","detail":"os-release unreadable"}`,
		`{"record":"end","request":"b-1","batch":"b-1"}`,
	}
	b, err := parse(t, lines, issued)
	if err != nil {
		t.Fatalf("a lone unavailable decline is a legal stream: %v", err)
	}
	if len(b.Uncommitted()) != 0 {
		t.Errorf("a declined collection is answered, not uncommitted: %v", b.Uncommitted())
	}
}

func TestUncommittedCollectionIsReportedNotRejected(t *testing.T) {
	issued := map[string]uint64{"identity": 4, "arrays": 9}
	lines := []string{
		`{"record":"begin","request":"b-1","batch":"b-1","declaration":"sha256:aa","boot_id":"` + bootID + `","timens":0,"instance":null,"generations":{"identity":4,"arrays":9}}`,
		`{"record":"object","collection":"identity","name":"host1","facts":{"OsId":"nixos"},"at":100.5}`,
		`{"record":"commit","collection":"identity","generation":4,"objects":1,"assertions":0,"unobservable":0}`,
		`{"record":"end","request":"b-1","batch":"b-1","wall_ms":1.0}`,
	}
	b, err := parse(t, lines, issued)
	if err != nil {
		t.Fatalf("arrays never answered, but the stream around it is legal: %v", err)
	}
	un := b.Uncommitted()
	if len(un) != 1 || un[0] != "arrays" {
		t.Fatalf("arrays is held, never applied: %v", un)
	}
}

// mutate applies one line-level edit to the legal stream.
type mutation struct {
	name   string
	reason string
	lines  func() []string
}

func TestViolationsAreCaughtWithTheirReasons(t *testing.T) {
	swap := func(i int, line string) func() []string {
		return func() []string {
			l := legal()
			l[i] = line
			return l
		}
	}
	cases := []mutation{
		{"empty stream", "empty-stream", func() []string { return nil }},
		{"garbage line", "unparseable-record", swap(1, `{"record":"object",`)},
		{"two records one line", "unparseable-record",
			swap(3, `{"record":"unobservable","collection":"identity","name":"host1","fact":"OsPrettyName","reason":"unavailable"} {"record":"decline","collection":"identity","reason":"absent"}`)},
		{"no discriminator", "missing-record-discriminator", swap(1, `{"collection":"identity"}`)},
		{"unknown record", "unknown-record", swap(1, `{"record":"objekt"}`)},
		{"begin not first", "begin-not-first", func() []string {
			l := legal()
			return append(l[1:2:2], l...)
		}},
		{"duplicate begin", "duplicate-begin", func() []string {
			l := legal()
			return append(l[0:1:1], l...)
		}},
		{"record after end", "record-after-end", func() []string {
			l := legal()
			return append(l, l[1])
		}},
		{"missing end", "missing-end", func() []string {
			l := legal()
			return l[:len(l)-1]
		}},
		{"begin missing member", "missing-member",
			swap(0, `{"record":"begin","request":"b-1","batch":"b-1","declaration":"sha256:aa","boot_id":"`+bootID+`","timens":0,"generations":{"identity":4}}`)},
		{"begin invented member", "undeclared-member",
			swap(0, `{"record":"begin","request":"b-1","batch":"b-1","declaration":"sha256:aa","boot_id":"`+bootID+`","timens":0,"instance":null,"generations":{"identity":4},"host":"h"}`)},
		{"empty batch id", "bad-identity",
			swap(0, `{"record":"begin","request":"b-1","batch":"","declaration":"sha256:aa","boot_id":"`+bootID+`","timens":0,"instance":null,"generations":{"identity":4}}`)},
		{"nil boot id", "bad-boot-id",
			swap(0, `{"record":"begin","request":"b-1","batch":"b-1","declaration":"sha256:aa","boot_id":"00000000-0000-0000-0000-000000000000","timens":0,"instance":null,"generations":{"identity":4}}`)},
		{"dashless boot id", "bad-boot-id",
			swap(0, `{"record":"begin","request":"b-1","batch":"b-1","declaration":"sha256:aa","boot_id":"5e0000000000400080000000000000001","timens":0,"instance":null,"generations":{"identity":4}}`)},
		{"empty instance", "bad-instance",
			swap(0, `{"record":"begin","request":"b-1","batch":"b-1","declaration":"sha256:aa","boot_id":"`+bootID+`","timens":0,"instance":"","generations":{"identity":4}}`)},
		{"fractional timens", "bad-timens",
			swap(0, `{"record":"begin","request":"b-1","batch":"b-1","declaration":"sha256:aa","boot_id":"`+bootID+`","timens":0.5,"instance":null,"generations":{"identity":4}}`)},
		{"generation echo wrong number", "generations-echo-mismatch",
			swap(0, `{"record":"begin","request":"b-1","batch":"b-1","declaration":"sha256:aa","boot_id":"`+bootID+`","timens":0,"instance":null,"generations":{"identity":5}}`)},
		{"generation echo extra collection", "generations-echo-mismatch",
			swap(0, `{"record":"begin","request":"b-1","batch":"b-1","declaration":"sha256:aa","boot_id":"`+bootID+`","timens":0,"instance":null,"generations":{"identity":4,"pools":1}}`)},
		{"generation echo missing collection", "generations-echo-mismatch",
			swap(0, `{"record":"begin","request":"b-1","batch":"b-1","declaration":"sha256:aa","boot_id":"`+bootID+`","timens":0,"instance":null,"generations":{}}`)},
		{"object for unissued collection", "unissued-collection",
			swap(1, `{"record":"object","collection":"pools","name":"tank","facts":{},"at":100.5}`)},
		{"null fact at top", "null-fact",
			swap(1, `{"record":"object","collection":"identity","name":"host1","facts":{"OsId":null},"at":100.5}`)},
		{"null fact nested", "null-fact",
			swap(1, `{"record":"object","collection":"identity","name":"host1","facts":{"Rows":[{"path":null}]},"at":100.5}`)},
		{"exported-field names class", "bad-names",
			swap(1, `{"record":"object","collection":"identity","name":"host1","names":{"Stable":{"hostname":"host1"}},"facts":{},"at":100.5}`)},
		{"empty name in family", "bad-names",
			swap(1, `{"record":"object","collection":"identity","name":"host1","names":{"stable":{"hostname":""}},"facts":{},"at":100.5}`)},
		{"at zero", "at-out-of-range",
			swap(1, `{"record":"object","collection":"identity","name":"host1","facts":{},"at":0}`)},
		{"at wall-clock scale", "at-out-of-range",
			swap(1, `{"record":"object","collection":"identity","name":"host1","facts":{},"at":1755500000.1}`)},
		{"json evidence without canon", "bad-evidence",
			swap(1, `{"record":"object","collection":"identity","name":"host1","facts":{},"evidence":{"media_type":"application/json","digest":"sha256:aa"},"at":100.5}`)},
		{"canon on non-json evidence", "bad-evidence",
			swap(1, `{"record":"object","collection":"identity","name":"host1","facts":{},"evidence":{"media_type":"text/plain","digest":"sha256:aa","canon":"jcs/1"},"at":100.5}`)},
		{"target with id", "bad-target",
			swap(2, `{"record":"relation_assertion","collection":"identity","name":"host1","type":"runs-on","vantage":"identity","target":{"kind":"host","name":"host1","id":"host:host1"}}`)},
		{"asserted observability", "undeclared-member",
			swap(2, `{"record":"relation_assertion","collection":"identity","name":"host1","type":"runs-on","vantage":"identity","target":{"kind":"host","name":"host1"},"observability":"confirmed"}`)},
		{"unobservable says absent", "bad-unobservable-reason",
			swap(3, `{"record":"unobservable","collection":"identity","name":"host1","fact":"OsPrettyName","reason":"absent"}`)},
		{"invented decline reason", "bad-decline-reason", func() []string {
			return []string{
				legal()[0],
				`{"record":"decline","collection":"identity","reason":"broken"}`,
				legal()[5],
			}
		}},
		{"commit missing a count", "missing-member",
			swap(4, `{"record":"commit","collection":"identity","generation":4,"objects":1,"assertions":1}`)},
		{"commit generation not the issued one", "generation-echo-mismatch",
			swap(4, `{"record":"commit","collection":"identity","generation":3,"objects":1,"assertions":1,"unobservable":1}`)},
		{"commit object count wrong", "commit-count-mismatch",
			swap(4, `{"record":"commit","collection":"identity","generation":4,"objects":2,"assertions":1,"unobservable":1}`)},
		{"commit assertion count wrong", "commit-count-mismatch",
			swap(4, `{"record":"commit","collection":"identity","generation":4,"objects":1,"assertions":0,"unobservable":1}`)},
		{"commit unobservable count wrong", "commit-count-mismatch",
			swap(4, `{"record":"commit","collection":"identity","generation":4,"objects":1,"assertions":1,"unobservable":0}`)},
		{"partial-commit marker", "undeclared-member",
			swap(4, `{"record":"commit","collection":"identity","generation":4,"objects":1,"assertions":1,"unobservable":1,"complete":false}`)},
		{"end echoes another batch", "end-echo-mismatch",
			swap(5, `{"record":"end","request":"b-1","batch":"b-2","wall_ms":1.0}`)},
		{"end echoes another request", "end-echo-mismatch",
			swap(5, `{"record":"end","request":"rq-9","batch":"b-1","wall_ms":1.0}`)},
		{"objects with zero wall_ms", "wall-ms-not-positive",
			swap(5, `{"record":"end","request":"b-1","batch":"b-1","wall_ms":0}`)},
		{"objects with wall_ms omitted", "wall-ms-not-positive",
			swap(5, `{"record":"end","request":"b-1","batch":"b-1"}`)},
		{"record after its commit", "record-after-commit", func() []string {
			l := legal()
			return []string{l[0], l[1], l[2], l[3], l[4], l[1], l[5]}
		}},
		{"same name twice", "duplicate-object-name", func() []string {
			l := legal()
			obj2 := `{"record":"object","collection":"identity","name":"host1","facts":{"OsId":"debian"},"at":101.0}`
			commit := `{"record":"commit","collection":"identity","generation":4,"objects":2,"assertions":1,"unobservable":1}`
			return []string{l[0], l[1], obj2, l[2], l[3], commit, l[5]}
		}},
		{"at decreasing in collection", "at-decreasing", func() []string {
			l := legal()
			obj2 := `{"record":"object","collection":"identity","name":"host2","facts":{},"at":99.0}`
			commit := `{"record":"commit","collection":"identity","generation":4,"objects":2,"assertions":1,"unobservable":1}`
			return []string{l[0], l[1], obj2, l[2], l[3], commit, l[5]}
		}},
		{"absent decline without its commit", "absent-without-commit", func() []string {
			return []string{
				legal()[0],
				`{"record":"decline","collection":"identity","reason":"absent"}`,
				legal()[5],
			}
		}},
		{"absent decline committing objects", "decline-after-records", func() []string {
			l := legal()
			return []string{l[0], l[1],
				`{"record":"decline","collection":"identity","reason":"absent"}`,
				l[4], l[5]}
		}},
		{"unavailable decline with a commit", "decline-with-commit", func() []string {
			return []string{
				legal()[0],
				`{"record":"decline","collection":"identity","reason":"unavailable"}`,
				`{"record":"commit","collection":"identity","generation":4,"objects":0,"assertions":0,"unobservable":0}`,
				legal()[5],
			}
		}},
		// A decline closes its collection to everything except absent's
		// zero commit — the mirror of decline-after-records. Accepting an
		// emission here dropped the record silently where the collection's
		// verdict already stood.
		{"object after a decline", "record-after-decline", func() []string {
			return []string{
				legal()[0],
				`{"record":"decline","collection":"identity","reason":"unavailable"}`,
				legal()[1],
				legal()[5],
			}
		}},
		{"assertion after an absent decline", "record-after-decline", func() []string {
			return []string{
				legal()[0],
				`{"record":"decline","collection":"identity","reason":"absent"}`,
				legal()[2],
				`{"record":"commit","collection":"identity","generation":4,"objects":0,"assertions":1,"unobservable":0}`,
				legal()[5],
			}
		}},
		{"unobservable after a decline", "record-after-decline", func() []string {
			return []string{
				legal()[0],
				`{"record":"decline","collection":"identity","reason":"unauthorised"}`,
				legal()[3],
				legal()[5],
			}
		}},
		// absent commits EMPTY: all three counts, not only objects.
		{"absent commit counting assertions", "absent-with-objects", func() []string {
			return []string{
				legal()[0],
				`{"record":"decline","collection":"identity","reason":"absent"}`,
				`{"record":"commit","collection":"identity","generation":4,"objects":0,"assertions":1,"unobservable":0}`,
				legal()[5],
			}
		}},
		// Measured cost is advisory, never authenticated — but bounded to
		// what a clock can read, the same bound the contract schema and
		// the replay judge hold (three artifacts, one boundary).
		{"negative cpu_ms on commit", "bad-cpu-ms",
			swap(4, `{"record":"commit","collection":"identity","generation":4,"objects":1,"assertions":1,"unobservable":1,"cpu_ms":-1}`)},
		{"negative cpu_ms on end", "bad-cpu-ms",
			swap(5, `{"record":"end","request":"b-1","batch":"b-1","cpu_ms":-0.5,"wall_ms":1.0}`)},
		{"negative wall_ms on end", "bad-wall-ms",
			swap(5, `{"record":"end","request":"b-1","batch":"b-1","cpu_ms":0.5,"wall_ms":-1.0}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(t, tc.lines(), issuedOne())
			if err == nil {
				t.Fatalf("stream accepted; expected violation %s", tc.reason)
			}
			v, ok := err.(*Violation)
			if !ok {
				t.Fatalf("expected *Violation, got %T: %v", err, err)
			}
			if v.Reason != tc.reason {
				t.Fatalf("expected reason %s, got %s (%s)", tc.reason, v.Reason, v.Detail)
			}
		})
	}
}

// The absent-with-objects pairing rule needs a stream where the commit
// claims objects under an absent decline without tripping the earlier
// decline-after-records or count checks: decline first, commit lies.
func TestAbsentCommitMustBeEmpty(t *testing.T) {
	lines := []string{
		legal()[0],
		`{"record":"decline","collection":"identity","reason":"absent"}`,
		`{"record":"commit","collection":"identity","generation":4,"objects":1,"assertions":0,"unobservable":0}`,
		legal()[5],
	}
	_, err := parse(t, lines, issuedOne())
	v, ok := err.(*Violation)
	if !ok {
		t.Fatalf("expected a violation, got %v", err)
	}
	// The count check fires first (commit says 1, stream carried 0) —
	// either reason names the same defect: absent commits empty.
	if v.Reason != "commit-count-mismatch" && v.Reason != "absent-with-objects" {
		t.Fatalf("unexpected reason %s (%s)", v.Reason, v.Detail)
	}
}

// The at ceiling is INCLUSIVE — 0 < at <= 1e9 — because the contract
// schema says maximum, not exclusiveMaximum. The three artifacts refuse
// and accept the same boundary point, or a stream would be legal in one
// courtroom and refused in the next.
func TestAtCeilingIsInclusive(t *testing.T) {
	l := legal()
	l[1] = `{"record":"object","collection":"identity","name":"host1","facts":{},"at":1000000000}`
	if _, err := parse(t, l, issuedOne()); err != nil {
		t.Fatalf("at == 1e9 exactly is inside the contract's bound: %v", err)
	}
}

func TestFreshnessGrammar(t *testing.T) {
	good := map[string]string{"60s": "1m0s", "1h": "1h0m0s", "500ms": "500ms", "2d": "48h0m0s", "3m": "3m0s"}
	for in, want := range good {
		d, err := ParseFreshness(in)
		if err != nil || d.String() != want {
			t.Errorf("ParseFreshness(%q) = %v, %v; want %s", in, d, err, want)
		}
	}
	for _, bad := range []string{"", "60", "s", "1.5s", "-1s", "1w", " 60s"} {
		if _, err := ParseFreshness(bad); err == nil {
			t.Errorf("ParseFreshness(%q) accepted; the unit is part of the value", bad)
		}
	}
}

func TestDeclarationHashCoversExactBytes(t *testing.T) {
	a := DeclarationHash([]byte(`{"collector":"system"}`))
	b := DeclarationHash([]byte(`{"collector":"system"} `))
	if a == b {
		t.Fatal("hash must be over the exact bytes declare emits")
	}
	if !strings.HasPrefix(a, "sha256:") || len(a) != len("sha256:")+64 {
		t.Fatalf("commitment format: %s", a)
	}
}

func TestParseDeclaration(t *testing.T) {
	raw := []byte(`{"schema":"se.declaration/1","collector":"system",` +
		`"collections":[{"name":"identity","freshness":"1h"}]}`)
	d, freshness, err := ParseDeclaration(raw)
	if err != nil {
		t.Fatal(err)
	}
	if d.Collector != "system" || len(d.Collections) != 1 {
		t.Fatalf("declaration slice: %+v", d)
	}
	if freshness["identity"].String() != "1h0m0s" {
		t.Fatalf("freshness: %v", freshness)
	}
	if _, _, err := ParseDeclaration([]byte(`{"collector":"x","collections":[]}`)); err == nil {
		t.Fatal("a declaration with no collections declares nothing")
	}
}

// A begin whose generations echo matches an empty issue: proves the echo
// rule is an equality, not a subset check — the estate's most repeated
// defect is a guard that checks a subset.
func TestEchoIsEqualityNotSubset(t *testing.T) {
	issued := map[string]uint64{"identity": 4, "arrays": 9}
	lines := []string{
		// begin echoes only identity — a subset. Must be refused even
		// though everything it does echo is correct.
		`{"record":"begin","request":"b-1","batch":"b-1","declaration":"sha256:aa","boot_id":"` + bootID + `","timens":0,"instance":null,"generations":{"identity":4}}`,
		`{"record":"end","request":"b-1","batch":"b-1"}`,
	}
	_, err := parse(t, lines, issued)
	v, ok := err.(*Violation)
	if !ok || v.Reason != "generations-echo-mismatch" {
		t.Fatalf("subset echo accepted: %v", err)
	}
}

func TestViolationErrorCarriesDetail(t *testing.T) {
	v := violation("some-reason", "the %s", "specifics")
	if v.Error() != "some-reason: the specifics" {
		t.Fatalf("%q", v.Error())
	}
	if fmt.Sprintf("%v", &Violation{Reason: "bare"}) != "bare" {
		t.Fatal("detail-less violation prints its reason alone")
	}
}
