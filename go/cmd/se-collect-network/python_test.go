package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Every expected value in this file was produced by the reference's own
// Python before it was written down: json.dumps for the dumps table,
// repr(float) for the numbers, system_explorer.text.one_line and .scrub for
// the bounding and stripping. They are the reference's spellings, which is
// why they are pinned rather than derived.

func decode(t *testing.T, document string) jsonValue {
	t.Helper()
	value, err := decodeDocument(strings.NewReader(document))
	if err != nil {
		t.Fatalf("%s: %v", document, err)
	}
	return value
}

func TestPythonDumpsMatchesTheReferencesDefaults(t *testing.T) {
	cases := map[string]string{
		`{"a":1,"b":[1,2],"c":null,"d":true}`: `{"a": 1, "b": [1, 2], "c": null, "d": true}`,
		`{}`:                                  `{}`,
		`[]`:                                  `[]`,
		`"bare"`:                              `"bare"`,
		`[42]`:                                `[42]`,
		// Member order is the document's own: sort_keys is off, and a
		// re-sorted statement is a different answer.
		`{"z":1,"a":2,"m":{"y":1,"b":2}}`: `{"z": 1, "a": 2, "m": {"y": 1, "b": 2}}`,
		// ensure_ascii, with a surrogate pair above the BMP.
		`{"z":"é café","y":"tab\there"}`: `{"z": "\u00e9 caf\u00e9", "y": "tab\there"}`,
		`{"emoji":"😀"}`:                  `{"emoji": "\ud83d\ude00"}`,
		// A literal carrying a fraction or an exponent is a Python float and
		// is re-spelled by repr; an integer literal is exact.
		`{"a":1.5,"b":1e16,"c":1e-5,"d":100.0,"e":1E2}`: `{"a": 1.5, "b": 1e+16, "c": 1e-05, "d": 100.0, "e": 100.0}`,
		`{"big":18446744073709551615}`:                  `{"big": 18446744073709551615}`,
	}
	for document, want := range cases {
		if got := pythonDumps(decode(t, document)); got != want {
			t.Errorf("%s\n  got  %s\n  want %s", document, got, want)
		}
	}
}

func TestPythonFloatReprMatchesTheReference(t *testing.T) {
	cases := map[string]string{
		"0.0":                    "0.0",
		"-0.0":                   "-0.0",
		"1.5":                    "1.5",
		"-2.75":                  "-2.75",
		"0.1":                    "0.1",
		"100.0":                  "100.0",
		"1E2":                    "100.0",
		"173725410.0":            "173725410.0",
		"1e15":                   "1000000000000000.0",
		"9999999999999998.0":     "9999999999999998.0",
		"1e16":                   "1e+16",
		"1e17":                   "1e+17",
		"1e-4":                   "0.0001",
		"1e-5":                   "1e-05",
		"2.5e-10":                "2.5e-10",
		"1e-323":                 "1e-323",
		"3.14159265358979":       "3.14159265358979",
		"1.7976931348623157e308": "1.7976931348623157e+308",
	}
	for literal, want := range cases {
		if got := pythonNumberText(literal); got != want {
			t.Errorf("%s: got %s, want %s", literal, got, want)
		}
	}
	// str(int) of a negative zero is "0"; every other integer literal is
	// exact, at any width.
	if got := pythonNumberText("-0"); got != "0" {
		t.Errorf("got %s", got)
	}
}

func TestPythonStrIsWhatTheRendererInterpolates(t *testing.T) {
	cases := map[string]string{
		`null`:         "None",
		`true`:         "True",
		`false`:        "False",
		`"text"`:       "text",
		`22`:           "22",
		`22.0`:         "22.0",
		`[1,"a"]`:      "[1, 'a']",
		`{"k":null}`:   "{'k': None}",
		`{"k":"it's"}`: `{'k': "it's"}`,
	}
	for document, want := range cases {
		if got := pythonStr(decode(t, document)); got != want {
			t.Errorf("%s: got %q, want %q", document, got, want)
		}
	}
}

func TestPythonHexIsLowercaseUnpaddedAndSignedOutsideThePrefix(t *testing.T) {
	cases := map[string]string{
		"16711680":             "0xff0000",
		"0":                    "0x0",
		"-16":                  "-0x10",
		"18446744073709551615": "0xffffffffffffffff",
	}
	for literal, want := range cases {
		if got := pythonHex(jsonValue{kind: jsonNumber, number: literal}); got != want {
			t.Errorf("%s: got %s, want %s", literal, got, want)
		}
	}
	// bool is an int in Python, so a JSON true reaches the mask branch.
	if got := pythonHex(jsonValue{kind: jsonBool, boolean: true}); got != "0x1" {
		t.Errorf("got %s", got)
	}
}

func TestOneLineCollapsesWhitespaceAndBoundsOnAWordBoundary(t *testing.T) {
	if got := oneLine("  a   b\tc  ", 400); got != "a b c" {
		t.Fatalf("got %q", got)
	}
	// An unbroken token has no word boundary to cut back to, so the window is
	// kept whole rather than emitting a marker with nothing in front of it.
	// The lengths are in characters, as the reference's rule is stated.
	long := oneLine(strings.Repeat("x", 500), 400)
	if utf8.RuneCountInString(long) != 414 || !strings.HasSuffix(long, " … (truncated)") {
		t.Fatalf("len %d: %q", utf8.RuneCountInString(long), long)
	}
	// A word boundary far to the left throws away everything after it — the
	// measured behaviour, and why a long unbroken value collapses the string.
	short := oneLine(strings.Repeat("q", 200)+" "+strings.Repeat("r", 300), 400)
	if utf8.RuneCountInString(short) != 214 {
		t.Fatalf("len %d: %q", utf8.RuneCountInString(short), short)
	}
	// Idempotent: bounding an already-bounded string returns it unchanged.
	if got := oneLine("a b", 400); got != "a b" {
		t.Fatalf("got %q", got)
	}
}

func TestScrubStripsQueryStringsAndUserinfoAndNothingElse(t *testing.T) {
	cases := map[string]string{
		"a?b c":             "a?[query-stripped] c",
		"a? b":              "a? b",
		`x?y"z`:             `x?[query-stripped]"z`,
		"?":                 "?",
		"??a":               "?[query-stripped]",
		"no marks":          "no marks",
		"https://u@h/p":     "https://[userinfo-stripped]@h/p",
		"https://u@h/p?a=1": "https://[userinfo-stripped]@h/p?[query-stripped]",
		"http://a://b@c":    "http://a://[userinfo-stripped]@c",
		"user@host":         "user@host",
	}
	for input, want := range cases {
		if got := scrub(input); got != want {
			t.Errorf("%q: got %q, want %q", input, got, want)
		}
	}
}

// A repeated member keeps the FIRST position and the LAST value, and len()
// sees one key — which is what the renderer's `len(left) == 1` test asks.
func TestARepeatedMemberCollapsesTheWayAPythonDictDoes(t *testing.T) {
	value := decode(t, `{"a":1,"b":2,"a":3}`)
	if value.size() != 2 {
		t.Fatalf("size %d", value.size())
	}
	if value.firstKey() != "a" {
		t.Fatalf("firstKey %q", value.firstKey())
	}
	if got := pythonDumps(value); got != `{"a": 3, "b": 2}` {
		t.Fatalf("got %s", got)
	}
}

func TestTruthinessIsPythons(t *testing.T) {
	falsy := []string{`null`, `false`, `0`, `-0`, `0.0`, `""`, `[]`, `{}`}
	truthy := []string{`true`, `1`, `-1`, `0.5`, `"x"`, `[0]`, `{"a":0}`, `1e400`}
	for _, document := range falsy {
		if decode(t, document).truthy() {
			t.Errorf("%s is falsy in Python", document)
		}
	}
	for _, document := range truthy {
		if !decode(t, document).truthy() {
			t.Errorf("%s is truthy in Python", document)
		}
	}
}

func TestATrailingDocumentIsRefused(t *testing.T) {
	// json.loads refuses trailing content and so does this: a second document
	// in the payload is a broken capture, never a longer ruleset.
	if _, err := decodeDocument(strings.NewReader(`{"a":1} {"b":2}`)); err == nil {
		t.Fatal("two documents in one payload must not read as one")
	}
}
