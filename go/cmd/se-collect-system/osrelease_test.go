package main

import "testing"

// The parser is held to os-release(5) itself — quoting, escapes, comments —
// because "parse per its spec" is the pin: this file is the native
// structured format, and a scrape that only handled the shapes its author
// had met would be the subset guard wearing a parser's clothes.
func TestParseOsReleasePerItsSpec(t *testing.T) {
	raw := []byte(`# a comment line
NAME="Debian GNU/Linux"
ID=debian
VERSION_ID="12"

PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
SINGLE='single quoted value'
ESCAPED="a \"quoted\" word and a \\ backslash"
UNQUOTED=plain-token
  INDENTED="leading whitespace is tolerated"
NOT_A_LINE
=nokey
`)
	doc := parseOsRelease(raw)
	want := map[string]string{
		"NAME":        "Debian GNU/Linux",
		"ID":          "debian",
		"VERSION_ID":  "12",
		"PRETTY_NAME": "Debian GNU/Linux 12 (bookworm)",
		"SINGLE":      "single quoted value",
		"ESCAPED":     `a "quoted" word and a \ backslash`,
		"UNQUOTED":    "plain-token",
		"INDENTED":    "leading whitespace is tolerated",
	}
	for key, value := range want {
		if doc[key] != value {
			t.Errorf("%s: got %q, want %q", key, doc[key], value)
		}
	}
	if _, ok := doc["NOT_A_LINE"]; ok {
		t.Error("a line with no '=' is not an assignment and must be skipped")
	}
	if len(doc) != len(want) {
		t.Errorf("parsed %d keys, want %d: %v", len(doc), len(want), doc)
	}
}

func TestUnquoteLeavesUnpairedQuotesAlone(t *testing.T) {
	// A value that merely starts with a quote is not a quoted value; the
	// spec's quoting is matched pairs, and inventing a pair would alter
	// evidence this collector promises to carry verbatim.
	for input, want := range map[string]string{
		`"unterminated`: `"unterminated`,
		`'unterminated`: `'unterminated`,
		`"`:             `"`,
		`""`:            ``,
		`"trailing\`:    `"trailing\`, // no closing quote: literal
		// The closing quote is itself escaped, so the shell would call
		// this unterminated; leniently the escape's backslash survives as
		// the literal it introduced nothing for.
		`"lone escape\"`: `lone escape\`,
	} {
		if got := unquote(input); got != want {
			t.Errorf("unquote(%q) = %q, want %q", input, got, want)
		}
	}
}
