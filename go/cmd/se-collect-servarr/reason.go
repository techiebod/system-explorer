package main

import "strings"

// The envelope's bounding and scrubbing, for the three facts that carry text
// the app wrote: a health item's Message, and a queue record's ErrorMessage and
// StatusMessages. Ported from go/cmd/se-collect-network/python.go, which
// carries the same rule for nftables rule residue — one reference behaviour,
// two collectors, no shared package because these binaries are separate main
// packages by construction.

// maxReasonLength is system_explorer.text.MAX_LENGTH, spelled at the call site
// in the reference as the literal 400. It is a bound for real native failure
// text — the longest measured on a live estate was 234 characters — and not a
// terminal width.
const maxReasonLength = 400

// oneLine collapses whitespace and bounds on a word boundary. Bounded, not
// clipped: a health message cut mid-word throws away the part that names the
// cause, which is what the bound exists to keep.
func oneLine(value string, limit int) string {
	flat := strings.Join(strings.Fields(value), " ")
	runes := []rune(flat)
	if len(runes) <= limit {
		return flat
	}
	window := string(runes[:limit])
	head := window
	if cut := strings.LastIndexByte(window, ' '); cut >= 0 {
		head = window[:cut]
	}
	if head == "" {
		// No space in the window at all: the reference keeps it whole rather
		// than emitting a marker with nothing in front of it.
		head = window
	}
	return strings.TrimRight(head, " ,;:.([{-") + " … (truncated)"
}

// scrub removes the two credential shapes a URL carries. It is deliberately
// NOT the whole of the reference's scrub: that also substitutes the values of
// the ambient *_TOKEN / *_API_KEY / *_SECRET / *_PASSWORD environment
// variables, read at call time — so two machines replaying one payload would
// emit different bytes, and a replayed collector's output must be a function of
// its payload alone (the adjudication queue's ruling, still provisional).
//
// The omission is smaller than it looks and the reason matters HERE more than
// anywhere: this collector is configured with SE_<NAME>_API_KEY, so the
// environment rule would fire on exactly this process. What replaces it is
// upstream — the key rides a header and never a URL, so it appears in no
// document, in no error this side builds, and in nothing that reaches a fact.
// The two rules kept are functions of the payload alone, and they are the ones
// that matter for a servarr message: an app that reports a failing indexer
// quotes the indexer's URL, and a newznab URL carries its api key in the query.
func scrub(value string) string {
	return stripUserinfo(stripQueryStrings(value))
}

// A '?' anywhere in the text takes everything after it up to the next
// whitespace or quote — the reference's rule is a bare regex over failure text,
// not a URL parse, so it fires on any question mark the message happens to
// hold.
func stripQueryStrings(value string) string {
	var out strings.Builder
	for i := 0; i < len(value); {
		if value[i] != '?' {
			out.WriteByte(value[i])
			i++
			continue
		}
		end := i + 1
		for end < len(value) && !isQueryTerminator(value[end]) {
			end++
		}
		if end == i+1 {
			out.WriteByte('?')
			i++
			continue
		}
		out.WriteString("?[query-stripped]")
		i = end
	}
	return out.String()
}

func isQueryTerminator(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r', '"', '\'', '<', '>':
		return true
	}
	return false
}

// The other half of a URL that carries a credential: user:pass@host. Matched
// only where "://" precedes it, which is the reference's lookbehind.
func stripUserinfo(value string) string {
	var out strings.Builder
	i := 0
	for {
		at := strings.Index(value[i:], "://")
		if at < 0 {
			out.WriteString(value[i:])
			return out.String()
		}
		start := i + at + 3
		out.WriteString(value[i:start])
		end := start
		for end < len(value) && !isUserinfoTerminator(value[end]) {
			end++
		}
		if end > start && end < len(value) && value[end] == '@' {
			out.WriteString("[userinfo-stripped]@")
			i = end + 1
			continue
		}
		i = start
	}
}

func isUserinfoTerminator(c byte) bool {
	switch c {
	case '/', ' ', '\t', '\n', '\v', '\f', '\r', '"', '\'', '<', '>', '@':
		return true
	}
	return false
}

// reasonText is envelope.reason(text, 400) — bound first, scrub second, in that
// order, because bounding a scrubbed string and scrubbing a bounded one cut in
// different places.
func reasonText(value string) string {
	return scrub(oneLine(value, maxReasonLength))
}
