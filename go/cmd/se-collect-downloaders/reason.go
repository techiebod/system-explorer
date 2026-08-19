package main

import (
	"regexp"
	"strings"
)

// env.reason(), which is system_explorer.text.scrub(one_line(value)).
//
// It is here because ONE fact goes through it: ErrorString, the client's own
// account of why a transfer is failing. That text arrives from a download
// client, which means it arrives from outside the estate, and it is the one
// value in this collector that nobody wrote a schema for.
//
// The environment-substitution arm of the shipping scrubber is deliberately NOT
// reproduced. It reads os.environ at call time and replaces the values of
// *_API_KEY, *_TOKEN, *_SECRET and *_PASSWORD variables, so two machines
// replaying one payload emit different bytes — and a replayed collector's
// output must be a function of its payload alone. That divergence is the
// standing ruling in DESIGN's adjudication queue ("The residue scrubber may not
// read ambient environment"), and this port takes the payload-driven half.

// maxReasonLength is text.MAX_LENGTH: sized for real native failure text (the
// longest measured on a live estate was 234 characters) rather than for a
// terminal, so a bound is a bound and not a clip.
const maxReasonLength = 400

// danglingRunes is text._DANGLING: punctuation left hanging by a word-boundary
// cut reads as damage rather than as a deliberate bound.
const danglingRunes = " ,;:.([{-"

// The two places a URL carries a credential. sabnzbd takes its API key ONLY as
// a query parameter, so a single failing request would otherwise publish the
// key into a fact — which is exactly why the query string goes wholesale and
// the path stays: the path identifies the endpoint and no diagnosis has ever
// needed the query back.
var (
	queryString = regexp.MustCompile(`\?[^\s"'<>]+`)
	urlUserinfo = regexp.MustCompile(`://[^/\s"'<>@]+@`)
)

// oneLine collapses whitespace and bounds on a WORD boundary, marking the cut.
// Idempotent, so text that has already been through it passes unchanged.
//
// Bounded in RUNES and not in bytes, because Python's slice counts characters:
// a client error line carrying a non-ASCII filename would otherwise be cut
// four hundred bytes in, at a different word from the reference's — and
// possibly mid-codepoint.
func oneLine(value string) string {
	flat := []rune(strings.Join(strings.Fields(value), " "))
	if len(flat) <= maxReasonLength {
		return string(flat)
	}
	head := string(flat[:maxReasonLength])
	if cut := strings.LastIndexByte(head, ' '); cut > 0 {
		head = head[:cut]
	}
	return strings.TrimRight(head, danglingRunes) + " … (truncated)"
}

// scrubReason is the pair of URL redactions, applied in the reference's order.
func scrubReason(text string) string {
	out := queryString.ReplaceAllString(text, "?[query-stripped]")
	// Go's RE2 has no lookbehind, so the "://" is matched and written back
	// rather than asserted — the substitution is the same and so is the anchor.
	out = urlUserinfo.ReplaceAllString(out, "://[userinfo-stripped]@")
	return out
}

func reason(value string) string { return scrubReason(oneLine(value)) }
