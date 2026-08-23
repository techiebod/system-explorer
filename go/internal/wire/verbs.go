package wire

// The reverse channel: the three verbs a request travels DOWN to a
// collector for (DESIGN §06, §18).
//
// **This existed at the leaf and nowhere else until 2026-08-23.** All
// twenty collectors answered `object`, `evidence` and `lookup`, and
// nothing in the shipping product could ask: the client offered `Declare`
// and `Collect` and no third method, so the verbs were reachable only by
// a person piping a request into a collector binary by hand. Register
// rows 1–3 read "built" over that for the whole of R3c and R3d, because
// their probe greps `go/cmd/se-collect-*/main.go` — the leaf — for a
// responsibility §06 places at the collator. It is register row 17's
// defect, found in three more rows by an audit of R3's own landings.
//
// **The verb list is CLOSED, and that is the security property.** §06:
// "That reverse channel carries `evidence`, `object` and `lookup` and
// nothing else, only for collections this collator's own declaration
// lists, and anything else is refused and recorded — a closed list, not a
// filter of known-bad verbs." A filter of known-bad verbs is the shape
// that fails open the day somebody adds a verb; an allow-list of three
// fails closed by construction.
//
// **Evidence stays captured-fresh and stored nowhere.** Only the
// direction of the request changes: the collator invokes the collector
// and streams the answer up. Nothing here writes to the store, and there
// is deliberately no cache — a remembered evidence document is a claim
// about a system as it was, served as though it were now.

import (
	"context"
	"fmt"
	"strings"
)

// The closed list. A verb absent from it is refused before a socket is
// dialled, so an unknown verb never reaches a collector at all.
const (
	VerbObject   = "object"
	VerbEvidence = "evidence"
	VerbLookup   = "lookup"
)

var reverseVerbs = map[string]bool{
	VerbObject:   true,
	VerbEvidence: true,
	VerbLookup:   true,
}

// Refused is a request this collator would not send, with the reason
// named. Returned rather than logged: §06 says an off-list request is
// "refused and recorded", and a caller that cannot see the refusal cannot
// record it.
type Refused struct {
	Verb   string
	Reason string
	Detail string
}

func (r *Refused) Error() string {
	return fmt.Sprintf("%s refused (%s): %s", r.Verb, r.Reason, r.Detail)
}

// EncodeNameToken applies §18's whitespace encoding to the name token:
// each space becomes %20 and each literal percent becomes %25, encoded in
// that order so decoding in the reverse order is unambiguous.
//
// **Not URL encoding**, and the difference is the whole point: names in
// this product legitimately contain slashes, colons and plus signs
// (`dataset:tank/photos`), and a general escape would mangle them into
// something no collector published. Exactly two sequences travel.
func EncodeNameToken(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "%", "%25"), " ", "%20")
}

// requestable refuses everything the closed list does not admit, before
// anything is dialled.
func requestable(verb, collection, token string, declared map[string]bool) error {
	if !reverseVerbs[verb] {
		return &Refused{verb, "unknown-verb",
			"the reverse channel carries object, evidence and lookup and " +
				"nothing else; this is a closed list rather than a filter of " +
				"known-bad verbs, so an unrecognised verb is refused rather " +
				"than forwarded"}
	}
	if collection == "" || token == "" {
		return &Refused{verb, "incomplete-request",
			"a reverse request is three tokens: the verb, the collection and " +
				"the name"}
	}
	// §06: "only for collections this collator's own declaration lists".
	// A nil map means the caller has no declaration to check against,
	// which is refused rather than waved through — an unchecked request
	// is the filter-shaped failure this list exists to avoid.
	if declared == nil {
		return &Refused{verb, "no-declaration",
			"this collator holds no declaration for the collector it would " +
				"ask, so it cannot establish that the collection is one the " +
				"collector serves"}
	}
	if !declared[collection] {
		return &Refused{verb, "undeclared-collection",
			fmt.Sprintf("%q is not a collection this collector's declaration "+
				"lists; the reverse channel reaches declared collections only",
				collection)}
	}
	// A newline in either token would make one request into two, which is
	// the one way a data token could become a second instruction.
	if strings.ContainsAny(collection, "\n\r ") || strings.ContainsAny(token, "\n\r") {
		return &Refused{verb, "malformed-token",
			"a request line is one line and its tokens are data; a token " +
				"carrying a line break would make one request into two"}
	}
	return nil
}

// Object asks for one object in full — the object density of §27.
//
// `declared` is the set of collections the collator holds a declaration
// for, and it is required: §06 admits the reverse channel only for
// collections the declaration lists.
func (c *Client) Object(ctx context.Context, collection, name string,
	declared map[string]bool) ([]byte, error) {
	return c.reverse(ctx, VerbObject, collection, name, declared)
}

// Evidence asks for the raw native payload behind an object, captured
// fresh and stored nowhere.
func (c *Client) Evidence(ctx context.Context, collection, name string,
	declared map[string]bool) ([]byte, error) {
	return c.reverse(ctx, VerbEvidence, collection, name, declared)
}

// Lookup asks a parameterised read-only question. The first token is the
// lookup's declared name rather than a collection, so the declared set a
// caller passes is the lookup palette, not the collection list.
func (c *Client) Lookup(ctx context.Context, lookup, input string,
	declared map[string]bool) ([]byte, error) {
	return c.reverse(ctx, VerbLookup, lookup, input, declared)
}

func (c *Client) reverse(ctx context.Context, verb, collection, token string,
	declared map[string]bool) ([]byte, error) {
	if err := requestable(verb, collection, token, declared); err != nil {
		return nil, err
	}
	raw, err := c.exchange(ctx,
		verb+" "+collection+" "+EncodeNameToken(token))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		// A verb response always ends with its terminator, so nothing at
		// all is a collector that died rather than one that declined —
		// and a decline is data under every verb (§18).
		return nil, fmt.Errorf("%s %s: the collector answered nothing, and a "+
			"verb response always carries its terminator", verb, collection)
	}
	return raw, nil
}
