package wire

// The closed list, asserted rather than described. §06 says the reverse
// channel carries three verbs "and nothing else ... a closed list, not a
// filter of known-bad verbs" — and the difference between those two
// shapes is exactly what these tests hold: a filter fails OPEN the day
// somebody adds a verb, an allow-list fails closed by construction.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func declared(names ...string) map[string]bool {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	return set
}

func refusal(t *testing.T, err error) *Refused {
	t.Helper()
	var refused *Refused
	if !errors.As(err, &refused) {
		t.Fatalf("expected a stated refusal, got %v", err)
	}
	return refused
}

func TestAnOffListVerbIsRefusedBeforeAnythingIsDialled(t *testing.T) {
	// The socket is deliberately a path that cannot exist: if the refusal
	// did not happen first, this would fail with a dial error instead,
	// which is how the test tells "refused" from "tried and failed".
	c := &Client{Socket: "/nonexistent/se-collect.sock"}
	err := (func() error {
		_, err := c.reverse(context.Background(), "collect", "pools", "tank",
			declared("pools"))
		return err
	})()
	if got := refusal(t, err); got.Reason != "unknown-verb" {
		t.Fatalf("%+v", got)
	}
}

func TestOnlyDeclaredCollectionsAreReachable(t *testing.T) {
	c := &Client{Socket: "/nonexistent/se-collect.sock"}
	_, err := c.Object(context.Background(), "secrets", "root", declared("pools"))
	if got := refusal(t, err); got.Reason != "undeclared-collection" {
		t.Fatalf("%+v", got)
	}
}

func TestNoDeclarationRefusesRatherThanWavingThrough(t *testing.T) {
	// An unchecked request is the filter-shaped failure the closed list
	// exists to avoid: it would admit any collection the moment the
	// caller had nothing to check against.
	c := &Client{Socket: "/nonexistent/se-collect.sock"}
	_, err := c.Evidence(context.Background(), "pools", "tank", nil)
	if got := refusal(t, err); got.Reason != "no-declaration" {
		t.Fatalf("%+v", got)
	}
}

func TestATokenCannotBecomeASecondRequest(t *testing.T) {
	c := &Client{Socket: "/nonexistent/se-collect.sock"}
	_, err := c.Object(context.Background(), "pools", "tank\ncollect pools:9",
		declared("pools"))
	if got := refusal(t, err); got.Reason != "malformed-token" {
		t.Fatalf("%+v", got)
	}
}

func TestTheNameTokenCarriesTheDeclaredWhitespaceEncoding(t *testing.T) {
	// §18: exactly two sequences travel, encoded percent-first so that
	// decoding space-first on arrival is unambiguous. NOT URL encoding —
	// a name legitimately carries slashes and colons, and a general
	// escape would mangle them into something no collector published.
	for _, testcase := range []struct{ name, want string }{
		{"inet filter", "inet%20filter"},
		{"100%", "100%25"},
		{"50% done", "50%25%20done"},
		{"dataset:tank/photos", "dataset:tank/photos"},
		{"tcp 0.0.0.0:22", "tcp%200.0.0.0:22"},
	} {
		if got := EncodeNameToken(testcase.name); got != testcase.want {
			t.Errorf("%q encoded to %q, want %q", testcase.name, got, testcase.want)
		}
	}
}

func TestEveryClosedListMemberIsReachableAndNothingElseIs(t *testing.T) {
	// The list is three, and it is the same three §06 names. A fourth
	// member arriving without a review is what this asserts against.
	if len(reverseVerbs) != 3 {
		t.Fatalf("the reverse channel carries three verbs, got %v", reverseVerbs)
	}
	for _, verb := range []string{VerbObject, VerbEvidence, VerbLookup} {
		if !reverseVerbs[verb] {
			t.Errorf("%s is one of the three", verb)
		}
	}
	for _, verb := range []string{"declare", "collect", "probe", "", "OBJECT"} {
		if reverseVerbs[verb] {
			t.Errorf("%q is not on the closed list", verb)
		}
	}
}

func TestARefusalNamesTheVerbAndTheReason(t *testing.T) {
	// A refusal a caller cannot record is one §06's "refused and
	// recorded" cannot be satisfied from.
	err := &Refused{"object", "undeclared-collection", "pools is not listed"}
	if !strings.Contains(err.Error(), "object") ||
		!strings.Contains(err.Error(), "undeclared-collection") {
		t.Fatalf("%q", err.Error())
	}
}
