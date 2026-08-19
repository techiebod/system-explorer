package main

import (
	"strings"
	"testing"
)

func row(t *testing.T, status, stats string) map[string]string {
	t.Helper()
	facts := daemonRow(reading{status: status, stats: stats})
	out := map[string]string{}
	for _, key := range facts.keys {
		out[key] = facts.tokens[key]
	}
	return out
}

// The whole record name, `total.` prefix included. A resolver with more than
// one thread reports every counter twice, and a parse keyed on the tail cannot
// tell the resolver's total from one thread's share of it — which is the class
// the unbound-second-thread mutation operator exists to expose, and this is the
// unit-level half of the same claim.
func TestTheTotalRecordIsReadAndTheThreadRecordIsNot(t *testing.T) {
	facts := row(t, "", strings.Join([]string{
		"thread0.num.queries=10",
		"thread1.num.queries=48",
		"total.num.queries=58",
	}, "\n"))
	if facts["NumQueries"] != "58" {
		t.Fatalf("NumQueries is the resolver's total, not a thread's share: %v", facts)
	}
}

// Typed equality is the whole point: `21` and `21.0` are different answers to a
// consumer in a typed language, so the reference's int-then-float order is the
// contract and not an implementation detail.
func TestANumbersTypeIsDecidedByTheDocumentAndNotByTheParser(t *testing.T) {
	facts := row(t, "", strings.Join([]string{
		"total.num.queries=21",
		"total.recursion.time.avg=0.120223",
		"total.requestlist.current.all=0",
	}, "\n"))
	if facts["NumQueries"] != "21" {
		t.Errorf("an integer record travels as an integer: %q", facts["NumQueries"])
	}
	if facts["RecursionTimeAvgSeconds"] != "0.120223" {
		t.Errorf("a decimal record travels with its own digits: %q", facts["RecursionTimeAvgSeconds"])
	}
	if facts["RequestListCurrent"] != "0" {
		t.Errorf("zero is a reading and travels as the integer it is: %q", facts["RequestListCurrent"])
	}
}

// A counter above 2^53 is a number a float64 cannot hold, and unbound's
// counters are unsigned 64-bit. The value is carried as its token precisely so
// a busy resolver's total does not come back rounded.
func TestALargeCounterKeepsEveryDigit(t *testing.T) {
	facts := row(t, "", "total.num.queries=18446744073709551615")
	if facts["NumQueries"] != "18446744073709551615" {
		t.Fatalf("a u64 counter lost digits on the way through: %q", facts["NumQueries"])
	}
}

func TestTheStatusDocumentYieldsTheVersionAndTheUptime(t *testing.T) {
	facts := row(t, healthyStatus, "")
	if facts["Version"] != `"1.24.2"` {
		t.Errorf("Version is the release string: %q", facts["Version"])
	}
	// "3648 seconds" — two tokens, and only the first is the number.
	if facts["Uptime"] != "3648" {
		t.Errorf("Uptime is the leading token of the uptime field: %q", facts["Uptime"])
	}
}

// Omission is a legitimate shape for any fact (rule 7), and it is the only
// lawful one here: a value the document does not carry, or carries in a form
// that is not a number, has no value channel to travel on — and a null names
// none of the three channels (DESIGN 19).
func TestARecordThatIsNotANumberIsNotAFact(t *testing.T) {
	cases := map[string]string{
		"an empty value":          "total.num.queries=",
		"a word":                  "total.num.queries=many",
		"a not-a-number average":  "total.recursion.time.avg=nan",
		"an infinity":             "total.recursion.time.avg=inf",
		"a record with no equals": "total.num.queries 21",
	}
	for label, line := range cases {
		facts := daemonRow(reading{stats: line})
		if facts.has("NumQueries") || facts.has("RecursionTimeAvgSeconds") {
			t.Errorf("%s produced a fact: %v", label, facts.tokens)
		}
		if strings.Contains(string(facts.encode()), "null") {
			t.Errorf("%s produced a null, which names no channel at all", label)
		}
	}
}

// The two shapes the status parse must refuse, both from the reference's own
// isdigit() test: an uptime that is not a whole number of seconds is not a
// reading this daemon takes, and publishing a rounded or truncated one would be
// inventing a figure.
func TestAnUptimeThatIsNotWholeSecondsIsNotAFact(t *testing.T) {
	for _, line := range []string{"uptime: -1 seconds", "uptime: 3648.5 seconds", "uptime: seconds"} {
		if facts := daemonRow(reading{status: line}); facts.has("Uptime") {
			t.Errorf("%q produced Uptime %q", line, facts.tokens["Uptime"])
		}
	}
}

// One resolver, two documents, one row — and the row survives a document that
// carried nothing this collection reads, because the reference publishes the
// object either way. A collector that dropped the row would retire the resolver
// on the strength of an unreadable counter block.
func TestOneRowIsPublishedEvenWhenADocumentSaysNothingReadable(t *testing.T) {
	facts := daemonRow(reading{status: healthyStatus, stats: "banana\n"})
	if !facts.has("Version") || facts.has("NumQueries") {
		t.Fatalf("the status half must still be published: %v", facts.tokens)
	}
	if got := string(facts.encode()); !strings.HasPrefix(got, `{"Version":`) {
		t.Fatalf("facts encode as an object in derivation order: %s", got)
	}
}
