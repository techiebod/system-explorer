package collate

import (
	"strings"
	"testing"
	"time"

	"github.com/techiebod/system-explorer/go/internal/store"
)

// The §15 promise check: every branch, and the two states that must
// never share a chip.

func fv(oldest *float64, boot *string, skew *int64) store.CollectionState {
	return store.CollectionState{Generation: 3, OldestAt: oldest,
		BootID: boot, TimensSkew: skew}
}

func TestThePromiseCheckTruthTable(t *testing.T) {
	boot := "boot-1"
	oldest := 10.0
	minute := time.Minute
	cases := []struct {
		name  string
		cs    store.CollectionState
		decl  time.Duration
		now   float64
		state string
	}{
		// age 20s against 60s declared: within 2x, current.
		{"fresh", fv(&oldest, &boot, nil), minute, 30.0, "current"},
		// age 121s: past 2x60s, overdue.
		{"overdue", fv(&oldest, &boot, nil), minute, 131.0, "overdue"},
		// exactly at the bound is NOT overdue — the bound is the grace.
		{"at-bound", fv(&oldest, &boot, nil), minute, 130.0, "current"},
		// no declared freshness: the promise cannot be checked.
		{"no-declaration", fv(&oldest, &boot, nil), 0, 131.0, "unverifiable"},
		// measured clock-domain skew: no age can be stated.
		{"skew", fv(&oldest, &boot, ptrI64(5)), minute, 131.0, "unverifiable"},
		// applied but no stamp.
		{"no-stamp", fv(nil, &boot, nil), minute, 131.0, "unverifiable"},
		// previous boot, uptime beyond the bound: uptime is an honest
		// LOWER bound on the age, no cross-domain subtraction.
		{"prev-boot-overdue", fv(&oldest, ptrS("other"), nil), minute, 131.0, "overdue"},
		// previous boot, young uptime: cannot say yet.
		{"prev-boot-young", fv(&oldest, ptrS("other"), nil), minute, 30.0, "unverifiable"},
		// impossible arithmetic on this boot.
		{"negative-age", fv(ptrF(500.0), &boot, nil), minute, 30.0, "unverifiable"},
	}
	for _, c := range cases {
		got := freshnessVerdict(c.cs, c.decl, c.now, "boot-1")
		if got.State != c.state {
			t.Errorf("%s: want %s, got %s (%s)", c.name, c.state, got.State, got.Detail)
		}
		if got.State != "current" && got.Detail == "" {
			t.Errorf("%s: a non-current verdict carries its reason", c.name)
		}
	}
}

func ptrI64(v int64) *int64   { return &v }
func ptrS(v string) *string   { return &v }
func ptrF(v float64) *float64 { return &v }

func TestAnOverdueCollectionNeverWearsTheCurrentChip(t *testing.T) {
	// The founding failure's fix, at the chip: a dead collector's
	// collections rendered `current` forever, because declared freshness
	// had exactly one consumer — the scheduler's sleep.
	boot := "boot-1"
	oldest := 10.0
	cs := store.CollectionState{Name: "units", Generation: 3,
		OldestAt: &oldest, BootID: &boot, ObjectCount: 4}
	verdict := freshnessVerdict(cs, time.Minute, 500.0, "boot-1")
	if verdict.State != "overdue" {
		t.Fatalf("setup: %+v", verdict)
	}
	out := freshnessChip(cs, verdict)
	if strings.Contains(out, ">current<") {
		t.Fatalf("overdue wore the current chip: %s", out)
	}
	if !strings.Contains(out, "overdue") {
		t.Fatalf("and must say overdue: %s", out)
	}
	// unverifiable is its OWN state: "cannot check the promise" and
	// "promise kept" must never share a chip.
	unv := freshnessChip(cs, FreshnessVerdict{"unverifiable", "no stamp"})
	if strings.Contains(unv, ">current<") || strings.Contains(unv, "warn") {
		t.Fatalf("unverifiable is neither current nor a failure: %s", unv)
	}
}
