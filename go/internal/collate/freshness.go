// The freshness verdict: is a collection's newest applied state within
// the promise its producer declared? (DESIGN §15.)
//
// **This did not exist, and its absence was the founding failure live in
// production.** Declared freshness had exactly one consumer in the whole
// product — the scheduler's sleep — so a hung, crashed or unplugged
// collector left every one of its collections rendering `current`
// forever, on the host chip, /v1/collections, /v1/status and everything
// the hub serves from them. §15: "a product that then serves those
// readings without comment has reintroduced its own founding failure
// through the door marked performance." Found by the 2026-08-24 design
// conformance audit (register row 45), which also found the chip's own
// comment stating the definition this file now computes.
//
// **The bound is 2× the declared freshness, and the reasoning is owed to
// the reader.** The scheduler paces a collector at the MINIMUM freshness
// across its collections, so a healthy tightest collection routinely
// ages to its full promise plus acquisition time — a strict `age >
// declared` flags a healthy loop at every cycle. One whole extra
// promise-window is the smallest grace that cannot do that, and it is
// derived from the declaration rather than being an invented constant:
// overdue means a full second window passed with no new reading. If the
// owner prefers the strict reading of "past its declared freshness",
// this is one line.
//
// **Age never crosses a clock domain (§09).** Freshness derives from the
// OLDEST contributing read (acceptance item 5), in the boot-time domain:
//   - same boot, no skew: age = now − OldestAt, exactly as the page
//     already states it;
//   - a reading from a PREVIOUS boot is at least as old as this boot,
//     and now() is CLOCK_BOOTTIME seconds since boot — so uptime itself
//     is an honest lower bound on the age, with no cross-domain
//     subtraction;
//   - a measured time-namespace skew, a missing stamp, or impossible
//     arithmetic make the age UNKNOWABLE, and unknowable must render as
//     neither current nor overdue — unverifiable is its own state,
//     because "cannot check the promise" and "promise kept" must never
//     share a chip.
//
// **What this file cannot say: WHY.** §15 wants the reason named —
// budget exhausted, collector timed out, host under pressure — and that
// needs the scheduler to record per-attempt outcomes, which it does not
// yet (row 45). The detail therefore states what was measured and
// claims nothing about cause.
//
// **The checkpoint cannot carry this verdict.** Its `freshness` member
// is a closed current|stale enum and `stale_reason` is the closed
// decline vocabulary, so `overdue` is unrepresentable on the estate wire
// until row 41's contract batch — sending `stale` with a decline reason
// that never happened would trade one lie for another. Until then the
// collator's own surfaces are the honest source, and the hub's copy is
// KNOWN to be blind to overdue: stated here, in row 41, and in
// checkpoint.go.
package collate

import (
	"fmt"
	"strings"
	"time"

	"github.com/techiebod/system-explorer/go/internal/store"
	"github.com/techiebod/system-explorer/go/internal/wire"
)

// FreshnessVerdict is the answer for one collection that HAS applied
// state and is not declined — callers handle never-read and declines
// first, because those dominate (freshnessChip's switch).
type FreshnessVerdict struct {
	// State is one of "current", "overdue", "unverifiable".
	State string
	// Detail carries the measured facts for overdue, and the reason the
	// promise cannot be checked for unverifiable. Empty for current.
	Detail string
}

// freshnessVerdict computes the promise check for one collection.
// declared <= 0 means the declaration could not supply a freshness.
func freshnessVerdict(cs store.CollectionState, declared time.Duration,
	now float64, bootID string) FreshnessVerdict {
	if declared <= 0 {
		return FreshnessVerdict{"unverifiable",
			"no declared freshness could be read, so the promise cannot be checked"}
	}
	if cs.TimensSkew != nil && *cs.TimensSkew != 0 {
		return FreshnessVerdict{"unverifiable",
			"the collector's clock domain differs from this collator's, so no age can be stated"}
	}
	if cs.OldestAt == nil {
		return FreshnessVerdict{"unverifiable",
			"the applied reading carries no stamp, so no age can be stated"}
	}
	bound := 2 * declared.Seconds()
	if cs.BootID == nil || !equalFoldPtr(cs.BootID, bootID) {
		// The reading predates this boot, so uptime is an honest lower
		// bound on its age — no cross-domain subtraction.
		if now > bound {
			return FreshnessVerdict{"overdue", fmt.Sprintf(
				"the newest reading is from a previous boot, at least %.0fs ago, "+
					"against a declared promise of %s", now, declared)}
		}
		return FreshnessVerdict{"unverifiable",
			"the newest reading is from a previous boot; its age cannot be stated yet"}
	}
	age := now - *cs.OldestAt
	if age < 0 {
		return FreshnessVerdict{"unverifiable",
			"the arithmetic on this boot's stamps is impossible, so no age is stated"}
	}
	if age > bound {
		return FreshnessVerdict{"overdue", fmt.Sprintf(
			"no reading for %.0fs against a declared promise of %s — the "+
				"values shown are the last known, not the current state", age, declared)}
	}
	return FreshnessVerdict{"current", ""}
}

func equalFoldPtr(a *string, b string) bool {
	// EqualFold: "UUID-shaped" is the ruling, not any one platform's case
	// (linux lowercases the boot id, darwin does not) — the same rule the
	// page's age column already applies.
	return a != nil && strings.EqualFold(*a, b)
}

// declaredFreshnessOf reads each collection's declared promise from the
// documents the store already holds. A collection whose document cannot
// be read maps to 0, which the verdict states as unverifiable rather
// than defaulting to any promise.
func declaredFreshnessOf(st *store.Store) map[string]time.Duration {
	out := map[string]time.Duration{}
	documents, err := st.DeclarationDocuments()
	if err != nil {
		return out
	}
	for _, document := range documents {
		decl, _, err := wire.ParseDeclaration([]byte(document))
		if err != nil {
			continue
		}
		for _, c := range decl.Collections {
			if d, err := wire.ParseFreshness(c.Freshness); err == nil {
				out[c.Name] = d
			}
		}
	}
	return out
}

// freshnessMap is one verdict per collection, computed once per request
// and shared by every surface on the page — the chip, the rail, the
// REST row and the status roll-up must never disagree about whether a
// promise is kept.
func freshnessMap(st *store.Store, states []store.CollectionState,
	now float64, bootID string) map[string]FreshnessVerdict {
	declared := declaredFreshnessOf(st)
	out := map[string]FreshnessVerdict{}
	for _, cs := range states {
		if cs.Generation == 0 || cs.Stale {
			// Never-read and declined-stale dominate; the promise check
			// is about applied state believed current.
			continue
		}
		out[cs.Name] = freshnessVerdict(cs, declared[cs.Name], now, bootID)
	}
	return out
}
