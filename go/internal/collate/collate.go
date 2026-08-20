// Package collate is the collator core's driving logic: one acquisition
// is declare → issue generations → collect → validate → apply → ack,
// with the crash boundaries of harness/crash/boundaries.json marked at
// exactly the points the protocol says state must be all-or-nothing.
package collate

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/techiebod/system-explorer/go/internal/store"
	"github.com/techiebod/system-explorer/go/internal/wire"
)

// AcquireOnce runs one full acquisition against one collector socket and
// applies whatever the batch authority admits. The error return is for
// the caller's log line; every effect on state — including refusals —
// has already been recorded in the store, because a failure the loop
// forgot would be the product's founding failure re-imported.
func AcquireOnce(ctx context.Context, st *store.Store, client *wire.Client) error {
	declBytes, err := client.Declare(ctx)
	if err != nil {
		recordFailure(st, "", "declare-failed", err)
		return fmt.Errorf("declare: %w", err)
	}
	declHash := wire.DeclarationHash(declBytes)
	decl, _, err := wire.ParseDeclaration(declBytes)
	if err != nil {
		recordFailure(st, "", "declaration-unparseable", err)
		return fmt.Errorf("declaration: %w", err)
	}

	names := make([]string, 0, len(decl.Collections))
	for _, c := range decl.Collections {
		names = append(names, c.Name)
	}
	sort.Strings(names)

	// The generation is issued and durable BEFORE the request goes out:
	// a crash from here on can only ever waste a number, never reuse one.
	issued, err := st.IssueGenerations(names, declHash)
	if err != nil {
		return fmt.Errorf("issue generations: %w", err)
	}

	batch, err := client.Collect(ctx, issued)
	if err != nil {
		// A structural violation rejects the whole batch with a recorded
		// reason — an invalid stream applies NOTHING (DESIGN §18/19).
		if v, ok := err.(*wire.Violation); ok {
			recordFailure(st, "", v.Reason, fmt.Errorf("%s", v.Detail))
		} else {
			recordFailure(st, "", "collect-failed", err)
		}
		return fmt.Errorf("collect: %w", err)
	}

	// begin.declaration commits to the exact bytes declare emits. On a
	// mismatch the contract's remedy is a refetch, not a second spawn on
	// every collect (DESIGN §19): the collector may have been upgraded
	// between our declare and our collect. Refetch once; a batch whose
	// hash still matches nothing we can fetch is held un-applied.
	if batch.Begin.Declaration != declHash {
		fresh, err := client.Declare(ctx)
		if err != nil || batch.Begin.Declaration != wire.DeclarationHash(fresh) {
			recordFailure(st, "", "declaration-unknown",
				fmt.Errorf("begin declares %s, which matches no fetched declaration", batch.Begin.Declaration))
			return fmt.Errorf("declaration hash %s is unknown", batch.Begin.Declaration)
		}
	}

	// harness/crash/boundaries.json post-commit-pre-apply — "on restart
	// the collection is at its previous generation; the batch is re-run".
	// The stream is fully read and structurally valid; nothing durable
	// has happened yet, so dying here loses only work, never state.
	store.Crashpoint("post-commit-pre-apply")

	// Retry idempotency by id: the one safe retry is same-bytes-same-id
	// (DESIGN §19), so the ack table stores what was acknowledged — the
	// echoed generations and the content hash — and judges this arrival
	// against it. A true retry is a silent no-op; the same id carrying
	// anything else is a recorded protocol error, because an ack check
	// that answered only "seen" silently discarded every fresh batch
	// from a collector minting stable ids. The generation rules govern
	// everything this table does not.
	switch outcome, err := st.JudgeAcked(batch.Begin.Batch, batch.Begin.Generations, batch.ContentHash); {
	case err != nil:
		return err
	case outcome == store.AckRetry:
		return nil
	case outcome == store.AckReused:
		// Recorded by the authority; nothing applies.
		return fmt.Errorf("batch %s: batch-id-reused", batch.Begin.Batch)
	}

	scope := store.HostNative
	if batch.Begin.Instance != nil {
		scope = *batch.Begin.Instance
	}

	// The declaration is what makes relation targets resolvable at all: a
	// target's KIND names the prefix a collection declared, so the collator
	// walks the producer's own declaration rather than guessing that
	// "block-device" probably means a collection called "block-devices"
	// (law 3 — minted from names a collector published, never correlated).
	prefixes := map[string]string{}
	types := map[string]map[string]store.RelationType{}
	for _, c := range decl.Collections {
		prefixes[c.Name] = c.Prefix
		table := map[string]store.RelationType{}
		for _, r := range c.Relations {
			table[r.Type] = store.RelationType{
				Discriminator:     r.Discriminator,
				InverseObservable: r.InverseObservable,
				ConfirmedBy:       r.ConfirmedBy,
			}
		}
		types[c.Name] = table
	}
	byKind, err := store.PrefixIndex(prefixes)
	if err != nil {
		recordFailure(st, "", "ambiguous-prefix", err)
		return err
	}

	// Acceptance item 7's second half, checked here because this is the tier
	// that holds both the declaration and the stream. A value under a name
	// the collector never declared has no sentence, no kind and no
	// temperament anywhere in the estate, so nothing downstream could tell a
	// consumer what it means — and it would nonetheless be joined, keyed and
	// answered with. The whole batch is refused rather than the fact dropped:
	// a stream this wrong is authoritative for nothing, and silently
	// discarding part of a reading is how a collection comes to be believed
	// while being incomplete.
	//
	// The same reasoning the relation-type check already states one tier
	// down: the contract check owns this at the collector, but the authority
	// must not depend on its caller's diligence.
	if err := checkDeclaredFacts(decl, batch); err != nil {
		if v, ok := err.(*wire.Violation); ok {
			recordFailure(st, "", v.Reason, fmt.Errorf("%s", v.Detail))
		}
		return err
	}

	var firstErr error
	for _, name := range names {
		if err := applyCollection(st, name, scope, batch); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return firstErr
	}

	// Relations are assembled AFTER every collection's objects have landed,
	// and that ordering is the whole of collator-side resolution. The test
	// is "does anything on this host claim the name" — so a rule asserting
	// membership of a chain resolves only once the chains collection of the
	// same batch has been applied. Resolving as each collection landed would
	// make the answer depend on the order the collector happened to emit
	// them, which is a reading of the stream rather than of the host.
	for _, name := range names {
		if err := applyRelations(st, name, scope, batch, byKind, types[name]); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return firstErr
	}

	// harness/crash/boundaries.json post-apply-pre-ack — "applied and
	// durable; a re-sent identical batch at the same generation is a
	// no-op". The apply transactions are committed; only the ack is
	// missing, and the equal-generation content-hash no-op is precisely
	// the recovery for that window.
	store.Crashpoint("post-apply-pre-ack")

	return st.RecordAck(batch.Begin.Batch, batch.Begin.Generations, batch.ContentHash)
}

// applyCollection lands one collection's share of a validated batch.
// The per-reason authority effects are acceptance item 2; the generation
// rules inside ApplyCommit are item 4.
func applyCollection(st *store.Store, name, scope string, batch *wire.Batch) error {
	cs := batch.Collections[name]
	gen := batch.Begin.Generations[name]

	// Issued, and then neither committed nor declined: a partial read.
	// Held and never applied — but recorded, because a collection that
	// silently never answers is absence wearing health's clothes. The
	// detail names this side's blast radius (DESIGN §19): the live
	// collator holds only the offending collection, where replay refuses
	// the whole stream, because one bad collection must not cost the
	// host its other facts.
	if cs == nil || (cs.Commit == nil && cs.Decline == nil) {
		return st.RecordRejection(name, batch.Begin.Batch, "uncommitted-collection",
			fmt.Sprintf("issued generation %d, stream carried no commit and no decline — "+
				"only this collection is held; the rest of the batch applies, "+
				"because one bad collection must not cost the host its other facts", gen))
	}

	// unauthorised/unavailable/unsupported established nothing: prior
	// objects stand and are served marked stale with the reason. The
	// wire has already proven such a collection carries no commit.
	if cs.Decline != nil && cs.Decline.Reason != "absent" {
		return st.MarkStale(name, cs.Decline.Reason)
	}

	// Committed — including absent's zero-object commit, which applies
	// EMPTY: prior objects retired, collection not stale, because "there
	// are none" is a successful reading of the interface.
	objects := make([]store.Object, 0, len(cs.Objects))
	for _, o := range cs.Objects {
		objects = append(objects, store.Object{
			ID:     store.MintID(name, o.Name),
			Name:   o.Name,
			Facts:  o.Facts,
			Names:  o.Names,
			Absent: o.Absent,
			At:     o.At,
		})
	}
	_, err := st.ApplyCommit(name, scope, gen, batch.Begin.Batch, batch.Begin.BootID, objects)
	return err
}

// applyRelations mints one collection's assertions into relations (DESIGN
// §13, acceptance item 6). A collection that did not commit asserts nothing,
// for the same reason it publishes no objects: an uncommitted collection is
// authoritative for nothing, and minting its edges would let a partial read
// retire the relations a complete one established.
func applyRelations(st *store.Store, name, scope string, batch *wire.Batch,
	byKind map[string]string, types map[string]store.RelationType) error {
	cs := batch.Collections[name]
	if cs == nil || cs.Commit == nil {
		return nil
	}

	assertions := make([]store.Assertion, 0, len(cs.Assertions))
	for _, a := range cs.Assertions {
		assertions = append(assertions, store.Assertion{
			Collection: a.Collection,
			SourceName: a.Name,
			Type:       a.Type,
			Vantage:    a.Vantage,
			TargetKind: a.TargetKind,
			TargetName: a.TargetName,
			Facts:      a.Facts,
		})
	}

	relations, err := st.ApplyAssertions(name, scope, assertions, types,
		st.ResolverFor(byKind, scope), inverseIn(batch))
	if err != nil {
		// A collision or an undeclared type is a statement about the
		// collector, recorded rather than swallowed: an edge that silently
		// replaced another is the failure the discriminator exists to stop,
		// and a loop that forgot it would be the founding failure again.
		return st.RecordRejection(name, batch.Begin.Batch, "relation-assembly", err.Error())
	}
	_ = relations
	return nil
}

// inverseIn answers "did some vantage in this batch assert the confirming
// type back the other way?" — which is how an edge observed at BOTH ends
// becomes `confirmed` rather than two independent `asserted` halves.
//
// Batch-scoped on purpose. Two assertions farther apart in time than the
// tighter collection's declared freshness neither confirm nor contradict,
// because they are two ages of the world (DESIGN §19); everything inside one
// batch shares one acquisition, which is the only window this tier can prove
// anything about. Cross-batch confirmation belongs to the hub, with the age
// spread it can measure and this cannot.
func inverseIn(batch *wire.Batch) func(relType, from, to string) (json.RawMessage, bool) {
	index := map[[3]string]json.RawMessage{}
	for _, cs := range batch.Collections {
		if cs == nil || cs.Commit == nil {
			continue
		}
		for _, a := range cs.Assertions {
			index[[3]string{a.Type, a.Name, a.TargetName}] = a.Facts
		}
	}
	return func(relType, from, to string) (json.RawMessage, bool) {
		facts, ok := index[[3]string{relType, from, to}]
		return facts, ok
	}
}

func recordFailure(st *store.Store, collection, reason string, err error) {
	// Recording is best-effort by design: the loop must never die because
	// its own bookkeeping write lost a race with a reader.
	_ = st.RecordRejection(collection, "", reason, err.Error())
}

// checkDeclaredFacts refuses a batch that names a fact its declaration does
// not, across ALL THREE of DESIGN 19's channels — the measured value, the
// absent list, and the unobservable record. Covering only the first would
// leave two ways to smuggle an undeclared name past a check that reported
// success, and the absent list is the easier of the two: a collector cannot
// state "this object has no such property" about a property the estate has
// never heard of.
//
// A collection whose declaration carries no fact table is not checked. That
// is the seam this file does not close alone: se.declaration/1 requires
// `facts` with at least one entry, the contract suite refuses a declaration
// without it, and the fixture loader refuses a fixture that writes one. The
// exception is a hand-written stub in an in-process Go test, which judges a
// different tier and is not a route a collector can take.
func checkDeclaredFacts(decl *wire.Declaration, batch *wire.Batch) error {
	for _, c := range decl.Collections {
		if len(c.Facts) == 0 {
			continue
		}
		stream := batch.Collections[c.Name]
		if stream == nil {
			continue
		}
		for _, o := range stream.Objects {
			var facts map[string]json.RawMessage
			if len(o.Facts) > 0 {
				if err := json.Unmarshal(o.Facts, &facts); err != nil {
					return violation("undeclared-fact",
						"%s/%s: facts do not parse: %v", c.Name, o.Name, err)
				}
			}
			for name := range facts {
				if _, declared := c.Facts[name]; !declared {
					return violation("undeclared-fact",
						"%s/%s: fact %q was never declared", c.Name, o.Name, name)
				}
			}
			for _, name := range o.Absent {
				if _, declared := c.Facts[name]; !declared {
					return violation("undeclared-fact",
						"%s/%s: absent names %q, which was never declared",
						c.Name, o.Name, name)
				}
			}
		}
		for _, u := range stream.Unobservables {
			if _, declared := c.Facts[u.Fact]; !declared {
				return violation("undeclared-fact",
					"%s/%s: unobservable names %q, which was never declared",
					c.Name, u.Name, u.Fact)
			}
		}
	}
	return nil
}

// violation mirrors wire's own constructor. The reason is recorded verbatim
// in the store, so it is spelled once and never formatted into.
func violation(reason, format string, args ...any) *wire.Violation {
	return &wire.Violation{Reason: reason, Detail: fmt.Sprintf(format, args...)}
}
