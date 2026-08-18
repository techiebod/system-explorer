// Package collate is the collator core's driving logic: one acquisition
// is declare → issue generations → collect → validate → apply → ack,
// with the crash boundaries of harness/crash/boundaries.json marked at
// exactly the points the protocol says state must be all-or-nothing.
package collate

import (
	"context"
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
	issued, err := st.IssueGenerations(names)
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

	var firstErr error
	for _, name := range names {
		if err := applyCollection(st, name, scope, batch); err != nil && firstErr == nil {
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

func recordFailure(st *store.Store, collection, reason string, err error) {
	// Recording is best-effort by design: the loop must never die because
	// its own bookkeeping write lost a race with a reader.
	_ = st.RecordRejection(collection, "", reason, err.Error())
}
