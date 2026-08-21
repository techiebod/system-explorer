// Acceptance item 6: unresolved, resolved-later, absent, confirmed,
// contradicted and parallel relations each reach their defined state — and an
// upgrade never re-keys.
//
// Every test here is paired with its reversion (standing rule 6): the case is
// constructed so that the WRONG implementation — the obvious one — produces a
// visibly different answer, and the assertion names which. A relation suite
// that only checked the states the code already produces would certify the
// founding failure as readily as it certifies the fix.
package collate

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
	"github.com/techiebod/system-explorer/go/internal/wire"
)

// twoCollectionDecl declares a chains collection and a rules collection with
// the prefixes and relation types the network collector actually ships, so
// these tests exercise the same declaration shape production does.
func twoCollectionDecl() []byte {
	return []byte(`{"schema":"se.declaration/1","collector":"network","collections":[
		{"name":"chains","freshness":"1h","prefix":"chain",
		 "relations":[{"type":"member-of","carries_facts":false,"inverse_observable":false}]},
		{"name":"rules","freshness":"1h","prefix":"rule",
		 "relations":[
		   {"type":"member-of","carries_facts":false,"inverse_observable":false},
		   {"type":"dispatches-to","carries_facts":true,"discriminator":["Handle"],
		    "inverse_observable":false}]}]}`)
}

// relationBatch scripts one batch over the two-collection declaration.
func relationBatch(decl []byte, id string, body func(issued map[string]uint64) []string) func(map[string]uint64) []string {
	return func(issued map[string]uint64) []string {
		batch := id
		begin := fmt.Sprintf(`{"record":"begin","request":%q,"batch":%q,"declaration":%q,`+
			`"boot_id":%q,"timens":0,"instance":null,"generations":{"chains":%d,"rules":%d}}`,
			batch, batch, wire.DeclarationHash(decl), fakeBootID, issued["chains"], issued["rules"])
		end := fmt.Sprintf(`{"record":"end","request":%q,"batch":%q,"cpu_ms":0.5,"wall_ms":1.0}`, batch, batch)
		return append(append([]string{begin}, body(issued)...), end)
	}
}

func commitLine(collection string, gen uint64, objects, assertions int) string {
	return fmt.Sprintf(`{"record":"commit","collection":%q,"generation":%d,`+
		`"objects":%d,"assertions":%d,"unobservable":0,"cpu_ms":0.5}`,
		collection, gen, objects, assertions)
}

func relationsByTarget(t *testing.T, st *store.Store, collection string) map[string]store.Relation {
	t.Helper()
	rels, err := st.Relations(collection)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]store.Relation{}
	for _, r := range rels {
		out[r.TargetName] = r
	}
	return out
}

// A target naming a collection this host serves, whose name that collection
// published, resolves. A target naming a KIND no collection declares as its
// prefix cannot resolve, and is minted `asserted` carrying the bare name.
//
// The reversion this proves: an implementation that dropped unresolvable
// targets — which sounds like rigour — would leave the second edge absent
// entirely, and the founding incident is precisely a repository nothing in
// the estate reads. Discarding it is clean, defensible, and identical in
// effect to never having looked.
func TestAnUnresolvedTargetIsMintedAndAResolvedOneCarriesItsID(t *testing.T) {
	decl := twoCollectionDecl()
	f := newScriptedFake(t, decl, relationBatch(decl, "batch-resolve", func(issued map[string]uint64) []string {
		return []string{
			`{"record":"object","collection":"chains","name":"ip filter INPUT","facts":{"Family":"ip"},"at":10.5}`,
			// A table: nothing here declares the prefix "table", so it
			// resolves against nothing on this host.
			`{"record":"relation_assertion","collection":"chains","name":"ip filter INPUT",` +
				`"type":"member-of","vantage":"chains","target":{"kind":"table","name":"ip filter"}}`,
			commitLine("chains", issued["chains"], 1, 1),
			`{"record":"object","collection":"rules","name":"ip filter INPUT handle 58","facts":{"Handle":58},"at":11.5}`,
			// A chain, and the chains collection above published exactly
			// this name in this batch: it resolves.
			`{"record":"relation_assertion","collection":"rules","name":"ip filter INPUT handle 58",` +
				`"type":"member-of","vantage":"rules","target":{"kind":"chain","name":"ip filter INPUT"}}`,
			commitLine("rules", issued["rules"], 1, 1),
		}
	}))
	st := openStore(t)
	if err := AcquireOnce(context.Background(), st, &wire.Client{Socket: f.Socket}); err != nil {
		t.Fatal(err)
	}

	chains := relationsByTarget(t, st, "chains")
	table, minted := chains["ip filter"]
	if !minted {
		t.Fatal("an unresolved target is MINTED, not dropped: the edge into open " +
			"space is the condition DESIGN 13 exists for, and deleting it is " +
			"identical in effect to never having looked")
	}
	if table.Resolved || table.TargetID != "" {
		t.Fatalf("nothing on this host publishes an object of kind table: %+v", table)
	}
	if table.TargetName != "ip filter" {
		t.Fatalf("an unresolved target carries the bare NAME: %+v", table)
	}
	if table.Observability != store.Asserted {
		t.Fatalf("one end observed is `asserted`, never a degraded confirmed: %+v", table)
	}

	rules := relationsByTarget(t, st, "rules")
	chain, ok := rules["ip filter INPUT"]
	if !ok {
		t.Fatal("the rules edge is missing entirely")
	}
	if !chain.Resolved || chain.TargetID != store.MintID("chains", "ip filter INPUT") {
		t.Fatalf("a name this host published resolves, and to the id the collator "+
			"minted for it: %+v", chain)
	}
	// Resolved is NOT confirmed. The far end being nameable here says the
	// object exists; it says nothing about whether anything looked back.
	if chain.Observability != store.Asserted {
		t.Fatalf("resolution and observability are different questions — "+
			"a resolved target whose type cannot be confirmed from the far "+
			"end is still `asserted`: %+v", chain)
	}
}

// The engaged spare, which is where the discriminator stops being theory: one
// pool asserts backed-by to ONE device twice, once inside the spare-N
// pseudo-vdev where it is doing the work and once under the `spares` key
// where it is accounted for. Both are true.
//
// The reversion: keyed on (source, type, target) alone the second assertion
// silently replaces the first and the pool reports a spare that is either
// standing by or working, never the truth that it is both. That is a lost
// edge with no error anywhere — exactly the silent overwrite DESIGN 13's
// discriminator exists to prevent.
func TestParallelRelationsSurviveOnTheirDiscriminator(t *testing.T) {
	decl := []byte(`{"schema":"se.declaration/1","collector":"storage","collections":[
		{"name":"pools","freshness":"1h","prefix":"pool",
		 "relations":[{"type":"backed-by","carries_facts":true,"discriminator":["VdevPath"],
		               "inverse_observable":false}]}]}`)
	f := newScriptedFake(t, decl, func(issued map[string]uint64) []string {
		batch := "batch-spare"
		return []string{
			fmt.Sprintf(`{"record":"begin","request":%q,"batch":%q,"declaration":%q,`+
				`"boot_id":%q,"timens":0,"instance":null,"generations":{"pools":%d}}`,
				batch, batch, wire.DeclarationHash(decl), fakeBootID, issued["pools"]),
			`{"record":"object","collection":"pools","name":"tank","facts":{"State":"DEGRADED"},"at":10.5}`,
			`{"record":"relation_assertion","collection":"pools","name":"tank","type":"backed-by",` +
				`"vantage":"pools","target":{"kind":"block-device","name":"sdd"},"facts":{"VdevPath":"spare-3"}}`,
			`{"record":"relation_assertion","collection":"pools","name":"tank","type":"backed-by",` +
				`"vantage":"pools","target":{"kind":"block-device","name":"sdd"},"facts":{"VdevPath":"spares"}}`,
			commitLine("pools", issued["pools"], 1, 2),
			fmt.Sprintf(`{"record":"end","request":%q,"batch":%q,"cpu_ms":0.5,"wall_ms":1.0}`, batch, batch),
		}
	})
	st := openStore(t)
	if err := AcquireOnce(context.Background(), st, &wire.Client{Socket: f.Socket}); err != nil {
		t.Fatal(err)
	}
	rels, err := st.Relations("pools")
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 2 {
		t.Fatalf("one device, two true statements, two relations — a key without "+
			"the discriminator collapses them to %d and loses the other silently", len(rels))
	}
	paths := map[string]bool{}
	for _, r := range rels {
		var facts map[string]any
		if err := json.Unmarshal(r.Facts, &facts); err != nil {
			t.Fatal(err)
		}
		paths[fmt.Sprint(facts["VdevPath"])] = true
		if r.TargetName != "sdd" {
			t.Fatalf("both edges name the same device: %+v", r)
		}
	}
	if !paths["spare-3"] || !paths["spares"] {
		t.Fatalf("both vdev paths survive: %v", paths)
	}
	if rels[0].Key == rels[1].Key {
		t.Fatal("two relations, two keys")
	}
}

// A type declaring NO discriminator asserts it is at-most-singular between
// any pair. That assertion is checkable, and a second instance is an error
// the collator reports — not a silent overwrite.
//
// The reversion: without this the missing declaration is invisible. One edge
// vanishes, nothing is recorded, and the collection reports a clean apply.
func TestASecondSingularAssertionIsReportedNotOverwritten(t *testing.T) {
	decl := []byte(`{"schema":"se.declaration/1","collector":"net","collections":[
		{"name":"rules","freshness":"1h","prefix":"rule",
		 "relations":[{"type":"dispatches-to","carries_facts":true,"inverse_observable":false}]}]}`)
	f := newScriptedFake(t, decl, func(issued map[string]uint64) []string {
		batch := "batch-collide"
		return []string{
			fmt.Sprintf(`{"record":"begin","request":%q,"batch":%q,"declaration":%q,`+
				`"boot_id":%q,"timens":0,"instance":null,"generations":{"rules":%d}}`,
				batch, batch, wire.DeclarationHash(decl), fakeBootID, issued["rules"]),
			`{"record":"object","collection":"rules","name":"r1","facts":{"X":1},"at":10.5}`,
			// Two jumps from one rule to one chain, differing only in a
			// fact the type does NOT declare as its discriminator.
			`{"record":"relation_assertion","collection":"rules","name":"r1","type":"dispatches-to",` +
				`"vantage":"rules","target":{"kind":"chain","name":"c"},"facts":{"Handle":1}}`,
			`{"record":"relation_assertion","collection":"rules","name":"r1","type":"dispatches-to",` +
				`"vantage":"rules","target":{"kind":"chain","name":"c"},"facts":{"Handle":2}}`,
			commitLine("rules", issued["rules"], 1, 2),
			fmt.Sprintf(`{"record":"end","request":%q,"batch":%q,"cpu_ms":0.5,"wall_ms":1.0}`, batch, batch),
		}
	})
	st := openStore(t)
	// The acquisition returns the error; the point is that it is RECORDED,
	// because a collision the loop only logged would be a lost edge nobody
	// could find later.
	_ = AcquireOnce(context.Background(), st, &wire.Client{Socket: f.Socket})
	rejections, err := st.Rejections()
	if err != nil {
		t.Fatal(err)
	}
	var found *store.Rejection
	for i := range rejections {
		if rejections[i].Reason == "relation-assembly" {
			found = &rejections[i]
		}
	}
	if found == nil {
		t.Fatalf("a second singular assertion is an error the collator reports, "+
			"not a silent overwrite: %+v", rejections)
	}
	if found.Collection != "rules" {
		t.Fatalf("recorded against the collection that asserted it: %+v", found)
	}
}

// Both ends observed and agreeing is `confirmed`; both ends observed and
// disagreeing is `contradicted`. The declaration is what says a type CAN be
// confirmed and which assertion does it — a type that cannot is honestly
// `asserted` forever rather than perpetually waiting.
//
// The reversion: treating `asserted` as a degraded `confirmed`, or inferring
// confirmation from resolution alone, renders the founding failure as a
// success. Both halves are asserted here so neither can pass by accident.
func TestConfirmedAndContradictedNeedBothEnds(t *testing.T) {
	// `mounts` claims a filesystem is mounted from a device; `devices`
	// claims the device carries it back. Each names the other's type as its
	// confirmation, which is the only way this tier may conclude anything.
	decl := []byte(`{"schema":"se.declaration/1","collector":"storage","collections":[
		{"name":"mounts","freshness":"1h","prefix":"mount",
		 "relations":[{"type":"mounted-from","carries_facts":true,"discriminator":["Fs"],
		               "inverse_observable":true,"confirmed_by":"carries"}]},
		{"name":"devices","freshness":"1h","prefix":"device",
		 "relations":[{"type":"carries","carries_facts":true,"discriminator":["Fs"],
		               "inverse_observable":false}]}]}`)
	f := newScriptedFake(t, decl, func(issued map[string]uint64) []string {
		batch := "batch-conf"
		return []string{
			fmt.Sprintf(`{"record":"begin","request":%q,"batch":%q,"declaration":%q,`+
				`"boot_id":%q,"timens":0,"instance":null,"generations":{"devices":%d,"mounts":%d}}`,
				batch, batch, wire.DeclarationHash(decl), fakeBootID,
				issued["devices"], issued["mounts"]),
			`{"record":"object","collection":"mounts","name":"/srv","facts":{"X":1},"at":10.5}`,
			`{"record":"object","collection":"mounts","name":"/var","facts":{"X":1},"at":10.6}`,
			// /srv: the device asserts it back with the SAME facts.
			`{"record":"relation_assertion","collection":"mounts","name":"/srv","type":"mounted-from",` +
				`"vantage":"mounts","target":{"kind":"device","name":"sda1"},"facts":{"Fs":"ext4"}}`,
			// /var: the device asserts it back claiming a DIFFERENT
			// filesystem — two vantages that both looked and disagree.
			`{"record":"relation_assertion","collection":"mounts","name":"/var","type":"mounted-from",` +
				`"vantage":"mounts","target":{"kind":"device","name":"sdb1"},"facts":{"Fs":"xfs"}}`,
			commitLine("mounts", issued["mounts"], 2, 2),
			`{"record":"object","collection":"devices","name":"sda1","facts":{"X":1},"at":10.7}`,
			`{"record":"object","collection":"devices","name":"sdb1","facts":{"X":1},"at":10.8}`,
			`{"record":"relation_assertion","collection":"devices","name":"sda1","type":"carries",` +
				`"vantage":"devices","target":{"kind":"mount","name":"/srv"},"facts":{"Fs":"ext4"}}`,
			`{"record":"relation_assertion","collection":"devices","name":"sdb1","type":"carries",` +
				`"vantage":"devices","target":{"kind":"mount","name":"/var"},"facts":{"Fs":"btrfs"}}`,
			commitLine("devices", issued["devices"], 2, 2),
			fmt.Sprintf(`{"record":"end","request":%q,"batch":%q,"cpu_ms":0.5,"wall_ms":1.0}`, batch, batch),
		}
	})
	st := openStore(t)
	if err := AcquireOnce(context.Background(), st, &wire.Client{Socket: f.Socket}); err != nil {
		t.Fatal(err)
	}
	mounts := relationsByTarget(t, st, "mounts")
	if got := mounts["sda1"].Observability; got != store.Confirmed {
		t.Fatalf("both ends observed and agreeing is confirmed, got %q", got)
	}
	if got := mounts["sdb1"].Observability; got != store.Contradicted {
		t.Fatalf("both ends observed and disagreeing is contradicted — a state, "+
			"not a merge conflict and not a silent win for either vantage; got %q", got)
	}
	// The far side declared inverse_observable false, so nothing confirms IT
	// even though the mount asserted the edge back. A type is judged by its
	// OWN declaration, never by whether some other assertion happens to
	// point the right way.
	devices := relationsByTarget(t, st, "devices")
	if got := devices["/srv"].Observability; got != store.Asserted {
		t.Fatalf("a type declaring it cannot be confirmed from the far end is "+
			"honestly asserted, not confirmed by coincidence; got %q", got)
	}
}

// The key is the lifecycle. A target that resolves in a later batch must keep
// the key it had while unresolved, or every relation in the estate resets its
// history the moment the estate learns something.
//
// The reversion: keying on the resolved target id — the obvious choice, since
// an id is the stable thing everywhere else in this product — makes the two
// batches below produce two different keys for one edge. The relation looks
// new, its lifecycle restarts, and any finding hanging off it is re-raised as
// a fresh condition.
func TestResolutionUpgradesWithoutReKeying(t *testing.T) {
	decl := twoCollectionDecl()
	// Batch 1: the rule asserts membership of a chain the chains collection
	// declines to publish — nothing on this host claims the name.
	first := newScriptedFake(t, decl, relationBatch(decl, "batch-one", func(issued map[string]uint64) []string {
		return []string{
			`{"record":"decline","collection":"chains","reason":"absent","detail":"no chains"}`,
			commitLine("chains", issued["chains"], 0, 0),
			`{"record":"object","collection":"rules","name":"r1","facts":{"Handle":58},"at":10.5}`,
			`{"record":"relation_assertion","collection":"rules","name":"r1","type":"member-of",` +
				`"vantage":"rules","target":{"kind":"chain","name":"ip filter INPUT"}}`,
			commitLine("rules", issued["rules"], 1, 1),
		}
	}))
	st := openStore(t)
	if err := AcquireOnce(context.Background(), st, &wire.Client{Socket: first.Socket}); err != nil {
		t.Fatal(err)
	}
	before := relationsByTarget(t, st, "rules")["ip filter INPUT"]
	if before.Key == "" || before.Resolved {
		t.Fatalf("batch one leaves the edge minted and unresolved: %+v", before)
	}

	// Batch 2: identical assertion, but now the chain IS published.
	second := newScriptedFake(t, decl, relationBatch(decl, "batch-two", func(issued map[string]uint64) []string {
		return []string{
			`{"record":"object","collection":"chains","name":"ip filter INPUT","facts":{"Family":"ip"},"at":20.5}`,
			commitLine("chains", issued["chains"], 1, 0),
			`{"record":"object","collection":"rules","name":"r1","facts":{"Handle":58},"at":20.6}`,
			`{"record":"relation_assertion","collection":"rules","name":"r1","type":"member-of",` +
				`"vantage":"rules","target":{"kind":"chain","name":"ip filter INPUT"}}`,
			commitLine("rules", issued["rules"], 1, 1),
		}
	}))
	if err := AcquireOnce(context.Background(), st, &wire.Client{Socket: second.Socket}); err != nil {
		t.Fatal(err)
	}
	after := relationsByTarget(t, st, "rules")["ip filter INPUT"]
	if !after.Resolved || after.TargetID != store.MintID("chains", "ip filter INPUT") {
		t.Fatalf("the second batch resolves the target: %+v", after)
	}
	if after.Key != before.Key {
		t.Fatalf("an upgrade never re-keys: %q became %q — the edge is the same "+
			"edge, and a key that moved with resolution would reset its "+
			"lifecycle every time the estate learned something",
			before.Key, after.Key)
	}
}

// A committed collection is authoritative, and that governs its relations
// exactly as it governs its objects: everything the commit did not assert is
// gone. An absent decline commits zero, so it retires the edges a previous
// batch established — the same statement as retiring its objects.
//
// The reversion: relations that accumulated instead would leave a pool
// asserting membership of devices it no longer has, which is stale structure
// presented as current — the failure mode the batch authority exists for.
func TestACommittedCollectionRetiresTheRelationsItDidNotAssert(t *testing.T) {
	decl := twoCollectionDecl()
	st := openStore(t)
	full := newScriptedFake(t, decl, relationBatch(decl, "batch-full", func(issued map[string]uint64) []string {
		return []string{
			`{"record":"decline","collection":"chains","reason":"absent","detail":"none"}`,
			commitLine("chains", issued["chains"], 0, 0),
			`{"record":"object","collection":"rules","name":"r1","facts":{"Handle":1},"at":10.5}`,
			`{"record":"relation_assertion","collection":"rules","name":"r1","type":"member-of",` +
				`"vantage":"rules","target":{"kind":"chain","name":"c1"}}`,
			`{"record":"relation_assertion","collection":"rules","name":"r1","type":"dispatches-to",` +
				`"vantage":"rules","target":{"kind":"chain","name":"c2"},"facts":{"Handle":1}}`,
			commitLine("rules", issued["rules"], 1, 2),
		}
	}))
	if err := AcquireOnce(context.Background(), st, &wire.Client{Socket: full.Socket}); err != nil {
		t.Fatal(err)
	}
	if rels, _ := st.Relations("rules"); len(rels) != 2 {
		t.Fatalf("the first batch establishes two edges, got %d", len(rels))
	}

	// The jump is gone from the ruleset; the membership remains.
	fewer := newScriptedFake(t, decl, relationBatch(decl, "batch-fewer", func(issued map[string]uint64) []string {
		return []string{
			`{"record":"decline","collection":"chains","reason":"absent","detail":"none"}`,
			commitLine("chains", issued["chains"], 0, 0),
			`{"record":"object","collection":"rules","name":"r1","facts":{"Handle":1},"at":20.5}`,
			`{"record":"relation_assertion","collection":"rules","name":"r1","type":"member-of",` +
				`"vantage":"rules","target":{"kind":"chain","name":"c1"}}`,
			commitLine("rules", issued["rules"], 1, 1),
		}
	}))
	if err := AcquireOnce(context.Background(), st, &wire.Client{Socket: fewer.Socket}); err != nil {
		t.Fatal(err)
	}
	rels, err := st.Relations("rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 1 || rels[0].TargetName != "c1" {
		t.Fatalf("everything a committed collection did not assert is gone: %+v", rels)
	}
}

// An uncommitted collection is authoritative for nothing, and its assertions
// must therefore establish nothing either. A partial read must not be allowed
// to delete edges any more than it may delete objects.
func TestAnUncommittedCollectionAssertsNothing(t *testing.T) {
	decl := twoCollectionDecl()
	st := openStore(t)
	seed := newScriptedFake(t, decl, relationBatch(decl, "batch-seed", func(issued map[string]uint64) []string {
		return []string{
			`{"record":"decline","collection":"chains","reason":"absent","detail":"none"}`,
			commitLine("chains", issued["chains"], 0, 0),
			`{"record":"object","collection":"rules","name":"r1","facts":{"Handle":1},"at":10.5}`,
			`{"record":"relation_assertion","collection":"rules","name":"r1","type":"member-of",` +
				`"vantage":"rules","target":{"kind":"chain","name":"c1"}}`,
			commitLine("rules", issued["rules"], 1, 1),
		}
	}))
	if err := AcquireOnce(context.Background(), st, &wire.Client{Socket: seed.Socket}); err != nil {
		t.Fatal(err)
	}

	// rules is issued a generation and then neither commits nor declines.
	// Its objects are held; its relations must be held with them.
	partial := newScriptedFake(t, decl, relationBatch(decl, "batch-partial", func(issued map[string]uint64) []string {
		return []string{
			`{"record":"decline","collection":"chains","reason":"absent","detail":"none"}`,
			commitLine("chains", issued["chains"], 0, 0),
		}
	}))
	_ = AcquireOnce(context.Background(), st, &wire.Client{Socket: partial.Socket})
	rels, err := st.Relations("rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(rels) != 1 {
		t.Fatalf("a partial read deletes nothing — the prior edge stands: %+v", rels)
	}
}

// Two collections declaring one prefix is refused rather than resolved to
// whichever was read last. An ambiguous prefix is a declaration bug, and
// silently picking one lands an edge on the wrong object — a wrong answer
// delivered with full confidence, which is what this product is about.
func TestAnAmbiguousPrefixIsRefused(t *testing.T) {
	if _, err := store.PrefixIndex(map[string]string{
		"nft-chains": "chain", "nft-chains-v2": "chain",
	}); err == nil {
		t.Fatal("two collections claiming one prefix must be refused, not resolved " +
			"to whichever was read last")
	}
	// The unambiguous case still works, and an empty prefix (a collection
	// nothing targets) is simply not indexed rather than colliding with
	// every other empty one.
	index, err := store.PrefixIndex(map[string]string{
		"nft-chains": "nft-chain", "pools": "pool", "identity": "",
	})
	if err != nil {
		t.Fatal(err)
	}
	if index["nft-chain"] != "nft-chains" || index["pool"] != "pools" || len(index) != 2 {
		t.Fatalf("prefix index: %v", index)
	}
}

// The discriminator is compared under typed equality, like every other value
// in this product: 12 and "12" are two different readings, and a key that
// stringified would quietly merge them.
func TestTheDiscriminatorKeepsItsType(t *testing.T) {
	numeric, err := store.RelationKey("rules:r1", "dispatches-to", []string{"Handle"},
		json.RawMessage(`{"Handle":12}`), "c")
	if err != nil {
		t.Fatal(err)
	}
	textual, err := store.RelationKey("rules:r1", "dispatches-to", []string{"Handle"},
		json.RawMessage(`{"Handle":"12"}`), "c")
	if err != nil {
		t.Fatal(err)
	}
	if numeric == textual {
		t.Fatal("12 and \"12\" are two discriminators, not one")
	}
	// A declared discriminator the assertion does not carry is its own
	// value, distinguishable from carrying the empty string — otherwise a
	// missing reading and an empty one collide.
	missing, err := store.RelationKey("rules:r1", "dispatches-to", []string{"Handle"},
		json.RawMessage(`{}`), "c")
	if err != nil {
		t.Fatal(err)
	}
	empty, err := store.RelationKey("rules:r1", "dispatches-to", []string{"Handle"},
		json.RawMessage(`{"Handle":""}`), "c")
	if err != nil {
		t.Fatal(err)
	}
	if missing == empty {
		t.Fatal("an absent discriminator and an empty one are different statements")
	}
}

// A host runs SEVERAL collectors, and the test resolution applies is "does
// anything on this HOST claim the name" (DESIGN 16) — not "does this batch's
// own declaration claim it". A hardware disk asserts `backs` a block device
// that only the storage collector publishes, and neither declaration names
// the other's collection.
//
// The reversion this proves, and it is the shape that looks like success:
// building the prefix index from the batch's own declaration alone leaves the
// edge minted, carrying its name, and UNRESOLVED — an edge into open space on
// a host where the far end is sitting in the same store. Nothing errors,
// nothing is dropped, and a reader is told the disk backs something nobody
// here publishes. This is R3c's third acceptance item, and it failed in that
// direction until 2026-08-21.
func TestATargetResolvesAgainstTheHostNotTheBatch(t *testing.T) {
	storageDecl := []byte(`{"schema":"se.declaration/1","collector":"storage","collections":[
		{"name":"block-devices","freshness":"1h","prefix":"block-device"}]}`)
	hardwareDecl := []byte(`{"schema":"se.declaration/1","collector":"hardware","collections":[
		{"name":"scsi","freshness":"1h","prefix":"scsi",
		 "relations":[{"type":"backs","carries_facts":false,"inverse_observable":false}]}]}`)

	st := openStore(t)

	storage := newScriptedFake(t, storageDecl, func(issued map[string]uint64) []string {
		return []string{
			fmt.Sprintf(`{"record":"begin","request":"s1","batch":"s1","declaration":%q,`+
				`"boot_id":%q,"timens":0,"instance":null,"generations":{"block-devices":%d}}`,
				wire.DeclarationHash(storageDecl), fakeBootID, issued["block-devices"]),
			`{"record":"object","collection":"block-devices","name":"sda","facts":{},"at":10.1}`,
			commitLine("block-devices", issued["block-devices"], 1, 0),
			`{"record":"end","request":"s1","batch":"s1","cpu_ms":0.5,"wall_ms":1.0}`,
		}
	})
	if err := AcquireOnce(context.Background(), st, &wire.Client{Socket: storage.Socket}); err != nil {
		t.Fatal(err)
	}

	// The hardware batch lands AFTER storage's, so the edge must resolve as
	// it is asserted — the later-upgrade path cannot be what does it here,
	// which is what makes this test isolate the host-wide index.
	hardware := newScriptedFake(t, hardwareDecl, func(issued map[string]uint64) []string {
		return []string{
			fmt.Sprintf(`{"record":"begin","request":"h1","batch":"h1","declaration":%q,`+
				`"boot_id":%q,"timens":0,"instance":null,"generations":{"scsi":%d}}`,
				wire.DeclarationHash(hardwareDecl), fakeBootID, issued["scsi"]),
			`{"record":"object","collection":"scsi","name":"0:0:0:0","type":"disk","facts":{},"at":10.2}`,
			`{"record":"relation_assertion","collection":"scsi","name":"0:0:0:0","type":"backs",` +
				`"vantage":"scsi","target":{"kind":"block-device","name":"sda"}}`,
			commitLine("scsi", issued["scsi"], 1, 1),
			`{"record":"end","request":"h1","batch":"h1","cpu_ms":0.5,"wall_ms":1.0}`,
		}
	})
	if err := AcquireOnce(context.Background(), st, &wire.Client{Socket: hardware.Socket}); err != nil {
		t.Fatal(err)
	}

	edge := relationsByTarget(t, st, "scsi")["sda"]
	if edge.Key == "" {
		t.Fatal("the edge was not minted at all")
	}
	if !edge.Resolved || edge.TargetID != store.MintID("block-devices", "sda") {
		t.Fatalf("a target another collector publishes must resolve against the "+
			"host: %+v", edge)
	}
}
