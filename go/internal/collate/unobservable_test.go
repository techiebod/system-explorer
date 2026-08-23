package collate

import (
	"encoding/json"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
	"github.com/techiebod/system-explorer/go/internal/wire"
)

// The per-fact could-not-read, from the wire to the store.
//
// It was parsed, counted against the commit and validated against the
// declaration — and then dropped, from the day the wire carried it. So
// the `unobservable` render state had no data at either tier, and a fact
// the collector COULD NOT READ rendered exactly like a fact it never
// had: the distinction §28 calls the most common rendering bug in this
// product's history.
func TestAnUnobservableFactSurvivesTheApply(t *testing.T) {
	st := recordStore(t)
	issued, err := st.IssueGenerations([]string{"nft-rules"}, "sha256:d")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeclaration("sha256:d", nftDeclaration); err != nil {
		t.Fatal(err)
	}
	batch := &wire.Batch{
		Begin: wire.Begin{Batch: "b1", BootID: "boot", Generations: issued},
		Collections: map[string]*wire.CollectionStream{
			"nft-rules": {
				Objects: []wire.Object{{
					Name:  "accept-ssh",
					Facts: json.RawMessage(`{"Expression":"tcp dport 22 accept"}`),
				}},
				Unobservables: []wire.Unobservable{{
					Collection: "nft-rules", Name: "accept-ssh", Fact: "Handle",
					Reason: "unauthorised",
					Detail: "the ruleset is readable only to root on this host",
				}},
				Commit: &wire.Commit{},
			},
		},
	}
	if err := applyCollection(st, "nft-rules", store.HostNative, batch); err != nil {
		t.Fatal(err)
	}
	held, err := st.Unobservables("nft-rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 1 {
		t.Fatalf("the could-not-read must survive the apply: %+v", held)
	}
	if held[0].Fact != "Handle" || held[0].Reason != "unauthorised" {
		t.Fatalf("%+v", held[0])
	}
	if held[0].Detail == "" {
		t.Fatal("the detail is the half a person acts on; a reason alone " +
			"says the fact is missing without saying why")
	}
	if held[0].Object != store.MintID("nft-rules", "accept-ssh") {
		t.Fatalf("keyed on the minted id, as the object is: %q", held[0].Object)
	}
}

func TestAReAppliedCollectionRetiresItsOldUnobservables(t *testing.T) {
	// Objects and their could-not-reads are one statement about one
	// reading. A collection re-applied with the fact now readable must
	// not keep the previous batch's claim that it was not.
	st := recordStore(t)
	issued, err := st.IssueGenerations([]string{"nft-rules"}, "sha256:d")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeclaration("sha256:d", nftDeclaration); err != nil {
		t.Fatal(err)
	}
	object := []store.Object{{ID: "rule:1", Name: "a",
		Facts: json.RawMessage(`{"Expression":"drop"}`)}}
	if _, err := st.ApplyCommitWith("nft-rules", store.HostNative,
		issued["nft-rules"], "b1", "boot", object,
		[]store.Unobserved{{Object: "rule:1", Fact: "Handle",
			Reason: "unauthorised", Detail: "root only"}}); err != nil {
		t.Fatal(err)
	}
	if held, _ := st.Unobservables("nft-rules"); len(held) != 1 {
		t.Fatalf("%+v", held)
	}
	next, err := st.IssueGenerations([]string{"nft-rules"}, "sha256:d")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyCommitWith("nft-rules", store.HostNative,
		next["nft-rules"], "b2", "boot", object, nil); err != nil {
		t.Fatal(err)
	}
	held, err := st.Unobservables("nft-rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(held) != 0 {
		t.Fatalf("a reading that no longer says a fact was unreadable must "+
			"not keep saying it: %+v", held)
	}
}

// The decline's own words, and the four empty states kept apart.
//
// `stale_reason` held the enum alone: the DETAIL was parsed off the wire
// and discarded, so a collection said which of four kinds of
// not-answering this was and never said what to do about it. And an
// `absent` decline stored nothing at all — so a collection reporting
// "the interface is not on this host" was indistinguishable in the store
// from one that answered and holds nothing, which collapses two of §28's
// four empty states one tier below the renderer.
func TestADeclineKeepsItsOwnWords(t *testing.T) {
	st := recordStore(t)
	issued, err := st.IssueGenerations([]string{"nft-rules"}, "sha256:d")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeclaration("sha256:d", nftDeclaration); err != nil {
		t.Fatal(err)
	}
	batch := &wire.Batch{
		Begin: wire.Begin{Batch: "b1", BootID: "boot", Generations: issued},
		Collections: map[string]*wire.CollectionStream{
			"nft-rules": {Decline: &wire.Decline{
				Collection: "nft-rules", Reason: "unauthorised",
				Detail: "the ruleset is readable only to root on this host"}},
		},
	}
	if err := applyCollection(st, "nft-rules", store.HostNative, batch); err != nil {
		t.Fatal(err)
	}
	held, err := st.DeclineFor("nft-rules")
	if err != nil {
		t.Fatal(err)
	}
	if held.Reason != "unauthorised" {
		t.Fatalf("%+v", held)
	}
	if held.Detail == "" {
		t.Fatal("the reason says which of four kinds this is; the detail " +
			"says what to do about it, and it travels out over MCP")
	}
	if held.At == "" {
		t.Fatal("a decline carries when it was made, or a stale one reads " +
			"like a fresh one")
	}
}

func TestAnAbsentDeclineIsRecordedThoughItCommits(t *testing.T) {
	// absent is the one decline that COMMITS — a successful reading that
	// retires prior objects — and it stored nothing, so "there is no ZFS
	// here" and "there are no pools" were the same row.
	st := recordStore(t)
	issued, err := st.IssueGenerations([]string{"nft-rules"}, "sha256:d")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeclaration("sha256:d", nftDeclaration); err != nil {
		t.Fatal(err)
	}
	batch := &wire.Batch{
		Begin: wire.Begin{Batch: "b1", BootID: "boot", Generations: issued},
		Collections: map[string]*wire.CollectionStream{
			"nft-rules": {
				Decline: &wire.Decline{Collection: "nft-rules", Reason: "absent",
					Detail: "no nftables on this host"},
				Commit: &wire.Commit{},
			},
		},
	}
	if err := applyCollection(st, "nft-rules", store.HostNative, batch); err != nil {
		t.Fatal(err)
	}
	held, err := st.DeclineFor("nft-rules")
	if err != nil {
		t.Fatal(err)
	}
	if held.Reason != "absent" || held.Detail == "" {
		t.Fatalf("an absent decline is a statement, not a silence: %+v", held)
	}
	// And it is NOT stale: absent is a successful reading.
	states, err := st.Collections()
	if err != nil {
		t.Fatal(err)
	}
	for _, cs := range states {
		if cs.Name == "nft-rules" && cs.Stale {
			t.Fatal("absent commits and is not stale; marking it stale would " +
				"make a question that does not apply look like one that failed")
		}
	}
}

func TestAnAnsweringCollectionStopsCarryingItsDecline(t *testing.T) {
	// The columns are not write-only. A collection that declined
	// unauthorised once and answers today must not still read as
	// declined — that is the stale-confident-claim failure one tier
	// below the renderer, where nothing downstream can tell it apart
	// from a live refusal.
	st := recordStore(t)
	issued, err := st.IssueGenerations([]string{"nft-rules"}, "sha256:d")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordDeclaration("sha256:d", nftDeclaration); err != nil {
		t.Fatal(err)
	}
	declined := &wire.Batch{
		Begin: wire.Begin{Batch: "b1", BootID: "boot", Generations: issued},
		Collections: map[string]*wire.CollectionStream{
			"nft-rules": {Decline: &wire.Decline{
				Collection: "nft-rules", Reason: "unauthorised",
				Detail: "root only"}},
		},
	}
	if err := applyCollection(st, "nft-rules", store.HostNative, declined); err != nil {
		t.Fatal(err)
	}
	next, err := st.IssueGenerations([]string{"nft-rules"}, "sha256:d")
	if err != nil {
		t.Fatal(err)
	}
	answered := &wire.Batch{
		Begin: wire.Begin{Batch: "b2", BootID: "boot", Generations: next},
		Collections: map[string]*wire.CollectionStream{
			"nft-rules": {
				Objects: []wire.Object{{Name: "filter", Type: "table",
					Facts: []byte(`{"Family":"inet"}`), At: 1}},
				Commit: &wire.Commit{},
			},
		},
	}
	if err := applyCollection(st, "nft-rules", store.HostNative, answered); err != nil {
		t.Fatal(err)
	}
	held, err := st.DeclineFor("nft-rules")
	if err != nil {
		t.Fatal(err)
	}
	if held.Reason != "" || held.Detail != "" || held.At != "" {
		t.Fatalf("a commit is an answer and clears the decline: %+v", held)
	}
}
