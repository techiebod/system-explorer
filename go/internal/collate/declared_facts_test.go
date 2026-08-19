// Acceptance item 7's second half: undeclared facts reach no join.
//
// The check lives in the collator because this is the only tier that holds
// both the declaration and the stream. Its reversion is the point of this
// file: the collections these tests drive are structurally perfect, every
// count echoes, every generation is the issued one, and the ONLY defect is a
// name nothing declared — so a collator that trusted its caller applies all
// of them and reports success, which is what it did until 2026-08-19.
package collate

import (
	"context"
	"fmt"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
	"github.com/techiebod/system-explorer/go/internal/wire"
)

// declaredFactsDecl declares exactly one fact, so every test below differs
// from the passing case by one name and nothing else.
func declaredFactsDecl() []byte {
	return []byte(`{"schema":"se.declaration/1","collector":"fixture","collections":[
		{"name":"pools","freshness":"1h","prefix":"pool",
		 "facts":{"Health":{"type":"string","kind":"state"}}}]}`)
}

// runDeclaredFacts scripts one batch over declaredFactsDecl and returns the
// store it was applied to, plus the acquisition's error.
func runDeclaredFacts(t *testing.T, records func(issued map[string]uint64) []string) (*store.Store, error) {
	t.Helper()
	decl := declaredFactsDecl()
	f := newScriptedFake(t, decl, func(issued map[string]uint64) []string {
		batch := "batch-1"
		begin := fmt.Sprintf(`{"record":"begin","request":%q,"batch":%q,"declaration":%q,`+
			`"boot_id":%q,"timens":0,"instance":null,"generations":{"pools":%d}}`,
			batch, batch, wire.DeclarationHash(decl), fakeBootID, issued["pools"])
		end := fmt.Sprintf(`{"record":"end","request":%q,"batch":%q,"cpu_ms":0.5,"wall_ms":1.0}`,
			batch, batch)
		return append(append([]string{begin}, records(issued)...), end)
	})
	st := openStore(t)
	return st, AcquireOnce(context.Background(), st, &wire.Client{Socket: f.Socket})
}

func mustApplyNothing(t *testing.T, st *store.Store, err error, channel string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: an undeclared name was applied — the collator has no "+
			"sentence for it, and nothing downstream could tell a consumer "+
			"what it means", channel)
	}
	rows, rerr := st.Objects("pools")
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(rows) != 0 {
		t.Fatalf("%s: the batch is refused whole, not half-applied: %+v", channel, rows)
	}
	rejections, rerr := st.Rejections()
	if rerr != nil {
		t.Fatal(rerr)
	}
	if len(rejections) != 1 || rejections[0].Reason != "undeclared-fact" {
		t.Fatalf("%s: the refusal must be recorded and auditable: %+v", channel, rejections)
	}
}

// The positive control, and the reason the three refusals below mean
// anything: the identical batch carrying only the declared name applies.
func TestADeclaredFactApplies(t *testing.T) {
	st, err := runDeclaredFacts(t, func(issued map[string]uint64) []string {
		return []string{
			`{"record":"object","collection":"pools","name":"tank","facts":{"Health":"ONLINE"},"at":10.5}`,
			commitLine("pools", issued["pools"], 1, 0),
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := st.Objects("pools")
	if len(rows) != 1 {
		t.Fatalf("the declared name is the passing case: %+v", rows)
	}
}

func TestAnUndeclaredFactValueRefusesTheBatch(t *testing.T) {
	st, err := runDeclaredFacts(t, func(issued map[string]uint64) []string {
		return []string{
			`{"record":"object","collection":"pools","name":"tank",` +
				`"facts":{"Health":"ONLINE","Capacity":92},"at":10.5}`,
			commitLine("pools", issued["pools"], 1, 0),
		}
	})
	mustApplyNothing(t, st, err, "measured value")
}

// The absent list names facts too, and it is the easier of the two smuggling
// routes: a collector cannot state "this object has no such property" about a
// property the estate has never heard of.
func TestAnUndeclaredAbsentNameRefusesTheBatch(t *testing.T) {
	st, err := runDeclaredFacts(t, func(issued map[string]uint64) []string {
		return []string{
			`{"record":"object","collection":"pools","name":"tank",` +
				`"facts":{"Health":"ONLINE"},"absent":["Capacity"],"at":10.5}`,
			commitLine("pools", issued["pools"], 1, 0),
		}
	})
	mustApplyNothing(t, st, err, "absent list")
}

func TestAnUndeclaredUnobservableNameRefusesTheBatch(t *testing.T) {
	st, err := runDeclaredFacts(t, func(issued map[string]uint64) []string {
		return []string{
			`{"record":"object","collection":"pools","name":"tank",` +
				`"facts":{"Health":"ONLINE"},"at":10.5}`,
			`{"record":"unobservable","collection":"pools","name":"tank",` +
				`"fact":"Capacity","reason":"unavailable","detail":"the pool did not answer"}`,
			fmt.Sprintf(`{"record":"commit","collection":"pools","generation":%d,`+
				`"objects":1,"assertions":0,"unobservable":1,"cpu_ms":0.5}`, issued["pools"]),
		}
	})
	mustApplyNothing(t, st, err, "unobservable record")
}
