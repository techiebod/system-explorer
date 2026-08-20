// One whole session on the wire, and the samples the hub suite is driven
// by. The two halves of the protocol are proven against the same bytes:
// anything here that stops agreeing with contract/ or with the Python
// receiver fails in one of the two suites rather than in an estate.
package collate

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/store"
	"github.com/techiebod/system-explorer/go/internal/wire"
)

type fakeDeclarer struct {
	raw []byte
	err error
}

func (f fakeDeclarer) Declare(context.Context) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.raw, nil
}

func nixDeclaration(collector string) []byte {
	return []byte(`{"schema":"se.declaration/1","collector":"` + collector + `","version":"0.7.0",` +
		`"collections":[{"name":"generations","question":"what has this host been?",` +
		`"prefix":"generation","freshness":"300s","perishability":"reconstructible",` +
		`"answer":["ConfigurationRevision"],"facts":{` +
		`"ConfigurationRevision":{"type":"string","temperament":"configuration","kind":"observed","discloses":"nothing","sentence":"."},` +
		`"Booted":{"type":"boolean","temperament":"state","kind":"observed","discloses":"nothing","sentence":"."}}}]}`)
}

func sessionFor(t *testing.T, host, revision string, gen uint64) *bytes.Buffer {
	t.Helper()
	st := openStore(t)
	// The SAME hash the session will send. In the daemon this is automatic
	// — AcquireOnce stamps the store from the very bytes it hashed for
	// begin.declaration — and getting it wrong here produced exactly the
	// manifest-names-a-hash-nobody-holds failure the hub refuses on.
	declHash := wire.DeclarationHash(nixDeclaration("nix"))
	for i := uint64(0); i < gen; i++ {
		if _, err := st.IssueGenerations([]string{"generations"}, declHash); err != nil {
			t.Fatal(err)
		}
	}
	facts := fmt.Sprintf(`{"Booted":true,"ConfigurationRevision":%q}`, revision)
	if _, err := st.ApplyCommit("generations", store.HostNative, gen, "b1", fakeBootID,
		[]store.Object{obj("generation:7", "7", facts, 10)}); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	err := WriteSession(context.Background(), &buf, st,
		map[string]Declarer{"nix": fakeDeclarer{raw: nixDeclaration("nix")}},
		"cp-"+host, host, fakeBootID, nil)
	if err != nil {
		t.Fatalf("write session for %s: %v", host, err)
	}
	return &buf
}

func TestASessionIsDeclarationsThenCheckpoint(t *testing.T) {
	recs := records(t, sessionFor(t, "storage-1", "4f9c2e1", 7))
	if recs[0]["record"] != "declaration" {
		t.Fatalf("a session opens with its declarations: %v", recs[0])
	}
	if recs[0]["digest"] == "" || recs[0]["document"] == nil {
		t.Fatalf("a framed declaration carries document and digest: %v", recs[0])
	}
	doc := recs[0]["document"].(map[string]any)
	if doc["schema"] != "se.declaration/1" {
		t.Fatalf("the framing CARRIES a declaration, it is not one: %v", doc)
	}
	if recs[1]["record"] != "manifest" {
		t.Fatalf("declarations come before the checkpoint: %v", recs[1])
	}
	sent := recs[0]["digest"]
	named := recs[1]["declarations"].([]any)
	if len(named) != 1 || named[0] != sent {
		t.Fatalf("manifest names %v, session sent %v", named, sent)
	}
}

func TestOneSilentCollectorDoesNotCostTheRest(t *testing.T) {
	st := openStore(t)
	seed(t, st, "generations", 1, "b1", []store.Object{obj("generation:7", "7", `{}`, 10)})
	var buf bytes.Buffer
	err := WriteSession(context.Background(), &buf, st, map[string]Declarer{
		"nix":    fakeDeclarer{raw: nixDeclaration("nix")},
		"broken": fakeDeclarer{err: errors.New("socket refused")},
	}, "cp-1", "storage-1", fakeBootID, nil)
	if err == nil {
		t.Fatal("a session that dropped a collector silently would leave the hub's axes quietly short")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("broken")) {
		t.Fatalf("the error must name which collector: %v", err)
	}
	recs := records(t, &buf)
	if recs[0]["record"] != "declaration" || recs[len(recs)-1]["record"] != "terminal" {
		t.Fatalf("the rest of the session must still be sent: %v", recs)
	}
}

func TestNoDeclarationAtAllIsRefusedHere(t *testing.T) {
	st := openStore(t)
	seed(t, st, "generations", 1, "b1", nil)
	err := WriteSession(context.Background(), &bytes.Buffer{}, st,
		map[string]Declarer{"broken": fakeDeclarer{err: errors.New("nope")}},
		"cp-1", "storage-1", fakeBootID, nil)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("fact axes")) {
		t.Fatalf("refused here so the reason names the collector: %v", err)
	}
}

// TestEmitsSessionSamples writes two hosts' sessions for the hub suite,
// under the same skip rule as the checkpoint samples.
func TestEmitsSessionSamples(t *testing.T) {
	dir := os.Getenv("SE_CHECKPOINT_SAMPLES")
	if dir == "" {
		t.Skip("set SE_CHECKPOINT_SAMPLES to emit; conformance does")
	}
	if err := os.MkdirAll(filepath.Join(dir, "sessions"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Two hosts at DIFFERENT revisions: the estate the founding failure
	// answered `yes` over.
	for host, revision := range map[string]string{
		"storage-1": "4f9c2e1", "edge-1": "9ab31d0",
	} {
		buf := sessionFor(t, host, revision, 7)
		if err := os.WriteFile(
			filepath.Join(dir, "sessions", host+".jsonl"), buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
