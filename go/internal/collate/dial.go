// The collator's outbound session to its hub (DESIGN §06).
//
// The connection reverses in the new architecture: nothing dials a host,
// and the collator originates. That is what removes the inbound port a
// site's hosts would otherwise have to expose, and it is why a hub has no
// way to reach a collator at all — the property the federation rules then
// rest on.
//
// The order is fixed and this file is the whole of it: declarations, then
// a checkpoint, then the ordinary stream. A hub that only receives has no
// way of its own to know when it knows enough to answer, so completeness
// is explicit rather than inferred.
//
// **The declaration's digest is a join key at this hop.** The collator
// computed it over the exact bytes a collector emitted and already
// refused any batch whose begin.declaration disagreed — integrity belongs
// to that hop, where the bytes are. The hub needs a key to join a
// manifest entry to the fact axes it names, so the document travels
// parsed with its digest beside it.
package collate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/techiebod/system-explorer/go/internal/store"
	"github.com/techiebod/system-explorer/go/internal/wire"
)

// declarationRecord is the session framing. It is not se.declaration/1 —
// it CARRIES one, beside the digest the collator holds for it.
type declarationRecord struct {
	Record   string          `json:"record"`
	Digest   string          `json:"digest"`
	Document json.RawMessage `json:"document"`
}

// Declarer is the slice of wire.Client a session needs, so a test can
// drive one without a collector process.
type Declarer interface {
	Declare(ctx context.Context) ([]byte, error)
}

// WriteSession writes one whole session onto w: every collector's
// declaration, then the checkpoint.
//
// A collector that will not answer `declare` is REPORTED and skipped, not
// fatal: one silent collector must not cost the hub every other
// collection on the host. But its collections are still in the manifest,
// carrying whatever state the store holds — which is how the hub learns
// that something here is unreadable rather than absent. The returned
// error names every collector that failed, because a session that
// dropped one silently would be a checkpoint whose axes are quietly
// short.
func WriteSession(
	ctx context.Context,
	w io.Writer,
	st *store.Store,
	collectors map[string]Declarer,
	id, host, bootID string,
	gap *HistoryGap,
) error {
	enc := json.NewEncoder(w)
	var failed []string
	sent := 0
	for _, name := range sortedNames(collectors) {
		raw, err := collectors[name].Declare(ctx)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if err := enc.Encode(declarationRecord{
			Record:   "declaration",
			Digest:   wire.DeclarationHash(raw),
			Document: json.RawMessage(raw),
		}); err != nil {
			return fmt.Errorf("write declaration for %s: %w", name, err)
		}
		sent++
	}
	if sent == 0 {
		// The hub can render nothing and serve no tool without axes, and
		// it refuses a checkpoint that arrives without them. Saying so
		// here names WHICH collectors were unreachable; letting the hub
		// refuse would only say that none arrived.
		return fmt.Errorf("no declaration could be read (%v); a checkpoint without "+
			"fact axes would be refused by the hub", failed)
	}
	if err := WriteCheckpoint(w, st, id, host, bootID, gap); err != nil {
		return err
	}
	if failed != nil {
		return fmt.Errorf("session sent, with %d collector(s) undeclared: %v",
			len(failed), failed)
	}
	return nil
}

func sortedNames(collectors map[string]Declarer) []string {
	names := make([]string, 0, len(collectors))
	for name := range collectors {
		names = append(names, name)
	}
	// Deterministic order: a session that varied its order between runs
	// would make a captured one impossible to compare against another.
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j] < names[j-1]; j-- {
			names[j], names[j-1] = names[j-1], names[j]
		}
	}
	return names
}
