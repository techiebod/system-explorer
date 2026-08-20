// The checkpoint a collator sends after connecting to a hub, rendered
// from the store as NDJSON (DESIGN §06, contract/se.checkpoint.1.json).
//
// A hub that only receives has no way of its own to know when it knows
// enough to answer, so completeness is explicit rather than inferred:
// the manifest opens by naming EVERY declared collection — including the
// ones that have never applied — and the terminal closes by counting the
// state records that went between them. Nothing is visible to a roll-up,
// a problem domain or a projection until the terminal arrives.
//
// The whole of this file is deliberately a pure function of the store
// plus its four parameters: the wire has no clock, no network and no
// retry in it, so what a checkpoint says can be asserted without one.
package collate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/techiebod/system-explorer/go/internal/store"
)

// nilUUID is the documented "no boot id" sentinel. A checkpoint carrying
// it would claim a clock domain that does not exist, and every `at` in
// it would be uninterpretable — so it is refused here rather than at the
// hub, where the whole checkpoint would be discarded instead of one
// misconfigured collator being told why.
const nilUUID = "00000000-0000-0000-0000-000000000000"

// ErrNothingToCheckpoint is a collator that knows no collection at all —
// a daemon started with no collectors, or one whose first acquisition has
// not run. It is a legitimate state and NOT an error to log as a fault:
// the caller waits and checkpoints when there is something to say. The
// manifest cannot express it, because a manifest with no collections
// would make "I have nothing" and "I sent you nothing" the same record.
var ErrNothingToCheckpoint = errors.New("collator declares no collection")

// HistoryGap is the interval over which transitions were not delivered.
// Nil means a first connection with nothing to have missed, and it
// serialises as an explicit null: a missing member and a stated absence
// of gap are the difference between a timeline with a hole in it and a
// timeline that says where its hole is.
type HistoryGap struct {
	From float64 `json:"from"`
	To   float64 `json:"to"`
}

type manifestEntry struct {
	Collection  string  `json:"collection"`
	Generation  uint64  `json:"generation"`
	Freshness   string  `json:"freshness"`
	StaleReason *string `json:"stale_reason,omitempty"`
	Objects     int     `json:"objects"`
}

type manifestRecord struct {
	Record       string          `json:"record"`
	Checkpoint   string          `json:"checkpoint"`
	Host         string          `json:"host"`
	BootID       string          `json:"boot_id"`
	Collections  []manifestEntry `json:"collections"`
	Declarations []string        `json:"declarations"`
}

// checkpointObject carries `instance` for the same reason objectView
// does: two instances mint one id string, so a hub handed rows without
// it would merge them — acceptance item 1, at the tier the item's hub
// half is judged in.
type checkpointObject struct {
	ID       string          `json:"id"`
	Instance *string         `json:"instance"`
	Name     string          `json:"name"`
	Facts    json.RawMessage `json:"facts"`
	At       float64         `json:"at"`
}

type collectionStateRecord struct {
	Record     string             `json:"record"`
	Checkpoint string             `json:"checkpoint"`
	Collection string             `json:"collection"`
	Generation uint64             `json:"generation"`
	Objects    []checkpointObject `json:"objects"`
	// Absent when the collection declares no rules; an empty array when it
	// declares some and none fired. Different readings, so omitempty would
	// be wrong — the pointer is what keeps them apart.
	Opinions *[]Opinion `json:"opinions,omitempty"`
}

type terminalRecord struct {
	Record      string      `json:"record"`
	Checkpoint  string      `json:"checkpoint"`
	Collections int         `json:"collections"`
	HistoryGap  *HistoryGap `json:"history_gap"`
}

// WriteCheckpoint renders one checkpoint for host under bootID, tagged
// id, onto w. Host is a parameter rather than a reading: the transport's
// idea of who dialled is not a reading of the machine, and a NAT-mode
// dial makes it wrong.
//
// What it refuses, and why each refusal is here rather than at the hub:
// a nil boot id (every `at` would be uninterpretable), a collection whose
// declaration hash the store cannot name (the hub would fetch a hash
// nobody holds), and an empty authority (ErrNothingToCheckpoint). What
// it does NOT check is the JSON Schema — shapes are pinned by the types
// above and validated in the conformance suite, which is the only place
// the schema file itself is the judge.
func WriteCheckpoint(w io.Writer, st *store.Store, id, host, bootID string, gap *HistoryGap) error {
	switch {
	case strings.TrimSpace(id) == "":
		return errors.New("checkpoint id is empty")
	case strings.TrimSpace(host) == "":
		return errors.New("checkpoint host is empty")
	case bootID == "" || bootID == nilUUID:
		return fmt.Errorf("checkpoint boot id %q names no clock domain", bootID)
	}

	states, err := st.Collections()
	if err != nil {
		return fmt.Errorf("read collections: %w", err)
	}
	if len(states) == 0 {
		return ErrNothingToCheckpoint
	}

	entries := make([]manifestEntry, 0, len(states))
	seenDecl := map[string]bool{}
	var declarations []string
	for _, cs := range states {
		if cs.Declaration == nil {
			// Refused rather than omitted. Omitting the collection would
			// make the manifest's completeness unfalsifiable — the exact
			// property it exists to provide — and inventing a hash would
			// send the hub to fetch something nothing holds. Reachable
			// only from a store written before the declaration column,
			// and it clears the next time that collector acquires.
			return fmt.Errorf("collection %s names no declaration; "+
				"it cannot be checkpointed until its collector acquires once", cs.Name)
		}
		if !seenDecl[*cs.Declaration] {
			seenDecl[*cs.Declaration] = true
			declarations = append(declarations, *cs.Declaration)
		}
		e := manifestEntry{
			Collection: cs.Name,
			Generation: cs.Generation,
			Freshness:  "current",
			Objects:    cs.ObjectCount,
		}
		if cs.Stale {
			e.Freshness = "stale"
			e.StaleReason = cs.StaleReason
		}
		entries = append(entries, e)
	}

	enc := json.NewEncoder(w)
	if err := enc.Encode(manifestRecord{
		Record: "manifest", Checkpoint: id, Host: host, BootID: bootID,
		Collections: entries, Declarations: declarations,
	}); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	sent := 0
	for _, cs := range states {
		// Generation 0 has never applied, so there is no state to send —
		// which is why the manifest lists it and the stream does not, and
		// why the hub can tell a collection that is empty from one that
		// never ran.
		if cs.Generation == 0 {
			continue
		}
		rows, err := st.Objects(cs.Name)
		if err != nil {
			return fmt.Errorf("read objects for %s: %w", cs.Name, err)
		}
		// Never nil: an empty array is the reading that a decline of
		// `absent` leaves behind, and null would be a different claim.
		document, err := st.DeclarationFor(cs.Name)
		if err != nil {
			return fmt.Errorf("read declaration for %s: %w", cs.Name, err)
		}
		secrets, err := SecretFacts(document, cs.Name)
		if err != nil {
			return fmt.Errorf("%s: %w", cs.Name, err)
		}
		objects := make([]checkpointObject, 0, len(rows))
		for _, o := range rows {
			co := checkpointObject{ID: o.ID, Name: o.Name, Facts: o.Facts, At: o.At}
			// A declared credential never leaves this process, on any
			// channel. It should not have been stored either; dropping it
			// on the way out is what makes that true of collectors this
			// repository does not ship.
			if len(secrets) > 0 {
				co.Facts = withoutSecrets(o.Facts, secrets)
			}
			if o.Scope != store.HostNative {
				co.Instance = &o.Scope
			}
			objects = append(objects, co)
		}
		// Self-evident opinions, minted here because this is the lowest
		// tier that can reach the facts (law 2). A declaration the store
		// cannot produce yields no rules and no opinions member at all,
		// which says "cannot evaluate" rather than "nothing is wrong".
		var opinions *[]Opinion
		rules, err := RulesFor(document, cs.Name)
		if err != nil {
			return fmt.Errorf("%s: %w", cs.Name, err)
		}
		if rules != nil {
			fired := []Opinion{}
			for _, o := range objects {
				var facts map[string]any
				if err := json.Unmarshal(o.Facts, &facts); err != nil {
					continue
				}
				fired = append(fired, Judge(rules, o.ID, o.Instance, facts)...)
			}
			opinions = &fired
		}
		if err := enc.Encode(collectionStateRecord{
			Record: "collection_state", Checkpoint: id, Collection: cs.Name,
			Generation: cs.Generation, Objects: objects, Opinions: opinions,
		}); err != nil {
			return fmt.Errorf("write state for %s: %w", cs.Name, err)
		}
		sent++
	}

	if err := enc.Encode(terminalRecord{
		Record: "terminal", Checkpoint: id, Collections: sent, HistoryGap: gap,
	}); err != nil {
		return fmt.Errorf("write terminal: %w", err)
	}
	return nil
}


// withoutSecrets drops declared credentials from a fact mapping, keeping
// everything else byte-identical where it can.
func withoutSecrets(raw json.RawMessage, secrets map[string]bool) json.RawMessage {
	var facts map[string]json.RawMessage
	if json.Unmarshal(raw, &facts) != nil {
		// Unreadable facts are sent as they were rather than silently
		// blanked: this function withholds credentials, and pretending it
		// can parse what it cannot would be a different claim.
		return raw
	}
	changed := false
	for name := range facts {
		if secrets[name] {
			delete(facts, name)
			changed = true
		}
	}
	if !changed {
		return raw
	}
	out, err := json.Marshal(facts)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return out
}
