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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

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

// DeclarationDigest is the digest a session frames a declaration with —
// exported so anything staging a store for a session stamps the SAME
// value the session will send. Getting the two out of step produces a
// manifest naming a hash the hub does not hold, which it refuses.
func DeclarationDigest(raw []byte) string { return wire.DeclarationHash(raw) }

// ClientConfig builds the collator's side of the mutual identity.
//
// The collator holds exactly one credential of its own — this one — and
// it is a different category from anything it observes: an identity for
// the collator as a network participant, useless for reading anything on
// the host. RootCAs is the hub's authority, and it is REQUIRED rather
// than defaulted to the system pool: a collator that would accept any
// publicly-trusted certificate would accept a hub it was never told
// about, which is the whole of what the reversal put at stake.
func ClientConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("client identity: %w", err)
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("hub authority: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("hub authority %s holds no certificate", caFile)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// Session is one dial: connect, write the whole session, close.
//
// Close is deliberate rather than incidental. A collator holds the
// connection open for the stream that follows a checkpoint, and until
// that stream exists a session that lingered would leave the hub holding
// a host as `connected` while nothing was coming — which is exactly the
// state `dark` is for. Closing makes the honest reading the automatic
// one.
func Session(
	ctx context.Context,
	addr string,
	cfg *tls.Config,
	st *store.Store,
	collectors map[string]Declarer,
	id, host, bootID string,
	gap *HistoryGap,
) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	var err error
	if cfg != nil {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, cfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("dial hub %s: %w", addr, err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	return WriteSession(ctx, conn, st, collectors, id, host, bootID, gap)
}
