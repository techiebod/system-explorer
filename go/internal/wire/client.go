// The transport half of the wire: dial the collector's unix socket, write
// one request line, read to EOF under a ceiling and a deadline. The
// collector never opens a socket itself — systemd hands it the accepted
// connection as stdin/stdout — so from here the wire contract and the
// command-line contract are the same contract (DESIGN §18).
package wire

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"time"
)

const (
	// DefaultByteCeiling bounds one response. A ceiling is a scope error
	// made visible, not a transport limit to paginate around (DESIGN §19):
	// exceeding it voids the batch rather than truncating it silently.
	DefaultByteCeiling = 4 << 20
	// DefaultDeadline bounds one exchange end to end. A hung collector is
	// systemd's RuntimeMaxSec problem; a hung read here must not wedge the
	// acquisition loop.
	DefaultDeadline = 30 * time.Second
)

// Client speaks to one collector socket. The zero value is unusable;
// callers set Socket and may narrow the bounds (tests do).
type Client struct {
	Socket      string
	ByteCeiling int64
	Deadline    time.Duration
}

func (c *Client) ceiling() int64 {
	if c.ByteCeiling > 0 {
		return c.ByteCeiling
	}
	return DefaultByteCeiling
}

func (c *Client) deadline() time.Duration {
	if c.Deadline > 0 {
		return c.Deadline
	}
	return DefaultDeadline
}

// exchange writes one request line and reads the whole response. The
// request line is data on both sides: it is written as one bounded line
// and never interpolated into anything (DESIGN §18).
func (c *Client) exchange(ctx context.Context, request string) ([]byte, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", c.Socket, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(c.deadline())); err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte(request + "\n")); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}
	// Half-close where the transport allows it, so a collector reading
	// stdin to EOF is not left waiting for a second line.
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	// Read one byte past the ceiling: the only way to tell "exactly at
	// the limit" from "over it" without trusting a length nobody sent.
	limited := io.LimitedReader{R: conn, N: c.ceiling() + 1}
	raw, err := io.ReadAll(&limited)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if limited.N == 0 {
		return nil, &Violation{Reason: "byte-ceiling-exceeded",
			Detail: fmt.Sprintf("response exceeds %d bytes", c.ceiling())}
	}
	return raw, nil
}

// Declare fetches the declaration document: the exact canonical bytes,
// which are also the input to the hash that begin.declaration must echo.
func (c *Client) Declare(ctx context.Context) ([]byte, error) {
	raw, err := c.exchange(ctx, "declare")
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("declare returned nothing")
	}
	return raw, nil
}

// Collect issues one acquisition for the given collections at their
// issued generations and returns the validated batch. Any structural
// violation surfaces as *Violation and the batch is nothing.
func (c *Client) Collect(ctx context.Context, issued map[string]uint64) (*Batch, error) {
	if len(issued) == 0 {
		return nil, fmt.Errorf("no collections to collect")
	}
	names := make([]string, 0, len(issued))
	for name := range issued {
		names = append(names, name)
	}
	sort.Strings(names)
	request := "collect"
	for _, name := range names {
		request += fmt.Sprintf(" %s:%d", name, issued[name])
	}
	raw, err := c.exchange(ctx, request)
	if err != nil {
		return nil, err
	}
	return ParseBatch(raw, issued)
}

// ContentHash is the "sha256:<hex>" commitment over the exact bytes of
// one exchange. For a stream it is the transport-retry identity: a retry
// is same-bytes-same-id (DESIGN §19), so equal hashes under one batch id
// mean the retry and unequal ones mean the id was reused.
func ContentHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// DeclarationHash is the same commitment over the bytes declare emitted —
// the value begin.declaration must carry.
func DeclarationHash(raw []byte) string {
	return ContentHash(raw)
}

// Declaration is the thin slice of se.declaration/1 the collator core
// needs: which collections exist and how fresh each claims to be. The
// full document is validated by the contract suite, not re-validated
// here — the collator consumes it, it does not judge it.
type Declaration struct {
	Collector   string                  `json:"collector"`
	Collections []DeclarationCollection `json:"collections"`
}

type DeclarationCollection struct {
	Name      string `json:"name"`
	Freshness string `json:"freshness"`
}

// ParseDeclaration extracts the slice above and parses each freshness.
func ParseDeclaration(raw []byte) (*Declaration, map[string]time.Duration, error) {
	var d Declaration
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, nil, fmt.Errorf("declaration does not parse: %w", err)
	}
	if len(d.Collections) == 0 {
		return nil, nil, fmt.Errorf("declaration names no collections")
	}
	freshness := map[string]time.Duration{}
	for _, col := range d.Collections {
		if !collectionName.MatchString(col.Name) {
			return nil, nil, fmt.Errorf("declaration collection name %q", col.Name)
		}
		dur, err := ParseFreshness(col.Freshness)
		if err != nil {
			return nil, nil, fmt.Errorf("collection %s: %w", col.Name, err)
		}
		freshness[col.Name] = dur
	}
	return &d, freshness, nil
}

// ParseFreshness reads the contract's freshness grammar ^[0-9]+(ms|s|m|h|d)$.
// The unit is part of the value — a bare number would be read as seconds
// by one consumer and milliseconds by another — so a missing unit is an
// error here, never a default.
func ParseFreshness(s string) (time.Duration, error) {
	units := []struct {
		suffix string
		unit   time.Duration
	}{
		// ms before s and m: longest suffix first, or "500ms" parses as
		// 50 zero-minutes... it does not, but the order makes it obvious.
		{"ms", time.Millisecond},
		{"s", time.Second},
		{"m", time.Minute},
		{"h", time.Hour},
		{"d", 24 * time.Hour},
	}
	for _, u := range units {
		if len(s) > len(u.suffix) && s[len(s)-len(u.suffix):] == u.suffix {
			digits := s[:len(s)-len(u.suffix)]
			var n int64
			for _, r := range digits {
				if r < '0' || r > '9' {
					return 0, fmt.Errorf("freshness %q is not <digits><unit>", s)
				}
				n = n*10 + int64(r-'0')
				if n > 1<<40 {
					return 0, fmt.Errorf("freshness %q is out of range", s)
				}
			}
			return time.Duration(n) * u.unit, nil
		}
	}
	return 0, fmt.Errorf("freshness %q has no unit from ms|s|m|h|d", s)
}
