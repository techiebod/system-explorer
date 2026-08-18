// Package store is the collator's durable state: applied objects, the
// generation authority, refusals, and batch acknowledgements. SQLite in
// WAL mode with synchronous=FULL, because the batch authority rules
// (DESIGN §19) hang off one promise — applying a collection and
// advancing its generation are ONE durable transaction, so a collator
// that dies mid-apply comes back having done all of it or none.
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure Go, so the linux/amd64 CGO_ENABLED=0 target holds
)

// Crashpoint kills the process at a named boundary from
// harness/crash/boundaries.json when SE_CRASH_AT selects it. It lives in
// this package rather than beside the loop because the one boundary that
// must sit inside a transaction (mid-apply) is inside this package, and
// store cannot import the package that drives it.
func Crashpoint(id string) {
	if os.Getenv("SE_CRASH_AT") == id {
		// 137 is SIGKILL's exit status: the point is to be indistinguishable
		// from the kernel killing us, because that is what is being rehearsed.
		os.Exit(137)
	}
}

// Store wraps one SQLite database. A single connection serialises writers
// and readers in-process; cross-process readers (the crash tests) come in
// through WAL.
type Store struct {
	db *sql.DB
}

// HostNative is the scope value for instance=null batches. The wire
// refuses "" as an instance, so using it as the storage key for null
// cannot collide with a real instance name.
const HostNative = ""

const schema = `
CREATE TABLE IF NOT EXISTS collections (
  name         TEXT PRIMARY KEY,
  issued_gen   INTEGER NOT NULL DEFAULT 0,
  applied_gen  INTEGER NOT NULL DEFAULT 0,
  applied_at   TEXT,
  content_hash TEXT,
  boot_id      TEXT,
  stale        INTEGER NOT NULL DEFAULT 0,
  stale_reason TEXT
);
CREATE TABLE IF NOT EXISTS objects (
  collection TEXT NOT NULL,
  scope      TEXT NOT NULL,
  id         TEXT NOT NULL,
  name       TEXT NOT NULL,
  facts      TEXT NOT NULL,
  names      TEXT,
  absent     TEXT,
  at         REAL NOT NULL,
  PRIMARY KEY (collection, scope, id)
);
CREATE TABLE IF NOT EXISTS rejections (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  at_wall    TEXT NOT NULL,
  collection TEXT,
  batch      TEXT,
  reason     TEXT NOT NULL,
  detail     TEXT
);
CREATE TABLE IF NOT EXISTS acks (
  batch        TEXT PRIMARY KEY,
  generations  TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  applied_wall TEXT NOT NULL
);
`

// Open creates or opens the store at path and applies the schema.
func Open(path string) (*Store, error) {
	// _pragma values ride the DSN so every new connection gets them:
	// WAL for multi-process readers, FULL because "durable" here means
	// surviving the machine dying, not only the process. Only ? and # are
	// escaped: they end the URI path early, and SQLite %-decodes the rest.
	escaped := strings.NewReplacer("?", "%3F", "#", "%23").Replace(path)
	dsn := "file:" + escaped +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection: the apply path must never interleave with itself,
	// and the read load (one host's REST) does not need a pool.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema + relationSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func wallNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// IssueGenerations mints a fresh generation for each named collection —
// monotonic and persisted BEFORE any collect request goes out, so a
// crash between issuing and applying can never lead to a reuse. A fresh
// acquisition always takes a new generation; only re-sending bytes
// already captured may reuse one (DESIGN §19).
func (s *Store) IssueGenerations(names []string) (map[string]uint64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	issued := map[string]uint64{}
	for _, name := range names {
		var gen uint64
		err := tx.QueryRow(`
			INSERT INTO collections (name, issued_gen) VALUES (?, 1)
			ON CONFLICT(name) DO UPDATE SET issued_gen = issued_gen + 1
			RETURNING issued_gen`, name).Scan(&gen)
		if err != nil {
			return nil, fmt.Errorf("issue generation for %s: %w", name, err)
		}
		issued[name] = gen
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return issued, nil
}

// Object is one applied object as the store keeps it: the minted id, the
// native name the collector published, every name family it published,
// and the at stamp verbatim — freshness derives from that stamp, never
// from arrival time (acceptance item 5).
type Object struct {
	ID     string
	Name   string
	Facts  json.RawMessage
	Names  json.RawMessage
	Absent []string
	At     float64
}

// MintID forms the object id the collator owns: "<collection>:<native-name>".
// Scope (host, instance) is carried beside it, not inside it — two
// instances publishing the same native name mint the same string under
// different scopes and never merge (acceptance item 1).
func MintID(collection, name string) string {
	return collection + ":" + name
}

// HashObjects is the content identity of an applied object set: SHA-256
// over a canonical serialisation, sorted by id. Equal generation + equal
// hash is the re-delivered batch (a no-op); equal generation + different
// hash is someone reusing a generation (a protocol error).
func HashObjects(objects []Object) string {
	sorted := make([]Object, len(objects))
	copy(sorted, objects)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	h := sha256.New()
	enc := json.NewEncoder(h)
	for _, o := range sorted {
		// A fixed-field struct, not the raw stream bytes: the wire already
		// canonicalised facts/names (sorted keys, source number lexemes),
		// so two byte-identical retransmissions hash equal and key-order
		// shuffles do not masquerade as new content.
		_ = enc.Encode(struct {
			ID     string          `json:"id"`
			Name   string          `json:"name"`
			Facts  json.RawMessage `json:"facts"`
			Names  json.RawMessage `json:"names"`
			Absent []string        `json:"absent"`
			At     float64         `json:"at"`
		}{o.ID, o.Name, o.Facts, o.Names, o.Absent, o.At})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Outcome is what ApplyCommit did, for the caller to record and for the
// tests to assert on.
type Outcome string

const (
	OutcomeApplied       Outcome = "applied"
	OutcomeNoop          Outcome = "noop-identical"
	OutcomeRefusedBelow  Outcome = "refused-below-applied"
	OutcomeProtocolError Outcome = "generation-reused-different-content"
)

// ApplyCommit is the batch authority (DESIGN §19, acceptance items 2 and
// 4), one durable transaction:
//
//   - generation below applied  → refused, recorded, nothing changes
//   - equal, identical content  → no-op — what makes a re-delivered batch safe
//   - equal, different content  → protocol error, recorded, never merged
//   - above                     → prior objects of this scope retired, the
//     emitted set applied, generation advanced, staleness cleared
//
// An empty object set is the absent decline's authoritative emptiness:
// the same path, applying zero objects, which retires everything and
// leaves the collection not stale (acceptance item 2).
//
// bootID is the batch's begin.boot_id, stored beside the applied set:
// the at stamps are readings on that boot's clock and mean nothing
// outside it (DESIGN §09), so the read API must be able to compare it
// against the collator's own domain and state a mismatch. Required,
// because an apply whose clock domain is unknown serves uninterpretable
// ages — the authority must not depend on its caller's diligence.
func (s *Store) ApplyCommit(collection, scope string, gen uint64, batch, bootID string, objects []Object) (Outcome, error) {
	if bootID == "" {
		return "", fmt.Errorf("collection %s: apply without a boot id", collection)
	}
	hash := HashObjects(objects)
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var issuedGen, appliedGen uint64
	var appliedHash sql.NullString
	err = tx.QueryRow(`SELECT issued_gen, applied_gen, content_hash FROM collections WHERE name = ?`,
		collection).Scan(&issuedGen, &appliedGen, &appliedHash)
	if err == sql.ErrNoRows {
		// A commit for a collection that was never issued a generation:
		// the wire refuses this before it gets here, but the authority
		// must not depend on its caller's diligence.
		return "", fmt.Errorf("collection %s has no generation row", collection)
	}
	if err != nil {
		return "", err
	}

	// Deny-by-default on the high side too: a generation this authority
	// never issued cannot be applied, however new it claims to be. The
	// wire's echo check catches this earlier, but the authority must not
	// depend on its caller's diligence.
	if gen > issuedGen {
		return "", fmt.Errorf("collection %s: generation %d was never issued (issued is %d)",
			collection, gen, issuedGen)
	}
	if gen < appliedGen {
		if err := record(tx, collection, batch, string(OutcomeRefusedBelow),
			fmt.Sprintf("commit at generation %d, applied is %d", gen, appliedGen)); err != nil {
			return "", err
		}
		return OutcomeRefusedBelow, tx.Commit()
	}
	if gen == appliedGen {
		if appliedHash.Valid && appliedHash.String == hash {
			// Identical content at the applied generation: the transport
			// retry. Nothing to do, and nothing to record — safe is silent.
			return OutcomeNoop, nil
		}
		if err := record(tx, collection, batch, string(OutcomeProtocolError),
			fmt.Sprintf("generation %d re-used with different content", gen)); err != nil {
			return "", err
		}
		return OutcomeProtocolError, tx.Commit()
	}

	// Above applied: everything a committed collection did not emit is
	// gone — deletion is expressed by absence from the committed set.
	if _, err := tx.Exec(`DELETE FROM objects WHERE collection = ? AND scope = ?`,
		collection, scope); err != nil {
		return "", err
	}
	for _, o := range objects {
		absent := sql.NullString{}
		if o.Absent != nil {
			raw, err := json.Marshal(o.Absent)
			if err != nil {
				return "", err
			}
			absent = sql.NullString{String: string(raw), Valid: true}
		}
		names := sql.NullString{}
		if o.Names != nil {
			names = sql.NullString{String: string(o.Names), Valid: true}
		}
		if _, err := tx.Exec(`
			INSERT INTO objects (collection, scope, id, name, facts, names, absent, at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			collection, scope, o.ID, o.Name, string(o.Facts), names, absent, o.At); err != nil {
			return "", fmt.Errorf("apply object %s: %w", o.ID, err)
		}
	}
	if _, err := tx.Exec(`
		UPDATE collections
		SET applied_gen = ?, applied_at = ?, content_hash = ?, boot_id = ?, stale = 0, stale_reason = NULL
		WHERE name = ?`,
		gen, wallNow(), hash, bootID, collection); err != nil {
		return "", err
	}

	// harness/crash/boundaries.json mid-apply — "all of it or none of it;
	// a generation may never advance over unapplied objects". Dying here,
	// after every write and before COMMIT, is exactly the case SQLite's
	// rollback journal must erase on the next open.
	Crashpoint("mid-apply")

	return OutcomeApplied, tx.Commit()
}

func record(tx *sql.Tx, collection, batch, reason, detail string) error {
	_, err := tx.Exec(`
		INSERT INTO rejections (at_wall, collection, batch, reason, detail)
		VALUES (?, ?, ?, ?, ?)`, wallNow(), collection, batch, reason, detail)
	return err
}

// MarkStale is the effect of the three non-absent declines: prior objects
// stand and are served marked stale, because nothing was established
// (acceptance item 2). It touches neither objects nor generation.
func (s *Store) MarkStale(collection, reason string) error {
	_, err := s.db.Exec(`
		UPDATE collections SET stale = 1, stale_reason = ? WHERE name = ?`,
		reason, collection)
	return err
}

// RecordRejection notes a batch or collection the authority refused to
// apply, outside any apply transaction — wire violations, declaration
// mismatches, uncommitted collections, transport failures.
func (s *Store) RecordRejection(collection, batch, reason, detail string) error {
	_, err := s.db.Exec(`
		INSERT INTO rejections (at_wall, collection, batch, reason, detail)
		VALUES (?, ?, ?, ?, ?)`, wallNow(), collection, batch, reason, detail)
	return err
}

// Acked reports whether a batch id has already been acknowledged. The
// judging form is JudgeAcked; this exists for the tests and the crash
// harness, which ask about the id alone.
func (s *Store) Acked(batch string) (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM acks WHERE batch = ?`, batch).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// AckOutcome is what an arriving batch id means against the ack table.
type AckOutcome string

const (
	// AckNew: never acknowledged — the generation rules govern it.
	AckNew AckOutcome = "new"
	// AckRetry: same id, same echoed generations, same bytes — the one
	// retry the contract promises safe, and safe is silent.
	AckRetry AckOutcome = "retry-noop"
	// AckReused: same id with different generations or content. A
	// transport retry is same-bytes-same-id; a second look at the system
	// is a different event, so this is a recorded protocol error.
	AckReused AckOutcome = "batch-id-reused"
)

func encodeGenerations(generations map[string]uint64) string {
	// json.Marshal sorts map keys, so this is canonical per content.
	raw, err := json.Marshal(generations)
	if err != nil {
		return "" // unreachable for a string-keyed map of integers
	}
	return string(raw)
}

// JudgeAcked compares an arriving batch against the acknowledgement its
// id already carries, if any. The reuse rejection is recorded HERE, in
// the authority, so no caller can turn a protocol error into a silent
// skip — an ack table that answered only "seen" disabled every future
// acquisition from a collector minting stable batch ids.
func (s *Store) JudgeAcked(batch string, generations map[string]uint64, contentHash string) (AckOutcome, error) {
	var storedGens, storedHash string
	err := s.db.QueryRow(`SELECT generations, content_hash FROM acks WHERE batch = ?`,
		batch).Scan(&storedGens, &storedHash)
	if err == sql.ErrNoRows {
		return AckNew, nil
	}
	if err != nil {
		return "", err
	}
	gens := encodeGenerations(generations)
	if storedGens == gens && storedHash == contentHash {
		return AckRetry, nil
	}
	detail := fmt.Sprintf(
		"batch id %s was acknowledged with generations %s; it re-arrived with generations %s and %s content — "+
			"a transport retry is same-bytes-same-id, and a second look at the system takes a fresh batch id",
		batch, storedGens, gens, sameOrDifferent(storedHash, contentHash))
	if err := s.RecordRejection("", batch, string(AckReused), detail); err != nil {
		return "", err
	}
	return AckReused, nil
}

func sameOrDifferent(a, b string) string {
	if a == b {
		return "identical"
	}
	return "different"
}

// RecordAck acknowledges an applied batch, carrying the echoed
// generations and the content hash so JudgeAcked can later tell a
// re-delivery of these bytes from a reuse of this id. Deliberately
// outside the apply transaction: the post-apply-pre-ack boundary exists
// because these are two durability events, and the recovery for losing
// the second is the equal-generation no-op, not a merge.
func (s *Store) RecordAck(batch string, generations map[string]uint64, contentHash string) error {
	_, err := s.db.Exec(`
		INSERT INTO acks (batch, generations, content_hash, applied_wall) VALUES (?, ?, ?, ?)
		ON CONFLICT(batch) DO NOTHING`, batch, encodeGenerations(generations), contentHash, wallNow())
	return err
}

// CollectionState is one row of the authority's public accounting.
// BootID is the boot domain of the last applied batch — the clock the
// objects' at stamps were read on; nil only before any apply.
type CollectionState struct {
	Name        string
	Generation  uint64
	AppliedAt   *string
	OldestAt    *float64
	BootID      *string
	ObjectCount int
	Stale       bool
	StaleReason *string
}

// Collections reports every known collection. OldestAt is MIN(at) over
// the applied objects: a collection's served freshness derives from the
// oldest contributing read, never from arrival time (acceptance item 5).
func (s *Store) Collections() ([]CollectionState, error) {
	rows, err := s.db.Query(`
		SELECT c.name, c.applied_gen, c.applied_at, c.boot_id, c.stale, c.stale_reason,
		       (SELECT COUNT(*) FROM objects o WHERE o.collection = c.name),
		       (SELECT MIN(o.at) FROM objects o WHERE o.collection = c.name)
		FROM collections c ORDER BY c.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CollectionState
	for rows.Next() {
		var cs CollectionState
		var appliedAt, bootID, staleReason sql.NullString
		var stale int
		var oldest sql.NullFloat64
		if err := rows.Scan(&cs.Name, &cs.Generation, &appliedAt, &bootID, &stale,
			&staleReason, &cs.ObjectCount, &oldest); err != nil {
			return nil, err
		}
		if appliedAt.Valid {
			cs.AppliedAt = &appliedAt.String
		}
		if bootID.Valid {
			cs.BootID = &bootID.String
		}
		if staleReason.Valid {
			cs.StaleReason = &staleReason.String
		}
		if oldest.Valid {
			cs.OldestAt = &oldest.Float64
		}
		cs.Stale = stale != 0
		out = append(out, cs)
	}
	return out, rows.Err()
}

// ObjectRow is one served object.
type ObjectRow struct {
	ID    string
	Name  string
	Facts json.RawMessage
	At    float64
}

// Objects lists a collection's applied objects, every scope, ordered by
// id for a stable read.
func (s *Store) Objects(collection string) ([]ObjectRow, error) {
	rows, err := s.db.Query(`
		SELECT id, name, facts, at FROM objects
		WHERE collection = ? ORDER BY scope, id`, collection)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ObjectRow
	for rows.Next() {
		var o ObjectRow
		var facts string
		if err := rows.Scan(&o.ID, &o.Name, &facts, &o.At); err != nil {
			return nil, err
		}
		o.Facts = json.RawMessage(facts)
		out = append(out, o)
	}
	return out, rows.Err()
}

// HasCollection reports whether the authority knows the name at all —
// the 404 boundary for the read API.
func (s *Store) HasCollection(name string) (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM collections WHERE name = ?`, name).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// Rejection is one recorded refusal, exposed for tests and for the loop's
// own accounting.
type Rejection struct {
	Collection string
	Batch      string
	Reason     string
	Detail     string
}

// Rejections lists recorded refusals in arrival order.
func (s *Store) Rejections() ([]Rejection, error) {
	rows, err := s.db.Query(`
		SELECT COALESCE(collection, ''), COALESCE(batch, ''), reason, COALESCE(detail, '')
		FROM rejections ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rejection
	for rows.Next() {
		var r Rejection
		if err := rows.Scan(&r.Collection, &r.Batch, &r.Reason, &r.Detail); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
