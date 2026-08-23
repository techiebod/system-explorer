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
  stale_reason TEXT,
  declaration  TEXT
);
CREATE TABLE IF NOT EXISTS objects (
  collection TEXT NOT NULL,
  scope      TEXT NOT NULL,
  id         TEXT NOT NULL,
  name       TEXT NOT NULL,
  type       TEXT,
  facts      TEXT NOT NULL,
  names      TEXT,
  absent     TEXT,
  at         REAL NOT NULL,
  seq        INTEGER NOT NULL DEFAULT 0,
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
CREATE TABLE IF NOT EXISTS declarations (
  digest    TEXT PRIMARY KEY,
  document  TEXT NOT NULL,
  seen_wall TEXT NOT NULL
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
	if _, err := db.Exec(schema + relationSchema + recordSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// migrate adds columns that CREATE TABLE IF NOT EXISTS cannot: an
// existing store keeps the table it already has, so a new column has to
// be asked for by name. Additive only, and each step names the store it
// is upgrading FROM, because a migration nobody can date is one nobody
// can reason about.
//
// The `declaration` column was added on 2026-08-20 for the checkpoint's
// manifest, which must name the declaration each collection was learned
// under. A store written before it carries NULL, and BuildCheckpoint
// refuses to invent a hash for those rows rather than sending one the
// hub would fetch and fail to match.
func migrate(db *sql.DB) error {
	// The snapshots table gained `format` on 2026-08-23, when the
	// diffable object gained `scope`. A store written before it carries
	// 0, which ChangesSince refuses to compare against — a reading whose
	// shape predates the change is not a baseline, and saying so beats
	// reporting every object as added and removed at once.
	if _, err := db.Exec(
		`ALTER TABLE snapshots ADD COLUMN format INTEGER NOT NULL DEFAULT 0`,
	); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("add snapshots.format: %w", err)
	}
	var has bool
	rows, err := db.Query(`SELECT name FROM pragma_table_info('collections')`)
	if err != nil {
		return fmt.Errorf("inspect collections: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		if name == "declaration" {
			has = true
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !has {
		if _, err := db.Exec(`ALTER TABLE collections ADD COLUMN declaration TEXT`); err != nil {
			return fmt.Errorf("add collections.declaration: %w", err)
		}
	}
	// `type` and `seq` were added on 2026-08-21 (PLAN R1): the object's
	// structural kind, and the applied order — which the old store
	// DISCARDED by serving id-sorted rows, while both implementations of
	// units record that the systemctl-status order is the collection.
	// Rows written before the columns carry "" and 0; a whole-collection
	// re-apply (the ordinary case) replaces both.
	objectCols := map[string]bool{}
	orows, err := db.Query(`SELECT name FROM pragma_table_info('objects')`)
	if err != nil {
		return fmt.Errorf("inspect objects: %w", err)
	}
	defer orows.Close()
	for orows.Next() {
		var name string
		if err := orows.Scan(&name); err != nil {
			return err
		}
		objectCols[name] = true
	}
	if err := orows.Err(); err != nil {
		return err
	}
	if !objectCols["type"] {
		if _, err := db.Exec(`ALTER TABLE objects ADD COLUMN type TEXT`); err != nil {
			return fmt.Errorf("add objects.type: %w", err)
		}
	}
	if !objectCols["seq"] {
		if _, err := db.Exec(`ALTER TABLE objects ADD COLUMN seq INTEGER NOT NULL DEFAULT 0`); err != nil {
			return fmt.Errorf("add objects.seq: %w", err)
		}
	}
	// `cost_cpu_ms` was added on 2026-08-21 (register row 16): the
	// collector's own commit-record account of what the collection cost,
	// advisory by construction (DESIGN 19). NULL means "never reported",
	// which is a different reading from a reported zero.
	crows, err := db.Query(`SELECT name FROM pragma_table_info('collections') WHERE name = 'cost_cpu_ms'`)
	if err != nil {
		return fmt.Errorf("inspect collections cost: %w", err)
	}
	hasCost := crows.Next()
	if err := crows.Close(); err != nil {
		return err
	}
	if !hasCost {
		if _, err := db.Exec(`ALTER TABLE collections ADD COLUMN cost_cpu_ms REAL`); err != nil {
			return fmt.Errorf("add collections.cost_cpu_ms: %w", err)
		}
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

func wallNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }

// IssueGenerations mints a fresh generation for each named collection —
// monotonic and persisted BEFORE any collect request goes out, so a
// crash between issuing and applying can never lead to a reuse. A fresh
// acquisition always takes a new generation; only re-sending bytes
// already captured may reuse one (DESIGN §19).
func (s *Store) IssueGenerations(names []string, declaration string) (map[string]uint64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	issued := map[string]uint64{}
	for _, name := range names {
		var gen uint64
		// The declaration is stamped here rather than at apply, because
		// this is the moment the collector told us the collection exists
		// — a collection that never applies is still one the hub must be
		// able to resolve fact axes for, and it is exactly the row the
		// manifest carries at generation 0.
		err := tx.QueryRow(`
			INSERT INTO collections (name, issued_gen, declaration) VALUES (?, 1, ?)
			ON CONFLICT(name) DO UPDATE SET issued_gen = issued_gen + 1, declaration = excluded.declaration
			RETURNING issued_gen`, name, declaration).Scan(&gen)
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
	Type   string // "" when the record carried none
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
	seq := 0
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
		objectType := sql.NullString{}
		if o.Type != "" {
			objectType = sql.NullString{String: o.Type, Valid: true}
		}
		// seq is the batch's own emission order, stamped so a read can
		// serve it back: the applied order IS the collection for a
		// hierarchical one (units' systemctl-status walk), and the store
		// discarding it was found on 2026-08-21 after two implementations
		// had each carefully produced an order nothing kept.
		if _, err := tx.Exec(`
			INSERT INTO objects (collection, scope, id, name, type, facts, names, absent, at, seq)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			collection, scope, o.ID, o.Name, objectType, string(o.Facts), names, absent, o.At, seq); err != nil {
			return "", fmt.Errorf("apply object %s: %w", o.ID, err)
		}
		seq++
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
// RecordCost keeps the collector's commit-record account of what the
// last committed acquisition cost. Advisory by construction (DESIGN 19):
// the wire bounded it, nothing authenticated it, and the read surface
// says so beside the number.
func (s *Store) RecordCost(collection string, cpuMs float64) error {
	_, err := s.db.Exec(
		`UPDATE collections SET cost_cpu_ms = ? WHERE name = ?`, cpuMs, collection)
	return err
}

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
	// Declaration is the declaration hash this collection was last
	// learned under, or nil for a store written before the column
	// existed. Nil is a stated unknown and never a hash to invent.
	Declaration *string
	// CostCPUMs is the collector's own account of the last committed
	// acquisition, from the commit record — advisory by construction
	// (DESIGN 19), and nil when no commit ever reported one: "never
	// reported" and "cost zero" are different readings.
	CostCPUMs *float64
}

// Collections reports every known collection. OldestAt is MIN(at) over
// the applied objects: a collection's served freshness derives from the
// oldest contributing read, never from arrival time (acceptance item 5).
func (s *Store) Collections() ([]CollectionState, error) {
	rows, err := s.db.Query(`
		SELECT c.name, c.applied_gen, c.applied_at, c.boot_id, c.stale, c.stale_reason,
		       (SELECT COUNT(*) FROM objects o WHERE o.collection = c.name),
		       (SELECT MIN(o.at) FROM objects o WHERE o.collection = c.name),
		       c.declaration, c.cost_cpu_ms
		FROM collections c ORDER BY c.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CollectionState
	for rows.Next() {
		var cs CollectionState
		var appliedAt, bootID, staleReason, declaration sql.NullString
		var stale int
		var oldest, cost sql.NullFloat64
		if err := rows.Scan(&cs.Name, &cs.Generation, &appliedAt, &bootID, &stale,
			&staleReason, &cs.ObjectCount, &oldest, &declaration, &cost); err != nil {
			return nil, err
		}
		if cost.Valid {
			cs.CostCPUMs = &cost.Float64
		}
		if declaration.Valid && declaration.String != "" {
			cs.Declaration = &declaration.String
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
	Type  string // "" when the object carries none
	Facts json.RawMessage
	At    float64
	// Scope is the instance the object was published under, HostNative
	// for an instance-less batch. It is part of the row and not merely
	// part of the primary key: two instances mint the SAME id string,
	// so a reader handed rows without it sees one object twice and has
	// no way to tell that it is two (acceptance item 1).
	Scope string
}

// Objects lists a collection's applied objects, every scope, in APPLIED
// order — the batch's own emission sequence, which for a hierarchical
// collection is the collection (units' systemctl-status walk, hardware's
// attachment tree). Sorting is a consumer's choice to make and undo; the
// producer's order is not recoverable once discarded, which this store
// did until 2026-08-21.
// ObjectsInScope is one collection's applied objects under ONE instance
// scope, in applied order.
//
// The record needs this and Objects cannot serve it: Objects returns
// every scope, so a snapshot keyed (collection, scope) was built from
// whatever scopes had applied at that moment, and a question about one
// instance was diffed against every instance's live objects. Two
// instances applied, a snapshot taken at the first's apply, the second
// re-applied and the first untouched — and a question about the first
// answered that its object had been ADDED. Found by review 2026-08-23.
func (s *Store) ObjectsInScope(collection, scope string) ([]ObjectRow, error) {
	rows, err := s.db.Query(`
		SELECT id, name, type, facts, at, scope FROM objects
		WHERE collection = ? AND scope = ? ORDER BY seq, id`, collection, scope)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanObjectRows(rows)
}

func (s *Store) Objects(collection string) ([]ObjectRow, error) {
	rows, err := s.db.Query(`
		SELECT id, name, type, facts, at, scope FROM objects
		WHERE collection = ? ORDER BY scope, seq, id`, collection)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanObjectRows(rows)
}

// scanObjectRows is the one decoder both readers use, so a column added
// to one cannot be missing from the other.
func scanObjectRows(rows *sql.Rows) ([]ObjectRow, error) {
	var out []ObjectRow
	for rows.Next() {
		var o ObjectRow
		var facts string
		var objectType sql.NullString
		if err := rows.Scan(&o.ID, &o.Name, &objectType, &facts, &o.At, &o.Scope); err != nil {
			return nil, err
		}
		if objectType.Valid {
			o.Type = objectType.String
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

// RecordDeclaration keeps the declaration document beside its digest.
//
// Kept rather than re-fetched, for two reasons that turned out to be one.
// A session must send the declarations its manifest names, and re-asking
// a collector for them at checkpoint time makes the session depend on
// every collector being ALIVE at that moment — so a collector that had
// answered all day but was restarting during the checkpoint would cost
// the hub the fact axes for facts it already holds. And a rule table
// travels in the declaration, so the collator cannot evaluate its own
// self-evident opinions without it.
//
// Keyed by digest, so a re-declaration with identical bytes is a no-op
// and two versions of one collector are two rows rather than a race.
func (s *Store) RecordDeclaration(digest, document string) error {
	_, err := s.db.Exec(`
		INSERT INTO declarations (digest, document, seen_wall) VALUES (?, ?, ?)
		ON CONFLICT(digest) DO UPDATE SET seen_wall = excluded.seen_wall`,
		digest, document, wallNow())
	return err
}

// DeclarationDocuments returns every declaration the store holds that some
// known collection was learned under, keyed by digest. Scoped to what the
// collections reference rather than to everything ever seen: a session
// naming a declaration no collection uses would send the hub axes for
// facts that cannot arrive.
func (s *Store) DeclarationDocuments() (map[string]string, error) {
	rows, err := s.db.Query(`
		SELECT d.digest, d.document FROM declarations d
		WHERE d.digest IN (SELECT declaration FROM collections WHERE declaration IS NOT NULL)
		ORDER BY d.digest`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var digest, document string
		if err := rows.Scan(&digest, &document); err != nil {
			return nil, err
		}
		out[digest] = document
	}
	return out, rows.Err()
}

// DeclarationFor returns the document a collection was learned under, or
// "" when the store holds the digest but not the document — which a store
// written before declarations were kept will do, and which the caller
// must treat as "cannot evaluate" rather than as "no rules".
func (s *Store) DeclarationFor(collection string) (string, error) {
	var document string
	err := s.db.QueryRow(`
		SELECT COALESCE(d.document, '') FROM collections c
		LEFT JOIN declarations d ON d.digest = c.declaration
		WHERE c.name = ?`, collection).Scan(&document)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return document, err
}
