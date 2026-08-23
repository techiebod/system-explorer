package store

// The record: the snapshot store behind *what changed* (DESIGN 06 — the
// collator "keeps the record", and it is this tier because the collator
// is the one that already holds both samples).
//
// **Two rules make this store small rather than large, and both come from
// the temperament work in DESIGN 12.**
//
// A fact whose temperament is counter or gauge does not participate in
// the diff, so it must not participate in the SNAPSHOT either — otherwise
// every sample writes a new row that no diff will ever report. That is
// the reference implementation's measured failure carried the other way:
// 57 of 222 nft-rules rows changed hourly there and every one of them
// differed only in CounterPackets and CounterBytes, 96 times a day for
// thirty days.
//
// And a snapshot is written only when the DIFFABLE content changed, which
// falls out of the first rule: the caller hands over the digest of what
// is left after the measures are dropped, and an identical digest writes
// nothing. A store of a mostly-idle host is then a handful of rows per
// collection rather than one per sweep, and the retention horizon buys
// real time rather than a fixed number of samples.
//
// **The exclusion is DERIVED, never listed.** The set comes from the
// declaration each collection published — see collate.MeasureFacts —
// which is why a plugin's counter is excluded on the day it arrives and
// why there is no table here to fall out of step with one.

import (
	"database/sql"
	"fmt"
)

const recordSchema = `
CREATE TABLE IF NOT EXISTS snapshots (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  collection TEXT NOT NULL,
  scope      TEXT NOT NULL,
  taken_at   TEXT NOT NULL,
  generation INTEGER NOT NULL,
  digest     TEXT NOT NULL,
  objects    TEXT NOT NULL,
  format     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS snapshots_at ON snapshots (collection, scope, taken_at);
`

// SnapshotFormat is the shape of what `objects` holds. Bumped whenever a
// stored reading stops being comparable with a fresh one.
//
// It went to 1 on 2026-08-23, when the diffable object gained `scope`:
// rows written that morning carry objects with no scope member, so
// unmarshalling one yields Scope="" while the live side fills it from
// the store — and every object reads as both ADDED and REMOVED. A stored
// reading with an older format is not a baseline this code can compare,
// and the answer says so rather than inventing a change. There was no
// marker at all before, which is why an incompatible shape could arrive
// silently in the first place.
const SnapshotFormat = 1

// Snapshot is one stored reading of a collection, with the measures
// already dropped by the caller.
type Snapshot struct {
	Collection string
	Scope      string
	TakenAt    string
	Generation uint64
	Digest     string
	// The diffable objects, as the JSON array the diff reads back.
	Objects string
	// Format is SnapshotFormat at the moment of writing. A reading whose
	// format is older cannot be compared with a fresh one.
	Format int
}

// RecordSnapshot stores one reading, or reports that it was unchanged.
//
// Returns false when the newest stored snapshot for this collection and
// scope carries the same digest — nothing was written, and the caller
// should not treat that as a failure. Comparing against the NEWEST rather
// than against any is deliberate: a host that flips between two states
// must record every flip, and de-duplicating against the whole history
// would collapse a flapping condition into one entry.
func (s *Store) RecordSnapshot(snapshot Snapshot) (bool, error) {
	var newest string
	err := s.db.QueryRow(`
		SELECT digest FROM snapshots
		WHERE collection = ? AND scope = ?
		ORDER BY seq DESC LIMIT 1`,
		snapshot.Collection, snapshot.Scope).Scan(&newest)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	if err == nil && newest == snapshot.Digest {
		return false, nil
	}
	_, err = s.db.Exec(`
		INSERT INTO snapshots (collection, scope, taken_at, generation, digest, objects, format)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		snapshot.Collection, snapshot.Scope, snapshot.TakenAt,
		int64(snapshot.Generation), snapshot.Digest, snapshot.Objects,
		SnapshotFormat)
	if err != nil {
		return false, fmt.Errorf("record snapshot for %s: %w", snapshot.Collection, err)
	}
	return true, nil
}

// SnapshotAtOrBefore is the newest stored reading no later than `at`, or
// nil where the record does not reach that far back.
//
// Nil is the answer that matters and it is why this returns a pointer
// rather than a zero Snapshot: a caller asking about a moment before this
// store began must be able to SAY so. An empty snapshot silently compared
// against a live collection would report every object in it as added,
// which is a confident answer to a question the record cannot reach — and
// is exactly what the cut ruling forbids.
func (s *Store) SnapshotAtOrBefore(collection, scope, at string) (*Snapshot, error) {
	row := s.db.QueryRow(`
		SELECT collection, scope, taken_at, generation, digest, objects, format
		FROM snapshots
		WHERE collection = ? AND scope = ? AND taken_at <= ?
		ORDER BY taken_at DESC, seq DESC LIMIT 1`,
		collection, scope, at)
	var found Snapshot
	var generation int64
	switch err := row.Scan(&found.Collection, &found.Scope, &found.TakenAt,
		&generation, &found.Digest, &found.Objects, &found.Format); err {
	case sql.ErrNoRows:
		return nil, nil
	case nil:
		found.Generation = uint64(generation)
		return &found, nil
	default:
		return nil, err
	}
}

// RecordBegins is the oldest moment this store can answer about, per
// collection and scope. Absent where a collection has no snapshot yet.
//
// This is the horizon the cut ruling made visible: a question reaching
// before it is answered with a stated gap rather than from an empty
// baseline, and a caller cannot state a gap it cannot see the edge of.
func (s *Store) RecordBegins(collection, scope string) (string, error) {
	var begins string
	err := s.db.QueryRow(`
		SELECT taken_at FROM snapshots
		WHERE collection = ? AND scope = ?
		ORDER BY taken_at ASC, seq ASC LIMIT 1`,
		collection, scope).Scan(&begins)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return begins, err
}

// PruneSnapshots drops readings older than `before`, keeping at least one
// per collection and scope whatever its age.
//
// **The keep-one rule is the whole of why this is not a DELETE.** A
// collection whose last change predates the horizon is the ordinary case
// for configuration — a unit file nobody has touched in a year — and
// pruning it to nothing would move the record's horizon forward to the
// prune, turning "unchanged for a year" into "we cannot say". The oldest
// surviving row is the baseline every question inside the horizon needs.
func (s *Store) PruneSnapshots(before string) (int64, error) {
	result, err := s.db.Exec(`
		DELETE FROM snapshots
		WHERE taken_at < ?
		  AND seq NOT IN (
		    SELECT MAX(seq) FROM snapshots GROUP BY collection, scope
		  )`, before)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}
