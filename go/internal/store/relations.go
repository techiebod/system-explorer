package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Relations are the second founding failure's answer, and the whole of why
// this file is separate from the object authority beside it.
//
// The incident: months of green replication over data with no off-site copy.
// The push side was observed and honest. The far side was never looked at.
// And the product had no way to express the difference between a relationship
// confirmed at both ends and one asserted at one end, so it rendered the
// second as the first. Everything below exists to keep those two states
// distinguishable at every layer that touches them (DESIGN §13).
//
// Three rules carry the weight, and each was a way to rebuild that failure:
//
//   - A relation is keyed on the target's NAME AS PUBLISHED, never on its
//     resolved id. Resolution is a property that changes; a key that changed
//     with it would reset the relation's lifecycle every time the estate
//     learned something, so an upgrade from unresolved to resolved must be
//     invisible to the key (acceptance item 6's "an upgrade never re-keys").
//   - An unresolved target is MINTED, not dropped. Requiring both endpoints
//     to resolve sounds like rigour and deletes exactly the case the law was
//     written for: a repository nothing in the estate reads resolves to
//     nothing, and the strict rule discards it — clean, defensible, and
//     identical in effect to never having looked.
//   - Observability lives on the assembled relation, never on one vantage's
//     assertion. A collector that claimed `confirmed` would be minting a
//     judgement one tier below where the evidence for it exists.
const relationSchema = `
CREATE TABLE IF NOT EXISTS relations (
  collection    TEXT NOT NULL,
  scope         TEXT NOT NULL,
  key           TEXT NOT NULL,
  source_id     TEXT NOT NULL,
  source_name   TEXT NOT NULL,
  type          TEXT NOT NULL,
  vantage       TEXT NOT NULL,
  target_kind   TEXT NOT NULL,
  target_name   TEXT NOT NULL,
  -- Resolution is a PROPERTY, deliberately not part of the key: the hub
  -- upgrades it when another host or the intent declaration claims the
  -- name, and that upgrade must not re-key.
  target_id     TEXT,
  resolved      INTEGER NOT NULL DEFAULT 0,
  facts         TEXT,
  observability TEXT NOT NULL,
  PRIMARY KEY (collection, scope, key)
);
`

// Observability is the assembled relation's state. `asserted` is the state
// the product needed and never had: it is NOT a degraded `confirmed`, and it
// must never render as one, because it carries a positive claim about what
// was not looked at.
type Observability string

const (
	Confirmed    Observability = "confirmed"
	Asserted     Observability = "asserted"
	Contradicted Observability = "contradicted"
)

// RelationType is one entry of a collector's declared relation table.
type RelationType struct {
	Discriminator     []string
	InverseObservable bool
	ConfirmedBy       string
}

// Assertion is one vantage's directed claim, as it arrives off the wire.
type Assertion struct {
	Collection string
	SourceName string
	Type       string
	Vantage    string
	TargetKind string
	TargetName string
	Facts      json.RawMessage
}

// Relation is one assembled edge as the store holds it.
type Relation struct {
	Key           string
	SourceID      string
	SourceName    string
	Type          string
	Vantage       string
	TargetKind    string
	TargetName    string
	TargetID      string
	Resolved      bool
	Facts         json.RawMessage
	Observability Observability
	// Collection is the one that ASSERTED this edge, which is not
	// necessarily either end's own: a disk's `backs` edge to an array is
	// stored under block-devices, so the arrays page could never reach it
	// by looking in its own collection. Needed to mint a link back to the
	// source of an inbound edge.
	Collection string
}

// RelationsTouching is every edge with this object at EITHER end, across
// EVERY collection.
//
// The object page read Relations(collection) and matched only the
// SOURCE, so an edge was visible from one end and one collection only.
// An md array's page said "This object asserts no relations" while every
// member device asserted `member-of` pointing straight at it — the edges
// existed, were resolved, and were unreachable from the end a person was
// standing on.
//
// Both directions matter and they answer different questions: "what is
// this made of" is outbound, "what depends on this" is inbound, and the
// second is the one you want before unplugging something.
func (s *Store) RelationsTouching(objectID, name string) (out, in []Relation, err error) {
	rows, err := s.db.Query(`
		SELECT key, source_id, source_name, type, vantage, target_kind,
		       target_name, COALESCE(target_id, ''), resolved,
		       COALESCE(facts, ''), observability, collection
		FROM relations
		WHERE source_id = ? OR source_name = ? OR target_id = ? OR target_name = ?
		ORDER BY collection, key`, objectID, name, objectID, name)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r Relation
		var resolved int
		var facts string
		if err := rows.Scan(&r.Key, &r.SourceID, &r.SourceName, &r.Type,
			&r.Vantage, &r.TargetKind, &r.TargetName, &r.TargetID, &resolved,
			&facts, &r.Observability, &r.Collection); err != nil {
			return nil, nil, err
		}
		r.Resolved = resolved != 0
		r.Facts = json.RawMessage(facts)
		if r.SourceID == objectID || r.SourceName == name {
			out = append(out, r)
		} else {
			in = append(in, r)
		}
	}
	return out, in, rows.Err()
}

// RelationKey is the identity of an assembled relation: the source object's
// id, the type, the declared discriminator's values, and the target's name as
// published. Four inputs, and the two that are NOT here are the point —
// neither the target's resolved id nor the observability state may enter,
// because both change as the estate learns and a key that moved with them
// would retire the relation and mint a new one for the same edge.
//
// The discriminator values are taken in the DECLARED order, not sorted, so a
// type declaring ["Path", "Mode"] and one declaring ["Mode", "Path"] are
// distinguishable — a set would silently make them the same key. A declared
// discriminator fact the assertion does not carry contributes the empty
// string rather than being skipped, so "absent" and "" stay one value apart
// from a real reading and a missing one cannot collide with a present one by
// shortening the tuple.
func RelationKey(sourceID, relType string, discriminator []string, facts json.RawMessage, targetName string) (string, error) {
	parts := []string{sourceID, relType}
	if len(discriminator) > 0 {
		values := map[string]any{}
		if len(facts) > 0 {
			if err := json.Unmarshal(facts, &values); err != nil {
				return "", fmt.Errorf("assertion facts do not parse: %w", err)
			}
		}
		for _, name := range discriminator {
			value, ok := values[name]
			if !ok {
				parts = append(parts, "\x00absent")
				continue
			}
			// Canonical JSON of the value, so 12 and "12" are two
			// discriminators and not one. Typed equality is the law
			// everywhere else in this product; a key that stringified
			// would quietly break it here.
			raw, err := json.Marshal(value)
			if err != nil {
				return "", err
			}
			parts = append(parts, string(raw))
		}
	}
	parts = append(parts, targetName)
	// Hashed rather than joined: every part is attacker-adjacent text from a
	// native interface, and a separator that appears inside a part would let
	// two different tuples produce one key. Lengths are folded in so no
	// choice of separator matters.
	h := sha256.New()
	for _, part := range parts {
		fmt.Fprintf(h, "%d:%s", len(part), part)
	}
	return "rel-" + hex.EncodeToString(h.Sum(nil))[:32], nil
}

// ApplyAssertions assembles one collection's assertions into relations and
// lands them in the same transaction shape the objects took: everything the
// committed collection did not assert is gone, because a committed collection
// is authoritative and deletion is expressed by absence.
//
// resolveKind answers "does anything on this host publish this name, under
// the collection whose declared prefix is this kind?" — a walk along a link
// the producer published, never a correlation over values that resemble each
// other (law 3, DESIGN §16). It returns the object id and whether it
// resolved; an unresolved target is minted and carried by name.
//
// inverse is every assertion in this batch keyed by (type, source-name,
// target-name), which is what lets an edge asserted from BOTH ends be
// recognised as confirmed rather than stored twice as two asserted halves.
func (s *Store) ApplyAssertions(
	collection, scope string,
	assertions []Assertion,
	types map[string]RelationType,
	resolve func(kind, name string) (string, bool),
	inverse func(relType, from, to string) (json.RawMessage, bool),
) ([]Relation, error) {
	relations := make([]Relation, 0, len(assertions))
	seen := map[string]Assertion{}

	for _, a := range assertions {
		declared, known := types[a.Type]
		if !known {
			// A type the collector never declared. The contract check owns
			// this at the collector, but the authority must not depend on
			// its caller's diligence: an undeclared type has no
			// discriminator and no confirmation rule, so nothing here can
			// key it or judge it.
			return nil, fmt.Errorf("%s: relation type %q was never declared",
				collection, a.Type)
		}
		sourceID := MintID(collection, a.SourceName)
		key, err := RelationKey(sourceID, a.Type, declared.Discriminator, a.Facts, a.TargetName)
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", collection, a.SourceName, err)
		}
		if _, clash := seen[key]; clash {
			// A type declaring no discriminator asserts it is at-most-
			// singular between any pair, and that assertion is CHECKABLE.
			// A second instance is an error the collator reports rather
			// than a silent overwrite — which is the failure mode the
			// discriminator exists to prevent, and reporting it is how a
			// missing declaration gets found instead of losing an edge.
			return nil, fmt.Errorf(
				"%s/%s: a second %q assertion to %q collides with the first "+
					"(discriminator %v); declare a discriminator that tells the "+
					"parallel instances apart, or the second silently replaces "+
					"the first",
				collection, a.SourceName, a.Type, a.TargetName, declared.Discriminator)
		}
		seen[key] = a

		targetID, resolved := "", false
		if resolve != nil {
			targetID, resolved = resolve(a.TargetKind, a.TargetName)
		}

		relations = append(relations, Relation{
			Key:           key,
			SourceID:      sourceID,
			SourceName:    a.SourceName,
			Type:          a.Type,
			Vantage:       a.Vantage,
			TargetKind:    a.TargetKind,
			TargetName:    a.TargetName,
			TargetID:      targetID,
			Resolved:      resolved,
			Facts:         a.Facts,
			Observability: observabilityOf(a, declared, inverse),
		})
	}

	sort.Slice(relations, func(i, j int) bool { return relations[i].Key < relations[j].Key })

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM relations WHERE collection = ? AND scope = ?`,
		collection, scope); err != nil {
		return nil, err
	}
	for _, r := range relations {
		facts := any(nil)
		if len(r.Facts) > 0 {
			facts = string(r.Facts)
		}
		targetID := any(nil)
		if r.Resolved {
			targetID = r.TargetID
		}
		if _, err := tx.Exec(`
			INSERT INTO relations (collection, scope, key, source_id, source_name,
			                       type, vantage, target_kind, target_name,
			                       target_id, resolved, facts, observability)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			collection, scope, r.Key, r.SourceID, r.SourceName, r.Type, r.Vantage,
			r.TargetKind, r.TargetName, targetID, boolInt(r.Resolved), facts,
			string(r.Observability)); err != nil {
			return nil, fmt.Errorf("apply relation %s: %w", r.Key, err)
		}
	}
	return relations, tx.Commit()
}

// observabilityOf is the one judgement a collector may not make, made here.
//
// A type declaring inverse_observable false can never be confirmed from the
// far end, so it is honestly `asserted` forever rather than perpetually
// waiting for a confirmation that has no source. A type that CAN be confirmed
// names the assertion that would do it, and is confirmed only when that
// assertion actually arrived pointing back — both ends observed. Where the
// far end asserted the inverse but disagrees about the facts, that is
// `contradicted`: a state, not a verdict, because asymmetric visibility is
// sometimes benign, and where it matters a finding cites the state.
func observabilityOf(a Assertion, declared RelationType,
	inverse func(relType, from, to string) (json.RawMessage, bool)) Observability {
	if !declared.InverseObservable || declared.ConfirmedBy == "" || inverse == nil {
		return Asserted
	}
	back, found := inverse(declared.ConfirmedBy, a.TargetName, a.SourceName)
	if !found {
		return Asserted
	}
	if !sameFacts(a.Facts, back) {
		return Contradicted
	}
	return Confirmed
}

// sameFacts compares two assertions' fact dicts as VALUES, not as bytes: two
// vantages serialise independently and key order is not a disagreement.
func sameFacts(a, b json.RawMessage) bool {
	var av, bv any
	if len(a) > 0 {
		if json.Unmarshal(a, &av) != nil {
			return false
		}
	}
	if len(b) > 0 {
		if json.Unmarshal(b, &bv) != nil {
			return false
		}
	}
	ab, err1 := json.Marshal(av)
	bb, err2 := json.Marshal(bv)
	return err1 == nil && err2 == nil && string(ab) == string(bb)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Relations reads back one collection's assembled edges, newest applied set.
func (s *Store) Relations(collection string) ([]Relation, error) {
	rows, err := s.db.Query(`
		SELECT key, source_id, source_name, type, vantage, target_kind,
		       target_name, COALESCE(target_id, ''), resolved,
		       COALESCE(facts, ''), observability
		FROM relations WHERE collection = ? ORDER BY key`, collection)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Relation
	for rows.Next() {
		var r Relation
		var resolved int
		var facts string
		var obs string
		if err := rows.Scan(&r.Key, &r.SourceID, &r.SourceName, &r.Type, &r.Vantage,
			&r.TargetKind, &r.TargetName, &r.TargetID, &resolved, &facts, &obs); err != nil {
			return nil, err
		}
		r.Resolved = resolved == 1
		r.Observability = Observability(obs)
		if facts != "" {
			r.Facts = json.RawMessage(facts)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ResolverFor builds the collator-side resolution function for one batch:
// prefix → collection comes from the DECLARATION, and the name lookup runs
// against what this host has actually published.
//
// The test is "nothing on this host claims the name", and that is the whole
// of it, because intent never reaches a host. A kind naming no served
// collection therefore resolves to nothing and its relations stay `asserted`
// — which is the founding condition, preserved rather than papered over.
func (s *Store) ResolverFor(prefixes map[string]string, scope string) func(kind, name string) (string, bool) {
	return func(kind, name string) (string, bool) {
		collection, served := prefixes[kind]
		if !served {
			return "", false
		}
		var id string
		err := s.db.QueryRow(
			`SELECT id FROM objects WHERE collection = ? AND scope = ? AND name = ?`,
			collection, scope, name).Scan(&id)
		if err != nil {
			return "", false
		}
		return id, true
	}
}

// PrefixIndex inverts a declaration's collections into kind → collection.
// A prefix two collections both claim is refused rather than resolved to
// whichever came last: an ambiguous prefix is a declaration bug, and
// silently picking one is how an edge lands on the wrong object.
func PrefixIndex(prefixes map[string]string) (map[string]string, error) {
	out := map[string]string{}
	for collection, prefix := range prefixes {
		if prefix == "" {
			continue
		}
		if existing, clash := out[prefix]; clash {
			names := []string{existing, collection}
			sort.Strings(names)
			return nil, fmt.Errorf("prefix %q is declared by both %s — a relation "+
				"target of that kind would resolve against whichever was read last",
				prefix, strings.Join(names, " and "))
		}
		out[prefix] = collection
	}
	return out, nil
}

// UpgradeUnresolved re-tests every unresolved edge against the host as it is
// NOW, and upgrades in place the ones whose far end has since arrived.
//
// The hub does exactly this for the estate — "every asserted relation is
// re-tested against the intent declaration's objects and the names other
// hosts publish, and its resolution is upgraded where a match exists" — and
// the collator owes the same to the collectors under it. Without it an edge
// resolved only when its OWN collection was collected again, so a host that
// dialled hardware before storage carried `backs block-device:sda` as an edge
// into open space until hardware's next round, with the far end sitting in
// the same store the whole time. That is unobservable-and-healthy rendering
// as absent, one tier down from where this estate first met it.
//
// AN UPGRADE NEVER CHANGES THE KEY. The key is derived from the source, the
// type, the declared discriminator and the target's name AS PUBLISHED, never
// from the resolved id — resolution is a property that changes, and a key
// that changed with it would reset the relation's lifecycle every time the
// host learned something. So this writes `resolved` and `target_id` and
// touches nothing else.
//
// Downgrades are NOT this function's business: an edge whose target went away
// is retired by the authority of the commit that no longer publishes it, and
// re-testing here could only race that.
func (s *Store) UpgradeUnresolved(resolve func(kind, name string) (string, bool)) (int, error) {
	rows, err := s.db.Query(
		`SELECT key, target_kind, target_name FROM relations WHERE resolved = 0`)
	if err != nil {
		return 0, err
	}
	type pending struct{ key, kind, name string }
	var waiting []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.key, &p.kind, &p.name); err != nil {
			rows.Close()
			return 0, err
		}
		waiting = append(waiting, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	upgraded := 0
	for _, p := range waiting {
		id, ok := resolve(p.kind, p.name)
		if !ok {
			continue
		}
		if _, err := s.db.Exec(
			`UPDATE relations SET resolved = 1, target_id = ? WHERE key = ?`,
			id, p.key); err != nil {
			return upgraded, err
		}
		upgraded++
	}
	return upgraded, nil
}
