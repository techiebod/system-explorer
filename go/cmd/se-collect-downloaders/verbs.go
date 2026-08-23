package main

// The object and evidence verbs (DESIGN 18) — the fleet rollout of what R3c
// landed on the champions (register rows 1–2).
//
// downloaders has no density behind its rows, so an object response is the
// row the collection publishes, addressed by name — built by the SAME row
// builders collect uses. The EVIDENCE payloads follow the reference
// (adapters/downloaders.py get_evidence): transmission's client row serves
// its session and stats documents, sabnzbd's serves its fullstatus
// self-report, and a transfer serves its own raw entry — a torrent from
// torrent-get matched on lowercased hash, a slot from the queue matched on
// nzo_id, the same matching the row walk mints names by. A configured,
// keyless sabnzbd is the reference's stated fault, as a decline detail here:
// the row exists, so its evidence must not deny it.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

type verbEndRecord struct {
	Record    string `json:"record"`
	Verb      string `json:"verb"`
	Truncated bool   `json:"truncated"`
}

type evidenceDocumentRecord struct {
	Record    string `json:"record"`
	MediaType string `json:"media_type"`
	Digest    string `json:"digest"`
	Canon     string `json:"canon,omitempty"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
}

// The declared bounds, pinned against declaration.json by test: a bound only
// in the declaration is a promise, one only here is undeclared authority.
const (
	objectVerbBytes   = 262144
	evidenceVerbBytes = 1048576
)

const noSuchObject = "this collector publishes no object of that name in this collection"

func verbDecline(out *emitter, stderr io.Writer, verb, collection, reason, detail string) int {
	out.emit(declineRecord{Record: "decline", Collection: collection,
		Reason: reason, Detail: detail})
	out.emit(verbEndRecord{Record: "verb_end", Verb: verb})
	return verbExit(out, stderr)
}

func serveObject(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	build, serves := served[collection]
	if !serves {
		return verbDecline(out, stderr, "object", collection, "unsupported",
			"this collector serves clients and transfers only")
	}
	built, err := build(src, stderr)
	var refused *declined
	if errors.As(err, &refused) {
		return verbDecline(out, stderr, "object", collection,
			refused.reason, refused.detail)
	}
	if err != nil {
		fmt.Fprintln(stderr, collection+":", err)
		return exitRuntime
	}
	for _, one := range built {
		if one.name != name {
			continue
		}
		out.emit(objectRecord{
			Record:     "object",
			Type:       collectionTypes[collection],
			Collection: collection,
			Name:       one.name,
			Facts:      one.facts.encode(),
			At:         src.stamp(0),
		})
		out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
		return verbExit(out, stderr)
	}
	return verbDecline(out, stderr, "object", collection, "unavailable", noSuchObject)
}

// ── evidence ────────────────────────────────────────────────────────────

// evidenceCanonical is the payload bytes for one object, and whether the
// name is among what the same documents publish. A dark client is an answer
// for a request addressed to it — the same constant its row carries — and
// travels as an *declined the caller turns into the decline.
func evidenceCanonical(src source, collection, name string) ([]byte, bool, error) {
	gates := src.clients()
	if collection == "clients" {
		switch {
		case name == clientTransmission && gates.transmission:
			session, sessionErr := src.document(callSessionGet)
			stats, statsErr := src.document(callSessionStats)
			if err := errors.Join(sessionErr, statsErr); err != nil {
				return nil, false, darkClient(err, transmissionUnobservable)
			}
			// The top level is assembled here (Go marshals map keys sorted,
			// which is the canon the digest names); each document inside
			// keeps the daemon's own member order and number spellings.
			canonical, err := json.Marshal(map[string]json.RawMessage{
				"session": session.encode(),
				"stats":   stats.encode(),
			})
			return canonical, true, err
		case name == clientSabnzbd && gates.sab:
			if !gates.sabKey {
				// The row EXISTS (a stated-fault row), so its evidence must
				// not deny it: the fault is the honest answer.
				return nil, false, &declined{"unavailable",
					"sabnzbd is configured by URL but " + sabKeyVariable +
						" is missing — there is nothing to ask it"}
			}
			status, err := src.document(callFullStatus)
			if err != nil {
				return nil, false, darkClient(err, sabUnobservable)
			}
			return status.encode(), true, nil
		}
		return nil, false, nil
	}
	// transfers: the port names a transfer by its bare native id — a
	// lowercased info-hash or an nzo_id — so the search asks each configured
	// client's own document, exactly the documents the row walk mints from.
	if gates.transmission {
		document, err := src.document(callTorrentGet)
		if err != nil {
			return nil, false, darkClient(err, transmissionUnobservable)
		}
		for _, raw := range arrayItems(document.get("torrents")) {
			if strings.ToLower(raw.get("hashString").stringOr("")) == name {
				return raw.encode(), true, nil
			}
		}
	}
	if gates.sab && gates.sabKey {
		document, err := src.document(callQueue)
		if err != nil {
			return nil, false, darkClient(err, sabUnobservable)
		}
		for _, raw := range arrayItems(document.get("queue").get("slots")) {
			if raw.get("nzo_id").stringOr("") == name {
				return raw.encode(), true, nil
			}
		}
	}
	return nil, false, nil
}

func darkClient(err error, constant string) error {
	var refused *declined
	if errors.As(err, &refused) || fatalAcquisition(err) {
		return err
	}
	return &declined{"unavailable", constant}
}

func arrayItems(v *value) []*value {
	if v == nil || v.kind != jsonArray {
		return nil
	}
	return v.items
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if _, serves := served[collection]; !serves {
		return verbDecline(out, stderr, "evidence", collection, "unsupported",
			"this collector serves clients and transfers only")
	}
	canonical, found, err := evidenceCanonical(src, collection, name)
	var refused *declined
	if errors.As(err, &refused) {
		return verbDecline(out, stderr, "evidence", collection,
			refused.reason, refused.detail)
	}
	if err != nil {
		fmt.Fprintln(stderr, collection+":", err)
		return exitRuntime
	}
	if !found {
		return verbDecline(out, stderr, "evidence", collection, "unavailable", noSuchObject)
	}
	truncated := false
	if len(canonical) > evidenceVerbBytes {
		// A truncated document marked truncated is still evidence; an
		// unmarked one is a lie about the system (DESIGN 19). The digest is
		// over the bytes AS SERVED, so it stays checkable.
		canonical = canonical[:evidenceVerbBytes]
		truncated = true
	}
	sum := sha256.Sum256(canonical)
	out.emit(evidenceDocumentRecord{
		Record:    "evidence_document",
		MediaType: "application/json",
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		Canon:     "jcs/1",
		Bytes:     len(canonical),
		Truncated: truncated,
	})
	if out.err == nil {
		if _, err := stdout.Write(append(canonical, '\n')); err != nil {
			out.err = err
		}
	}
	out.emit(verbEndRecord{Record: "verb_end", Verb: "evidence", Truncated: truncated})
	return verbExit(out, stderr)
}

func verbExit(out *emitter, stderr io.Writer) int {
	if out.err != nil {
		fmt.Fprintln(stderr, "writing the response:", out.err)
		return exitRuntime
	}
	return exitOK
}
