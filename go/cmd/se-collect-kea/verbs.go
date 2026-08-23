package main

// The object and evidence verbs (DESIGN 18) — the fleet rollout of what R3c
// landed on the champions (register rows 1–2).
//
// kea has no density behind its rows: the collect walk already reads every
// fact the declaration declares, so an object response is one object
// addressed by NAME — the same row the collection publishes, because a row
// here that disagreed with the listing would be two answers about one
// subnet. What a question nobody anticipated is answered from is the raw
// control-socket documents, and those are the EVIDENCE payload's, in the
// reference's own shape (adapters/kea.py get_evidence): a subnet's evidence
// carries BOTH halves its row is joined from, reservations carry the config
// document their rows are folded from, and leases carry the lease4-get-all
// answer. Membership comes from the same documents the payload serves —
// fetched once, checked in place — so the answer and its evidence cannot
// straddle a reconfiguration.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
			"this collector serves daemon, subnets, reservations and leases only")
	}
	src.openCollection()
	built, err := build(src)
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
	return verbDecline(out, stderr, "object", collection, "unavailable",
		"this collector publishes no object of that name in this collection")
}

// ── evidence ────────────────────────────────────────────────────────────

// evidencePayload is the raw control-socket documents one object's facts were
// read from, and whether the name is among the rows THOSE documents publish.
// The top level is assembled here (Go marshals map keys sorted, which is the
// canon the digest names); each document inside keeps Kea's own member order
// and number spellings, exactly as the seam replays them.
func evidencePayload(src source, collection, name string) (map[string]json.RawMessage, bool, error) {
	switch collection {
	case collectionDaemon:
		version, err := src.document(commandVersion)
		if err != nil {
			return nil, false, err
		}
		status, err := src.document(commandStatus)
		if err != nil {
			return nil, false, err
		}
		if name != daemonName {
			return nil, false, nil
		}
		return map[string]json.RawMessage{
			"version": version.encode(),
			"status":  status.encode(),
		}, true, nil
	case collectionSubnets:
		statistics, err := src.document(commandStatistics)
		if err != nil {
			return nil, false, err
		}
		config, err := src.document(commandConfig)
		if err != nil {
			return nil, false, err
		}
		rows := buildSubnetRows(statistics.get("arguments"),
			configSubnetFacts(config.dig("arguments", "Dhcp4")))
		if !holdsName(rows, name) {
			return nil, false, nil
		}
		return map[string]json.RawMessage{
			"statistics": statistics.get("arguments").encode(),
			"config":     config.get("arguments").encode(),
		}, true, nil
	case collectionReservations:
		config, err := src.document(commandConfig)
		if err != nil {
			return nil, false, err
		}
		if !holdsName(buildReservationRows(config.dig("arguments", "Dhcp4")), name) {
			return nil, false, nil
		}
		return map[string]json.RawMessage{
			"config": config.get("arguments").encode(),
		}, true, nil
	case collectionLeases:
		answer, err := src.document(commandLeases)
		if err != nil {
			return nil, false, err
		}
		config, err := src.document(commandConfig)
		if err != nil {
			return nil, false, err
		}
		rows := buildLeaseRows(answer.dig("arguments", "leases"),
			subnetCIDRs(config.dig("arguments", "Dhcp4")))
		if !holdsName(rows, name) {
			return nil, false, nil
		}
		// The whole lease4-get-all answer, as the reference serves it.
		return map[string]json.RawMessage{
			"leases": answer.encode(),
		}, true, nil
	}
	return nil, false, nil
}

func holdsName(rows []row, name string) bool {
	for _, one := range rows {
		if one.name == name {
			return true
		}
	}
	return false
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if _, serves := served[collection]; !serves {
		return verbDecline(out, stderr, "evidence", collection, "unsupported",
			"this collector serves daemon, subnets, reservations and leases only")
	}
	src.openCollection()
	payload, found, err := evidencePayload(src, collection, name)
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
		return verbDecline(out, stderr, "evidence", collection, "unavailable",
			"this collector publishes no object of that name in this collection")
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintln(stderr, "evidence payload:", err)
		return exitRuntime
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
