package main

// The object and evidence verbs (DESIGN 18) — the last collector of the
// fleet rollout R3c opened (register rows 1–2), joining the lookup verb
// that arrived first (lookup.go, which owns the shared verb records).
//
// The nine collections are emitted by one bespoke collect walk, so the
// object verb answers by RUNNING that walk for the one collection into a
// capture and re-serving its object, relation_assertion, unobservable and
// decline records byte-for-byte — the walk's own unsupported decline
// included, so the served set has exactly one spelling. The EVIDENCE
// payloads are the reference's (adapters/network.py get_evidence): the nft
// document whole for its three collections; the four /proc/net tables
// verbatim for listening, an unreadable one shown as the reason; both
// halves for port-exposure, because the row is a join; the raw snapshot
// for tailscale; ip's own route listings; and the resolver's manager
// answer beside the per-link DNS map the rows are folded from.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

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

// captureCollection runs the SAME walk that emits the collection — collect
// itself, for one collection under a throwaway generation — and answers for
// one name: the records to re-serve byte-for-byte (begin, end and commit
// are collection-stream statements and are not), and whether the name
// matched at all.
func captureCollection(stderr io.Writer, src source, collection, name string) (kept []string, matched bool, code int) {
	var capture bytes.Buffer
	if code := collect(&capture, stderr, src, []string{collection},
		map[string]uint64{collection: 0}); code != exitOK {
		return nil, false, code
	}
	for _, line := range strings.Split(strings.TrimSpace(capture.String()), "\n") {
		if line == "" {
			continue
		}
		var envelope struct {
			Record string `json:"record"`
			Name   string `json:"name"`
		}
		if err := json.Unmarshal([]byte(line), &envelope); err != nil {
			fmt.Fprintln(stderr, "capturing the collection:", err)
			return nil, false, exitRuntime
		}
		switch envelope.Record {
		case "decline":
			// The walk's decline IS the verb's answer — unsupported included,
			// so the served set has one spelling.
			return []string{line}, true, exitOK
		case "object", "relation_assertion", "unobservable":
			if envelope.Name == name {
				kept = append(kept, line)
				matched = matched || envelope.Record == "object"
			}
		}
	}
	return kept, matched, exitOK
}

func serveObject(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	kept, matched, code := captureCollection(stderr, src, collection, name)
	if code != exitOK {
		return code
	}
	if !matched {
		return verbDecline(out, stderr, "object", collection, "unavailable", noSuchObject)
	}
	for _, line := range kept {
		if _, err := stdout.Write(append([]byte(line), '\n')); err != nil {
			fmt.Fprintln(stderr, "writing the response:", err)
			return exitRuntime
		}
	}
	out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
	return verbExit(out, stderr)
}

// ── evidence ────────────────────────────────────────────────────────────

// procTables is the reference's listening payload: the four tables
// verbatim, including one that would not open — shown as the reason it did
// not, because an unreadable table is the evidence for the fact that says
// so.
func procTables(src source) map[string]json.RawMessage {
	tables := map[string]json.RawMessage{}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		text, opened := src.procNet(name)
		if !opened || text == "" {
			text = "could not be read"
		}
		encoded, _ := json.Marshal(text)
		tables["/proc/net/"+name] = encoded
	}
	return tables
}

// linkDNSEvidence renders the per-link resolver map in the reference's own
// member spelling (_link_dns): the walk is resolver.go's, so the rows and
// their evidence come from one derivation.
func linkDNSEvidence(src source) map[string]json.RawMessage {
	perLink, _, _ := linkDNS(src)
	out := map[string]json.RawMessage{}
	for name, entry := range perLink {
		document := map[string]any{"DNSServers": entry.servers}
		if entry.current != "" {
			document["CurrentDNSServer"] = entry.current
		}
		if len(entry.domains) > 0 {
			document["Domains"] = entry.domains
		}
		if entry.defaultRouteKnown {
			document["DefaultRoute"] = entry.defaultRoute
		}
		encoded, _ := json.Marshal(document)
		out[name] = encoded
	}
	return out
}

// evidenceCanonical is the payload bytes for one collection's evidence.
// found=false is only ever "this collector does not serve this collection";
// per-name membership is the caller's, checked against the walk's own
// records.
func evidenceCanonical(stderr io.Writer, src source, collection string) ([]byte, bool, error) {
	switch collection {
	case collectionTables, collectionChains, collectionRules:
		doc, err := src.nftRuleset()
		if err != nil {
			return nil, true, err
		}
		return doc.appendJSON(nil), true, nil
	case "listening":
		canonical, err := json.Marshal(procTables(src))
		return canonical, true, err
	case collectionExposure:
		// Both halves, because the row is a join and neither half alone
		// lets a reader check it.
		doc, err := src.nftRuleset()
		if err != nil {
			return nil, true, err
		}
		sockets, err := json.Marshal(procTables(src))
		if err != nil {
			return nil, true, err
		}
		canonical, err := json.Marshal(map[string]json.RawMessage{
			"sockets": sockets,
			"ruleset": doc.appendJSON(nil),
		})
		return canonical, true, err
	case "tailscale":
		snapshot, _, err := src.tailscale()
		if err != nil {
			return nil, true, err
		}
		// The raw snapshot verbatim — the very document the facts were
		// shaped from; the mtime is the staleness rule's, not evidence.
		return snapshot.appendJSON(nil), true, nil
	case "routes":
		v4, err := src.ipRoute4()
		if err != nil {
			return nil, true, err
		}
		v6, err := src.ipRoute6()
		if err != nil {
			return nil, true, err
		}
		canonical, err := json.Marshal(map[string]json.RawMessage{
			"ipv4": v4.appendJSON(nil),
			"ipv6": v6.appendJSON(nil),
		})
		return canonical, true, err
	case "links":
		addr, err := src.ipAddr()
		if err != nil {
			return nil, true, err
		}
		canonical, err := json.Marshal(map[string]json.RawMessage{
			"ip_addr": addr.appendJSON(nil),
			"lldp":    lldpEvidence(src),
		})
		return canonical, true, err
	case "resolver":
		managerRaw, err := src.resolve1Call(resolve1ManagerRequest())
		if err != nil {
			return nil, true, err
		}
		if !json.Valid(managerRaw) {
			return nil, true, errors.New("resolve1 answered something that is not a document")
		}
		links, err := json.Marshal(linkDNSEvidence(src))
		if err != nil {
			return nil, true, err
		}
		canonical, err := json.Marshal(map[string]json.RawMessage{
			"manager": json.RawMessage(managerRaw),
			"links":   links,
		})
		return canonical, true, err
	}
	return nil, false, nil
}

// lldpEvidence is the reference's _lldp_by_link, through the same
// enrichment seam the links rows read: neighbours per interface, {} where
// nothing on the segment emits LLDP.
func lldpEvidence(src source) json.RawMessage {
	byLink := lldpByLink(src.lldp())
	if byLink == nil {
		byLink = map[string][]map[string]any{}
	}
	encoded, _ := json.Marshal(byLink)
	return encoded
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	// Membership against the walk's own records first: its unsupported and
	// per-collection declines are re-served as the answer.
	kept, matched, code := captureCollection(stderr, src, collection, name)
	if code != exitOK {
		return code
	}
	if len(kept) == 1 && matched {
		var envelope struct {
			Record string `json:"record"`
		}
		if json.Unmarshal([]byte(kept[0]), &envelope) == nil && envelope.Record == "decline" {
			if _, err := stdout.Write(append([]byte(kept[0]), '\n')); err != nil {
				fmt.Fprintln(stderr, "writing the response:", err)
				return exitRuntime
			}
			out.emit(verbEndRecord{Record: "verb_end", Verb: "evidence"})
			return verbExit(out, stderr)
		}
	}
	if !matched {
		return verbDecline(out, stderr, "evidence", collection, "unavailable", noSuchObject)
	}
	canonical, _, err := evidenceCanonical(stderr, src, collection)
	if err != nil {
		if isReplayGap(err) {
			fmt.Fprintln(stderr, collection+":", err)
			return exitRuntime
		}
		return verbDecline(out, stderr, "evidence", collection, "unavailable",
			"the interface answered the collection walk and not the evidence read")
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
