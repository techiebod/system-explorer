package main

// The object and evidence verbs (DESIGN 18) — the fleet rollout of what R3c
// landed on the champions (register rows 1–2), joining the lookup verb that
// arrived first (lookup.go, which owns the shared verb records).
//
// The five collections' collect functions emit whole responses, so the
// object verb answers by RUNNING the same function into a capture and
// re-serving its object, relation_assertion, unobservable and decline
// records byte-for-byte: one derivation, no second spelling of it. The
// EVIDENCE payloads are the reference's (adapters/storage.py get_evidence),
// which serves each collection's whole native document — the zpool status
// and list pair, lsblk, findmnt, the zfs listing, and the md scrape in the
// reference's own assembled shape — after the name is checked against the
// collection's own records, which the reference left to its route layer.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"strconv"
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

// collections binds each collection to the function that emits it — the
// same table collect builds, spelled once at package level so the collect
// walk and the verbs answer from one table. collect.go's local built this
// map before the verbs landed; it now calls here.
var collections = map[string]func(*emitter, io.Writer, source, string, uint64, *int) int{
	"pools":         collectPools,
	"block-devices": collectBlockDevices,
	"mounts":        collectMounts,
	"datasets":      collectDatasets,
	"arrays":        collectArrays,
}

func verbDecline(out *emitter, stderr io.Writer, verb, collection, reason, detail string) int {
	out.emit(declineRecord{Record: "decline", Collection: collection,
		Reason: reason, Detail: detail})
	out.emit(verbEndRecord{Record: "verb_end", Verb: verb})
	return verbExit(out, stderr)
}

// captureCollection runs the SAME function that emits the collection, into
// a buffer, and answers for one name: the object, relation_assertion,
// unobservable and decline records to re-serve byte-for-byte (a commit is a
// collection-stream statement and is not), and whether the name matched.
func captureCollection(stderr io.Writer, src source, collection, name string) (kept []string, matched bool, code int) {
	serve := collections[collection]
	var capture bytes.Buffer
	captured := newEmitter(&capture)
	objects := 0
	if code := serve(captured, stderr, src, collection, 0, &objects); code != exitOK {
		return nil, false, code
	}
	if captured.err != nil {
		fmt.Fprintln(stderr, "capturing the collection:", captured.err)
		return nil, false, exitRuntime
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
			// The collection's decline IS the verb's answer.
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
	if _, known := collections[collection]; !known {
		return verbDecline(out, stderr, "object", collection, "unsupported",
			"this collector does not serve this collection")
	}
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

// mdScrape rebuilds the reference's _md_scrape shape from the same tree
// interface the arrays walk reads: every md array on the host, derived
// members and all, because the reference's evidence is this assembly and
// not the raw directory.
func mdScrape(tree mdDocument) map[string]any {
	arrays := map[string]any{}
	readOr := func(p string) string {
		text, _ := tree.read(p)
		return text
	}
	intOrNull := func(text string) any {
		if n, err := strconv.ParseInt(strings.TrimSpace(text), 10, 64); err == nil {
			return n
		}
		return nil
	}
	for _, name := range tree.listdir("/sys/block") {
		md := "/sys/block/" + name + "/md"
		if len(tree.listdir(md)) == 0 {
			continue
		}
		members := map[string]any{}
		for _, entry := range tree.listdir(md) {
			if !strings.HasPrefix(entry, "dev-") {
				continue
			}
			dev := md + "/" + entry
			kname := path.Base(tree.realpath(dev + "/block"))
			members[kname] = map[string]any{
				"state":  readOr(dev + "/state"),
				"slot":   readOr(dev + "/slot"),
				"errors": intOrNull(readOr(dev + "/errors")),
			}
		}
		var percent any
		syncCompleted := readOr(md + "/sync_completed")
		if strings.Contains(syncCompleted, "/") {
			parts := strings.SplitN(syncCompleted, "/", 2)
			done, doneErr := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
			total, totalErr := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
			if doneErr == nil && totalErr == nil && total != 0 {
				percent = math.RoundToEven(float64(done)*100/float64(total)*10) / 10
			}
		}
		var sizeBytes any
		if sectors := intOrNull(readOr("/sys/block/" + name + "/size")); sectors != nil {
			sizeBytes = sectors.(int64) * 512
		}
		arrays[name] = map[string]any{
			"level":            readOr(md + "/level"),
			"array_state":      readOr(md + "/array_state"),
			"degraded":         intOrNull(readOr(md + "/degraded")),
			"raid_disks":       intOrNull(readOr(md + "/raid_disks")),
			"metadata_version": readOr(md + "/metadata_version"),
			"uuid":             readOr(md + "/uuid"),
			"sync_action":      readOr(md + "/sync_action"),
			"sync_completed":   syncCompleted,
			"sync_percent":     percent,
			"size_bytes":       sizeBytes,
			"members":          members,
		}
	}
	return arrays
}

// evidenceCanonical is the payload bytes for one collection's evidence —
// the whole native document, as the reference serves it.
func evidenceCanonical(src source, collection string) ([]byte, error) {
	switch collection {
	case "pools":
		reading, err := src.zpool()
		if err != nil {
			return nil, err
		}
		payload := map[string]json.RawMessage{
			"status": reading.status.encode(),
			"list":   json.RawMessage("null"),
		}
		// list is enrichment: could-not-read is an explicit null, exactly
		// the reference's _zpool_list() answer.
		if reading.list != nil {
			payload["list"] = reading.list.encode()
		}
		return json.Marshal(payload)
	case "block-devices":
		document, err := src.lsblk()
		if err != nil {
			return nil, err
		}
		return []byte(document.encode()), nil
	case "mounts":
		document, _, err := src.findmnt()
		if err != nil {
			return nil, err
		}
		return []byte(document.encode()), nil
	case "datasets":
		document, err := src.zfsList()
		if err != nil {
			return nil, err
		}
		return []byte(document.encode()), nil
	case "arrays":
		tree, err := src.mdTree()
		if err != nil {
			return nil, err
		}
		return json.Marshal(mdScrape(tree))
	}
	return nil, errors.New("no evidence source for " + collection)
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if _, known := collections[collection]; !known {
		return verbDecline(out, stderr, "evidence", collection, "unsupported",
			"this collector does not serve this collection")
	}
	// Membership against the collection's own records first — the
	// reference's route layer did this half — then the whole document.
	_, matched, code := captureCollection(stderr, src, collection, name)
	if code != exitOK {
		return code
	}
	if !matched {
		return verbDecline(out, stderr, "evidence", collection, "unavailable", noSuchObject)
	}
	canonical, err := evidenceCanonical(src, collection)
	var refused *declined
	if errors.As(err, &refused) {
		return verbDecline(out, stderr, "evidence", collection,
			refused.reason, refused.detail)
	}
	if err != nil {
		fmt.Fprintln(stderr, collection+":", err)
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
