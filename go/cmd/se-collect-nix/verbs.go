package main

// The object and evidence verbs (DESIGN 18) — the fleet rollout of what R3c
// landed on the champions (register rows 1–2).
//
// nix has no density behind its rows, so an object response is the row the
// collection publishes — facts and the store-path name family — addressed by
// the generation number. The EVIDENCE payload is the reference's
// (adapters/nix.py get_evidence): the profile link and its target, the three
// pointers whose disagreement is this collection's whole point, the
// closure's own version and revision files, the kernel it links, the build
// manifest and the deployment receipt — each read through the same five
// primitives the rows ride, and a manifest that is absent or does not parse
// is an explicit null, because "no manifest" is a reading.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
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

// verbLinks is the shared gate: the NixOS probe and the profile walk, routed
// exactly as collect routes them.
func verbLinks(out *emitter, stderr io.Writer, src source, verb string) ([]generation, bool, int) {
	present, err := src.exists(currentSystem)
	var refused *declined
	if err != nil && !errors.As(err, &refused) {
		fmt.Fprintln(stderr, err)
		return nil, false, exitRuntime
	}
	if refused != nil || !present {
		reason := declineNotNixOS
		if refused != nil {
			reason = *refused
		}
		return nil, false, verbDecline(out, stderr, verb, collectionGenerations,
			reason.reason, reason.detail)
	}
	links, err := generationLinks(src)
	if err != nil {
		fmt.Fprintln(stderr, "generations:", err)
		return nil, false, exitRuntime
	}
	return links, true, exitOK
}

func generationNamed(links []generation, name string) (generation, bool) {
	for _, gen := range links {
		if strconv.Itoa(gen.number) == name {
			return gen, true
		}
	}
	return generation{}, false
}

func serveObject(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if collection != collectionGenerations {
		return verbDecline(out, stderr, "object", collection, "unsupported",
			"this collector serves generations only")
	}
	links, ok, code := verbLinks(out, stderr, src, "object")
	if !ok {
		return code
	}
	gen, found := generationNamed(links, name)
	if !found {
		return verbDecline(out, stderr, "object", collection, "unavailable", noSuchObject)
	}
	ptr, err := readPointers(src)
	if err != nil {
		fmt.Fprintln(stderr, "generations:", err)
		return exitRuntime
	}
	facts, err := generationRow(src, gen, ptr)
	if err != nil {
		fmt.Fprintln(stderr, "generations:", err)
		return exitRuntime
	}
	at, err := src.stamp(0)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	names := newObject()
	stable := newObject()
	stable.set("store-path", stringValue(gen.target))
	names.set("stable", stable)
	out.emit(objectRecord{
		Record:     "object",
		Type:       "generation",
		Collection: collection,
		Name:       name,
		Facts:      facts.encode(),
		Names:      names.encode(),
		At:         at,
	})
	out.emit(verbEndRecord{Record: "verb_end", Verb: "object"})
	return verbExit(out, stderr)
}

// jsonOrNull is the reference's read_json: the file's own JSON compacted,
// or an explicit null for absent, unreadable or malformed — a half-written
// manifest is not evidence of anything.
func jsonOrNull(src source, path string) (json.RawMessage, error) {
	raw, err := src.read(path)
	if err != nil {
		return nil, err
	}
	if json.Valid([]byte(raw)) && len(raw) > 0 && raw[0] == '{' {
		var compact json.RawMessage
		if json.Unmarshal([]byte(raw), &compact) == nil {
			return compact, nil
		}
	}
	return json.RawMessage("null"), nil
}

func serveEvidence(stdout, stderr io.Writer, src source, collection, name string) int {
	out := newEmitter(stdout)
	if collection != collectionGenerations {
		return verbDecline(out, stderr, "evidence", collection, "unsupported",
			"this collector serves generations only")
	}
	links, ok, code := verbLinks(out, stderr, src, "evidence")
	if !ok {
		return code
	}
	gen, found := generationNamed(links, name)
	if !found {
		return verbDecline(out, stderr, "evidence", collection, "unavailable", noSuchObject)
	}
	payload := map[string]json.RawMessage{}
	rawString := func(s string) json.RawMessage {
		encoded, _ := json.Marshal(s)
		return encoded
	}
	payload["link"] = rawString(gen.link)
	payload["target"] = rawString(gen.target)
	// The three pointers, realpath answers exactly as the rows read them.
	pointerPaths := map[string]string{
		"current": currentSystem,
		"booted":  bootedSystem,
		"default": profilesDir + "/system",
	}
	pointerDoc := map[string]json.RawMessage{}
	for key, path := range pointerPaths {
		resolved, err := src.realpath(path)
		if err != nil {
			fmt.Fprintln(stderr, "generations:", err)
			return exitRuntime
		}
		if resolved == "" {
			pointerDoc[key] = json.RawMessage("null")
		} else {
			pointerDoc[key] = rawString(resolved)
		}
	}
	pointersRaw, _ := json.Marshal(pointerDoc)
	payload["pointers"] = pointersRaw
	for member, file := range map[string]string{
		"nixos-version":          gen.target + "/nixos-version",
		"configuration-revision": gen.target + "/configuration-revision",
	} {
		text, err := src.read(file)
		if err != nil {
			fmt.Fprintln(stderr, "generations:", err)
			return exitRuntime
		}
		payload[member] = rawString(text)
	}
	kernel, err := src.realpath(gen.target + "/kernel")
	if err != nil {
		fmt.Fprintln(stderr, "generations:", err)
		return exitRuntime
	}
	payload["kernel"] = rawString(kernel)
	manifest, err := jsonOrNull(src, gen.target+"/"+generationManifest)
	if err != nil {
		fmt.Fprintln(stderr, "generations:", err)
		return exitRuntime
	}
	payload[generationManifest] = manifest
	receipt := json.RawMessage("null")
	if directory := src.receiptsDir(); directory != "" {
		receipt, err = jsonOrNull(src, fmt.Sprintf("%s/%d.json", directory, gen.number))
		if err != nil {
			fmt.Fprintln(stderr, "generations:", err)
			return exitRuntime
		}
	}
	payload["deployment-receipt"] = receipt

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
