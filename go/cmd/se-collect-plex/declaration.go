package main

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

// The declaration is embedded so `declare` emits one artefact's exact bytes and
// the binary that must honour them cannot drift from them on disk — declaration
// and implementation deploy as one file, and a mismatch is a build to fix, not a
// host to debug.
//
//go:embed declaration.json
var declarationBytes []byte

// "sha256:<hex>" over exactly the bytes declare emits (DESIGN 19). It rides in
// begin so a collator holding a different declaration refetches instead of
// spawning declare on every collect — which only works if both sides hash the
// same bytes, hence hashing the embedded file rather than any re-serialisation
// of it.
var declarationDigest = func() string {
	sum := sha256.Sum256(declarationBytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}()
