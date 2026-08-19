package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// source is the acquisition seam (DESIGN 20; harness/se_harness/replay.py):
// with SE_REPLAY_DIR set, the native document comes from that directory
// instead of the live interface, while the parse, the declared semantics and
// the stream generation run unchanged.
//
// This interface is SIX PRIMITIVES rather than one document, because the
// interface being read is a filesystem. The ruled payload shape for a
// tree-shaped interface is the filesystem transcribed — the directory
// listings the collector walked — and that only substitutes cleanly where the
// walk goes through named calls. They mirror agent/nixos.py's five plus
// exists, one for one, because the two implementations must be able to
// disagree about a READING and never about which reads were taken.
type source interface {
	bootID() (string, error)
	timens() int64
	batch() (string, error)
	declaration() string

	// The five, plus exists. Each answers the absence of its target the way
	// the reference does — "" for a file that is not there, an empty list for
	// a directory that is not, false for a path that does not exist — so an
	// ordinary negative reading stays a reading. The error is reserved for
	// the one thing that is not a reading: a replay asked about a path the
	// variant never recorded.
	exists(path string) (bool, error)
	read(path string) (string, error)
	listdir(path string) ([]string, error)
	realpath(path string) (string, error)
	readlink(path string) (string, error)
	mtime(path string) (float64, bool, error)

	// receiptsDir is the directory of per-generation deployment receipts, or
	// "" for a process that was not told where they are. NOT one of the
	// primitives and deliberately not stubbed, because the reference reads it
	// from the ambient environment too — see the residual ledger entry
	// nix/receipts-dir-is-ambient, which names this as an escape rather than
	// leaving it to be discovered.
	receiptsDir() string

	stamp(i int) (float64, error)
	costs() (cpuMS, wallMS float64)
}

// declined is the seam's statement that the interface itself could not be
// reached, carried as an error so no caller can forget to route it. The
// detail is a constant: decline detail travels to a hub and out over MCP, and
// an interpolated error string is a redaction path nobody reviewed.
type declined struct{ reason, detail string }

func (d *declined) Error() string { return d.reason + ": " + d.detail }

// The interface-is-not-here reading, named ONCE and used by both sources, for
// the reason the storage collector demonstrated by spelling one condition two
// ways for as long as it existed. A shared constant makes the disagreement
// unspellable rather than merely currently-absent.
//
// `absent` is the reading. /run/current-system exists only where something
// activated a nix closure, so its absence means this host has no generations
// — a successful reading that establishes something, exactly as no `zpool` on
// PATH does. It must commit zero, because a host that WAS NixOS and was
// rebuilt as something else would otherwise serve its old generations for
// ever, stale and never retired.
var declineNotNixOS = declined{"absent", "no nix system closure on this host"}

// The paths this collector reads, spelled once. agent/nixos.py's constants.
const (
	profilesDir   = "/nix/var/nix/profiles"
	currentSystem = "/run/current-system"
	bootedSystem  = "/run/booted-system"
	// The optional build manifest a generation may carry, in the same place
	// and with the same properties as nixos-version: inside the closure,
	// immutable per generation, readable without executing anything.
	generationManifest = "se-generation.json"
	// The lowest manifest schema that promises a receipt exists for every
	// generation. Below it, a generation without one says nothing at all.
	receiptsExpectedSchema = 2
)

// errUncaptured marks a path the variant did not record. It must never fall
// back to the live filesystem of the machine REPLAYING the corpus — that seam
// escape once put a replaying workstation's tree into committed facts — and
// it must not become a decline either, which would state something about a
// machine nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is deliberately not consulted: nothing here is
		// derived against wall-clock now. Created is the profile link's own
		// mtime, which the capture recorded, so the pin has nothing to freeze
		// and reading it would invent a dependency the declaration does not
		// admit to.
		return &replaySource{dir: dir, documents: map[string]map[string]map[string]any{}}
	}
	return &liveSource{started: time.Now(), receipts: getenv("SE_DEPLOYMENT_RECEIPTS")}
}

// ── live ────────────────────────────────────────────────────────────────

type liveSource struct {
	started  time.Time
	receipts string
	at       float64
}

func (*liveSource) bootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", fmt.Errorf("boot_id: %v", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func (*liveSource) timens() int64 { return timensOffset() }

func (*liveSource) batch() (string, error) { return newUUIDv4() }

func (*liveSource) declaration() string { return declarationDigest }

func (*liveSource) exists(path string) (bool, error) {
	_, err := os.Stat(path)
	return err == nil, nil
}

// Stripped, and "" for absent — absence is not an error here, because on a
// host whose closures were built without a given file the honest answer is
// that this generation does not record it.
func (*liveSource) read(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", nil
	}
	return strings.TrimSpace(string(raw)), nil
}

// Sorted here rather than at the caller, so two hosts with the same tree emit
// the same order.
func (*liveSource) listdir(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return []string{}, nil
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

func (*liveSource) realpath(path string) (string, error) {
	if _, err := os.Stat(path); err != nil {
		return "", nil
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", nil
	}
	return resolved, nil
}

// The link's IMMEDIATE target, unresolved. Distinct from realpath and both
// are needed: a profile link's own target IS the store path the generation
// is, where resolving it follows through to whatever that path points at.
func (*liveSource) readlink(path string) (string, error) {
	target, err := os.Readlink(path)
	if err != nil {
		return "", nil
	}
	return target, nil
}

// The LINK's own mtime, not its target's — lstat, because a generation's
// creation time is when the link was made and every file under the closure
// carries whatever timestamp nix gave it.
func (*liveSource) mtime(path string) (float64, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return 0, false, nil
	}
	return float64(info.ModTime().UnixNano()) / 1e9, true, nil
}

func (s *liveSource) receiptsDir() string { return s.receipts }

// Taken once, before the walk, and shared by every row — which is what `at`
// means: the oldest byte a row rests on. A stamp taken per row after the walk
// would report each row fresher than the bytes it describes (DESIGN 19).
func (s *liveSource) stamp(int) (float64, error) {
	if s.at == 0 {
		at, err := bootClock()
		if err != nil {
			return 0, err
		}
		s.at = at
	}
	return s.at, nil
}

func (s *liveSource) costs() (float64, float64) {
	cpu := 0.0
	var usage syscall.Rusage
	if syscall.Getrusage(0, &usage) == nil {
		cpu = float64(usage.Utime.Nano()+usage.Stime.Nano()) / 1e6
	}
	return cpu, float64(time.Since(s.started)) / float64(time.Millisecond)
}

// ── replay ──────────────────────────────────────────────────────────────

// A replay has no boot, so the fixed v4-shaped id — "5e" up front so no
// reader mistakes it for a capture.
const replayBootID = "5e000000-0000-4000-8000-000000000001"

type replaySource struct {
	dir string
	// One decoded document per primitive, keyed the way a filesystem is:
	// directory, then the name inside it. Loaded on first use and kept,
	// because a walk asks the same document many times.
	documents map[string]map[string]map[string]any
}

func (r *replaySource) bootID() (string, error) {
	raw, err := os.ReadFile(filepath.Join(r.dir, "boot_id"))
	if errors.Is(err, fs.ErrNotExist) {
		return replayBootID, nil
	}
	if err != nil {
		return "", fmt.Errorf("boot_id: %v", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func (*replaySource) timens() int64 { return 0 }

func (*replaySource) batch() (string, error) { return "replay", nil }

func (*replaySource) declaration() string { return declarationDigest }

// The receipts directory comes from its own captured payload, never from the
// environment of the machine replaying. It is the one read agent/nixos.py
// makes that is not a file — an environment variable — so it is captured as a
// VALUE beside the six transcriptions rather than transcribed as a path, and
// a variant taken without SE_DEPLOYMENT_RECEIPTS records null, which is
// exactly what a process nobody pointed at a directory sees.
//
// A variant with no receipts-dir.json at all also answers "": the payload
// arrived on 2026-08-19 and the variants captured before it are legitimately
// without one. That is a default rather than a refusal because it is what the
// reference's own seam does with it — auxiliary, pinned to None when missing,
// which qualifies the reading instead of meaning the interface was absent.
func (r *replaySource) receiptsDir() string {
	raw, err := os.ReadFile(filepath.Join(r.dir, "receipts-dir.json"))
	if err != nil {
		return ""
	}
	var directory *string
	if json.Unmarshal(raw, &directory) != nil || directory == nil {
		return ""
	}
	return *directory
}

func (r *replaySource) stamp(i int) (float64, error) {
	return 1.0 + 0.001*float64(i), nil
}

func (*replaySource) costs() (float64, float64) { return 0.5, 1.0 }

// document loads one primitive's transcription. Its ABSENCE is the reading —
// the interface was not there — which is why a missing exists.json declines
// through the same constant the live path takes rather than failing.
func (r *replaySource) document(primitive string) (map[string]map[string]any, error) {
	if cached, ok := r.documents[primitive]; ok {
		return cached, nil
	}
	raw, err := os.ReadFile(filepath.Join(r.dir, primitive+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		reason := declineNotNixOS
		return nil, &reason
	}
	if err != nil {
		return nil, fmt.Errorf("%s %w: %v", primitive, errUncaptured, err)
	}
	var decoded map[string]map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("the staged %s.json is not a path transcription: %v", primitive, err)
	}
	r.documents[primitive] = decoded
	return decoded, nil
}

// answer is the tree seam's lookup, keyed the way a filesystem is. A path the
// variant DID record is answered with whatever it holds, including a negative
// reading; a path it did not is refused, because falling through would read
// the tree of the machine replaying the corpus.
func (r *replaySource) answer(primitive, path string) (any, error) {
	document, err := r.document(primitive)
	if err != nil {
		return nil, err
	}
	container, member := filepath.Dir(path), filepath.Base(path)
	inside, ok := document[container]
	if !ok {
		return nil, fmt.Errorf("%s %q %w", primitive, path, errUncaptured)
	}
	value, ok := inside[member]
	if !ok {
		return nil, fmt.Errorf("%s %q %w", primitive, path, errUncaptured)
	}
	return value, nil
}

func (r *replaySource) exists(path string) (bool, error) {
	value, err := r.answer("exists", path)
	if err != nil {
		return false, err
	}
	present, ok := value.(bool)
	if !ok {
		return false, fmt.Errorf("exists %q: the transcription holds %T, not a boolean", path, value)
	}
	return present, nil
}

func (r *replaySource) read(path string) (string, error) {
	return r.stringAnswer("read", path)
}

func (r *replaySource) realpath(path string) (string, error) {
	return r.stringAnswer("realpath", path)
}

func (r *replaySource) readlink(path string) (string, error) {
	return r.stringAnswer("readlink", path)
}

// A null is the reference's own "no such link" and decodes to "", which is
// what the live side answers for the same condition. That equivalence is why
// the transcription records negatives at all.
func (r *replaySource) stringAnswer(primitive, path string) (string, error) {
	value, err := r.answer(primitive, path)
	if err != nil {
		return "", err
	}
	if value == nil {
		return "", nil
	}
	text, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("%s %q: the transcription holds %T, not a string", primitive, path, value)
	}
	return text, nil
}

func (r *replaySource) listdir(path string) ([]string, error) {
	value, err := r.answer("listdir", path)
	if err != nil {
		return nil, err
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("listdir %q: the transcription holds %T, not a list", path, value)
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		name, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("listdir %q: an entry is %T, not a string", path, item)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func (r *replaySource) mtime(path string) (float64, bool, error) {
	value, err := r.answer("mtime", path)
	if err != nil {
		return 0, false, err
	}
	if value == nil {
		return 0, false, nil
	}
	seconds, ok := value.(float64)
	if !ok {
		return 0, false, fmt.Errorf("mtime %q: the transcription holds %T, not a number", path, value)
	}
	return seconds, true, nil
}

// ── shared ──────────────────────────────────────────────────────────────

// newUUIDv4 mints a lowercase RFC 4122 v4 id from the kernel's CSPRNG. No
// dependency: sixteen random bytes with the version and variant bits set is
// the whole format, and this binary stays stdlib-only and static.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("minting the batch id: %v", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

type probeVerdict struct {
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
}

// probe answers "can it run here" as a verdict, never an exit code (DESIGN
// 18). The question is the one that separates a NixOS host from every other
// kind — did something activate a closure — and nothing stronger is wanted: a
// host with exactly one generation still answers, and that is a reading of
// one generation rather than an inability.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes", Reason: "this host has an activated nix system closure"}
	present, err := src.exists(currentSystem)
	switch {
	case err != nil:
		var refused *declined
		reason := "the closure pointer could not be read"
		if errors.As(err, &refused) {
			reason = refused.detail
		}
		verdict = probeVerdict{Verdict: "no", Reason: reason}
		fmt.Fprintln(stderr, "probe:", err)
	case !present:
		verdict = probeVerdict{Verdict: "no", Reason: declineNotNixOS.detail}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(verdict); err != nil {
		fmt.Fprintln(stderr, "writing the probe verdict:", err)
		return exitRuntime
	}
	return exitOK
}
