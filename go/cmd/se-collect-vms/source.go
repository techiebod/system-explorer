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
	"strings"
	"syscall"
	"time"
)

// source is the acquisition seam (DESIGN 20; harness/se_harness/replay.py):
// with SE_REPLAY_DIR set, the native document comes from that directory
// instead of the live interface, while the parse, the declared semantics and
// the stream generation run unchanged. The seam is a value chosen at startup,
// not a build flag, so the binary the harness judges is the binary that
// deploys.
type source interface {
	// bootID names the boot whose clock every `at` reading belongs to;
	// without it the readings are meaningless (DESIGN 09).
	bootID() (string, error)
	// timens is the CLOCK_BOOTTIME namespace offset — stated, never
	// corrected, by whoever compares it (DESIGN 09).
	timens() int64
	// batch mints the batch id — collector-minted by ruling (appendix C):
	// the collector authors the batch, and a transport retry re-sending the
	// same bytes under the same id is what makes retry idempotent.
	// request := batch until a consumer needs them distinct.
	batch() (string, error)
	// declaration is the digest begin carries: the hash of the exact bytes
	// `declare` emits, so an unknown hash triggers a refetch rather than a
	// spawn on every collect (DESIGN 19).
	declaration() string
	// domains is the whole libvirt reading in one document — the domain walk
	// `_domains_raw()` returns. Its errors carry the decline shape.
	domains() (*value, error)
	// stamp is `at` for the i-th emitted object, taken BEFORE the earliest
	// native read that contributes to it so the tie breaks toward older
	// (DESIGN 19). Every row of a batch comes from ONE domain walk over one
	// connection, so the live reading is taken once and shared.
	stamp(i int) (float64, error)
	// costs are end's advisory self-report (DESIGN 19): bounded by the judge,
	// authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

// declined is the seam's statement that the interface itself could not be
// reached, carried as an error so no caller can forget to route it. The
// detail is a constant: decline detail travels to a hub and out over MCP, and
// an interpolated error string is a redaction path nobody reviewed.
type declined struct{ reason, detail string }

func (d *declined) Error() string { return d.reason + ": " + d.detail }

// The interface-is-not-here reading, named ONCE and used by both the live
// source and the replay source. It is a constant because the storage
// collector answered exactly this question two opposite ways for as long as
// it existed — live said `unsupported`, replay said `absent`, each under a
// confident comment arguing against the other — and nothing caught it,
// because replay exercises only the replay half. A shared constant is what
// makes the disagreement unspellable rather than merely currently-absent.
//
// `absent` is the reading, for the same reason no zpool on PATH is: a host
// with no libvirt socket runs no libvirt, and a host that runs no libvirt
// defines no domains. That is a successful reading of the interface which
// establishes something, which is DESIGN 19's own worked example — and it
// must commit zero, because a host that HAD a hypervisor and then lost it
// would otherwise serve its old domains forever, stale and never retired.
var declineNoLibvirt = declined{"absent", "no libvirt on this host"}

// The read-only socket, which is the whole of what this collector needs and
// the only thing it ever opens. adapters/vms.py SOCKET_RO.
const socketReadOnly = "/var/run/libvirt/libvirt-sock-ro"

// The live reading this binary cannot take, stated once and honestly.
//
// The reference reads libvirt through libvirt-python — a binding to the C
// library, not a document a command produces — and this binary is stdlib-only
// and static by design. `virsh` is not a substitute: it renders a domain's
// state as prose ("shut off"), and the collection's State fact is libvirt's
// own enum word ("shutoff"), so a virsh-driven reading would disagree with
// the reference about the one fact the collection exists to answer.
//
// So the honest statement is `unsupported`: something IS here and this build
// cannot read it. It commits nothing, which means a host's existing domains
// stand and are served marked stale — never retired by a batch that could not
// look. `unavailable` would be the wrong word: no retry helps, and it would
// send somebody hunting a transient failure that does not exist.
var declineNoLibvirtReader = declined{
	"unsupported",
	"libvirt is listening on this host and this build cannot read it; " +
		"the domain walk goes through the libvirt client library, which this " +
		"static binary does not link",
}

// errUncaptured marks a document the variant did not stage. It must never
// fall back to the live interface of the machine REPLAYING the corpus — that
// seam escape once put a replaying workstation's filesystem into committed
// facts — and it must not become a decline either, which would state
// something about a machine nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is deliberately not consulted: nothing here is
		// derived against wall-clock now — no age, no elapsed time, no
		// timestamp — so the pin has nothing to freeze, and reading it anyway
		// would invent a dependency the declaration does not admit to.
		return replaySource{dir: dir}
	}
	return &liveSource{started: time.Now()}
}

// ── live ────────────────────────────────────────────────────────────────

type liveSource struct {
	started time.Time
	at      float64
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

func (*liveSource) domains() (*value, error) {
	// Socket presence decides ABSENCE and nothing else. A host with no
	// libvirt socket runs no libvirt and defines no domains — a successful
	// reading which must commit zero, because a host that HAD a hypervisor
	// and lost it would otherwise serve its old domains forever.
	if _, err := os.Stat(socketReadOnly); err != nil {
		reason := declineNoLibvirt
		return nil, &reason
	}
	// And where it IS listening, this build now reads it. See live.go for why
	// virsh turned out to be a lawful source after all: the objection was
	// about `virsh list`, which renders state as prose, and `domstats`
	// answers the enum.
	return liveDomains()
}

// stamp is taken once, before the walk, and shared by every row — which is
// what `at` means: the oldest byte a row rests on. It used to be read per
// object with a comment saying that was harmless because no live path ever
// produced one; the walk has landed, so the reading moved to where that
// comment said it would. A stamp taken per row after the walk would report
// each row fresher than the bytes it describes (DESIGN 19).
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
	// 0 is RUSAGE_SELF on every POSIX platform this compiles for; a failed
	// reading reports zero cost rather than failing the batch, because the
	// self-report is advisory by construction (DESIGN 19).
	if syscall.Getrusage(0, &usage) == nil {
		cpu = float64(usage.Utime.Nano()+usage.Stime.Nano()) / 1e6
	}
	return cpu, float64(time.Since(s.started)) / float64(time.Millisecond)
}

// ── replay ──────────────────────────────────────────────────────────────

// A replay has no boot, so the fixed v4-shaped id — "5e" up front so no
// reader mistakes it for a capture. The shape rule refuses the old "replay"
// stub and the nil UUID; that this constant itself passes is DESIGN 19's
// named deferral, a cross-boot live variant's to catch.
const replayBootID = "5e000000-0000-4000-8000-000000000001"

type replaySource struct{ dir string }

func (r replaySource) bootID() (string, error) {
	raw, err := os.ReadFile(filepath.Join(r.dir, "boot_id"))
	if errors.Is(err, fs.ErrNotExist) {
		return replayBootID, nil
	}
	if err != nil {
		return "", fmt.Errorf("boot_id: %v", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// No time namespace was observed at capture, so the offset is the pinned
// zero — a live reading here would smuggle the replaying machine into a
// deterministic stream.
func (replaySource) timens() int64 { return 0 }

func (replaySource) batch() (string, error) { return "replay", nil }

// The real digest, under replay as much as live: the declaration identifies
// THIS collector's contract, and a replay does not change which contract this
// binary holds. It is rule-governed rather than byte-compared (DESIGN 19's
// two regimes), so the honest value costs nothing.
func (replaySource) declaration() string { return declarationDigest }

// The whole interface for this collector is one payload file. Its ABSENCE is
// the reading — the interface was not there — through the same constant the
// live path takes, so the two cannot spell one condition two ways. A payload
// that is present and unreadable is a broken capture rather than a statement
// about a machine, so it fails the batch instead of declining, and it must
// never fall back to the live libvirt of the workstation replaying the
// corpus.
func (r replaySource) domains() (*value, error) {
	raw, err := os.ReadFile(filepath.Join(r.dir, "domains.json"))
	if errors.Is(err, fs.ErrNotExist) {
		reason := declineNoLibvirt
		return nil, &reason
	}
	if err != nil {
		return nil, fmt.Errorf("domains %w: %v", errUncaptured, err)
	}
	document, err := decodeDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("the staged domains.json is not a document: %v", err)
	}
	return document, nil
}

func (replaySource) stamp(i int) (float64, error) {
	// The reference constant, 1.0 + 0.001*i in emission order and one counter
	// across the whole batch: finite, positive, boot-scale and advancing, so
	// the structural rule that governs `at` is exercised by replay instead of
	// satisfied by a hardcoded zero.
	return 1.0 + 0.001*float64(i), nil
}

func (replaySource) costs() (float64, float64) { return 0.5, 1.0 }

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
// 18). It runs the real acquisition, because nothing weaker establishes the
// answer — a socket on disk says nothing about whether the daemon answers,
// which is the two-stage question the reference's capability check asks — and
// nothing stronger is wanted either: a host with libvirt and no domains
// defined still answers, and that is a reading of zero domains rather than an
// inability.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes", Reason: "libvirt answers the read-only domain walk"}
	if _, err := src.domains(); err != nil {
		// The reason names the decline this side reached and nothing it has
		// not established; the error itself goes to stderr, where a person
		// debugging can read it.
		reason := "the domain walk could not be taken"
		var refused *declined
		if errors.As(err, &refused) {
			reason = refused.detail
		}
		verdict = probeVerdict{Verdict: "no", Reason: reason}
		fmt.Fprintln(stderr, "probe:", err)
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(verdict); err != nil {
		fmt.Fprintln(stderr, "writing the probe verdict:", err)
		return exitRuntime
	}
	return exitOK
}
