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
// with SE_REPLAY_DIR set, every native document comes from that directory
// instead of the live interface, while the parse, the declared semantics
// and the stream generation run unchanged. The seam is a value chosen at
// startup, not a build flag, so the binary the harness judges is the binary
// that deploys.
type source interface {
	// bootID names the boot whose clock every `at` reading belongs to;
	// without it the readings are meaningless (DESIGN 09).
	bootID() (string, error)
	// timens is the CLOCK_BOOTTIME namespace offset — stated, never
	// corrected, by whoever compares it (DESIGN 09).
	timens() int64
	// batch mints the batch id — collector-minted by ruling (appendix C):
	// the collector authors the batch, and a transport retry re-sending
	// the same bytes under the same id is what makes retry idempotent.
	// request := batch until a consumer needs them distinct.
	batch() (string, error)
	// stamp is `at` for the i-th emitted object, taken BEFORE the earliest
	// native read that contributes to it so the tie breaks toward older
	// (DESIGN 19).
	stamp(i int) (float64, error)
	osRelease() ([]byte, error)
	hostname() (string, error)
	// costs are end's advisory self-report (DESIGN 19): bounded by the
	// judge, authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is deliberately not consulted: this collector
		// derives nothing from wall time, so the pin has nothing here to
		// freeze — reading it anyway would invent a dependency the
		// declaration does not admit to.
		return replaySource{dir: dir}
	}
	return liveSource{started: time.Now()}
}

// ── live ────────────────────────────────────────────────────────────────

type liveSource struct{ started time.Time }

func (liveSource) bootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", fmt.Errorf("boot_id: %v", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func (liveSource) timens() int64 { return timensOffset() }

func (liveSource) batch() (string, error) { return newUUIDv4() }

func (liveSource) stamp(int) (float64, error) { return bootClock() }

func (liveSource) osRelease() ([]byte, error) {
	raw, err := os.ReadFile("/etc/os-release")
	if errors.Is(err, fs.ErrNotExist) {
		// The documented fallback location (os-release(5)). Only absence
		// falls back: a present-but-unreadable /etc file is an admin's
		// override this process failed to read, and serving the /usr/lib
		// copy instead would answer with configuration the host is not
		// running.
		raw, err = os.ReadFile("/usr/lib/os-release")
	}
	return raw, err
}

func (liveSource) hostname() (string, error) { return os.Hostname() }

func (s liveSource) costs() (float64, float64) {
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

// errUncaptured marks a document the variant did not stage. It must never
// fall back to the live interface of the machine REPLAYING the corpus —
// that seam escape once put a replaying workstation's filesystem into
// committed facts — and it must not become a decline either, which would
// state something about a machine nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

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

func (replaySource) stamp(i int) (float64, error) {
	// The reference constant, 1.0 + 0.001*i in emission order: finite,
	// positive, boot-scale and advancing, so the structural rule that
	// governs `at` is exercised by replay instead of satisfied by a
	// hardcoded zero.
	return 1.0 + 0.001*float64(i), nil
}

func (r replaySource) osRelease() ([]byte, error) {
	return os.ReadFile(filepath.Join(r.dir, "os-release"))
}

func (r replaySource) hostname() (string, error) {
	raw, err := os.ReadFile(filepath.Join(r.dir, "hostname"))
	if err != nil {
		return "", fmt.Errorf("hostname %w: %v", errUncaptured, err)
	}
	name := strings.TrimSpace(string(raw))
	if name == "" {
		return "", fmt.Errorf("hostname %w: the staged file is empty, and an empty string is not a name", errUncaptured)
	}
	return name, nil
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
// 18). os-release is deliberately not probed: a machine without it still
// answers, as an absent decline, so its absence is a reading rather than an
// inability — the probe asks only for what no request could succeed
// without.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes", Reason: "the kernel hostname and the boot id are readable"}
	if _, err := src.hostname(); err != nil {
		verdict = probeVerdict{Verdict: "no", Reason: "the kernel hostname did not answer"}
		fmt.Fprintln(stderr, "probe:", err)
	} else if _, err := src.bootID(); err != nil {
		verdict = probeVerdict{Verdict: "no", Reason: "the boot id is not readable, and `at` readings are meaningless without the boot they belong to"}
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
