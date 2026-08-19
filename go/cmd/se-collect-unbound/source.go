package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// source is the acquisition seam (DESIGN 20; harness/se_harness/replay.py):
// with SE_REPLAY_DIR set, the native documents come from that directory
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
	// daemon is both control-socket documents in one reading. They are taken
	// together because they describe one object and are published as one row:
	// a status without its counters is half an answer, and the reference
	// issues both commands before it builds anything.
	daemon() (reading, error)
	// stamp is `at` for the i-th emitted object. The whole row rests on one
	// pair of reads, so the live reading is taken once, before the first of
	// them, and the index is ignored — a stamp taken at completion would
	// report the row fresher than the bytes it describes (DESIGN 19).
	stamp(i int) float64
	// costs are end's advisory self-report (DESIGN 19): bounded by the judge,
	// authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

// reading is what the control socket answered, one document per command.
type reading struct{ status, stats string }

// declined is the seam's statement that the interface itself could not be
// read, carried as an error so no caller can forget to route it. The detail is
// a constant: decline detail travels to a hub and out over MCP, and an
// interpolated error string is a redaction path nobody reviewed — the socket
// path in particular is deployment configuration and belongs in stderr, where
// a person debugging can read it, not in a record that leaves the host.
type declined struct{ reason, detail string }

func (d *declined) Error() string { return d.reason + ": " + d.detail }

// The interface-is-not-here reading, named ONCE and used by the live source
// and the replay source alike. It is a constant because the storage collector
// answered exactly this question two opposite ways for as long as it existed —
// live said `unsupported`, replay said `absent`, each under a confident comment
// arguing against the other — and nothing caught it, because replay exercises
// only the replay half. A shared constant makes the disagreement unspellable
// rather than merely currently-absent.
//
// `unavailable` is the reading, and it does NOT commit — RULED 2026-08-19,
// reversing what stood here. The old text argued `absent` on the grounds that
// the configuration IS the statement, and that committing zero was needed so a
// host which lost this interface would not serve its daemon row forever. The
// second half of that is answered by staleness rather than by retirement: no
// decline but `absent` commits, so prior state STANDS and the collator marks it
// stale — visible as not-fresh, which is the honest rendering of a reading that
// did not happen.
//
// The first half was simply wrong, and THIS collector is where it was
// measured: unbound was installed, running and answering on a lab guest whose
// SE_UNBOUND_SOCKET had never been set, and this port declined `absent` over
// it — proposing to retire a resolver that was serving queries at the time.
//
// "Nobody told this process where to look" and "the thing is not here" are
// different statements, and only the second may retire a row: retirement is not
// recoverable, and a key rotation must not perform one.
//
// What still retires is a genuine absence, and a missing receipt cannot
// establish one from here.
var declineNoSocket = declined{"unavailable", "no unbound control socket on this host"}

// The socket is there and this collector may not open it. Distinct from
// absence in the one respect that matters: unauthorised commits nothing, so a
// permissions gap leaves the daemon row standing and marked stale instead of
// retiring a resolver that is running perfectly well. The reference's own
// capability check names the same fix.
var declineSocketRefused = declined{
	"unauthorised",
	"the unbound control socket exists and this collector may not open it; " +
		"the deployment grants the socket's group (the NixOS module's " +
		"grantUnboundAccess supplies that membership)",
}

// The socket is there and the reading did not come back: nothing listening,
// the daemon not answering inside the timeout, or a reply that begins `error`.
//
// `unavailable` rather than `unsupported`, and the choice is deliberate. The
// error text is the only thing that could tell a permanent refusal from a
// transient one, and reading intent out of prose is exactly what this product
// does not do — so the honest reason is the one that says "present, not
// answering" and leaves the question open. `unsupported` would tell an
// operator to stop asking about a resolver that is running and may well answer
// on the next sweep. Neither commits, so prior state stands either way.
var declineSocketSilent = declined{
	"unavailable",
	"the unbound control socket exists and did not answer the status command",
}

// errUncaptured marks a document the variant did not stage. It must never fall
// back to the live interface of the machine REPLAYING the corpus — that seam
// escape once put a replaying workstation's filesystem into committed facts —
// and it must not become a decline either, which would state something about a
// machine nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

// Where the socket is, and it is configuration rather than a constant: the
// NixOS module's unboundSocket option writes it, and the shipping adapter
// reads the same variable. A default path here would make this binary and the
// reference disagree about a host that configured neither — the port would
// find a socket and the reference would not — which is a disagreement invented
// by the port rather than observed on the machine.
const socketVariable = "SE_UNBOUND_SOCKET"

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is deliberately not consulted: every fact here is a
		// figure the daemon stated, and nothing is derived against wall-clock
		// now — not an age, not an elapsed time — so the pin has nothing to
		// freeze and reading it would invent a dependency the declaration
		// does not admit to.
		return replaySource{dir: dir}
	}
	return &liveSource{started: time.Now(), socket: getenv(socketVariable)}
}

// ── live ────────────────────────────────────────────────────────────────

type liveSource struct {
	started time.Time
	socket  string
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

func (s *liveSource) stamp(int) float64 { return s.at }

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

// The two commands on the acquisition path. `stats_noreset` and never `stats`:
// the plain command ZEROES every counter as a side effect of reporting it, so
// a collector wired to it would destroy the numbers of anything else watching
// the same daemon and turn each reading into a delta over a window nobody
// declared. The suffix is what keeps this collector read-only, which is why it
// is spelled here once and never assembled.
const (
	commandStatus = "status"
	commandStats  = "stats_noreset"
)

// The control framing, which is the whole protocol: a version preamble and the
// command on one line, then the reply until the far end closes.
const controlPreamble = "UBCT1 "

// Matching the reference's asyncio.wait_for(…, timeout=10.0), and applied to
// the dial as well as the read: a socket that accepts and then says nothing
// stalls the sweep exactly as one that never accepts does.
const commandTimeout = 10 * time.Second

// A bound on one reply, because an unbounded read cannot be allowed to exhaust
// the slice (DESIGN 19). A stats document is a couple of kilobytes and an
// extended-statistics one from a many-threaded resolver is tens; a megabyte is
// a reply this interface does not produce. Exceeding it is "I could not run"
// rather than a decline or a truncated parse — a document cut in half parses
// into a row of plausible half-facts, which is the one outcome worse than an
// error.
const replyBound = 1 << 20

func (s *liveSource) daemon() (reading, error) {
	if s.socket == "" {
		// The configuration IS the statement: a host whose deployment names no
		// control socket observes no unbound. Checked before the clock is read
		// so the answer is the same on any platform — a machine with no
		// CLOCK_BOOTTIME still gets a truthful absence rather than a failure
		// to run.
		reason := declineNoSocket
		return reading{}, &reason
	}
	// The clock reading before the first byte: `at` must precede the earliest
	// native read that contributes to the row, and the tie breaks toward older
	// (DESIGN 19).
	at, err := bootClock()
	if err != nil {
		return reading{}, err
	}
	s.at = at

	status, err := s.command(commandStatus)
	if err != nil {
		return reading{}, err
	}
	stats, err := s.command(commandStats)
	if err != nil {
		return reading{}, err
	}
	return reading{status: status, stats: stats}, nil
}

// command runs one command on one connection, which is the protocol: unbound
// closes the socket when the reply ends, so the connection is the framing.
func (s *liveSource) command(name string) (string, error) {
	conn, err := net.DialTimeout("unix", s.socket, commandTimeout)
	if err != nil {
		return "", classify(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(commandTimeout)); err != nil {
		return "", classify(err)
	}
	if _, err := io.WriteString(conn, controlPreamble+name+"\n"); err != nil {
		return "", classify(err)
	}
	// One byte past the bound, so a reply AT the bound is told from one that
	// ran over it rather than being silently trimmed to fit.
	raw, err := io.ReadAll(io.LimitReader(conn, replyBound+1))
	if err != nil {
		return "", classify(err)
	}
	if len(raw) > replyBound {
		return "", fmt.Errorf("the unbound control socket answered %s with more than %d bytes", name, replyBound)
	}
	text := string(raw)
	if strings.HasPrefix(text, "error") {
		// The daemon answered and refused. Its own words ride the error, which
		// reaches stderr and stops there; the decline carries the constant.
		reason := declineSocketSilent
		return "", fmt.Errorf("unbound %s answered: %s: %w", name, strings.TrimSpace(text), &reason)
	}
	return text, nil
}

// classify turns a socket failure into the reading it is. Three conditions,
// three different things to tell an operator, and only the first may retire
// this host's daemon row.
func classify(err error) error {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Nothing at the configured path: the same reading as no path at all,
		// through the same constant, so the two cannot drift apart.
		reason := declineNoSocket
		return fmt.Errorf("%v: %w", err, &reason)
	case errors.Is(err, fs.ErrPermission):
		reason := declineSocketRefused
		return fmt.Errorf("%v: %w", err, &reason)
	default:
		// A refused connection, a timeout, a short write: the socket is there
		// and the reading did not come back.
		reason := declineSocketSilent
		return fmt.Errorf("%v: %w", err, &reason)
	}
}

// ── replay ──────────────────────────────────────────────────────────────

// A replay has no boot, so the fixed v4-shaped id — "5e" up front so no reader
// mistakes it for a capture. The shape rule refuses the old "replay" stub and
// the nil UUID; that this constant itself passes is DESIGN 19's named
// deferral, the live comparator's to catch.
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

// No time namespace was observed at capture, so the offset is the pinned zero
// — a live reading here would smuggle the replaying machine into a
// deterministic stream.
func (replaySource) timens() int64 { return 0 }

func (replaySource) batch() (string, error) { return "replay", nil }

// The real digest, under replay as much as live: the declaration identifies
// THIS collector's contract, and a replay does not change which contract this
// binary holds. It is rule-governed rather than byte-compared (DESIGN 19's two
// regimes), so the honest value costs nothing.
func (replaySource) declaration() string { return declarationDigest }

func (replaySource) stamp(i int) float64 {
	// The reference constant, 1.0 + 0.001*i in emission order and one counter
	// across the whole batch: finite, positive, boot-scale and advancing, so
	// the structural rule that governs `at` is exercised by replay instead of
	// satisfied by a hardcoded zero. Rounded because the reference rounds.
	return float64(int64((1.0+0.001*float64(i))*1000+0.5)) / 1000
}

// The payload each command's document is committed under: the command IS the
// key, because the command is what decides which document comes back. Text and
// not JSON — the control socket answers in a line protocol and the native
// format is the payload (DESIGN 20), so the bytes the parser sees here are the
// bytes the guest produced.
var replayPayload = map[string]string{
	commandStatus: commandStatus + ".txt",
	commandStats:  commandStats + ".txt",
}

func (r replaySource) daemon() (reading, error) {
	status, statusErr := os.ReadFile(filepath.Join(r.dir, replayPayload[commandStatus]))
	stats, statsErr := os.ReadFile(filepath.Join(r.dir, replayPayload[commandStats]))

	missing := func(err error) bool { return errors.Is(err, fs.ErrNotExist) }
	if missing(statusErr) && missing(statsErr) {
		// NEITHER document staged: the variant records a host with no control
		// socket. The same reading the live path takes, through the same
		// constant, so the two cannot spell one condition two ways.
		reason := declineNoSocket
		return reading{}, &reason
	}
	// One document staged and not the other is a broken capture rather than a
	// statement about a machine — the socket that answered `status` was there
	// to answer `stats_noreset` too — so it fails the batch instead of
	// declining, and it never falls back to the live resolver of whichever
	// machine is replaying.
	if statusErr != nil {
		return reading{}, fmt.Errorf("%s %w: %v", replayPayload[commandStatus], errUncaptured, statusErr)
	}
	if statsErr != nil {
		return reading{}, fmt.Errorf("%s %w: %v", replayPayload[commandStats], errUncaptured, statsErr)
	}
	return reading{status: string(status), stats: string(stats)}, nil
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
// 18). It takes the real reading, because nothing weaker establishes the
// answer: a socket on disk says nothing about whether the daemon behind it
// speaks, which is the two-stage question the reference's capability check
// asks. A resolver that has answered no queries still answers here, and that
// is a reading of zero rather than an inability.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes", Reason: "the unbound control socket answers"}
	if _, err := src.daemon(); err != nil {
		// The reason names the decline this side reached and nothing it has
		// not established; the error itself goes to stderr, where a person
		// debugging can read the path and the errno.
		reason := "the control socket could not be read"
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
