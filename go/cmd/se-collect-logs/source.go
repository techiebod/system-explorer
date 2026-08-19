package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	// journal is one page of entries, newest first. Its errors carry the
	// decline shape.
	journal() ([]*value, error)
	// stamp is `at` for the i-th emitted object. One journalctl read produces
	// the whole page, so the live reading is taken once before it and shared:
	// an acquisition stamped per row at completion would report the last entry
	// fresher than the first off bytes that arrived together (DESIGN 19).
	stamp(i int) float64
	// costs are end's advisory self-report (DESIGN 19): bounded by the judge,
	// authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

// declined is the seam's statement that the interface itself could not be
// reached, carried as an error so no caller can forget to route it. The detail
// is a constant: decline detail travels to a hub and out over MCP, and an
// interpolated error string is a redaction path nobody reviewed.
type declined struct{ reason, detail string }

func (d *declined) Error() string { return d.reason + ": " + d.detail }

// The no-journal reading, named ONCE and shared by the live source and the
// replay source. Storage learned this the expensive way: one collector, one
// condition, two paths, and for as long as it existed the two spelled the
// answer differently — live `unsupported`, replay `absent` — each under a
// confident comment arguing against the other, because replay exercises only
// the replay half. A shared constant makes the disagreement unspellable.
//
// `absent`, for the same reason no zpool on PATH is: journalctl ships with
// systemd and reads systemd's own journal, so a host without it is a host with
// no journal for this collector to see — a successful reading that establishes
// there are no entries here, which is DESIGN 19's own worked example. It is
// also the only decline that commits, and it must commit: a host that stopped
// running systemd would otherwise serve the last page it ever published
// forever, stale and never retired.
//
// The wording is the replay shim's and the live reference's too
// (harness/bin/se-reference-collector, harness/bin/se-live-reference: "no
// {interface} on this host" with interface "systemd journal"), because a
// decline detail reaches an operator and three spellings of one reading would
// reach them as three conditions.
var declineNoJournal = declined{"absent", "no systemd journal on this host"}

// noJournal hands that reading out as an error, and it is the ONLY way either
// path produces one. A function rather than two `reason := declineNoJournal`
// copies, because the copies are what the storage collector had: both paths
// could still be edited apart, and only one of them was ever exercised.
func noJournal() error {
	reason := declineNoJournal
	return &reason
}

// errUncaptured marks a document the variant did not stage. It must never fall
// back to the live interface of the machine REPLAYING the corpus — that seam
// escape once put a replaying workstation's filesystem into committed facts —
// and it must not become a decline either, which would state something about a
// machine nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is deliberately not consulted. Every timestamp this
		// collector publishes is read OUT of the entry — __REALTIME_TIMESTAMP,
		// rendered — and nothing is derived against wall-clock now: no age, no
		// elapsed time. The reference pins the clock for the collectors that
		// do, and reading the pin here would invent a dependency the
		// declaration does not admit to.
		return replaySource{dir: dir}
	}
	return &liveSource{started: time.Now()}
}

// The bound this collector reads under, and the whole of the argument list it
// builds. The collector contract carries no limit token (DESIGN 18) — one
// request line, one page — so the bound belongs to the collector, and it is
// the reference adapter's own DEFAULT_LIMIT (adapters/logs.py) rather than a
// number chosen here: the replay seam keys its payload on the argv, so a
// second copy of this figure would be a payload the seam cannot find.
//
// `-r` because pages run newest-first: journalctl -r starts at the newest
// entry and walks older, which is the order an operator reads a log in and the
// order the reference's own pagination established.
const defaultLimit = 100

// pageArgs is what the reference hands _run_journalctl, and therefore what the
// replay seam keys its payload on. journalArgv is what actually runs: the
// reference's own fixed prefix plus these. Kept apart because they are two
// different lists doing two different jobs, and collapsing them would key the
// payload on a string no seam ever produces.
//
// Every token is a literal from this file — nothing is built from a document —
// so no payload can add an argument.
func pageArgs(limit int) []string {
	return []string{"-r", "-n", strconv.Itoa(limit)}
}

func journalArgv(limit int) []string {
	return append([]string{"-o", "json", "--no-pager", "-q"}, pageArgs(limit)...)
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

func (s *liveSource) journal() ([]*value, error) {
	// Absence is settled before the clock is read, and that is not a
	// re-ordering of DESIGN 19's rule: `at` must precede the earliest byte
	// that contributes to a ROW, and a host with no journalctl contributes no
	// rows at all. Doing it this way is what lets the shared-constant guard
	// drive both paths on any platform, rather than testing the live half only
	// where CLOCK_BOOTTIME exists.
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, noJournal()
	}
	// Now the clock, before the command runs: the tie breaks toward older.
	at, err := bootClock()
	if err != nil {
		return nil, err
	}
	s.at = at

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "journalctl", journalArgv(defaultLimit)...).Output()
	if err != nil {
		// journalctl IS here and would not answer. Never `absent`: this host
		// has a journal right now, so committing zero would retire the entries
		// it holds. `unavailable` rather than `unsupported` — a corrupt journal
		// file or a lost read grant is the kind of thing that clears — and
		// neither reason commits, so prior state stands and is served marked
		// stale either way.
		//
		// It is deliberately not split by cause. A permission refusal is
		// `unauthorised` and nothing in either implementation maps it (the
		// adjudication queue's open item); inventing the mapping here would put
		// one collector's guess where a ruling belongs, and would do it in the
		// one direction that sends somebody hunting the wrong fault.
		return nil, &declined{"unavailable", "journalctl is installed but did not answer"}
	}
	return decodeLines(out)
}

// ── replay ──────────────────────────────────────────────────────────────

// A replay has no boot, so the fixed v4-shaped id — "5e" up front so no reader
// mistakes it for a capture. The shape rule refuses the old "replay" stub and
// the nil UUID; that this constant itself passes is DESIGN 19's named
// deferral, a cross-boot live variant's to catch.
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
	// satisfied by a hardcoded zero. Rounded because the reference rounds, and
	// at a hundred rows the float noise is the difference between 1.126 and
	// 1.1260000000000001 in a file people read.
	return float64(int64((1.0+0.001*float64(i))*1000+0.5)) / 1000
}

func (replaySource) costs() (float64, float64) { return 0.5, 1.0 }

// replayPayload is the file name the seam keys this collector's one document
// on. It is not a label somebody chose and it is not typed out here either:
// the reference's _run_journalctl is dispatched on its ARGUMENT, and
// se-reference-collector runs that argument through slug() to get a stem — so
// this DERIVES the same stem from the same arguments. Changing the bound above
// therefore moves the file this looks for, exactly as it moves the file the
// shim looks for, and the two cannot drift apart while one of them is a
// constant somebody remembered to edit.
func replayPayload() string {
	return slugArgument(pageArgs(defaultLimit)) + ".json"
}

// slugArgument reproduces harness/bin/se-reference-collector's slug() for a
// list of string arguments: Python's str() of the list, every character that
// is not alphanumeric or one of -_. replaced by a dash, the ends trimmed, and
// one pass of "--" -> "-". Reimplemented rather than approximated, because a
// name that is nearly right addresses no file at all and the seam's refusal
// would read as "the interface was absent" — the one decline that retires
// objects.
func slugArgument(args []string) string {
	var repr strings.Builder
	repr.WriteByte('[')
	for i, arg := range args {
		if i > 0 {
			repr.WriteString(", ")
		}
		repr.WriteByte('\'')
		repr.WriteString(arg)
		repr.WriteByte('\'')
	}
	repr.WriteByte(']')

	var kept strings.Builder
	for _, c := range strings.Trim(repr.String(), "/") {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z',
			c == '-', c == '_', c == '.':
			kept.WriteRune(c)
		default:
			kept.WriteByte('-')
		}
	}
	name := strings.ReplaceAll(strings.Trim(kept.String(), "-"), "--", "-")
	if name == "" {
		return "root"
	}
	return name
}

// The whole interface for this collector is one payload file. Its ABSENCE is
// the reading — the interface was not there — through the same constant the
// live path takes, so the two cannot spell one condition two ways. A payload
// that is present and unreadable is a broken capture rather than a statement
// about a machine, so it fails the batch instead of declining, and it must
// never fall back to the live journal of the workstation replaying the corpus.
func (r replaySource) journal() ([]*value, error) {
	raw, err := os.ReadFile(filepath.Join(r.dir, replayPayload()))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, noJournal()
	}
	if err != nil {
		return nil, fmt.Errorf("%s %w: %v", replayPayload(), errUncaptured, err)
	}
	document, err := decodeDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("the staged %s is not a document: %v", replayPayload(), err)
	}
	// The seam's payload is what _run_journalctl RETURNS — the parsed entries,
	// as a list — not the NDJSON journalctl wrote. A capture that staged the
	// raw stream would replay against a document the reference never saw.
	if document.kind != jsonArray {
		return nil, fmt.Errorf(
			"the staged %s is not a list of journal entries: _run_journalctl "+
				"returns the parsed entries and the payload is what it returns",
			replayPayload())
	}
	return document.items, nil
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
// 18). It runs the real read, because nothing weaker establishes the answer —
// journalctl on PATH says nothing about whether this process may read the
// system journal, and an unprivileged reader is answered with its own uid's
// entries and nothing else. A host whose journal is empty still answers, and
// that is a reading of zero entries rather than an inability.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes", Reason: "journalctl answers the bounded newest-first read"}
	if _, err := src.journal(); err != nil {
		// The reason names the decline this side reached and nothing it has
		// not established; the error itself goes to stderr, where a person
		// debugging can read it.
		reason := "the journal could not be read"
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
