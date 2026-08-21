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
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// source is the acquisition seam (DESIGN 20; harness/se_harness/replay.py):
// with SE_REPLAY_DIR set, the native documents come from that directory
// instead of the live interface, while the parse, the declared semantics and
// the stream generation run unchanged. The seam is a value chosen at startup,
// not a build flag, so the binary the harness judges is the binary that
// deploys.
//
// The four methods are the four requests the acquisition makes, and each
// returns the RAW busctl document rather than anything parsed: the native
// document is systemd's own rendering (DESIGN's 2026-08-19 ruling), so live
// and replay hand the decoder the same bytes and the decode is judged once.
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
	// listUnits is the manager call the whole collection hangs from, and the
	// only one whose failure is a statement about the host.
	listUnits() ([]byte, error)
	// listUnitFiles says which units exist as a FILE. Its failure is NOT a
	// statement about the host: the adapter degrades to claiming nothing
	// about synthesised mounts rather than accusing every one of them.
	listUnitFiles() ([]byte, error)
	// unitProperties is org.freedesktop.DBus.Properties.GetAll on the Unit
	// interface, made once per unit systemd listed and could not load.
	unitProperties(path string) ([]byte, error)
	// unitSlice is Properties.Get for the Slice property of a service or a
	// scope — the one type-specific property on the acquisition path.
	unitSlice(path, iface string) ([]byte, error)
	// The verb path (DESIGN 18, landed at R3c): LoadUnit resolves a name
	// to its object path — systemd keeps a Unit object for every name
	// anything references, which is what lets the verbs answer for a
	// not-found unit too — and typedProperties is the type-specific
	// GetAll the object verb adds for a unit that loaded.
	loadUnit(name string) (string, error)
	typedProperties(path, iface string) ([]byte, error)
	// stamp is `at` for the i-th emitted object. One acquisition pass feeds
	// every row, so the live reading is taken once, before the first native
	// read, and the index is ignored — a stamp taken at completion would
	// report a row fresher than the bytes it describes (DESIGN 19).
	stamp(i int) float64
	// costs are end's advisory self-report (DESIGN 19): bounded by the judge,
	// authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

// The bus addresses this collector reads. Constants because they are protocol,
// not configuration: systemd's well-known name, its manager object, and the
// standard properties interface are the same on every host that has systemd at
// all, which is why the absent reading below can be about systemd rather than
// about a path somebody set.
const (
	systemdBus      = "org.freedesktop.systemd1"
	managerPath     = "/org/freedesktop/systemd1"
	managerIface    = "org.freedesktop.systemd1.Manager"
	propertiesIface = "org.freedesktop.DBus.Properties"
	unitIface       = "org.freedesktop.systemd1.Unit"
	sliceProperty   = "Slice"
)

// declined is the seam's statement that the interface itself could not be
// read, carried as an error so no caller can forget to route it. The detail is
// a constant: decline detail travels to a hub and out over MCP, and an
// interpolated error string is a redaction path nobody reviewed — a unit name
// in particular is content by DESIGN 21 and belongs in stderr, where a person
// debugging can read it, not in a record that leaves the host.
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
// `absent` is the reading, and it is the one decline that commits. busctl is
// systemd's own binary and ships in the same package as the manager it talks
// to, so a host without it runs no systemd and therefore has no units — a
// successful reading that establishes something, which is DESIGN 19's own
// worked example. It must commit zero, because a host that HAD systemd and was
// rebuilt without it would otherwise serve its last unit table forever, stale
// and never retired.
//
// The wording is the replay shim's own ("no <interface> on this host"), so the
// two implementations produce the same record for the same condition rather
// than two spellings a reader would take for two conditions.
var declineNoSystemd = declined{"absent", "no systemd on the system bus on this host"}

// systemd is here and the manager did not answer. `unavailable` and never
// `unauthorised`, and the choice is deliberate rather than lazy: the only
// thing that could tell a permission refusal from a busy or degraded manager
// is the wording of busctl's own error, and reading intent out of prose is
// exactly what this product does not do. `unavailable` says "present, not
// answering" and leaves the question open; neither reason commits, so prior
// state stands either way. The permission axis is unmapped in every
// implementation of this fleet and is an open item in DESIGN's queue — this
// collector does not close it by guessing.
var declineManagerSilent = declined{
	"unavailable",
	"systemd is installed and its manager did not answer ListUnits on the system bus",
}

// errUncaptured marks a document the variant did not stage. It must never fall
// back to the live interface of the machine REPLAYING the corpus — that seam
// escape once put a replaying workstation's filesystem into committed facts —
// and it must not become a decline either, which would state something about a
// machine nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is deliberately not consulted: every fact here is a
		// string systemd stated, and nothing is derived against wall-clock now
		// — not an age, not an elapsed time — so the pin has nothing to freeze
		// and reading it would invent a dependency the declaration does not
		// admit to.
		return &replaySource{dir: dir}
	}
	return &liveSource{started: time.Now()}
}

// ── the request, spelled once ───────────────────────────────────────────

// busRequest is the busctl argument line after the destination, and it is both
// halves of the seam: the live source runs it and the replay source looks it
// up. One builder, because the corpus is KEYED on this string — a port that
// spelled the key one way and the command another would replay a capture it
// could never have taken.
func busRequest(path, iface, member, signature string, arguments ...string) string {
	parts := []string{path, iface, member}
	if signature != "" {
		parts = append(parts, signature)
		parts = append(parts, arguments...)
	}
	return strings.Join(parts, " ")
}

func listUnitsRequest() string {
	return busRequest(managerPath, managerIface, "ListUnits", "")
}

func listUnitFilesRequest() string {
	return busRequest(managerPath, managerIface, "ListUnitFiles", "")
}

func propertiesRequest(path string) string {
	return busRequest(path, propertiesIface, "GetAll", "s", unitIface)
}

func sliceRequest(path, iface string) string {
	return busRequest(path, propertiesIface, "Get", "ss", iface, sliceProperty)
}

func loadUnitRequest(name string) string {
	return busRequest(managerPath, managerIface, "LoadUnit", "s", name)
}

// objectPathReply reads the one "o" argument a LoadUnit reply carries,
// through the same single-argument gate every other reply takes.
func objectPathReply(raw []byte) (string, error) {
	argument, err := singleArgument(raw, "o")
	if err != nil {
		return "", err
	}
	var path string
	if err := json.Unmarshal(argument, &path); err != nil || path == "" {
		return "", fmt.Errorf("the object path does not decode: %v", err)
	}
	return path, nil
}

// ── live ────────────────────────────────────────────────────────────────

type liveSource struct {
	started time.Time
	at      float64
	once    sync.Once
	tool    string
	toolErr error
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

// The tool that renders a D-Bus reply as the native document, and the reason
// this collector needs no bus library: busctl IS the reference command the
// declaration names, so the bytes an operator gets by hand are the bytes this
// binary parses. Resolved once — a missing busctl is the absent reading and
// must answer the same way on the first call and the three-hundredth.
const busctl = "busctl"

// A bound on one reply, because an unbounded read cannot be allowed to
// exhaust the slice (DESIGN 19). ListUnits on a 735-unit host is 165 kB and a
// GetAll is 5 kB; sixty-four megabytes is a reply this interface does not
// produce. Exceeding it is "I could not run" rather than a truncated parse —
// a document cut in half decodes into a row of plausible half-facts, which is
// the one outcome worse than an error.
const replyBound = 64 << 20

// Matching the reference's own patience with the bus. A manager that has not
// answered in this long is not about to.
const callTimeout = 30 * time.Second

func (s *liveSource) locate() (string, error) {
	s.once.Do(func() {
		s.tool, s.toolErr = exec.LookPath(busctl)
		if s.toolErr != nil {
			// systemd's own binary, shipped in the same package as the manager
			// it talks to: no busctl is no systemd, which is the absent
			// reading rather than a tooling gap.
			reason := declineNoSystemd
			s.toolErr = fmt.Errorf("%v: %w", s.toolErr, &reason)
		}
	})
	return s.tool, s.toolErr
}

// call runs one busctl invocation and returns the document it printed. Each
// token is passed as a separate argument and never interpolated into a command
// string (DESIGN 18) — a unit's object path is data, and a shell is never
// between this process and the bus.
func (s *liveSource) call(path, iface, member, signature string, arguments ...string) ([]byte, error) {
	tool, err := s.locate()
	if err != nil {
		return nil, err
	}
	argv := []string{"call", systemdBus, path, iface, member}
	if signature != "" {
		argv = append(argv, signature)
		argv = append(argv, arguments...)
	}
	argv = append(argv, "--json=short")

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, tool, argv...)
	var stdout, stderr strings.Builder
	command.Stdout = &limitedWriter{to: &stdout, left: replyBound + 1}
	command.Stderr = &limitedWriter{to: &stderr, left: 4096}
	if err := command.Run(); err != nil {
		// busctl's own words ride the error to stderr, where a person
		// debugging can read them; the decline carries the constant.
		reason := declineManagerSilent
		return nil, fmt.Errorf("busctl %s %s: %v: %s: %w",
			member, path, err, strings.TrimSpace(stderr.String()), &reason)
	}
	if stdout.Len() > replyBound {
		return nil, fmt.Errorf("busctl %s answered with more than %d bytes", member, replyBound)
	}
	return []byte(stdout.String()), nil
}

func (s *liveSource) listUnits() ([]byte, error) {
	// Whether systemd is here at all is settled BEFORE the clock is read, so
	// the answer is the same on any platform — a machine with no CLOCK_BOOTTIME
	// still gets a truthful absence rather than a failure to run, which is the
	// only way the shared-constant test below can be executed anywhere.
	if _, err := s.locate(); err != nil {
		return nil, err
	}
	// The clock reading before the first byte: `at` must precede the earliest
	// native read that contributes to a row, and the tie breaks toward older
	// (DESIGN 19). Taken here rather than in collect() because this is the
	// call the whole collection hangs from.
	at, err := bootClock()
	if err != nil {
		return nil, err
	}
	s.at = at
	return s.call(managerPath, managerIface, "ListUnits", "")
}

func (s *liveSource) listUnitFiles() ([]byte, error) {
	return s.call(managerPath, managerIface, "ListUnitFiles", "")
}

func (s *liveSource) unitProperties(path string) ([]byte, error) {
	return s.call(path, propertiesIface, "GetAll", "s", unitIface)
}

func (s *liveSource) unitSlice(path, iface string) ([]byte, error) {
	return s.call(path, propertiesIface, "Get", "ss", iface, sliceProperty)
}

func (s *liveSource) loadUnit(name string) (string, error) {
	raw, err := s.call(managerPath, managerIface, "LoadUnit", "s", name)
	if err != nil {
		return "", err
	}
	return objectPathReply(raw)
}

func (s *liveSource) typedProperties(path, iface string) ([]byte, error) {
	return s.call(path, propertiesIface, "GetAll", "s", iface)
}

// limitedWriter caps what a subprocess can put in this process's memory. The
// bound is checked by the caller rather than reported here, so a reply AT the
// bound is told from one that ran over it instead of being silently trimmed.
type limitedWriter struct {
	to   *strings.Builder
	left int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.left <= 0 {
		return len(p), nil
	}
	if len(p) > w.left {
		w.to.Write(p[:w.left])
		w.left = 0
		return len(p), nil
	}
	w.to.Write(p)
	w.left -= len(p)
	return len(p), nil
}

// ── replay ──────────────────────────────────────────────────────────────

// A replay has no boot, so the fixed v4-shaped id — "5e" up front so no reader
// mistakes it for a capture. The shape rule refuses the old "replay" stub and
// the nil UUID; that this constant itself passes is DESIGN 19's named
// deferral, the live comparator's to catch.
const replayBootID = "5e000000-0000-4000-8000-000000000001"

type replaySource struct {
	dir      string
	once     sync.Once
	requests map[string]json.RawMessage
	loadErr  error
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

// No time namespace was observed at capture, so the offset is the pinned zero
// — a live reading here would smuggle the replaying machine into a
// deterministic stream.
func (*replaySource) timens() int64 { return 0 }

func (*replaySource) batch() (string, error) { return "replay", nil }

// The real digest, under replay as much as live: the declaration identifies
// THIS collector's contract, and a replay does not change which contract this
// binary holds. It is rule-governed rather than byte-compared (DESIGN 19's two
// regimes), so the honest value costs nothing.
func (*replaySource) declaration() string { return declarationDigest }

func (*replaySource) stamp(i int) float64 {
	// The reference constant, 1.0 + 0.001*i in emission order and one counter
	// across the whole batch: finite, positive, boot-scale and advancing, so
	// the structural rule that governs `at` is exercised by replay instead of
	// satisfied by a hardcoded zero. Rounded because the reference rounds.
	return float64(int64((1.0+0.001*float64(i))*1000+0.5)) / 1000
}

func (*replaySource) costs() (float64, float64) { return 0.5, 1.0 }

// load builds the request index from every payload file in the directory.
//
// The corpus commits one file per reply SHAPE — the scrub manifest classifies
// by path, and a manifest cannot say that index 1 of a row is a description in
// one document and an enablement state in another — but the seam addresses the
// BUS, not a file, so the union is what a request is looked up in. A request
// staged twice is refused rather than resolved to whichever file was read
// last.
func (r *replaySource) load() (map[string]json.RawMessage, error) {
	r.once.Do(func() {
		entries, err := os.ReadDir(r.dir)
		if err != nil {
			r.loadErr = fmt.Errorf("reading the replay directory: %v", err)
			return
		}
		requests := map[string]json.RawMessage{}
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") ||
				filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			names = append(names, entry.Name())
		}
		sort.Strings(names)
		for _, name := range names {
			raw, err := os.ReadFile(filepath.Join(r.dir, name))
			if err != nil {
				r.loadErr = fmt.Errorf("reading payload %s: %v", name, err)
				return
			}
			var staged map[string]json.RawMessage
			if err := json.Unmarshal(raw, &staged); err != nil {
				r.loadErr = fmt.Errorf("payload %s is not a request/response map: %v", name, err)
				return
			}
			for request, document := range staged {
				if _, seen := requests[request]; seen {
					r.loadErr = fmt.Errorf("%q is staged twice; one request, one reply", request)
					return
				}
				requests[request] = document
			}
		}
		r.requests = requests
	})
	return r.requests, r.loadErr
}

func (r *replaySource) reply(request string) ([]byte, error) {
	requests, err := r.load()
	if err != nil {
		return nil, err
	}
	document, ok := requests[request]
	if !ok {
		return nil, fmt.Errorf("%q %w", request, errUncaptured)
	}
	return document, nil
}

func (r *replaySource) listUnits() ([]byte, error) {
	requests, err := r.load()
	if err != nil {
		return nil, err
	}
	if len(requests) == 0 {
		// NOTHING staged: the variant records a host with no systemd on the
		// system bus. The same reading the live path takes, through the same
		// constant, so the two cannot spell one condition two ways.
		reason := declineNoSystemd
		return nil, &reason
	}
	// Requests staged and the listing not among them is a broken capture
	// rather than a statement about a machine — a bus that answered a
	// per-unit GetAll answered ListUnits first, because the object paths came
	// from it — so it fails the batch instead of declining.
	return r.reply(listUnitsRequest())
}

func (r *replaySource) listUnitFiles() ([]byte, error) {
	return r.reply(listUnitFilesRequest())
}

func (r *replaySource) unitProperties(path string) ([]byte, error) {
	return r.reply(propertiesRequest(path))
}

func (r *replaySource) unitSlice(path, iface string) ([]byte, error) {
	return r.reply(sliceRequest(path, iface))
}

func (r *replaySource) loadUnit(name string) (string, error) {
	raw, err := r.reply(loadUnitRequest(name))
	if err != nil {
		return "", err
	}
	return objectPathReply(raw)
}

func (r *replaySource) typedProperties(path, iface string) ([]byte, error) {
	return r.reply(busRequest(path, propertiesIface, "GetAll", "s", iface))
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
// 18). It takes the real reading, because nothing weaker establishes the
// answer: busctl on PATH says nothing about whether the manager behind it
// answers, which is the two-stage question the reference's capability check
// asks. A host whose unit table is empty still answers here, and that is a
// reading of zero rather than an inability.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes", Reason: "systemd's manager answers on the system bus"}
	if _, err := src.listUnits(); err != nil {
		// The reason names the decline this side reached and nothing it has
		// not established; the error itself goes to stderr, where a person
		// debugging can read busctl's own words.
		reason := "the systemd manager could not be read"
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
