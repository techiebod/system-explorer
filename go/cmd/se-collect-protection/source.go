package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// source is the acquisition seam (DESIGN 20; harness/se_harness/replay.py):
// with SE_REPLAY_DIR set, every native document comes from that directory
// instead of the live filesystem, while the parse, the declared semantics and
// the stream generation run unchanged. The seam is a value chosen at startup,
// not a build flag, so the binary the harness judges is the binary that
// deploys.
//
// The seam is dispatched on the PATH, because that is what decides which
// document comes back: the reference's whole acquisition is one module-level
// `_load(path)` and the shim keys its payloads on `slug(path)`. So a reviewer
// reading `var-lib-homelab-protection-receipts-config-sweep.last.json.json`
// can see which file it answers, which is most of what a corpus is for.
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

	// load is the reference's module-level `_load(path)`, and it returns the
	// same PAIR: the document, and why it could not be read. Absence and
	// malformation are different answers — a host with no protection layer
	// has no file, while a file that will not parse is a fault to state — and
	// collapsing them would let a half-written manifest read as "nothing is
	// declared here". A document of nil with an empty whyNot is the first; a
	// document of nil with a whyNot is the second. The error return is
	// neither: it is a replay directory that never staged this path, which
	// says nothing about any machine.
	load(path string) (document *value, whyNot string, err error)

	// interfaceAbsent is the whole-collector reading that there is no
	// protection layer here at all. Behind the seam because the live answer
	// is whether /etc holds a rendered manifest and the replay answer is
	// whether the variant staged any document — two readings of one
	// condition, which is why they route through one constant below.
	interfaceAbsent() bool

	// hostname is the host a target's ownerHost is compared against, and the
	// reason this seam has an entry the other file-shaped ports do not. A
	// target's opinions fire only where its ownerHost matches THIS host, so
	// an unpinned replay would judge the capture against whichever machine
	// happened to be replaying it — severity moving with the replaying
	// machine while the payloads sat still. It also decides which
	// implementedBy hops count as local, which reaches the FACTS: a job's
	// TargetClass and ImplementsHops both come from hops this host runs.
	hostname() (string, error)

	// now is wall-clock seconds, for the one fact derived against it:
	// CheckedAgeSeconds, how long ago the staleness verdict was computed.
	// Behind the seam because replay pins it (SE_REPLAY_NOW), and a fact
	// derived from an unpinned clock would move every day the corpus sat on
	// the shelf.
	now() float64

	// mark takes the live `at` reading for one collection, before its first
	// document is opened: a stamp taken at completion would report the rows
	// fresher than the bytes they describe (DESIGN 19).
	mark()
	// stamp is `at` for the i-th emitted object.
	stamp(i int) float64
	// costs are end's advisory self-report (DESIGN 19): bounded by the judge,
	// authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

// The three surfaces, exactly as the reference names them. Constants rather
// than configuration: the NixOS module renders the manifest to this path and
// installs the checker that writes the other two, so a deployment that moved
// them would be a different subsystem rather than the same one relocated.
const (
	manifestPath = "/etc/homelab/protection-manifest.json"
	statusPath   = "/var/lib/homelab/protection/status.json"
	receiptsDir  = "/var/lib/homelab/protection/receipts"
)

// receiptPath is the file one job's receipt of one outcome is written to. Two
// files per job deliberately: "it ran and failed" must not overwrite the
// evidence that it once worked.
func receiptPath(job, suffix string) string {
	return receiptsDir + "/" + job + "." + suffix + ".json"
}

// declined is the seam's statement that the interface itself could not be
// read, carried as an error so no caller can forget to route it. The detail is
// a constant: decline detail travels to a hub and out over MCP, and an
// interpolated error string is a redaction path nobody reviewed — a manifest
// path is estate configuration and an errno is a machine's, and both belong on
// stderr where a person debugging can read them.
type declined struct{ reason, detail string }

func (d *declined) Error() string { return d.reason + ": " + d.detail }

// The interface-is-not-here reading, named ONCE and reached by the live source
// and the replay source alike. It is a constant because the storage collector
// answered exactly this question two opposite ways for as long as it existed —
// live said `unsupported`, replay said `absent`, each under a confident comment
// arguing against the other — and nothing caught it, because replay exercises
// only the replay half. A shared constant makes the disagreement unspellable
// rather than merely currently-absent.
//
// `absent` is the reading, and it is the one decline that commits. A host with
// no rendered manifest declares no protection inventory: the collections are
// genuinely empty there, which is a successful reading that establishes
// something, and it must be able to retire the rows a previous batch published
// — a host that HAD a manifest and lost it would otherwise serve its last
// targets for ever, stale and never retired.
//
// The wording is the replay shim's own ("no <interface> on this host") with the
// interface named as the SEAM names it, so the two implementations produce one
// record for one condition rather than two spellings a reader would take for
// two conditions.
var declineNoManifest = declined{"absent", "no homelab protection surfaces on this host"}

// The manifest is there and will not open. Distinct from absence in the one
// respect that matters: `unavailable` commits nothing, so a half-written
// render leaves the declared targets standing and marked stale instead of
// retiring an estate that is protecting itself perfectly well.
var declineManifestUnreadable = declined{
	"unavailable",
	"the protection manifest exists on this host and could not be read",
}

// No staleness verdict, and it is NOT "nothing is protected here". The same
// NixOS conditional renders the manifest and installs the checker, so a
// manifest this readable proves the checker is installed: a missing verdict is
// one nobody has written yet (a fresh deploy, a wiped /var/lib) or one that is
// not running. Unobservable, never absent — which is why this declines
// `unavailable` and commits nothing, leaving the job rows standing rather than
// retiring every job on a host whose checker stopped.
//
// The reference states two discriminators in its capability reason — the
// targets this host owns with a cadence, and the jobs that have ever written a
// receipt here. Neither travels in a decline detail: both are estate content
// and this channel reaches a hub and out over MCP. They are on stderr instead,
// where the person running `systemctl status
// homelab-protection-staleness.service` can read them.
var declineNoVerdict = declined{
	"unavailable",
	"no staleness verdict has been written on this host, so whether its protection ran is unobservable rather than absent",
}

// errUncaptured marks a document the variant did not stage. It must never fall
// back to the live filesystem of the machine REPLAYING the corpus — that seam
// escape once put a replaying workstation's filesystem into committed facts —
// and it must not become a decline either, which would state something about a
// machine nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is consulted, unlike most of the ports before this
		// one: CheckedAgeSeconds is derived against wall-clock now, and it is
		// the one number here a port can get wrong without touching a
		// payload. Unpinned it would change every run, and the corpus anchors
		// it at exactly 1800.
		return newReplaySource(dir, getenv("SE_REPLAY_NOW"))
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

func (s *liveSource) mark() {
	// A failed clock reading leaves the previous stamp rather than failing the
	// batch: `at` is a freshness reading and the rows are still true. The
	// stream rule that governs it is checked by the judge, not here.
	if at, err := bootClock(); err == nil {
		s.at = at
	}
}

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

func (*liveSource) now() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func (*liveSource) hostname() (string, error) {
	name, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("hostname: %v", err)
	}
	// The SHORT name, as the reference takes it (envelope.HOST): a machine
	// whose kernel hostname carries a domain is the same machine, and the two
	// spellings would compare differently against one ownerHost.
	return strings.SplitN(name, ".", 2)[0], nil
}

// A bound on one document. The manifest of the estate this was written for is
// 191 leaves; a receipt is eight members. A megabyte is a file this subsystem
// does not produce, and an unbounded read cannot be allowed to exhaust the
// slice (DESIGN 19).
const documentBound = 1 << 20

func (*liveSource) load(path string) (*value, string, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		// The file is not there. No document and no fault: a host with no
		// protection layer has no manifest, and a job that has never
		// succeeded has no last-success receipt. Reporting a fault for either
		// would alarm on every job that has not got there yet.
		return nil, "", nil
	}
	if err != nil {
		return nil, boundedReason(fmt.Sprintf("OSError: %v", err)), nil
	}
	if len(raw) > documentBound {
		return nil, fmt.Sprintf("ValueError: the document exceeds the %d-byte bound", documentBound), nil
	}
	document, err := decodeDocument(raw)
	if err != nil {
		// The reference spells this with Python's own exception rendering
		// (`JSONDecodeError: Expecting ',' delimiter: line 1 column 78`), and
		// no independent implementation can reproduce that text — it is a
		// library's phrasing, not a reading of the machine. So the two agree
		// on the CHANNEL and disagree on the words, which is the same bound
		// the downloaders port carries and is named in the corpus's residual
		// ledger. The venue is the live comparator; under replay the reason
		// is served from the payload and the streams match exactly.
		return nil, boundedReason(fmt.Sprintf("JSONDecodeError: %v", err)), nil
	}
	return document, "", nil
}

// boundedReason keeps failure text to one line and to a length a fact can
// carry. Failure text is the one channel that reaches a poller from inside an
// error path nobody reviews, so it is bounded where it is produced rather than
// where it is rendered.
func boundedReason(text string) string {
	text = strings.Join(strings.Fields(text), " ")
	const bound = 300
	if len(text) > bound {
		return text[:bound]
	}
	return text
}

// The live half of the absence question: no rendered manifest means this host
// declares no protection inventory. Asked with Stat rather than by reading,
// because the answer must be the same whether or not this process may open the
// file — a manifest that exists and is unreadable is a fault to state, not an
// absence to commit.
func (*liveSource) interfaceAbsent() bool {
	_, err := os.Stat(manifestPath)
	return errors.Is(err, fs.ErrNotExist)
}

// ── replay ──────────────────────────────────────────────────────────────

// A replay has no boot, so the fixed v4-shaped id — "5e" up front so no reader
// mistakes it for a capture. The shape rule refuses the old "replay" stub and
// the nil UUID; that this constant itself passes is DESIGN 19's named
// deferral, the live comparator's to catch.
const replayBootID = "5e000000-0000-4000-8000-000000000001"

// The payload the host identity is committed under. Text, not JSON: the kernel
// hostname IS the document (DESIGN 20), and the replay seam serves it verbatim.
const payloadHostname = "hostname"

type replaySource struct {
	dir string

	// stem -> file name, indexed once, exactly as the shim's load_payloads
	// reads the directory.
	payloads map[string]string
	loaded   bool
	loadErr  error

	pinned float64
}

func newReplaySource(dir, replayNow string) *replaySource {
	r := &replaySource{dir: dir}
	// SE_REPLAY_NOW freezes the one clock a fact is derived against, so the
	// verdict's age is the same number on every machine that replays and on
	// every day it is replayed. Unpinned, the live clock stands — the same
	// choice the reference makes, and the corpus pins it.
	if replayNow != "" {
		if moment, err := time.Parse(time.RFC3339, strings.Replace(replayNow, "Z", "+00:00", 1)); err == nil {
			r.pinned = float64(moment.UnixNano()) / 1e9
		}
	}
	return r
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

// Nothing to mark: under replay `at` is the index formula below, so there is
// no clock to read before a collection's first document.
func (*replaySource) mark() {}

func (*replaySource) stamp(i int) float64 {
	// The reference constant, 1.0 + 0.001*i in emission order and one counter
	// across the whole batch: finite, positive, boot-scale and advancing, so
	// the structural rule that governs `at` is exercised by replay instead of
	// satisfied by a hardcoded zero. Rounded because the reference rounds.
	return float64(int64((1.0+0.001*float64(i))*1000+0.5)) / 1000
}

func (*replaySource) costs() (float64, float64) { return 0.5, 1.0 }

func (r *replaySource) now() float64 {
	if r.pinned != 0 {
		return r.pinned
	}
	return float64(time.Now().UnixNano()) / 1e9
}

// load indexes the payload directory once, by stem, exactly as the shim's
// load_payloads does: EVERY file that is not a dotfile, because not every
// native document is JSON — the kernel hostname is text and wrapping it in a
// JSON string would put a transcription between the capture and the parser it
// feeds. The shim's own glob was once `*.json` and `*.txt` only, which made a
// payload committed under a bare stem silently invisible while sitting in the
// directory; this reads the directory the way the corpus loader does.
func (r *replaySource) index() error {
	if r.loaded {
		return r.loadErr
	}
	r.loaded = true
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		r.loadErr = fmt.Errorf("reading %s: %v", r.dir, err)
		return r.loadErr
	}
	r.payloads = make(map[string]string, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		// Python's Path.stem: the last suffix removed, and a name with no
		// suffix kept whole. `a.last.json.json` is staged for `a.last.json`
		// and `hostname` is staged for `hostname`.
		r.payloads[strings.TrimSuffix(name, filepath.Ext(name))] = name
	}
	return nil
}

// The replay half of the same condition, and it is the shim's own rule: a
// dispatched seam has no fixed payload names, so its presence test is whether
// the variant staged ANYTHING. Nothing staged is a capture of a host with no
// protection surfaces, which is what "no document at all was captured" means.
func (r *replaySource) interfaceAbsent() bool {
	if err := r.index(); err != nil {
		// A directory that cannot be listed is not an absent interface, and
		// saying so here would commit an empty collection over a broken
		// replay. The error surfaces on the next load instead.
		return false
	}
	return len(r.payloads) == 0
}

// The name the capture was taken under, required rather than defaulted. The
// live kernel's hostname would name the machine REPLAYING, and one capture
// would then produce different facts on every host that read it — silently,
// because a hostname is a plausible value wherever it came from.
func (r *replaySource) hostname() (string, error) {
	if err := r.index(); err != nil {
		return "", err
	}
	name, ok := r.payloads[payloadHostname]
	if !ok {
		return "", fmt.Errorf("payload %q %w; it pins the host a target's ownerHost is compared against, and without it the facts would be derived against the machine replaying the corpus",
			payloadHostname, errUncaptured)
	}
	raw, err := os.ReadFile(filepath.Join(r.dir, name))
	if err != nil {
		return "", fmt.Errorf("%s: %v", name, err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func (r *replaySource) load(path string) (*value, string, error) {
	if err := r.index(); err != nil {
		return nil, "", err
	}
	stem := slug(path)
	name, ok := r.payloads[stem]
	if !ok {
		// Never a fall-back to the live filesystem of the machine replaying,
		// and never a decline: a path the capture did not record is a broken
		// transcription, not a statement about any machine.
		return nil, "", fmt.Errorf("_load %q (payload %q) %w", path, stem, errUncaptured)
	}
	raw, err := os.ReadFile(filepath.Join(r.dir, name))
	if err != nil {
		return nil, "", fmt.Errorf("%s: %v", name, err)
	}
	// Every payload here is the PAIR `_load` returns, not the document alone.
	// That is the whole reason this collector's payloads are two-element
	// arrays: capturing the document by itself would erase the only member
	// that separates a file which is not there from one that exists and will
	// not parse, and those two are different answers on every row.
	var pair []json.RawMessage
	if err := json.Unmarshal(raw, &pair); err != nil || len(pair) != 2 {
		return nil, "", fmt.Errorf("%s is not a (document, why-not) pair", name)
	}
	document, err := decodeDocument(pair[0])
	if err != nil {
		return nil, "", fmt.Errorf("%s: the document half does not parse: %v", name, err)
	}
	if !document.stated() {
		document = nil
	}
	why, err := decodeDocument(pair[1])
	if err != nil {
		return nil, "", fmt.Errorf("%s: the why-not half does not parse: %v", name, err)
	}
	switch {
	case !why.stated():
		return document, "", nil
	case why.isString():
		return document, why.text, nil
	}
	return nil, "", fmt.Errorf("%s: the why-not half is neither a string nor null", name)
}

// slug is the payload seam's addressing, and it mirrors
// harness/bin/se-reference-collector's slug() character for character: the
// argument that decides WHICH document comes back is what the payload is keyed
// on, so `/var/lib/homelab/protection/status.json` is committed as
// `var-lib-homelab-protection-status.json.json` and a reviewer reading the
// file name is reading the path it answers.
func slug(argument string) string {
	trimmed := strings.Trim(argument, "/")
	var b strings.Builder
	for _, c := range trimmed {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z',
			c == '-', c == '_', c == '.':
			b.WriteRune(c)
		default:
			b.WriteByte('-')
		}
	}
	name := strings.ReplaceAll(strings.Trim(b.String(), "-"), "--", "-")
	if name == "" {
		return "root"
	}
	return name
}

// ── shared ──────────────────────────────────────────────────────────────

// epochISO is the reference's `_epoch_iso`: a unix time as the estate spells a
// timestamp. Sub-second precision is dropped rather than rounded, which is
// what strftime does to a datetime carrying microseconds.
func epochISO(seconds float64) string {
	whole := int64(math.Floor(seconds))
	return time.Unix(whole, 0).UTC().Format("2006-01-02T15:04:05Z")
}

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
// answer: a manifest path in a constant says nothing about whether this host
// renders one. A host whose manifest opens is a YES even when its staleness
// verdict is missing — the targets and destinations are served and the jobs
// collection says why it is not, which is a reading rather than an inability.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes", Reason: "the protection manifest is present and readable"}
	if _, err := readManifest(src); err != nil {
		reason := "the protection manifest could not be read"
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
