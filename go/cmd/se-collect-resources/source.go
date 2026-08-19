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
// instead of the live interface, while the derivation, the declared semantics
// and the stream generation run unchanged. The seam is a value chosen at
// startup, not a build flag, so the binary the harness judges is the binary
// that deploys.
//
// TWO readers, not one, and that is what makes this collector's seam
// different from every port before it. Its interface is a filesystem, so the
// native document is the filesystem transcribed — the listings walked plus
// the contents of every file read — and BOTH halves have to be redirected for
// a replay to be a replay. A seam that stubbed the reads and left the walk
// alone would enumerate the cgroup tree of whichever machine is REPLAYING and
// then serve it captured contents, which is the seam escape that once put a
// workstation's filesystem into committed facts, wearing a green suite.
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
	// walk is the tree's directory structure, top-down, in the order the
	// walker yielded it — load-bearing, because the shallowest occurrence of
	// a duplicated unit name wins and equal depths are broken by that order.
	// A directory that would not list is a step in the SAME sequence rather
	// than a list beside it, because os.walk reports one the moment it meets
	// it and the derivation's answer depends on what it had already placed.
	walk(root string) ([]listing, error)
	// readText is one kernel file, or the statement that it is not there.
	// Absent and empty are different answers and the difference is
	// load-bearing: memory.current is absent on the root cgroup by kernel
	// design, and rendering that as 0 would report a workload consuming
	// nothing, which is a measurement nobody took.
	readText(path string) (text string, present bool, err error)
	// clockTick is USER_HZ: /proc/stat counts jiffies and every fact derived
	// from it is microseconds, so this is the multiplier between them.
	clockTick() int64
	// stamp is `at` for the i-th emitted object. Every row rests on one walk,
	// so the live reading is taken once, before the first listing, and the
	// index is ignored — a stamp taken at completion would report the rows
	// fresher than the bytes they describe (DESIGN 19).
	stamp(i int) float64
	// costs are end's advisory self-report (DESIGN 19): bounded by the judge,
	// authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

// listing is one step of the walk: what os.walk hands over as (dirpath,
// dirnames, filenames), and what the capture transcribes — or, with
// unlistable set, the directory it could not open at all.
type listing struct {
	dir        string
	dirs       []string
	files      []string
	unlistable bool
}

// declined is the seam's statement that the interface itself could not be
// read, carried as an error so no caller can forget to route it. The detail is
// a constant: decline detail travels to a hub and out over MCP, and an
// interpolated error string is a redaction path nobody reviewed.
type declined struct{ reason, detail string }

func (d *declined) Error() string { return d.reason + ": " + d.detail }

// The interface-is-not-here reading, named ONCE and reached by the live source
// and the replay source alike. It is a constant because the storage collector
// answered exactly this question two opposite ways for as long as it existed —
// live said `unsupported`, replay said `absent`, each under a confident comment
// arguing against the other — and nothing caught it, because replay exercises
// only the replay half. A shared constant makes the disagreement unspellable
// rather than merely currently-absent (see that collector's declineNoZpool).
//
// `absent` is the reading, and it is the one decline that commits. cgroup v2's
// unified hierarchy is where every fact here lives; a host that does not
// present one — a v1 host, a container without the host's cgroupfs, a kernel
// built without it — runs no workload this collector can measure. That is a
// successful reading which establishes something, and it must commit zero,
// because a host that HAD a v2 hierarchy and lost it would otherwise serve its
// last workload rows forever, stale and never retired.
//
// The wording is the replay shim's own ("no <interface> on this host"), so the
// two implementations produce the same record for the same condition rather
// than two spellings a reader would take for two conditions.
var declineNoCgroupV2 = declined{"absent", "no cgroup v2 hierarchy on this host"}

// The hierarchy is there and this collector may not walk it. Distinct from
// absence in the one respect that matters: unauthorised commits nothing, so a
// permissions gap leaves the workload rows standing and marked stale instead
// of retiring a machine that is running perfectly well.
var declineCgroupRefused = declined{
	"unauthorised",
	"the cgroup v2 hierarchy exists and this collector may not read its root",
}

// errUncaptured marks a document the variant did not stage. It must never fall
// back to the live interface of the machine REPLAYING the corpus, and it must
// not become a decline either, which would state something about a machine
// nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

// The tree this collector reads, and the one file outside it. Both are
// constants rather than configuration: cgroup v2's mount point is fixed by
// systemd and by the kernel's own documentation, and /proc/stat is uapi.
const (
	cgroupRoot = "/sys/fs/cgroup"
	procStat   = "/proc/stat"
	// The capability probe's file. It exists only on a unified v2 mount,
	// which is what every fact here is read from — the same two-stage
	// question the reference's capability() asks.
	cgroupControllersPath = cgroupRoot + "/cgroup.controllers"
)

// The probe path as a var so a test can point it at a state THIS platform does
// not happen to be in. The first version of the both-paths test asserted that
// walking a missing root errors, which is true only on a machine with no
// cgroup hierarchy at all: it passed on a developer's macOS and failed on a
// Linux runner, having asserted nothing about the gate either time.
var cgroupControllers = cgroupControllersPath

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is deliberately not consulted: every fact here is a
		// counter or an average the kernel stated, and nothing is derived
		// against wall-clock now — not an age, not an elapsed time — so the
		// pin has nothing to freeze and reading it would invent a dependency
		// the declaration does not admit to.
		return &replaySource{dir: dir}
	}
	return &liveSource{started: time.Now()}
}

// ── live ────────────────────────────────────────────────────────────────

type liveSource struct {
	started time.Time
	at      float64
	stamped bool
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

func (*liveSource) clockTick() int64 { return userHZ() }

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

// The nesting bound, applied in the walk as well as in the derivation. cgroup
// nesting is shallow in practice (slice → slice → unit); the bound stops a
// pathological tree from turning one collection into a filesystem crawl. The
// bounding directory is still LISTED — the derivation needs its `dirnames` to
// know its subtree was cut — and only descent below it stops, which is exactly
// what `dirnames[:] = []` does to os.walk.
const cgroupMaxDepth = 6

func (s *liveSource) walk(root string) ([]listing, error) {
	if _, err := os.Stat(cgroupControllers); err != nil {
		// The capability question, asked of the machine rather than assumed:
		// no cgroup.controllers is no unified v2 hierarchy. Checked before
		// the clock is read so the answer is the same on any platform.
		if errors.Is(err, fs.ErrPermission) {
			reason := declineCgroupRefused
			return nil, fmt.Errorf("%v: %w", err, &reason)
		}
		reason := declineNoCgroupV2
		return nil, fmt.Errorf("%v: %w", err, &reason)
	}
	// The clock reading before the first byte: `at` must precede the earliest
	// native read that contributes to a row, and the tie breaks toward older
	// (DESIGN 19). Taken here rather than per row because one walk feeds them
	// all.
	at, err := bootClock()
	if err != nil {
		return nil, err
	}
	s.at, s.stamped = at, true

	root = strings.TrimRight(root, "/")
	rootDepth := strings.Count(root, "/")
	var listings []listing
	var descend func(dir string)
	descend = func(dir string) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			// The subtree a walk could not list — denied, or removed under it,
			// which is the ordinary end of a transient scope. Recorded rather
			// than dropped: os.walk discards such a subtree without a word by
			// default, and that silence is the failure this collection exists
			// to prevent, because the slice above would go on to state
			// positively that every member was read.
			listings = append(listings, listing{dir: dir, unlistable: true})
			return
		}
		var dirs, files []string
		for _, entry := range entries {
			if entry.IsDir() {
				dirs = append(dirs, entry.Name())
			} else {
				files = append(files, entry.Name())
			}
		}
		listings = append(listings, listing{dir: dir, dirs: dirs, files: files})
		if strings.Count(dir, "/")-rootDepth >= cgroupMaxDepth {
			return
		}
		for _, name := range dirs {
			descend(dir + "/" + name)
		}
	}
	descend(root)
	return listings, nil
}

func (*liveSource) readText(path string) (string, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		// ANY failure is "the kernel does not keep this here", which is what
		// the reference's `_read_text` says by catching OSError whole: a
		// controller that is off, a file this kernel predates, a read the
		// kernel refuses on the root cgroup. Distinguishing them would invent
		// a vocabulary the collection has no channel for.
		return "", false, nil
	}
	return string(raw), true, nil
}

// ── replay ──────────────────────────────────────────────────────────────

// A replay has no boot, so the fixed v4-shaped id — "5e" up front so no reader
// mistakes it for a capture. The shape rule refuses the old "replay" stub and
// the nil UUID; that this constant itself passes is DESIGN 19's named
// deferral, the live comparator's to catch.
const replayBootID = "5e000000-0000-4000-8000-000000000001"

// USER_HZ under replay. /proc/self/auxv is not a file this collector reads, so
// the captured machine's tick is not in the payload — and reading the
// REPLAYING machine's would make a replayed stream a function of the host
// rather than of the capture, which is the one property replay exists to have.
// 100 is USER_HZ on Linux everywhere this product deploys; the reference calls
// sysconf here and therefore does read the replaying machine's, which is a
// divergence reported rather than inherited.
const replayClockTick = 100

type replaySource struct {
	dir      string
	payloads map[string]string // slug -> file name, built once
	loaded   bool
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

func (*replaySource) clockTick() int64 { return replayClockTick }

func (*replaySource) stamp(i int) float64 {
	// The reference constant, 1.0 + 0.001*i in emission order and one counter
	// across the whole batch: finite, positive, boot-scale and advancing, so
	// the structural rule that governs `at` is exercised by replay instead of
	// satisfied by a hardcoded zero. Rounded because the reference rounds.
	return float64(int64((1.0+0.001*float64(i))*1000+0.5)) / 1000
}

func (*replaySource) costs() (float64, float64) { return 0.5, 1.0 }

// slug is the payload seam's addressing, and it mirrors
// harness/bin/se-reference-collector's slug() character for character: the
// argument that decides WHICH document comes back is what the payload is keyed
// on, so `/sys/fs/cgroup/system.slice/cpu.stat` is committed as
// `sys-fs-cgroup-system.slice-cpu.stat` and a reviewer reading the file name
// is reading the path it answers.
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

// load indexes the payload directory once, by stem, exactly as the shim's
// load_payloads does: `.json` and `.txt` and nothing else, because those are
// the two forms the seam reads and a file in a third form would be a payload
// the reference could not see either.
func (r *replaySource) load() error {
	if r.loaded {
		return nil
	}
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return fmt.Errorf("reading %s: %v", r.dir, err)
	}
	r.payloads = make(map[string]string, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") {
			continue
		}
		ext := filepath.Ext(name)
		if ext != ".json" && ext != ".txt" {
			continue
		}
		r.payloads[strings.TrimSuffix(name, ext)] = name
	}
	r.loaded = true
	return nil
}

func (r *replaySource) walk(root string) ([]listing, error) {
	if err := r.load(); err != nil {
		return nil, err
	}
	name, ok := r.payloads[slug(root)]
	if !ok {
		// NOTHING staged for the tree: the variant records a host with no
		// unified hierarchy. The same reading the live path takes, through
		// the same constant, so the two cannot spell one condition two ways.
		reason := declineNoCgroupV2
		return nil, &reason
	}
	raw, err := os.ReadFile(filepath.Join(r.dir, name))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	var triples [][]json.RawMessage
	if err := json.Unmarshal(raw, &triples); err != nil {
		return nil, fmt.Errorf("%s is not a walk transcription: %v", name, err)
	}
	listings := make([]listing, 0, len(triples))
	for i, triple := range triples {
		if len(triple) != 3 {
			return nil, fmt.Errorf("%s[%d]: a listing is [dir, dirs, files]", name, i)
		}
		var entry listing
		if err := json.Unmarshal(triple[0], &entry.dir); err != nil {
			return nil, fmt.Errorf("%s[%d]: %v", name, i, err)
		}
		if err := json.Unmarshal(triple[1], &entry.dirs); err != nil {
			return nil, fmt.Errorf("%s[%d]: %v", name, i, err)
		}
		if err := json.Unmarshal(triple[2], &entry.files); err != nil {
			return nil, fmt.Errorf("%s[%d]: %v", name, i, err)
		}
		listings = append(listings, entry)
	}
	// A directory the captured walk could not list is a shape no committed
	// variant holds and the transcription has no member for, so a replay
	// reports none rather than inventing one — the collector's declaration
	// names where that truth is owned instead.
	return listings, nil
}

func (r *replaySource) readText(path string) (string, bool, error) {
	if err := r.load(); err != nil {
		return "", false, err
	}
	name, ok := r.payloads[slug(path)]
	if !ok {
		// Never a fall-back to the live kernel of the machine replaying, and
		// never a decline: a path the capture did not record is a broken
		// transcription, not a statement about any machine.
		return "", false, fmt.Errorf("%s (payload %q) %w", path, slug(path), errUncaptured)
	}
	raw, err := os.ReadFile(filepath.Join(r.dir, name))
	if err != nil {
		return "", false, fmt.Errorf("%s: %v", name, err)
	}
	if filepath.Ext(name) != ".json" {
		return string(raw), true, nil
	}
	// `null` is how the transcription records a path that was not there, and
	// it is a different answer from a document holding nothing.
	var document *string
	if err := json.Unmarshal(raw, &document); err != nil {
		return "", false, fmt.Errorf("%s is neither a string nor null: %v", name, err)
	}
	if document == nil {
		return "", false, nil
	}
	return *document, true, nil
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
// answer: a cgroup.controllers file on disk says nothing about whether the
// tree under it can be walked, which is the two-stage question the reference's
// capability check asks. A host running nothing but its own init still answers
// here, and that is a reading of one cgroup rather than an inability.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes", Reason: "the cgroup v2 hierarchy is present and walkable"}
	if _, err := readTree(src); err != nil {
		reason := "the cgroup v2 hierarchy could not be read"
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
