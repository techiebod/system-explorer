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
	// declaration is the digest begin carries. It is on the seam because
	// the corpus pairs were captured with the reference's replay constant
	// in that member, and begin.declaration is byte-compared.
	declaration() string
	// now is epoch seconds for the one fact derived against the wall clock,
	// ScanAgeDays. Under replay it is the moment the capture was taken, or
	// the pair would report a different age every day it is judged.
	now() (float64, error)
	// zpool is the whole ZFS interface in one reading: the fact source, the
	// enrichment that may be missing, and the alias trees that may be
	// unreadable — three states this collector must tell apart.
	zpool() (zpoolReading, error)
	// costs are end's advisory self-report (DESIGN 19): bounded by the
	// judge, authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

type zpoolReading struct {
	// status is `zpool status -j`, the fact source. Never nil where the
	// error is nil: without it there is nothing to say about any pool.
	status *value
	// list is `zpool list -j -p -v`, enrichment only. nil is could-not-read,
	// which puts five capacity facts on the unobservable channel; an empty
	// document is a document that reported no such properties, which is
	// absence.
	list *value
	// links is the device alias tree. nil is "no tree was readable", which
	// makes every disk leaf's Device an unobservable; an empty tree is one
	// that was read and holds nothing for these members, which is a silent
	// absence. That distinction is load-bearing and the corpus pins both.
	links *aliasTree
}

// declined is the seam's statement that the interface itself could not be
// reached, carried as an error so no caller can forget to route it. The
// detail is a constant: decline detail travels to a hub and out over MCP,
// and an interpolated error string is a redaction path nobody reviewed.
type declined struct{ reason, detail string }

func (d *declined) Error() string { return d.reason + ": " + d.detail }

// errUncaptured marks a document the variant did not stage. It must never
// fall back to the live interface of the machine REPLAYING the corpus —
// that seam escape once put a replaying workstation's filesystem into
// committed facts — and it must not become a decline either, which would
// state something about a machine nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		return replaySource{dir: dir, pinned: getenv("SE_REPLAY_NOW")}
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

func (liveSource) declaration() string { return declarationDigest }

func (liveSource) now() (float64, error) {
	return float64(time.Now().UnixNano()) / 1e9, nil
}

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

// The two live acquisitions, written as literal argv so a reader can run
// them by hand and get the same document (SPEC section 11, rule 5).
//
// --json-int renders scan_stats times as epoch integers; without it end_time
// is a locale string no machine consumer can compare, and older OpenZFS
// rejects the flag — so the fallback is on a command failure only, and the
// reading degrades honestly rather than failing.
//
// -p gives exact byte values rather than human units, and -v adds the
// per-vdev rows that carry their own size/alloc/capacity, which is the whole
// of the capacity enrichment.
var (
	zpoolStatusJSONInt = []string{"zpool", "status", "-j", "--json-int"}
	zpoolStatusPlain   = []string{"zpool", "status", "-j"}
	zpoolListVerbose   = []string{"zpool", "list", "-j", "-p", "-v", "-o", "name,size,alloc,free,cap,frag,health"}
)

func (liveSource) zpool() (zpoolReading, error) {
	if _, err := exec.LookPath("zpool"); err != nil {
		// A host with no OpenZFS is not an empty pool list — it is a
		// question this collector cannot answer here. unsupported states
		// that without retiring pools some other batch published, which is
		// what an absent decline would do.
		return zpoolReading{}, &declined{"unsupported", "zpool is not installed on this host"}
	}
	status, err := runJSON(zpoolStatusJSONInt)
	if err != nil {
		status, err = runJSON(zpoolStatusPlain)
	}
	if err != nil {
		// zpool on PATH says nothing about /dev/zfs permissions or a
		// pool-less host. Nothing was established, so this must not commit.
		return zpoolReading{}, &declined{"unavailable", "zpool is installed but did not answer"}
	}
	// The listing is enrichment and degrades to the unobservable channel;
	// only the fact source can refuse the reading.
	list, _ := runJSON(zpoolListVerbose)
	return zpoolReading{status: status, list: list, links: devlinks()}, nil
}

func runJSON(argv []string) (*value, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Every token is data and the argv is a literal: nothing here is built
	// from a payload, so no document can add an argument.
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).Output()
	if err != nil {
		return nil, err
	}
	return decodeDocument(out)
}

// devlinks builds {alias path: kernel name} over the three trees, the one
// place vdev resolution touches the filesystem. nil is returned only when NO
// tree could be listed: that is could-not-read, a different statement from
// an empty tree, and the caller routes it to the unobservable channel rather
// than letting it impersonate absence.
func devlinks() *aliasTree {
	var links *aliasTree
	for _, tree := range devlinkTrees {
		entries, err := os.ReadDir(tree)
		if err != nil {
			continue
		}
		if links == nil {
			links = newAliasTree()
		}
		for _, entry := range entries {
			path := tree + "/" + entry.Name()
			target, err := os.Readlink(path)
			if err != nil {
				continue // /dev/mapper/control and friends: nodes, not aliases
			}
			links.add(path, filepath.Base(target))
		}
	}
	return links
}

// ── replay ──────────────────────────────────────────────────────────────

// A replay has no boot, so the fixed v4-shaped id — "5e" up front so no
// reader mistakes it for a capture. The shape rule refuses the old "replay"
// stub and the nil UUID; that this constant itself passes is DESIGN 19's
// named deferral, a cross-boot live variant's to catch.
const replayBootID = "5e000000-0000-4000-8000-000000000001"

type replaySource struct {
	dir    string
	pinned string
}

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

// The real digest, under replay as much as live: the declaration
// identifies THIS collector's contract, and a replay does not change which
// contract this binary holds. It was a constant here — the one value neither
// port could derive from its payload — because begin.declaration was
// byte-compared against a committed half another implementation generated,
// which asked a port to publish somebody else's identity. It is rule-governed
// now (DESIGN 19's two regimes), so the honest value costs nothing.
func (replaySource) declaration() string { return declarationDigest }

// now honours SE_REPLAY_NOW because this collector genuinely derives a fact
// against it: ScanAgeDays is whole days since the recorded scan, and a live
// clock would make the committed pair report a different answer every day.
// A variant that stages no pin gets the wall clock, which is what the
// reference does and is why any storage variant must declare `captured`.
func (r replaySource) now() (float64, error) {
	if r.pinned == "" {
		return float64(time.Now().UnixNano()) / 1e9, nil
	}
	moment, err := time.Parse(time.RFC3339Nano, r.pinned)
	if err != nil {
		return 0, fmt.Errorf("SE_REPLAY_NOW=%q is not an ISO-8601 moment: %v", r.pinned, err)
	}
	return float64(moment.UnixNano()) / 1e9, nil
}

func (r replaySource) zpool() (zpoolReading, error) {
	status, statusErr := r.payload("status")
	list, listErr := r.payload("list")
	if errors.Is(statusErr, fs.ErrNotExist) && errors.Is(listErr, fs.ErrNotExist) {
		// Neither interface document was captured: the variant records a
		// host with no zpool. absent is authoritative-empty and the only
		// decline reason that commits, because it must retire pools a
		// previous batch published.
		return zpoolReading{}, &declined{"absent", "no zpool on this host"}
	}
	if statusErr != nil {
		// A variant staging the enrichment but not the fact source is a
		// broken capture, not a statement about any machine: "I could not
		// run", never a decline and never a fall-back to this host's zpool.
		return zpoolReading{}, fmt.Errorf("status %w: %v", errUncaptured, statusErr)
	}
	if listErr != nil {
		list = nil
	}
	links, err := r.devlinks()
	if err != nil {
		return zpoolReading{}, err
	}
	return zpoolReading{status: status, list: list, links: links}, nil
}

// devlinks under replay reproduces the live acquisition's own two-state
// answer from the payload. The corpus pins both ends: no file at all is a
// tree that could not be read (nil), and a file holding a valid object is a
// tree that was read, empty or not.
//
// Two shapes no corpus pins, ruled here. A JSON null is could-not-read, for
// the same reason a live listdir failure is, and so is a document this seam
// cannot parse — the alternative would be claiming the trees hold nothing on
// the strength of bytes nobody could read. A document that parses to
// something that is not an object is neither: it was read and it is not an
// alias tree, so the batch reports "I could not run" rather than inventing a
// reading, which is what the reference does when it tries to index it.
func (r replaySource) devlinks() (*aliasTree, error) {
	raw, err := os.ReadFile(filepath.Join(r.dir, "devlinks.json"))
	if err != nil {
		return nil, nil
	}
	document, err := decodeDocument(raw)
	if err != nil || document.kind == jsonNull {
		return nil, nil
	}
	if document.kind != jsonObject {
		return nil, fmt.Errorf("the staged devlinks payload is not an alias tree")
	}
	links := newAliasTree()
	for _, alias := range document.members.keys {
		target := document.members.byKey[alias]
		if target.isString() {
			links.add(alias, target.text)
		} else {
			links.addRaw(alias, target)
		}
	}
	return links, nil
}

func (r replaySource) payload(stem string) (*value, error) {
	raw, err := os.ReadFile(filepath.Join(r.dir, stem+".json"))
	if err != nil {
		return nil, err
	}
	return decodeDocument(raw)
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
// 18). It asks the whole question the reference's capability check asks in
// two stages: zpool on PATH says nothing about /dev/zfs permissions or a
// pool-less host, so the probe is satisfied only by `zpool status -j`
// actually answering. A host with zpool and no pools still answers — that is
// a reading of zero pools, not an inability.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes", Reason: "zpool is installed and zpool status answers"}
	if _, err := src.zpool(); err != nil {
		verdict = probeVerdict{Verdict: "no", Reason: "zpool did not answer on this host"}
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
