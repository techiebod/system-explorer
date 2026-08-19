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
	"regexp"
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
	// stamp is `at` for the i-th emitted object. Every row of a batch comes
	// out of ONE listing, so live readings share the moment that listing was
	// read and the index is ignored: an acquisition stamped per row at
	// completion would report the last package fresher than the first, off
	// bytes that arrived together (DESIGN 19).
	stamp(i int) float64
	// declaration is the digest begin carries. It sits on the seam because
	// the two ports before this one needed it to: the corpus's committed
	// halves carried the reference's replay constant while begin.declaration
	// was byte-compared, which asked a port to publish somebody else's
	// identity. It is rule-governed now (DESIGN 19's two regimes), so both
	// paths answer honestly and the seam keeps only the shape.
	declaration() string
	// packages is which manager answered and what it said, in one reading.
	// The two are inseparable on purpose: WHICH manager this host has is
	// both the capability answer and an acquisition, so a seam that pinned
	// the rows and not the manager would replay a dpkg capture while asking
	// the replaying machine what it runs.
	packages() (reading, error)
	// costs are end's advisory self-report (DESIGN 19): bounded by the
	// judge, authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

// reading is one manager's whole answer. `manager` is never empty where the
// error is nil, because it is the fact every row carries: the operator asks
// one question and the answer names its own provenance.
type reading struct {
	manager string
	// rows are the tab-split fields of the dpkg or rpm listing, in the
	// order this collector's own format string asked for them. Nil for nix,
	// whose interface is the store rather than a subprocess.
	rows [][]string
	// store is the nix system environment's name-version → store path map.
	// Nil for dpkg and rpm.
	store map[string]string
}

// declined is the seam's statement that the interface itself could not be
// reached, carried as an error so no caller can forget to route it. The
// detail is a constant: decline detail travels to a hub and out over MCP,
// and an interpolated error string is a redaction path nobody reviewed.
type declined struct{ reason, detail string }

func (d *declined) Error() string { return d.reason + ": " + d.detail }

// The no-manager reading, named ONCE and shared by the live source and the
// replay source. Storage learned this the expensive way: one collector, one
// condition, two paths, and for as long as it existed the two spelled the
// answer differently — live `unsupported`, replay `absent` — each under a
// confident comment arguing against the other, because replay exercises only
// the replay half. A shared constant makes the disagreement unspellable.
//
// absent, not unsupported: a host with no package manager this collector can
// read is a host with no packages this collector can see, which is a
// successful reading establishing there are none — DESIGN 19's worked example
// ("there are no md devices"). It is also the only decline that commits, and
// it must commit: a host that HAD dpkg and lost it would otherwise serve its
// last inventory forever, stale and never retired.
var declineNoManager = declined{"absent", "no package manager on this host"}

// errUncaptured marks a document the variant did not stage. It must never
// fall back to the live interface of the machine REPLAYING the corpus —
// that seam escape once put a replaying workstation's filesystem into
// committed facts — and it must not become a decline either, which would
// state something about a machine nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is deliberately not consulted: an inventory is a
		// set of strings the interface handed over and nothing here is
		// derived against a clock, so the pin has nothing to freeze and
		// reading it would invent a dependency the declaration denies.
		return replaySource{dir: dir}
	}
	return &liveSource{started: time.Now()}
}

// The three managers, spelled once: this is the Manager fact's declared enum,
// the switch every branch turns on, and the word a capture stages.
const (
	managerNix  = "nix"
	managerDpkg = "dpkg"
	managerRPM  = "rpm"
)

// The NixOS read surface, which is the whole of what only exists there: the
// activated-closure pointer and the link farm it publishes. buildEnv links a
// package's own subdirectories, so the environment is walked one level deeper
// than its root.
const (
	currentSystem = "/run/current-system"
	swRoot        = currentSystem + "/sw"
)

var swSubdirs = [...]string{"bin", "sbin", "lib", "libexec", "share", "etc"}

// A store path and the name-version it publishes. Anchored, because a link
// target is a whole path and the derivation name is its last component after
// the 32-character hash.
var storeRe = regexp.MustCompile(`^(/nix/store/[a-z0-9]{32}-([^/]+))`)

// The format strings, supplied by this file rather than read off the tool.
// This is the opposite of parsing human output: the fields and their order
// are ours, so neither a locale nor a version can move them under us, and the
// two commands are allow-listed on their format flag rather than on a --json
// neither has. Tab-separated because a package version can contain almost
// anything except a tab, and a field count we chose is a contract we can
// check. The backslash is literal in the argv: dpkg-query and rpm expand \t
// themselves.
const (
	dpkgFormat = `${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n`
	rpmFormat  = `%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n`
)

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

func (s *liveSource) stamp(int) float64 { return s.at }

func (*liveSource) declaration() string { return declarationDigest }

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

// detect names which manager can answer here, and it is the capability probe
// as much as an acquisition. Nix first where a closure is activated: there it
// is the truth about the system environment, and dpkg is not installed at all.
func detect() string {
	if info, err := os.Stat(currentSystem); err == nil && info != nil {
		if sw, err := os.Stat(swRoot); err == nil && sw.IsDir() {
			return managerNix
		}
	}
	if _, err := exec.LookPath("dpkg-query"); err == nil {
		return managerDpkg
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		return managerRPM
	}
	return ""
}

func (s *liveSource) packages() (reading, error) {
	// The clock reading FIRST, before the capability probe and before the
	// listing: `at` must precede the earliest byte that contributes to a row,
	// and the tie breaks toward older.
	at, err := bootClock()
	if err != nil {
		return reading{}, err
	}
	s.at = at

	switch manager := detect(); manager {
	case managerNix:
		return reading{manager: manager, store: storePaths(swRoot)}, nil
	case managerDpkg:
		rows, err := rowsFrom(30*time.Second, "dpkg-query", "-W", "-f", dpkgFormat)
		if err != nil {
			// dpkg IS here and would not answer. That must never be absent:
			// this host has an inventory right now, so committing zero would
			// retire every package it holds. unavailable rather than
			// unsupported — a database lock or a broken dpkg is the kind of
			// thing that clears, and neither reason commits, so the previous
			// inventory stands and is served marked stale either way.
			return reading{}, &declined{"unavailable", "dpkg-query is installed but did not answer"}
		}
		return reading{manager: manager, rows: rows}, nil
	case managerRPM:
		rows, err := rowsFrom(60*time.Second, "rpm", "-qa", "--qf", rpmFormat)
		if err != nil {
			return reading{}, &declined{"unavailable", "rpm is installed but did not answer"}
		}
		return reading{manager: manager, rows: rows}, nil
	default:
		reason := declineNoManager
		return reading{}, &reason
	}
}

// rowsFrom runs one listing and splits it on the tabs this collector asked
// for. Every token of the argv is a literal from this file — nothing is built
// from a document — so no payload can add an argument. Blank lines are
// dropped rather than becoming an empty row: a trailing newline is the format
// string's own, not a package.
func rowsFrom(timeout time.Duration, argv ...string) ([][]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).Output()
	if err != nil {
		return nil, err
	}
	var rows [][]string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		rows = append(rows, strings.Split(line, "\t"))
	}
	return rows, nil
}

// storePaths walks a system environment's link farm into {name-version: store
// path}. The store IS the structured interface here, so there is no subprocess
// at all — `nix store diff-closures` would answer with prose this collector is
// not allowed to parse. Two scandir levels, because buildEnv links packages
// directly or, on a collision, merges one directory level and links inside it;
// first writer wins, matching the reference, so a package linked from two
// subdirectories is recorded once.
func storePaths(root string) map[string]string {
	seen := map[string]string{}
	record := func(target string) {
		if match := storeRe.FindStringSubmatch(target); match != nil {
			if _, already := seen[match[2]]; !already {
				seen[match[2]] = match[1]
			}
		}
	}
	for _, sub := range swSubdirs {
		entries, err := os.ReadDir(filepath.Join(root, sub))
		if err != nil {
			continue // a system environment need not publish every subdirectory
		}
		for _, entry := range entries {
			path := filepath.Join(root, sub, entry.Name())
			if entry.Type()&fs.ModeSymlink != 0 {
				if target, err := os.Readlink(path); err == nil {
					record(target)
				}
				continue
			}
			if !entry.IsDir() {
				continue
			}
			nested, err := os.ReadDir(path)
			if err != nil {
				continue
			}
			for _, inner := range nested {
				if inner.Type()&fs.ModeSymlink == 0 {
					continue
				}
				if target, err := os.Readlink(filepath.Join(path, inner.Name())); err == nil {
					record(target)
				}
			}
		}
	}
	return seen
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

func (replaySource) stamp(i int) float64 {
	// The reference constant, 1.0 + 0.001*i in emission order and one counter
	// across the whole batch: finite, positive, boot-scale and advancing, so
	// the structural rule that governs `at` is exercised by replay instead of
	// satisfied by a hardcoded zero. Rounded because the reference rounds, and
	// at a thousand rows the float noise is the difference between 1.126 and
	// 1.1260000000000001 in a file people read.
	return float64(int64((1.0+0.001*float64(i))*1000+0.5)) / 1000
}

// The real digest, under replay as much as live: the declaration identifies
// THIS collector's contract, and a replay does not change which contract this
// binary holds (DESIGN 19's two regimes — begin.declaration is rule-governed,
// not byte-compared).
func (replaySource) declaration() string { return declarationDigest }

// The payload stems this seam knows, and which manager each belongs to. A
// variant stages exactly the one its manager names, so this table is also how
// absence is told from a broken capture: no document at ALL is a host with no
// manager, and a rows document with no manager beside it is a capture that
// cannot say who was speaking.
var replayRowsPayload = map[string]string{
	managerDpkg: "dpkg",
	managerRPM:  "rpm",
	managerNix:  "nixstore",
}

// The same three in the order detect() prefers them. A slice beside the map
// because the scan below reports the first stem it finds, and a map's order is
// whatever Go feels like that run — a diagnostic that changes between two runs
// of the same broken capture is one nobody can act on.
var managerOrder = [...]string{managerNix, managerDpkg, managerRPM}

func (r replaySource) packages() (reading, error) {
	raw, err := os.ReadFile(filepath.Join(r.dir, "manager.json"))
	if errors.Is(err, fs.ErrNotExist) {
		for _, manager := range managerOrder {
			stem := replayRowsPayload[manager]
			if _, err := os.Stat(filepath.Join(r.dir, stem+".json")); err == nil {
				// Rows staged and no manager: the capture cannot say who was
				// speaking, and Manager is a fact on every row. "I could not
				// run" — never a guess from which file happens to be present,
				// which would make the seam decide what the machine runs.
				return reading{}, fmt.Errorf("manager %w, and %s.json is — a capture that stages rows must say which manager produced them", errUncaptured, stem)
			}
		}
		// Nothing staged at all: the variant records a host with no package
		// manager. The same reading the live path takes, through the same
		// constant, so the two cannot drift apart again.
		reason := declineNoManager
		return reading{}, &reason
	}
	if err != nil {
		return reading{}, fmt.Errorf("manager %w: %v", errUncaptured, err)
	}
	var manager string
	if err := json.Unmarshal(raw, &manager); err != nil {
		return reading{}, fmt.Errorf("the staged manager payload is not a manager name: %v", err)
	}
	stem, known := replayRowsPayload[manager]
	if !known {
		// A manager this collector cannot read is not an empty inventory.
		// Committing zero here would retire every package the host has on the
		// strength of a word nobody understood, which is absence-as-health
		// with the sign flipped.
		return reading{}, fmt.Errorf("the staged manager payload names %q, and this collector reads nix, dpkg and rpm", manager)
	}
	body, err := os.ReadFile(filepath.Join(r.dir, stem+".json"))
	if err != nil {
		return reading{}, fmt.Errorf("%s %w: %v", stem, errUncaptured, err)
	}
	if manager == managerNix {
		store := map[string]string{}
		if err := json.Unmarshal(body, &store); err != nil {
			return reading{}, fmt.Errorf("the staged %s payload is not a name-version to store-path map: %v", stem, err)
		}
		return reading{manager: manager, store: store}, nil
	}
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return reading{}, fmt.Errorf("the staged %s payload is not a list of field rows: %v", stem, err)
	}
	return reading{manager: manager, rows: rows}, nil
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
// 18). It asks exactly the question the reference's capability check asks —
// which manager can answer — because that answer is what every row's Manager
// fact carries. A host with a manager and nothing installed still answers:
// that is a reading of zero packages, not an inability.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes"}
	if got, err := src.packages(); err != nil {
		verdict = probeVerdict{Verdict: "no", Reason: "no package manager this collector can read: neither an activated Nix system closure, nor dpkg-query, nor rpm answered"}
		fmt.Fprintln(stderr, "probe:", err)
	} else {
		verdict.Reason = "the " + got.manager + " inventory answers on this host"
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(verdict); err != nil {
		fmt.Fprintln(stderr, "writing the probe verdict:", err)
		return exitRuntime
	}
	return exitOK
}
