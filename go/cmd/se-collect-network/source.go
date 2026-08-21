package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
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
	batch() (string, error)
	// declaration is begin's declaration digest. It is a seam value because
	// a replay has no declaration to hash: the reference publishes a
	// placeholder, and the two sides must publish the same one or a collator
	// comparing them would refetch a declaration that does not exist.
	declaration() string
	// nftRuleset is the parsed `nft -j list ruleset` document. Its errors
	// carry the decline shape: see the four sentinels below.
	nftRuleset() (jsonValue, error)
	// The three iproute2 documents behind the routes collection. An error
	// wrapping errIPSilent declines the collection unavailable; under
	// replay a payload nobody staged is errUncaptured and fatal.
	ipRoute4() (jsonValue, error)
	ipRoute6() (jsonValue, error)
	ipRule() (jsonValue, error)
	// procNet is one /proc/net table's text, and whether it opened: an
	// unreadable table is a statement the rows must carry, never an empty
	// table — a host whose udp6 will not open has not stopped listening.
	procNet(table string) (string, bool)
	// The resolver's two modes. resolve1 answers busctl documents keyed by
	// the shared request convention; errCallFailed means the interface is
	// not there (the file mode's cue), errUncaptured stays fatal. The
	// resolv.conf reading is text plus symlink target, exists=false where
	// there is no file — one acquisition, because two reads could straddle
	// a resolvconf rewrite.
	resolve1Call(request string) ([]byte, error)
	ifNameIndex() []ifEntry
	resolvConf() (text string, target string, exists bool)
	// hostname names the resolver object; under replay it is the CAPTURED
	// machine's, staged, and its absence is fatal — an object named after
	// whichever machine replays is a different object per reader.
	hostname() (string, error)
	// stamp is `at` for the i-th emitted object. Every row of a batch comes
	// from ONE document, read once, so the live reading is taken before that
	// read and shared: an acquisition stamped at completion would report
	// itself fresher than its oldest contributing byte (DESIGN 19).
	stamp(i int) float64
	// costs are end's advisory self-report (DESIGN 19): bounded by the judge,
	// authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

// What went wrong reaching nft, in the four shapes the decline vocabulary
// distinguishes. Only `absent` is judged by anything committed — it is the
// reference's one decline and the corpus pins its detail byte for byte. The
// other three are this side's reading of the adapter's own capability
// branches (`nft not on PATH`, `nft cannot read the ruleset (CAP_NET_ADMIN
// not granted?)`, everything else) and no variant exercises them yet.
var (
	errIPSilent   = errors.New("ip did not answer")
	errCallFailed = errors.New("the interface did not answer")
	errUncaptured = errors.New("not captured in this replay directory")
)

type ifEntry struct {
	Index int
	Name  string
}

// The resolve1 request lines, spelled once in the shared busctl-argument
// convention the corpus is keyed on (the units collector's rule).
const (
	resolve1Dest    = "org.freedesktop.resolve1"
	resolve1Path    = "/org/freedesktop/resolve1"
	resolve1Manager = "org.freedesktop.resolve1.Manager"
	resolve1Link    = "org.freedesktop.resolve1.Link"
	propertiesIface = "org.freedesktop.DBus.Properties"
)

func resolve1ManagerRequest() string {
	return resolve1Path + " " + propertiesIface + " GetAll s " + resolve1Manager
}

func getLinkRequest(ifindex int) string {
	return resolve1Path + " " + resolve1Manager + " GetLink i " +
		strconv.Itoa(ifindex)
}

func linkPropertiesRequest(path string) string {
	return path + " " + propertiesIface + " GetAll s " + resolve1Link
}

var (
	errNftAbsent     = errors.New("nft is not on this host")
	errNftRefused    = errors.New("nft ran and refused to read the ruleset")
	errNftSilent     = errors.New("nft did not answer")
	errNftUnreadable = errors.New("nft answered something that is not a JSON document")
)

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

// nftTimeout matches the reference's subprocess timeout. A ruleset large
// enough to take longer is a host this collector reports as unavailable
// rather than one it blocks a slice on.
const nftTimeout = 10 * time.Second

func (s *liveSource) nftRuleset() (jsonValue, error) {
	// Before the read, not after: `at` belongs to the oldest byte the row
	// rests on, and a failure here is "I could not run" rather than a
	// decline, because a stream whose `at` is unmeasured says nothing about
	// when it was true.
	at, err := bootClock()
	if err != nil {
		return jsonValue{}, err
	}
	s.at = at

	if _, err := exec.LookPath("nft"); err != nil {
		return jsonValue{}, fmt.Errorf("%w: %v", errNftAbsent, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), nftTimeout)
	defer cancel()
	// The interface is a subprocess talking netlink, and this is the whole of
	// it. Every token is a literal: nothing from the request line or from any
	// document reaches this argv.
	cmd := exec.CommandContext(ctx, "nft", "-j", "list", "ruleset")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	// nft's own stderr is discarded rather than relayed: it is interface
	// output, and this process's stderr goes straight to the journal, past
	// every redaction path. The exit status is what this side reads.
	cmd.Stderr = nil
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return jsonValue{}, fmt.Errorf("%w: no answer in %s", errNftSilent, nftTimeout)
	}
	if runErr != nil {
		var exit *exec.ExitError
		if errors.As(runErr, &exit) {
			// nft ran and refused. The adapter's own text hedges the cause
			// with a question mark — a missing CAP_NET_ADMIN is the
			// overwhelmingly common one, and unauthorised is the reading that
			// tells an operator what to change.
			return jsonValue{}, fmt.Errorf("%w: exit %d", errNftRefused, exit.ExitCode())
		}
		return jsonValue{}, fmt.Errorf("%w: %v", errNftSilent, runErr)
	}
	raw := stdout.Bytes()
	if len(bytes.TrimSpace(raw)) == 0 {
		// The reference reads empty output as the empty document, not as a
		// failure: `json.loads(proc.stdout or "{}")`.
		return jsonValue{kind: jsonObject}, nil
	}
	doc, err := decodeDocument(bytes.NewReader(raw))
	if err != nil {
		return jsonValue{}, fmt.Errorf("%w: %v", errNftUnreadable, err)
	}
	return doc, nil
}

func (s *liveSource) stamp(int) float64 { return s.at }

// ipJSON runs one iproute2 read. Literal tokens only, `-j` always, the
// same patience as nft, and empty output is the empty document — a host
// with no rules prints nothing and has none.
func (s *liveSource) ipJSON(args ...string) (jsonValue, error) {
	at, err := bootClock()
	if err != nil {
		return jsonValue{}, err
	}
	s.at = at
	if _, err := exec.LookPath("ip"); err != nil {
		return jsonValue{}, fmt.Errorf("%w: %v", errIPSilent, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), nftTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ip", append([]string{"-j"}, args...)...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	if err := cmd.Run(); err != nil {
		return jsonValue{}, fmt.Errorf("%w: %v", errIPSilent, err)
	}
	raw := bytes.TrimSpace(stdout.Bytes())
	if len(raw) == 0 {
		return jsonValue{kind: jsonArray}, nil
	}
	doc, err := decodeDocument(bytes.NewReader(raw))
	if err != nil {
		return jsonValue{}, fmt.Errorf("%w: %v", errIPSilent, err)
	}
	return doc, nil
}

func (s *liveSource) ipRoute4() (jsonValue, error) {
	return s.ipJSON("-4", "route", "show", "table", "all")
}

func (s *liveSource) ipRoute6() (jsonValue, error) {
	return s.ipJSON("-6", "route", "show", "table", "all")
}

func (s *liveSource) ipRule() (jsonValue, error) {
	return s.ipJSON("rule", "show")
}

// resolve1Call shells one busctl invocation, the system collector's
// discipline: literal tokens, the reply buffered, failures to stderr's
// journal channel only.
func (s *liveSource) resolve1Call(request string) ([]byte, error) {
	at, err := bootClock()
	if err != nil {
		return nil, err
	}
	s.at = at
	tool, err := exec.LookPath("busctl")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errCallFailed, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), nftTimeout)
	defer cancel()
	args := append([]string{"call", resolve1Dest}, strings.Fields(request)...)
	args = append(args, "--json=short")
	out, err := exec.CommandContext(ctx, tool, args...).Output()
	if err != nil {
		return nil, fmt.Errorf("busctl %s: %w", resolve1Dest, errCallFailed)
	}
	return out, nil
}

func (s *liveSource) ifNameIndex() []ifEntry {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]ifEntry, 0, len(interfaces))
	for _, entry := range interfaces {
		out = append(out, ifEntry{Index: entry.Index, Name: entry.Name})
	}
	return out
}

func (s *liveSource) resolvConf() (string, string, bool) {
	const path = "/etc/resolv.conf"
	info, err := os.Lstat(path)
	if err != nil {
		return "", "", false
	}
	target := ""
	if info.Mode()&os.ModeSymlink != 0 {
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			target = resolved
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", false
	}
	return string(raw), target, true
}

func (s *liveSource) hostname() (string, error) { return os.Hostname() }

func (s *liveSource) procNet(table string) (string, bool) {
	at, err := bootClock()
	if err != nil {
		return "", false
	}
	s.at = at
	raw, err := os.ReadFile("/proc/net/" + table)
	if err != nil {
		return "", false
	}
	return string(raw), true
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

// The real digest, under replay as much as live: the declaration
// identifies THIS collector's contract, and a replay does not change which
// contract this binary holds. It was a constant here — the one value neither
// port could derive from its payload — because begin.declaration was
// byte-compared against a committed half another implementation generated,
// which asked a port to publish somebody else's identity. It is rule-governed
// now (DESIGN 19's two regimes), so the honest value costs nothing.
func (replaySource) declaration() string { return declarationDigest }

// The whole interface for this collector is one payload file. Its ABSENCE is
// the reading — the interface was not there — and that is the only decline
// any committed pair holds. A payload that is present and unreadable is a
// broken capture rather than a statement about a machine, so it fails the
// batch instead of declining, and it must never fall back to the live nft of
// the workstation replaying the corpus: that seam escape once put a replaying
// machine's own state into committed facts.
func (r replaySource) nftRuleset() (jsonValue, error) {
	file, err := os.Open(filepath.Join(r.dir, "nft.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return jsonValue{}, errNftAbsent
	}
	if err != nil {
		return jsonValue{}, fmt.Errorf("the staged nft.json could not be read: %v", err)
	}
	defer file.Close()
	doc, err := decodeDocument(file)
	if err != nil {
		return jsonValue{}, fmt.Errorf("the staged nft.json is not a document: %v", err)
	}
	return doc, nil
}

// ipPayload resolves one staged iproute2 document; absence is a capture
// this variant never took, refused rather than read off the replaying
// machine.
func (r replaySource) ipPayload(stem string) (jsonValue, error) {
	file, err := os.Open(filepath.Join(r.dir, stem+".json"))
	if err != nil {
		return jsonValue{}, fmt.Errorf("%s %w: %v", stem, errUncaptured, err)
	}
	defer file.Close()
	doc, err := decodeDocument(file)
	if err != nil {
		return jsonValue{}, fmt.Errorf("the staged %s.json is not a document: %v", stem, err)
	}
	return doc, nil
}

func (r replaySource) ipRoute4() (jsonValue, error) { return r.ipPayload("ip-route4") }
func (r replaySource) ipRoute6() (jsonValue, error) { return r.ipPayload("ip-route6") }
func (r replaySource) ipRule() (jsonValue, error)   { return r.ipPayload("ip-rule") }

// procNet under replay reads the staged transcript — the reference's tree
// seam shape, one object per directory: {"/proc/net": {"tcp": text|null}}.
// A null is a table that would not open on the captured machine; a table
// the variant never staged reads the same way, because both are "this
// capture holds no such reading" and neither may touch the replaying
// machine's /proc.
func (r replaySource) procNet(table string) (string, bool) {
	raw, err := os.ReadFile(filepath.Join(r.dir, "procnet.json"))
	if err != nil {
		return "", false
	}
	var staged map[string]map[string]*string
	if json.Unmarshal(raw, &staged) != nil {
		return "", false
	}
	entry, ok := staged["/proc/net"][table]
	if !ok || entry == nil {
		return "", false
	}
	return *entry, true
}

// resolve1Call under replay reads the staged bus.json request map; the
// value false stages "the call failed at capture" — a file-mode host's
// resolve1 probe — distinct from a request nobody staged, which refuses.
func (r replaySource) resolve1Call(request string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(r.dir, "bus.json"))
	if err != nil {
		return nil, fmt.Errorf("bus.json: %w", errCallFailed)
	}
	var staged map[string]json.RawMessage
	if err := json.Unmarshal(raw, &staged); err != nil {
		return nil, fmt.Errorf("bus.json is not a request/response map: %v", err)
	}
	document, ok := staged[request]
	if !ok {
		return nil, fmt.Errorf("%q %w", request, errUncaptured)
	}
	if string(document) == "false" {
		return nil, fmt.Errorf("%q: %w (staged at capture)", request, errCallFailed)
	}
	return document, nil
}

func (r replaySource) ifNameIndex() []ifEntry {
	raw, err := os.ReadFile(filepath.Join(r.dir, "ifindex.json"))
	if err != nil {
		return nil
	}
	var staged [][2]any
	if json.Unmarshal(raw, &staged) != nil {
		return nil
	}
	out := make([]ifEntry, 0, len(staged))
	for _, pair := range staged {
		index, ok := pair[0].(float64)
		name, ok2 := pair[1].(string)
		if ok && ok2 {
			out = append(out, ifEntry{Index: int(index), Name: name})
		}
	}
	return out
}

func (r replaySource) hostname() (string, error) {
	raw, err := os.ReadFile(filepath.Join(r.dir, "hostname"))
	if err != nil {
		return "", fmt.Errorf("hostname %w: %v", errUncaptured, err)
	}
	name := strings.TrimSpace(string(raw))
	if name == "" {
		return "", fmt.Errorf("hostname %w: the staged file is empty", errUncaptured)
	}
	return name, nil
}

func (r replaySource) resolvConf() (string, string, bool) {
	raw, err := os.ReadFile(filepath.Join(r.dir, "resolv-conf.json"))
	if err != nil {
		return "", "", false
	}
	var staged struct {
		Text   string  `json:"text"`
		Target *string `json:"target"`
	}
	if json.Unmarshal(raw, &staged) != nil {
		return "", "", false
	}
	target := ""
	if staged.Target != nil {
		target = *staged.Target
	}
	return staged.Text, target, true
}

func (replaySource) stamp(i int) float64 {
	// The reference constant, 1.0 + 0.001*i in emission order and one counter
	// across the whole batch: finite, positive, boot-scale and advancing, so
	// the structural rule that governs `at` is exercised by replay instead of
	// satisfied by a hardcoded zero.
	return 1.0 + 0.001*float64(i)
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
// answer: nft on PATH says nothing about netlink authority, and nothing
// stronger is wanted either — an EMPTY ruleset is a successful read and an
// authoritative-empty commit, never a probe failure.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes", Reason: "nft answers `nft -j list ruleset`"}
	if _, err := src.nftRuleset(); err != nil {
		// The fallback names no cause it has not established — the acquisition
		// can also fail before nft is reached — and the error itself goes to
		// stderr, where a person debugging can read it.
		reason := "the ruleset could not be read"
		switch {
		case errors.Is(err, errNftAbsent):
			reason = "nft is not on PATH"
		case errors.Is(err, errNftRefused):
			reason = "nft cannot read the ruleset (CAP_NET_ADMIN not granted?)"
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
