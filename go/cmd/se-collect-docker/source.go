package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// source is the acquisition seam (DESIGN 20; harness/se_harness/replay.py):
// with SE_REPLAY_DIR set, every native document comes from that directory
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
	// document is one Engine API response, addressed by the path that answers
	// it. Dispatching on the path rather than naming three methods is what
	// keeps this seam the same shape as the reference's: adapters/docker.py
	// acquires through one `_get(path)`, and the replay shim keys the captured
	// documents on that argument (harness/bin/se-reference-collector, slug()).
	// Its errors carry the decline shape.
	document(path string) (*value, error)
	// reachable is the capability question, asked of the interface rather than
	// of a collection: is there a docker here this collector may read. It is
	// its own method because /_ping answers in plain text, not JSON, so it can
	// never travel `document` — and because under replay the answer is the
	// corpus's, not the replaying machine's.
	reachable() error
	// stamp is `at` for the i-th emitted object. Taken BEFORE the earliest
	// native read that contributes to it so the tie breaks toward older
	// (DESIGN 19) — see the live implementation, where the reading is taken
	// per COLLECTION because each collection is one Engine API response and
	// every row in it rests on the same bytes.
	stamp(i int) float64
	// costs are end's advisory self-report (DESIGN 19): bounded by the judge,
	// authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

// The socket, and the three paths. adapters/docker.py SOCKET, and the three
// arguments its acquire() hands to _get.
const (
	socketPath     = "/var/run/docker.sock"
	pathPing       = "/_ping"
	pathContainers = "/containers/json?all=1"
	pathVolumes    = "/volumes"
	pathNetworks   = "/networks"
)

// declined is the seam's statement that the interface itself could not be
// reached, carried as an error so no caller can forget to route it. The detail
// is a constant: decline detail travels to a hub and out over MCP, and an
// interpolated error string is a redaction path nobody reviewed.
type declined struct{ reason, detail string }

func (d *declined) Error() string { return d.reason + ": " + d.detail }

// The interface-is-not-here reading, named ONCE and used by both the live
// source and the replay source. It is a constant because the storage collector
// answered exactly this question two opposite ways for as long as it existed —
// live said `unsupported`, replay said `absent`, each under a confident comment
// arguing against the other — and nothing caught it, because replay exercises
// only the replay half. A shared constant is what makes the disagreement
// unspellable rather than merely currently-absent.
//
// `absent` is the reading. A host with no docker socket runs no dockerd, and a
// host that runs no dockerd holds no containers, no volumes and no networks —
// a successful reading of the interface that establishes something, which is
// DESIGN 19's own worked example. It must commit zero, because a host that HAD
// docker and then lost it would otherwise serve its old containers forever,
// stale and never retired.
//
// The wording is the reference's, to the byte: the replay shim and
// se-live-reference both spell it "no <interface> on this host" with the
// interface named "docker socket", and a decline detail that reached an
// operator in three spellings would read as three conditions.
var declineNoSocket = declined{"absent", "no docker socket on this host"}

// The socket is there and this collector may not use it. `unauthorised` is a
// deployment error and never commits: the containers are running right now, so
// retiring them because the agent is not in the docker group would delete a
// whole subsystem over a group membership. The reference's capability probe
// makes the same three-way split, which is why it asks /_ping rather than
// stopping at os.path.exists.
var declineSocketRefused = declined{
	"unauthorised",
	socketPath + " exists and this collector may not read it; the collector's " +
		"user needs the group that owns the socket",
}

// The socket is there and the daemon did not answer. `unavailable` is an
// incident and never commits either: dockerd restarting, a stale socket left
// by a crash, a request that timed out. It is the reason that says "try again",
// which is the honest thing to say about all three.
var declineDaemonSilent = declined{
	"unavailable",
	socketPath + " exists and the daemon did not answer; dockerd may be " +
		"restarting, or the socket may be stale",
}

// errUncaptured marks a document the variant did not stage. It must never fall
// back to the live interface of the machine REPLAYING the corpus — that seam
// escape once put a replaying workstation's filesystem into committed facts —
// and it must not become a decline either, which would state something about a
// machine nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is deliberately not consulted: the one derived fact
		// here, Created, is computed from the document's own epoch and not
		// against wall-clock now, so the pin has nothing to freeze and reading
		// it would invent a dependency the declaration does not admit to.
		return replaySource{dir: dir}
	}
	return &liveSource{started: time.Now(), client: unixClient()}
}

// ── live ────────────────────────────────────────────────────────────────

type liveSource struct {
	started time.Time
	client  *http.Client
	at      float64
}

// unixClient is the whole of what talking to the Engine API takes: HTTP/1.1
// over a unix socket, which is stdlib, so this binary stays dependency-free
// and static. The host in the URL is a placeholder the daemon ignores — the
// socket decides who answers — and the timeout is the reference's own 10s.
func unixClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
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

// stamp is the reading taken in document(), shared by every row that response
// produced. One Engine API response is one acquisition, so a per-row clock
// reading would report the last container fresher than the first off bytes
// that arrived together (DESIGN 19).
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

// reachable is adapters/docker.py's capability(): existence, reachability and
// permission are three different failures, so the socket is stat'ed and then
// /_ping is asked, and the reason names the real one. The split decides more
// than wording — absence retires this host's containers, and the other two
// leave them standing.
func (s *liveSource) reachable() error {
	if _, err := os.Stat(socketPath); err != nil {
		reason := declineNoSocket
		return &reason
	}
	// /_ping answers "OK" in plain text, so it is fetched and its status read
	// rather than decoded. That is the whole of what it is for.
	_, err := s.fetch(pathPing)
	return err
}

func (s *liveSource) document(path string) (*value, error) {
	// The socket's existence is the one thing this path must ask separately,
	// because it is the discriminator between the decline that RETIRES and the
	// two that do not, and a failed GET cannot tell them apart. /_ping is not
	// re-asked here: it is the probe's question, and paying three extra round
	// trips per batch to re-establish what the next request is about to
	// establish anyway would buy nothing.
	if _, err := os.Stat(socketPath); err != nil {
		reason := declineNoSocket
		return nil, &reason
	}
	// The clock BEFORE the read that the rows will rest on, not after it.
	at, err := bootClock()
	if err != nil {
		return nil, err
	}
	s.at = at

	raw, err := s.fetch(path)
	if err != nil {
		return nil, err
	}
	document, decodeErr := decodeDocument(raw)
	if decodeErr != nil {
		// The daemon answered with something that is not a document. That is
		// the interface behaving unexpectedly rather than a machine to make a
		// statement about, so it is "I could not run".
		return nil, fmt.Errorf("the daemon's answer to %s is not a document: %v", path, decodeErr)
	}
	return document, nil
}

// fetch is one GET, with the two non-absent declines mapped where they are
// distinguishable. Permission is decided by the dial's own errno rather than by
// stat'ing the socket's mode: the mode says what the bits are and the errno
// says what happened to this process, and the second is the question.
func (s *liveSource) fetch(path string) ([]byte, error) {
	response, err := s.client.Get("http://docker" + path)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.EACCES) {
			reason := declineSocketRefused
			return nil, &reason
		}
		reason := declineDaemonSilent
		return nil, &reason
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		reason := declineSocketRefused
		return nil, &reason
	}
	if response.StatusCode != http.StatusOK {
		reason := declineDaemonSilent
		return nil, &reason
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		reason := declineDaemonSilent
		return nil, &reason
	}
	return body, nil
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

// No time namespace was observed at capture, so the offset is the pinned zero —
// a live reading here would smuggle the replaying machine into a deterministic
// stream.
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
	// past a few hundred rows the float noise is the difference between 1.126
	// and 1.1260000000000001 in a file people read.
	return float64(int64((1.0+0.001*float64(i))*1000+0.5)) / 1000
}

func (replaySource) costs() (float64, float64) { return 0.5, 1.0 }

// payloadStem is the replay shim's slug() for an Engine API path: strip the
// leading slash, and map every character that is not alphanumeric, '-', '_' or
// '.' to '-'. "/containers/json?all=1" is the stem the committed capture
// carries, which is what makes this reversible enough to read — a reviewer
// looking at containers-json-all-1.json can see which request it answers.
func payloadStem(path string) string {
	trimmed := strings.Trim(path, "/")
	kept := make([]byte, 0, len(trimmed))
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z',
			c == '-', c == '_', c == '.':
			kept = append(kept, c)
		default:
			kept = append(kept, '-')
		}
	}
	name := strings.ReplaceAll(strings.Trim(string(kept), "-"), "--", "-")
	if name == "" {
		return "root"
	}
	return name
}

// Every path this collector's acquisition asks for, so absence can be decided
// over the whole interface rather than over the one document a request happens
// to want. A variant staging none of them staged no docker at all; a variant
// staging some of them staged a docker whose other documents this collector
// cannot see, which is a broken capture and not a statement about a machine.
var acquiredPaths = [...]string{pathContainers, pathVolumes, pathNetworks}

func (r replaySource) document(path string) (*value, error) {
	stem := payloadStem(path)
	raw, err := os.ReadFile(filepath.Join(r.dir, stem+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		if r.staged() {
			// Some of the interface is here and this document is not. Never a
			// decline — a decline states something about a machine, and this
			// variant observed a machine that HAD docker — and never a fall
			// back to the live daemon of whatever workstation is replaying.
			return nil, fmt.Errorf("%s %w, and other engine-API documents are: a capture that stages docker stages every path this collector acquires", stem, errUncaptured)
		}
		// Nothing at all: the variant records a host with no docker socket.
		// The same reading the live path takes, through the same constant, so
		// the two cannot spell one condition two ways.
		reason := declineNoSocket
		return nil, &reason
	}
	if err != nil {
		return nil, fmt.Errorf("%s %w: %v", stem, errUncaptured, err)
	}
	document, err := decodeDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("the staged %s.json is not a document: %v", stem, err)
	}
	return document, nil
}

// reachable under replay is the corpus's answer, not the replaying machine's:
// what the capture establishes is that docker WAS readable on the host it came
// from, and re-asking the workstation doing the replay is the seam escape this
// whole mechanism exists to prevent.
func (r replaySource) reachable() error {
	if r.staged() {
		return nil
	}
	reason := declineNoSocket
	return &reason
}

// staged is whether this variant captured ANY of the engine-API documents. It
// is the replay half of the absence question, and it is asked over the whole
// acquisition rather than per request because absence is a property of the
// interface: the replay shim decides the same way, declining only when the
// variant staged nothing at all.
func (r replaySource) staged() bool {
	for _, path := range acquiredPaths {
		if _, err := os.Stat(filepath.Join(r.dir, payloadStem(path)+".json")); err == nil {
			return true
		}
	}
	return false
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
// 18). It asks /_ping, which is the question the reference's capability check
// asks and the only one that separates the three failures: a socket on disk
// says nothing about whether the daemon behind it answers, and a daemon that
// answers says nothing about whether this process may talk to it. A host with
// docker and no containers still answers, and that is a reading of zero
// containers rather than an inability.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes", Reason: "the docker daemon answers /_ping on " + socketPath}
	if err := src.reachable(); err != nil {
		// The reason names the decline this side reached and nothing it has
		// not established; the error itself goes to stderr, where a person
		// debugging can read it.
		reason := "the docker engine API could not be read"
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
