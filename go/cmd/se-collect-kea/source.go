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
	// openCollection is where `at` is taken. Every collection here rests on
	// TWO control-socket answers — the daemon row on version-get and
	// status-get, the subnet rows on statistic-get-all and config-get — so a
	// reading taken per DOCUMENT would stamp the row at the second one and
	// report it fresher than its oldest contributing byte (DESIGN 19). Taken
	// per collection rather than per batch because a collector reading two
	// interfaces legitimately has two ages, and these are two conversations.
	openCollection()
	// document is one control-socket answer, addressed by the COMMAND that
	// decides which document comes back. Dispatching on the command rather
	// than naming six methods is what keeps this seam the same shape as the
	// reference's: adapters/kea.py acquires through one `_command(command)`,
	// and the replay shim keys the captured documents on that argument
	// (harness/bin/se-reference-collector, slug()). Its errors carry the
	// decline shape.
	document(command string) (*value, error)
	// stamp is `at` for the i-th emitted object.
	stamp(i int) float64
	// costs are end's advisory self-report (DESIGN 19): bounded by the judge,
	// authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

// The commands, spelled once. Five sit on the acquisition path and one on the
// capability path — adapters/kea.py's REFERENCE list, and the arguments its
// acquire() and capability() hand to _command.
const (
	commandVersion    = "version-get"
	commandStatus     = "status-get"
	commandStatistics = "statistic-get-all"
	commandConfig     = "config-get"
	commandLeases     = "lease4-get-all"
	commandList       = "list-commands"
)

// Kea's own control result codes, in Kea's own numbering (its control-channel
// documentation): 0 success, 2 the command is not implemented here, 3 the
// command ran and matched nothing. Read as Kea spells them rather than
// translated, because the whole point of the result member is that the daemon
// said which of these happened.
const (
	keaSuccess            = 0
	keaCommandUnsupported = 2
	keaEmpty              = 3
)

// The results each command may answer with. lease4-get-all is the one that may
// answer 3: an empty lease table is an ANSWER, not a failure, and the reference
// spells that ok=(0, 3) at exactly this call.
func acceptedResults(command string) []int64 {
	if command == commandLeases {
		return []int64{keaSuccess, keaEmpty}
	}
	return []int64{keaSuccess}
}

// Every command on the ACQUISITION path, so absence can be decided over the
// whole interface rather than over the one document a request happens to want.
// list-commands is not among them: it is the capability probe's question, and a
// variant that staged only a command list staged no reading of this host.
var acquiredCommands = [...]string{
	commandVersion, commandStatus, commandStatistics, commandConfig, commandLeases,
}

// declined is the seam's statement that the interface itself could not be
// read, carried as an error so no caller can forget to route it. The detail is
// a constant: decline detail travels to a hub and out over MCP, and an
// interpolated error string is a redaction path nobody reviewed — the socket
// path in particular is deployment configuration and belongs on stderr, where a
// person debugging can read it, not in a record that leaves the host.
type declined struct{ reason, detail string }

func (d *declined) Error() string { return d.reason + ": " + d.detail }

// The interface-is-not-here reading, named ONCE and used by the live source and
// the replay source alike. It is a constant because the storage collector
// answered exactly this question two opposite ways for as long as it existed —
// live said `unsupported`, replay said `absent`, each under a confident comment
// arguing against the other — and nothing caught it, because replay exercises
// only the replay half. A shared constant makes the disagreement unspellable
// rather than merely currently-absent.
//
// `unavailable` is the reading, and it does NOT commit — RULED 2026-08-19,
// reversing what stood here. The old text argued `absent` on the grounds that
// the configuration IS the statement, and that committing zero was needed so a
// host which lost this interface would not serve its subnets, reservations and leases forever. The
// second half of that is answered by staleness rather than by retirement: no
// decline but `absent` commits, so prior state STANDS and the collator marks it
// stale — visible as not-fresh, which is the honest rendering of a reading that
// did not happen.
//
// The first half was simply wrong. An unset SE_KEA_SOCKET is not
// evidence that the interface is gone — measured on the sibling case, where
// unbound was installed, running and answering on a lab guest whose
// SE_UNBOUND_SOCKET had never been set and its port declined `absent` over it.
//
// "Nobody told this process where to look" and "the thing is not here" are
// different statements, and only the second may retire a row: retirement is not
// recoverable, and a key rotation must not perform one.
//
// What still retires is a genuine absence, and a missing receipt cannot
// establish one from here.
var declineNoSocket = declined{"unavailable", "no kea control socket configured for this process"}

// The socket is there and this collector may not open it. Distinct from absence
// in the one respect that matters: unauthorised commits nothing, so a
// permissions gap leaves the subnets and reservations standing and marked stale
// instead of retiring a DHCP server that is handing out addresses perfectly
// well. Kea's runtime directory is 0750 and the socket 0770, so this is the
// FIRST failure mode on the deployment target — the reference's own capability
// check says so in the same words.
var declineSocketRefused = declined{
	"unauthorised",
	"the kea control socket exists and this collector may not open it; the " +
		"deployment grants the socket's group (the NixOS module's " +
		"grantKeaAccess supplies that membership)",
}

// The socket is there and the reading did not come back: nothing listening, the
// daemon not answering inside the timeout, a reply that is not a document, or an
// answer whose result member is neither success nor a result this command
// accepts.
//
// `unavailable` rather than `unsupported`, and the choice is deliberate. Kea
// restarting mid-reload accepts a connection and then closes it, which is a
// transient this reason invites a retry for; reading permanence out of anything
// else the daemon said would be guessing. Neither commits, so prior state stands
// either way.
var declineSocketSilent = declined{
	"unavailable",
	"the kea control socket exists and did not answer the command cleanly",
}

// Kea answered, and answered that it does not implement the command. That is
// result 2 in its own numbering, and it is permanent until somebody changes the
// configuration — `unsupported` rather than `unavailable`, on exactly the
// reading the queue's OpenZFS-2.2.2 entry already ruled: `unavailable` would
// send an operator hunting a transient failure that does not exist.
var declineCommandUnsupported = declined{
	"unsupported",
	"the kea control socket answered and does not implement a command this " +
		"collection reads",
}

// The same reading, for the one command whose absence has a NAME and a fix.
// lease4-get-all ships in libdhcp_lease_cmds, so a Kea with no hooks loaded
// offers no lease table at all — a configuration gap, which must not read as an
// outage. The wording is the reference's gated_collections(), which says the
// same thing over the HTTP contract's capability channel.
var declineLeaseCommands = declined{
	"unsupported",
	"the libdhcp_lease_cmds hook is not loaded — lease4-get-all is not offered, " +
		"so this Kea keeps no lease table this collector can read",
}

// The decline a refused command reaches, by command. Two constants rather than
// one because only lease4-get-all has an actionable fix to name, and a decline
// detail that named the hook for config-get would send somebody to load a
// library that has nothing to do with it.
func unsupportedFor(command string) declined {
	if command == commandLeases {
		return declineLeaseCommands
	}
	return declineCommandUnsupported
}

// errUncaptured marks a document the variant did not stage. It must never fall
// back to the live interface of the machine REPLAYING the corpus — that seam
// escape once put a replaying workstation's filesystem into committed facts —
// and it must not become a decline either, which would state something about a
// machine nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

// Where the socket is, and it is configuration rather than a constant: the
// NixOS module's keaSocket option writes it and the shipping adapter reads the
// same variable. A default path here would make this binary and the reference
// disagree about a host that configured neither — the port would find a socket
// and the reference would not — which is a disagreement invented by the port
// rather than observed on the machine.
const socketVariable = "SE_KEA_SOCKET"

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is deliberately not consulted: every fact here is a
		// figure the daemon stated or a date computed from two figures IN the
		// document (a lease's cltt plus its valid lifetime), and nothing is
		// derived against wall-clock now — not an age, not an elapsed time —
		// so the pin has nothing to freeze and reading it would invent a
		// dependency the declaration does not admit to.
		return replaySource{dir: dir}
	}
	return &liveSource{started: time.Now(), socket: getenv(socketVariable)}
}

// ── live ────────────────────────────────────────────────────────────────

type liveSource struct {
	started time.Time
	socket  string
	at      float64
	marked  bool
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

func (s *liveSource) openCollection() { s.marked = false }

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

// Matching the reference's asyncio.wait_for(…, timeout=10.0), and applied to
// the dial as well as the read: a socket that accepts and then says nothing
// stalls the sweep exactly as one that never accepts does.
const commandTimeout = 10 * time.Second

// A bound on one reply, because an unbounded read cannot be allowed to exhaust
// the slice (DESIGN 19). config-get is the large one — an estate's whole DHCP
// configuration, every subnet and every reservation — and 16 MiB is the leases
// ceiling this collector declares, so the two agree rather than each choosing a
// number. Exceeding it is "I could not run" rather than a decline or a truncated
// parse: a document cut in half decodes into a configuration with subnets
// missing, which is the one outcome worse than an error.
const replyBound = 16 << 20

func (s *liveSource) document(command string) (*value, error) {
	if s.socket == "" {
		// The configuration IS the statement: a host whose deployment names no
		// control socket observes no Kea. Checked before the clock is read so
		// the answer is the same on any platform — a machine with no
		// CLOCK_BOOTTIME still gets a truthful absence rather than a failure
		// to run.
		reason := declineNoSocket
		return nil, &reason
	}
	if !s.marked {
		// The clock reading before the first byte of this collection: `at` must
		// precede the earliest native read that contributes to the row, and the
		// tie breaks toward older (DESIGN 19).
		at, err := bootClock()
		if err != nil {
			return nil, err
		}
		s.at, s.marked = at, true
	}
	raw, err := s.command(command)
	if err != nil {
		return nil, err
	}
	document, decodeErr := decodeDocument(raw)
	if decodeErr != nil {
		// An empty or truncated reply — Kea restarting mid-reload accepts the
		// connection and then closes it — is the interface behaving
		// unexpectedly rather than a machine to make a statement about. The
		// reference's own capability check names this case, so it is a decline
		// there and a decline here.
		reason := declineSocketSilent
		return nil, fmt.Errorf("kea %s answered something that is not a document: %v: %w", command, decodeErr, &reason)
	}
	return checkResult(command, document)
}

// command runs one command on one connection, which is Kea's own conversation
// shape: a JSON object in, the write side closed, the answer until the far end
// closes.
func (s *liveSource) command(name string) ([]byte, error) {
	conn, err := net.DialTimeout("unix", s.socket, commandTimeout)
	if err != nil {
		return nil, classify(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(commandTimeout)); err != nil {
		return nil, classify(err)
	}
	// Marshalled rather than assembled, so a command name could never carry a
	// quote into the document this side writes. The commands are constants
	// above, which makes that belt and braces — and belt and braces is what a
	// collector writing to a privileged socket should wear.
	request, err := json.Marshal(struct {
		Command string `json:"command"`
	}{name})
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(request); err != nil {
		return nil, classify(err)
	}
	// The half-close is the framing: Kea reads until the write side ends, then
	// answers and closes. Without it both ends wait for the other.
	if unix, ok := conn.(*net.UnixConn); ok {
		if err := unix.CloseWrite(); err != nil {
			return nil, classify(err)
		}
	}
	// One byte past the bound, so a reply AT the bound is told from one that
	// ran over it rather than being silently trimmed to fit.
	raw, err := io.ReadAll(io.LimitReader(conn, replyBound+1))
	if err != nil {
		return nil, classify(err)
	}
	if len(raw) > replyBound {
		return nil, fmt.Errorf("the kea control socket answered %s with more than %d bytes", name, replyBound)
	}
	return raw, nil
}

// checkResult reads Kea's own verdict on the command. Every real Kea answer
// carries a result member, so a reply that never said success in Kea's own
// vocabulary must not read as one — and the answer may arrive wrapped in a
// single-element list, which is what a Kea fronted by the control agent
// produces.
func checkResult(command string, document *value) (*value, error) {
	if document != nil && document.kind == jsonArray {
		if len(document.items) == 0 {
			document = newObject()
		} else {
			document = document.items[0]
		}
	}
	result, ok := document.get("result").integer()
	if ok {
		for _, accepted := range acceptedResults(command) {
			if result == accepted {
				return document, nil
			}
		}
	}
	if ok && result == keaCommandUnsupported {
		reason := unsupportedFor(command)
		return nil, fmt.Errorf("kea %s answered %d: %w", command, result, &reason)
	}
	reason := declineSocketSilent
	// The daemon's own `text` stays OUT of the error: it is a string Kea
	// composed and this side has not reviewed, and an error reaches stderr and
	// the journal. The result NUMBER is Kea's closed vocabulary and is safe to
	// name.
	return nil, fmt.Errorf("kea %s answered result %v: %w", command, document.get("result").text, &reason)
}

// classify turns a socket failure into the reading it is. Three conditions,
// three different things to tell an operator, and only the first may retire this
// host's DHCP objects.
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
// the nil UUID; that this constant itself passes is DESIGN 19's named deferral,
// the live comparator's to catch.
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

func (replaySource) openCollection() {}

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

// payloadStem is the replay shim's slug() for a dispatched acquisition's
// argument: strip the surrounding slashes, and map every character that is not
// alphanumeric, '-', '_' or '.' to '-'. For this collector the command already
// satisfies the grammar and comes back unchanged, which is what makes
// `config-get.json` readable as the answer to `config-get` — but the rule is
// implemented rather than assumed, because the seam's addressing is the shim's
// and not this binary's to redefine.
func payloadStem(command string) string {
	trimmed := strings.Trim(command, "/")
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

func (r replaySource) read(command string) ([]byte, error) {
	return os.ReadFile(filepath.Join(r.dir, payloadStem(command)+".json"))
}

// staged is whether this variant captured ANY of the acquisition documents. It
// is the replay half of the absence question, and it is asked over the whole
// acquisition rather than per command because absence is a property of the
// interface: the replay shim decides the same way, declining only when the
// variant staged nothing at all.
func (r replaySource) staged() bool {
	for _, command := range acquiredCommands {
		if _, err := os.Stat(filepath.Join(r.dir, payloadStem(command)+".json")); err == nil {
			return true
		}
	}
	return false
}

// offersLeaseCommands answers the leases gate from the CAPTURE rather than from
// the machine replaying it: list-commands is the document the reference's
// capability() reads, and a variant that committed it committed this host's
// command surface with it. Three answers, not two — the middle one is what
// stops a missing command list being read as a Kea that had no hook.
func (r replaySource) offersLeaseCommands() (offered bool, known bool) {
	raw, err := r.read(commandList)
	if err != nil {
		return false, false
	}
	document, err := decodeDocument(raw)
	if err != nil {
		return false, false
	}
	commands := document.get("arguments")
	if commands == nil || commands.kind != jsonArray {
		return false, false
	}
	for _, item := range commands.items {
		if item.isString() && item.text == commandLeases {
			return true, true
		}
	}
	return false, true
}

func (r replaySource) document(command string) (*value, error) {
	raw, err := r.read(command)
	if errors.Is(err, fs.ErrNotExist) {
		if !r.staged() {
			// Nothing at all: the variant records a host with no control
			// socket. The same reading the live path takes, through the same
			// constant, so the two cannot spell one condition two ways.
			reason := declineNoSocket
			return nil, &reason
		}
		if command == commandLeases {
			if offered, known := r.offersLeaseCommands(); known && !offered {
				// The capture's OWN command list says this Kea does not offer
				// lease4-get-all, so a missing lease document is not a hole in
				// the capture — it is the same statement the live path derives
				// from Kea's result 2, reached through the same constant. This
				// is the declineNoSocket discipline applied to the collector's
				// second reading: two paths, one spelling.
				reason := declineLeaseCommands
				return nil, &reason
			}
		}
		// Some of the interface is here and this document is not. Never a
		// decline — a decline states something about a machine, and this
		// variant observed a machine that HAD a control socket — and never a
		// fall back to the live daemon of whatever workstation is replaying.
		return nil, fmt.Errorf("%s %w, and other control-socket answers are: a capture that stages kea stages every command this collector asks", payloadStem(command), errUncaptured)
	}
	if err != nil {
		return nil, fmt.Errorf("%s %w: %v", payloadStem(command), errUncaptured, err)
	}
	document, err := decodeDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("the staged %s.json is not a document: %v", payloadStem(command), err)
	}
	// The staged answer is held to the same result check the live one is: a
	// capture that committed a refusal is not a reading, and serving it as one
	// would put Kea's own "I do not implement that" into a subnet row.
	return checkResult(command, document)
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

// The two yes verdicts, because "it answers" is not the whole answer here. The
// reference's capability() returns the served collections MINUS the ones its
// command surface cannot serve, and over the collector contract there is no
// channel for that list — so the probe's reason is where it lands, and a host
// whose lease table this collector cannot read says so before anybody asks for
// one and gets a decline.
const (
	probeReasonFull = "the kea control socket answers and offers lease4-get-all, " +
		"so all four collections are readable here"
	probeReasonNoLeases = "the kea control socket answers; it does not offer " +
		"lease4-get-all, so the daemon, subnets and reservations collections " +
		"are readable and the leases collection is not — the libdhcp_lease_cmds " +
		"hook is not loaded"
)

// probe answers "can it run here" as a verdict, never an exit code (DESIGN 18).
// It asks list-commands, which is the question the reference's capability check
// asks and the only one that separates the failures: a socket on disk says
// nothing about whether the daemon behind it speaks, a daemon that speaks says
// nothing about whether this process may talk to it, and a daemon this process
// can talk to says nothing about which commands it implements. One connection
// answers all three, which is why the reference probes with this command rather
// than with a stat.
func probe(stdout, stderr io.Writer, src source) int {
	commands, err := src.document(commandList)
	if err != nil {
		// The reason names the decline this side reached and nothing it has not
		// established; the error itself goes to stderr, where a person debugging
		// can read the path and the errno.
		reason := "the kea control socket could not be read"
		var refused *declined
		if errors.As(err, &refused) {
			reason = refused.detail
		}
		fmt.Fprintln(stderr, "probe:", err)
		return writeVerdict(stdout, stderr, probeVerdict{Verdict: "no", Reason: reason})
	}
	verdict := probeVerdict{Verdict: "yes", Reason: probeReasonNoLeases}
	if list := commands.get("arguments"); list != nil && list.kind == jsonArray {
		for _, item := range list.items {
			if item.isString() && item.text == commandLeases {
				verdict.Reason = probeReasonFull
				break
			}
		}
	}
	return writeVerdict(stdout, stderr, verdict)
}

func writeVerdict(stdout, stderr io.Writer, verdict probeVerdict) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(verdict); err != nil {
		fmt.Fprintln(stderr, "writing the probe verdict:", err)
		return exitRuntime
	}
	return exitOK
}
