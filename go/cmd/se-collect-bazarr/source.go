package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// source is the acquisition seam (DESIGN 20; harness/se_harness/replay.py):
// with SE_REPLAY_DIR set, both native documents come from that directory
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
	// instance is everything this collector could establish about the one
	// bazarr it fronts, in one reading. The receipts and both documents come
	// back together because they are one row: which of them is present is the
	// whole of what the row says, so splitting them into three calls would let
	// a caller publish half an answer.
	instance() (reading, error)
	// stamp is `at` for the i-th emitted object. The whole row rests on one
	// pair of reads, so the live reading is taken once, before the first of
	// them, and the index is ignored — a stamp taken at completion would
	// report the row fresher than the bytes it describes (DESIGN 19).
	stamp(i int) float64
	// costs are end's advisory self-report (DESIGN 19): bounded by the judge,
	// authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

// reading is what the seam established. Which members are populated IS the
// statement: receipts missing means nothing was fetched, a document read means
// the API answered it, and `unobservable` sits beside whatever was read before
// the failure — because the reference folds the status document onto the row
// before it asks for health, so a dark health endpoint costs the row its issue
// list and nothing else.
type reading struct {
	configMissing []string
	statusRead    bool
	status        jsonValue
	healthRead    bool
	health        jsonValue
	unobservable  string
}

// How the instance is addressed, and how the key travels. Both variables are
// the shipping adapter's own — a collector that invented its own spelling
// would read a different instance from the reference on the same host, and the
// comparator would report a difference nobody's machine has.
//
// The key rides a HEADER and never a query string. That is bazarr's own
// posture and it is the one that keeps a 401 from being a credential channel:
// two of this estate's other upstreams take their key as a query parameter,
// which is why the envelope scrubs query strings out of failure text at all.
const (
	urlVariable = "SE_BAZARR_URL"
	keyVariable = "SE_BAZARR_API_KEY"
	keyHeader   = "X-API-KEY"

	pathStatus = "/api/system/status"
	pathHealth = "/api/system/health"
)

// The reference's own asyncio timeout, applied to the whole exchange.
const requestTimeout = 10 * time.Second

// A bound on one response, because an unbounded read cannot be allowed to
// exhaust the slice (DESIGN 19). A status document is a few hundred bytes and a
// health list with an entry per provider is a few kilobytes; a megabyte is a
// reply this interface does not produce.
const responseBound = 1 << 20

// The receipt problem, spelled exactly as the reference spells it: this string
// is a FACT VALUE that travels the wire, so a port that reworded it would
// disagree with the reference on a shape neither the corpus nor a mutation
// operator stages. It names the variable and never its value — the point of
// the refusal is that the value is unfit to put in a header, and repeating it
// in a fact would put it somewhere far worse.
const keyProblemDetail = "SE_BAZARR_API_KEY contains control or" +
	" non-ASCII characters — refusing to send" +
	" it in a header"

// declined is the seam's statement that the interface itself could not be
// reached, carried as an error so no caller can forget to route it. The detail
// is a constant: decline detail travels to a hub and out over MCP, and an
// interpolated error string is a redaction path nobody reviewed — the instance
// URL in particular is deployment configuration that may carry basic-auth
// userinfo, and it belongs in stderr where a person debugging can read it.
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
// host which lost this interface would not serve its instance row forever. The
// second half of that is answered by staleness rather than by retirement: no
// decline but `absent` commits, so prior state STANDS and the collator marks it
// stale — visible as not-fresh, which is the honest rendering of a reading that
// did not happen.
//
// The first half was simply wrong. An unset SE_BAZARR_URL is not
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
var declineNoInstance = declined{"unavailable", "no bazarr api configured for this process"}

// errUncaptured marks a document the variant did not stage. It must never fall
// back to the live interface of the machine REPLAYING the corpus — that seam
// escape once put a replaying workstation's filesystem into committed facts —
// and it must not become a decline either, which would state something about a
// machine nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

// The three things that can go wrong on one request, said in words that name
// the request and nothing else. They become the StatusUnobservable fact, which
// travels to a hub exactly as a decline detail does — so no URL, no errno and
// no library message reaches them.
func detailNoAnswer(path string) string {
	return "the bazarr API did not answer GET " + path
}

func detailStatusCode(path string, code int) string {
	return "the bazarr API answered GET " + path + " with HTTP " + strconv.Itoa(code)
}

func detailUnreadable(path string) string {
	return "the bazarr API answered GET " + path + " with a document this collector cannot read"
}

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is deliberately not consulted: every fact here is a
		// string the instance stated, and nothing is derived against wall-clock
		// now — not an age, not an elapsed time — so the pin has nothing to
		// freeze and reading it would invent a dependency the declaration does
		// not admit to.
		return replaySource{dir: dir}
	}
	live := &liveSource{
		started: time.Now(),
		// rstrip("/"), the reference's own: an operator who wrote a trailing
		// slash addresses the same instance, and `<url>//api/system/status` is
		// a path bazarr does not serve.
		url: strings.TrimRight(getenv(urlVariable), "/"),
		client: &http.Client{
			Timeout: requestTimeout,
			// httpx does not follow redirects unless told to, and neither does
			// this — for a better reason than parity. The request carries an
			// API key in a header, and Go's default policy would re-send that
			// header to whatever host a 302 named.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	if key := getenv(keyVariable); key != "" {
		if isASCIIPrintable(key) {
			live.key = key
		} else {
			live.keyProblem = keyProblemDetail
		}
	}
	return live
}

// isASCIIPrintable is Python's `key.isascii() and key.isprintable()` over a
// key that has already been found non-empty. Restricted to ASCII, "printable"
// is exactly the 0x20–0x7e band: a DEL or a control character in a header
// value is a request-smuggling shape, and a key carrying one is a deployment
// error to report rather than a header to send.
func isASCIIPrintable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// ── live ────────────────────────────────────────────────────────────────

type liveSource struct {
	started    time.Time
	url        string
	key        string
	keyProblem string
	client     *http.Client
	at         float64
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

func (s *liveSource) instance() (reading, error) {
	if s.url == "" {
		// The configuration IS the statement: a host whose deployment names no
		// bazarr observes none. Checked before the clock is read so the answer
		// is the same on any platform — a machine with no CLOCK_BOOTTIME still
		// gets a truthful absence rather than a failure to run.
		reason := declineNoInstance
		return reading{}, &reason
	}
	// The clock reading before the first byte: `at` must precede the earliest
	// native read that contributes to the row, and the tie breaks toward older
	// (DESIGN 19).
	//
	// Taken BEFORE the receipt checks below, and after the URL check above,
	// because those two paths differ in the one way that matters here: no URL
	// is a DECLINE and emits no object, so it needs no stamp and must stay
	// answerable on a machine with no CLOCK_BOOTTIME; a missing key emits a
	// ROW, and every published object owes a real `at`. Reading the clock
	// after those returns left ConfigMissing rows carrying `at: 0` — a value
	// the contract refuses (0 < at <= 1e9) and which no test could see,
	// because the row is built from the environment and the replay seam pins
	// the receipts so a replaying host cannot reach this branch. The live
	// comparator caught it on the first run with a URL set and a key withheld,
	// which is the venue the bazarr/config-missing residual named.
	at, err := bootClock()
	if err != nil {
		return reading{}, err
	}
	s.at = at

	// The receipts, before anything is fetched. An instance named by URL with
	// no usable key is a row saying so — never a decline, because the estate
	// configured this instance and a missing receipt is a gap in THIS
	// deployment rather than an absence of the thing.
	if s.keyProblem != "" {
		return reading{configMissing: []string{s.keyProblem}}, nil
	}
	if s.key == "" {
		return reading{configMissing: []string{keyVariable}}, nil
	}

	status, detail := s.fetch(pathStatus)
	if detail != "" {
		return reading{unobservable: detail}, nil
	}
	health, detail := s.fetch(pathHealth)
	if detail != "" {
		return reading{statusRead: true, status: status, unobservable: detail}, nil
	}
	return reading{statusRead: true, status: status, healthRead: true, health: health}, nil
}

// fetch is one GET. Its second return is the could-not-read text the row
// carries; the empty string means the document came back.
func (s *liveSource) fetch(path string) (jsonValue, string) {
	request, err := http.NewRequest(http.MethodGet, s.url+path, nil)
	if err != nil {
		// A URL this side cannot even form is a configuration this collector
		// cannot ask with, which reads the same way to whoever must fix it as
		// an instance that did not answer.
		return jsonValue{}, detailNoAnswer(path)
	}
	request.Header.Set(keyHeader, s.key)
	response, err := s.client.Do(request)
	if err != nil {
		return jsonValue{}, detailNoAnswer(path)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return jsonValue{}, detailStatusCode(path, response.StatusCode)
	}
	// One byte past the bound, so a reply AT the bound is told from one that
	// ran over it rather than being silently trimmed to fit — a document cut in
	// half parses into a row of plausible half-facts, which is the one outcome
	// worse than an error.
	raw, err := io.ReadAll(io.LimitReader(response.Body, responseBound+1))
	if err != nil {
		return jsonValue{}, detailNoAnswer(path)
	}
	if len(raw) > responseBound {
		return jsonValue{}, detailUnreadable(path)
	}
	document, err := decodeDocument(bytes.NewReader(raw))
	if err != nil {
		return jsonValue{}, detailUnreadable(path)
	}
	return document, ""
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
	// satisfied by a hardcoded zero. Rounded because the reference rounds.
	return float64(int64((1.0+0.001*float64(i))*1000+0.5)) / 1000
}

func (replaySource) costs() (float64, float64) { return 0.5, 1.0 }

// payloadStem is the replay shim's slug() for an API path: strip the
// surrounding slashes, and map every character that is not alphanumeric, '-',
// '_' or '.' to '-'. "/api/system/status" is committed as
// api-system-status.json, which is what makes this reversible enough to read —
// a reviewer looking at the file can see which request it answers.
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

// The receipts are NOT consulted here, and their absence on the replaying
// machine is not a reading. A capture staged these documents, which is the
// evidence that the API answered on the host it came from with the key that
// host held; re-asking the workstation doing the replay for a key is the seam
// escape this whole mechanism exists to prevent, and it would publish a
// receipts-incomplete row from a variant whose payloads are the API answering.
// The reference's seam pins the same three attributes for the same reason.
func (r replaySource) instance() (reading, error) {
	statusFile := payloadStem(pathStatus) + ".json"
	healthFile := payloadStem(pathHealth) + ".json"
	status, statusErr := os.ReadFile(filepath.Join(r.dir, statusFile))
	health, healthErr := os.ReadFile(filepath.Join(r.dir, healthFile))

	missing := func(err error) bool { return errors.Is(err, fs.ErrNotExist) }
	if missing(statusErr) && missing(healthErr) {
		// NEITHER document staged: the variant records a host fronting no
		// bazarr. The same reading the live path takes, through the same
		// constant, so the two cannot spell one condition two ways.
		reason := declineNoInstance
		return reading{}, &reason
	}
	// One document staged and not the other is a broken capture rather than a
	// statement about a machine — the API that answered `status` was there to
	// answer `health` too — so it fails the batch instead of declining, and it
	// never falls back to the live instance of whichever machine is replaying.
	if statusErr != nil {
		return reading{}, fmt.Errorf("%s %w: %v", statusFile, errUncaptured, statusErr)
	}
	if healthErr != nil {
		return reading{}, fmt.Errorf("%s %w: %v", healthFile, errUncaptured, healthErr)
	}

	statusDoc, err := decodeDocument(bytes.NewReader(status))
	if err != nil {
		return reading{}, fmt.Errorf("the staged %s is not a document: %v", statusFile, err)
	}
	healthDoc, err := decodeDocument(bytes.NewReader(health))
	if err != nil {
		return reading{}, fmt.Errorf("the staged %s is not a document: %v", healthFile, err)
	}
	return reading{
		statusRead: true, status: statusDoc,
		healthRead: true, health: healthDoc,
	}, nil
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
// answer: a URL in the environment says nothing about whether anything answers
// it. An instance whose receipts are incomplete is still a YES — the collection
// is served and the row it publishes says which receipt is missing, which is a
// reading rather than an inability — and only an absence is a no.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes", Reason: "the bazarr API answers"}
	got, err := src.instance()
	switch {
	case err != nil:
		// The reason names the decline this side reached and nothing it has
		// not established; the error itself goes to stderr, where a person
		// debugging can read the URL and the errno.
		reason := "the bazarr API could not be read"
		var refused *declined
		if errors.As(err, &refused) {
			reason = refused.detail
		}
		verdict = probeVerdict{Verdict: "no", Reason: reason}
		fmt.Fprintln(stderr, "probe:", err)
	case len(got.configMissing) > 0:
		verdict.Reason = "a bazarr instance is configured and its receipts are incomplete: " +
			strings.Join(got.configMissing, ", ")
	case got.unobservable != "":
		verdict.Reason = got.unobservable
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(verdict); err != nil {
		fmt.Fprintln(stderr, "writing the probe verdict:", err)
		return exitRuntime
	}
	return exitOK
}
