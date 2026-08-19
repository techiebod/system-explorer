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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// source is the acquisition seam (DESIGN 20; harness/se_harness/replay.py):
// with SE_REPLAY_DIR set, every native document comes from that directory
// instead of the live interfaces, while the parse, the declared semantics and
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
	// clients is the CONFIGURATION gate, and it decides which rows exist at
	// all rather than what they say. adapters/downloaders.py reads three
	// environment variables in __init__ and every row it builds is gated on
	// them — the direct analogue of storage's `self._zfs`, and the reason the
	// replay seam pins all three rather than leaving them to the ambient
	// environment of whichever machine is replaying.
	clients() clientGates
	// openBatch takes the batch's clock reading, before the first native read
	// of the first collection.
	//
	// Explicit rather than lazy inside the acquisition, and the reason is a bug
	// this collector shipped for one afternoon: a batch can legitimately emit a
	// row WITHOUT reading anything. A sabnzbd configured by URL and missing its
	// key is a stated-fault row built from the environment alone, and a port
	// that stamped inside document() published `at` 0 for it — not a clock
	// reading, refused by the judge's own rule (0 < at <= 1e9), and invisible
	// to replay because the seam pins the receipts. The live comparator found
	// it in one run, which is the division of labour DESIGN 19 describes.
	openBatch() error
	// document is one native answer, addressed by the CALL that produces it:
	// three transmission RPC methods and one sabnzbd mode. Dispatching on the
	// call rather than naming four methods keeps this seam the same shape as
	// the reference's, where _rpc and _sab are stubbed by their first argument
	// and the payloads are keyed on it.
	document(call string) (*value, error)
	// stamp is `at` for the i-th emitted object. Taken BEFORE the earliest
	// native read that contributes to it so the tie breaks toward older
	// (DESIGN 19).
	stamp(i int) float64
	// costs are end's advisory self-report (DESIGN 19): bounded by the judge,
	// authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

// clientGates is which clients this process has the receipts to observe. Three
// booleans and not three URLs, because nothing outside the live source may see
// the URLs: a download-client URL is deployment configuration and can carry
// basic-auth userinfo, and a value that reaches a fact or a decline detail
// leaves the host.
type clientGates struct{ transmission, sab, sabKey bool }

func (g clientGates) any() bool { return g.transmission || g.sab }

// The four calls on the acquisition path, and the environment that addresses
// them. The names are the reference's arguments to _rpc and _sab, which is also
// how the corpus keys its payloads.
const (
	callSessionGet   = "session-get"
	callSessionStats = "session-stats"
	callTorrentGet   = "torrent-get"
	callQueue        = "queue"

	transmissionVariable = "SE_TRANSMISSION_URL"
	sabURLVariable       = "SE_SABNZBD_URL"
	sabKeyVariable       = "SE_SABNZBD_API_KEY"
)

// The two client handles, which are the rows' native names and the targets of
// the managers' dispatches-to edges. Spelled once: a second spelling would be a
// second object for one client.
const (
	clientTransmission = "transmission"
	clientSabnzbd      = "sabnzbd"
)

// The RPC and API paths, from adapters/downloaders.py's own constants.
const (
	transmissionRPC = "/transmission/rpc"
	sabAPI          = "/api"
)

// declined is the seam's statement that the interface itself could not be
// reached, carried as an error so no caller can forget to route it. The detail
// is a constant: decline detail travels to a hub and out over MCP, and an
// interpolated error string is a redaction path nobody reviewed — a client URL
// in particular is deployment configuration that can carry userinfo, and it
// belongs in stderr where a person debugging can read it.
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
// host which lost this interface would not serve its client and transfer rows forever. The
// second half of that is answered by staleness rather than by retirement: no
// decline but `absent` commits, so prior state STANDS and the collator marks it
// stale — visible as not-fresh, which is the honest rendering of a reading that
// did not happen.
//
// The first half was simply wrong. An unset SE_TRANSMISSION_URL is not
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
var declineNoClient = declined{"unavailable", "no download client configured for this process"}

// errUncaptured marks a document the variant did not stage. It must never fall
// back to the live interface of the machine REPLAYING the corpus — that seam
// escape once put a replaying workstation's filesystem into committed facts —
// and it must not become a dark-client fact either, which would state something
// about a machine nobody observed and would put this harness's own error text
// into a committed row.
var errUncaptured = errors.New("not captured in this replay directory")

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is deliberately not consulted: nothing here is derived
		// against wall-clock now — not an age, not an elapsed time; every
		// figure is one the client stated — so the pin has nothing to freeze
		// and reading it would invent a dependency the declaration does not
		// admit to.
		return replaySource{dir: dir}
	}
	return &liveSource{
		started:      time.Now(),
		transmission: strings.TrimRight(getenv(transmissionVariable), "/"),
		sab:          strings.TrimRight(getenv(sabURLVariable), "/"),
		sabKey:       getenv(sabKeyVariable),
		client:       &http.Client{Timeout: clientTimeout},
	}
}

// ── live ────────────────────────────────────────────────────────────────

// The reference's own httpx.AsyncClient(timeout=10.0).
const clientTimeout = 10 * time.Second

// A bound on one reply, because an unbounded read cannot be allowed to exhaust
// the slice (DESIGN 19). A torrent list on a busy seedbox is a few megabytes;
// thirty-two is a reply neither interface produces. Exceeding it is "I could
// not run" rather than a truncated parse — a document cut in half parses into
// rows of plausible half-facts, which is the one outcome worse than an error.
const replyBound = 32 << 20

type liveSource struct {
	started      time.Time
	transmission string
	sab          string
	sabKey       string
	client       *http.Client
	sessionID    string
	at           float64
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

// stamp is the reading taken in document(), shared by every row the batch
// emits. Taken once, before the first native read: a per-row clock reading
// would report the last transfer fresher than the first off bytes that arrived
// together (DESIGN 19).
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

func (s *liveSource) clients() clientGates {
	return clientGates{
		transmission: s.transmission != "",
		sab:          s.sab != "",
		sabKey:       s.sabKey != "",
	}
}

// openBatch reads the clock the whole batch is stamped from. One reading, not
// one per document: every row this collector publishes rests on documents
// fetched inside one sweep, and a per-row reading would report the last
// transfer fresher than the first off bytes that arrived together (DESIGN 19).
func (s *liveSource) openBatch() error {
	at, err := bootClock()
	if err != nil {
		return err
	}
	s.at = at
	return nil
}

func (s *liveSource) document(call string) (*value, error) {
	if !s.clients().any() {
		reason := declineNoClient
		return nil, &reason
	}
	switch call {
	case callSessionGet, callSessionStats:
		return s.rpc(call, "")
	case callTorrentGet:
		return s.rpc(call, torrentFieldsArgument)
	case callQueue:
		return s.sabMode(call)
	}
	return nil, fmt.Errorf("no acquisition named %q", call)
}

// The fields torrent-get is asked for, as one pre-rendered argument object.
// Written out rather than assembled from the fact table, because the ORDER is
// the request the reference sends and a reader comparing a capture with
// `curl` should meet the same bytes.
const torrentFieldsArgument = `{"fields":["hashString","name","status","percentDone",` +
	`"rateDownload","rateUpload","error","errorString","isStalled",` +
	`"sizeWhenDone","leftUntilDone"]}`

// rpc is one transmission RPC call, with the 409 session handshake: the refused
// first POST hands over X-Transmission-Session-Id, echoed on exactly ONE retry.
// Never a loop — a second 409 is a real error, and a collector that retried
// forever would hold a sweep open against a daemon that is refusing it.
func (s *liveSource) rpc(method, arguments string) (*value, error) {
	body := `{"method":` + string(quoteJSON(method)) + `,"arguments":`
	if arguments == "" {
		body += "{}}"
	} else {
		body += arguments + "}"
	}
	for attempt := 1; attempt <= 2; attempt++ {
		request, err := http.NewRequest(http.MethodPost, s.transmission+transmissionRPC,
			bytes.NewReader([]byte(body)))
		if err != nil {
			return nil, fmt.Errorf("transmission %s: %v", method, err)
		}
		request.Header.Set("Content-Type", "application/json")
		if s.sessionID != "" {
			request.Header.Set("X-Transmission-Session-Id", s.sessionID)
		}
		response, err := s.client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("transmission %s: %v", method, err)
		}
		if response.StatusCode == http.StatusConflict && attempt == 1 {
			s.sessionID = response.Header.Get("X-Transmission-Session-Id")
			response.Body.Close()
			continue
		}
		raw, err := readBounded(response)
		response.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("transmission %s: %v", method, err)
		}
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("transmission %s answered HTTP %d", method, response.StatusCode)
		}
		document, err := decodeDocument(raw)
		if err != nil {
			return nil, fmt.Errorf("transmission %s: the answer is not a document: %v", method, err)
		}
		// The RPC frame, checked exactly where the reference checks it: `result`
		// is transmission's status line and `arguments` is the body, which is
		// what the corpus commits and what every `from` path addresses.
		if result := document.get("result"); !result.isString() || result.text != "success" {
			return nil, fmt.Errorf("transmission RPC %s answered a result other than success", method)
		}
		answer := document.get("arguments")
		if answer == nil || answer.kind != jsonObject {
			return newObject(), nil // `payload.get("arguments") or {}`
		}
		return answer, nil
	}
	return nil, errors.New("transmission RPC handshake did not converge")
}

// sabMode is one sabnzbd API call. The key travels as a QUERY PARAMETER
// because that is the only place the API accepts it, which is exactly why every
// failure line this collector produces has its query string stripped and why no
// error here interpolates the URL.
func (s *liveSource) sabMode(mode string) (*value, error) {
	query := url.Values{"mode": {mode}, "output": {"json"}, "apikey": {s.sabKey}}
	response, err := s.client.Get(s.sab + sabAPI + "?" + query.Encode())
	if err != nil {
		// Go's http client puts the request URL in its error, key and all —
		// httpx does the same thing and text.scrub() exists because of it. The
		// query string goes before the error travels anywhere, including to
		// stderr.
		return nil, fmt.Errorf("sabnzbd %s: %v", mode, scrubReason(err.Error()))
	}
	defer response.Body.Close()
	raw, err := readBounded(response)
	if err != nil {
		return nil, fmt.Errorf("sabnzbd %s: %v", mode, err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sabnzbd %s answered HTTP %d", mode, response.StatusCode)
	}
	document, err := decodeDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("sabnzbd %s: the answer is not a document: %v", mode, err)
	}
	// sabnzbd answers a refusal with HTTP 200 and `"status": false`, so the
	// status code alone would read a rejected key as a successful empty queue.
	if status := document.get("status"); status != nil && status.kind == jsonBool && !status.boolean {
		return nil, fmt.Errorf("sabnzbd refused mode=%s", mode)
	}
	return document, nil
}

func readBounded(response *http.Response) ([]byte, error) {
	// One byte past the bound, so a reply AT the bound is told from one that
	// ran over it rather than being silently trimmed to fit.
	raw, err := io.ReadAll(io.LimitReader(response.Body, replyBound+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > replyBound {
		return nil, fmt.Errorf("the answer exceeded the %d-byte bound", replyBound)
	}
	return raw, nil
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

func (replaySource) stamp(i int) float64 {
	// The reference constant, 1.0 + 0.001*i in emission order and one counter
	// across the whole batch: finite, positive, boot-scale and advancing, so
	// the structural rule that governs `at` is exercised by replay instead of
	// satisfied by a hardcoded zero. Rounded because the reference rounds.
	return float64(int64((1.0+0.001*float64(i))*1000+0.5)) / 1000
}

func (replaySource) costs() (float64, float64) { return 0.5, 1.0 }

// A replay has no clock to open: every stamp is the reference constant, so
// there is nothing to read and nothing that can fail.
func (replaySource) openBatch() error { return nil }

// Every call this collector's acquisition makes, so absence is decided over the
// whole interface rather than over the one document a request happens to want.
var acquiredCalls = [...]string{callSessionGet, callSessionStats, callTorrentGet, callQueue}

// clients under replay is the CORPUS's answer, not the replaying machine's, and
// it is all-or-nothing on purpose. The replay seam pins the reference's three
// configuration gates to constants, so a downloaders variant records a host
// running BOTH clients — a variant staging one client's documents and not the
// other's would replay through the reference as a client that could not be
// asked, with the harness's own error text landing in a committed fact. Making
// that shape a broken capture here rather than a second reading is what keeps
// the two implementations answering one question one way.
func (r replaySource) clients() clientGates {
	if !r.staged() {
		return clientGates{}
	}
	return clientGates{transmission: true, sab: true, sabKey: true}
}

func (r replaySource) staged() bool {
	for _, call := range acquiredCalls {
		if _, err := os.Stat(r.path(call)); err == nil {
			return true
		}
	}
	return false
}

func (r replaySource) path(call string) string {
	return filepath.Join(r.dir, call+".json")
}

func (r replaySource) document(call string) (*value, error) {
	raw, err := os.ReadFile(r.path(call))
	if errors.Is(err, fs.ErrNotExist) {
		if r.staged() {
			// Some of the interface is here and this document is not. Never a
			// decline — a decline states something about a machine, and this
			// variant observed a machine that HAD clients — and never a fall
			// back to whatever download client the replaying workstation runs.
			return nil, fmt.Errorf("%s.json %w, and other documents are: a capture that stages a downloaders variant stages every call this collector acquires", call, errUncaptured)
		}
		reason := declineNoClient
		return nil, &reason
	}
	if err != nil {
		return nil, fmt.Errorf("%s.json %w: %v", call, errUncaptured, err)
	}
	document, err := decodeDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("the staged %s.json is not a document: %v", call, err)
	}
	return document, nil
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

func quoteJSON(s string) []byte { return appendJSONString(nil, s) }

type probeVerdict struct {
	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
}

// probe answers "can it run here" as a verdict, never an exit code (DESIGN 18).
// It asks the configured clients for the documents the acquisition would ask
// for, because nothing weaker establishes the answer: a URL in the environment
// says nothing about whether anything answers it, which is the two-stage
// question the reference's capability check asks. A client holding no transfers
// still answers, and that is a reading of zero rather than an inability.
func probe(stdout, stderr io.Writer, src source) int {
	gates := src.clients()
	if !gates.any() {
		return writeVerdict(stdout, stderr,
			probeVerdict{Verdict: "no", Reason: declineNoClient.detail})
	}
	var unreachable []string
	if gates.transmission {
		if _, err := src.document(callSessionGet); err != nil {
			fmt.Fprintln(stderr, "probe:", err)
			unreachable = append(unreachable, clientTransmission)
		}
	}
	if gates.sab {
		switch {
		case !gates.sabKey:
			unreachable = append(unreachable, clientSabnzbd+" (no "+sabKeyVariable+")")
		default:
			if _, err := src.document(callQueue); err != nil {
				fmt.Fprintln(stderr, "probe:", err)
				unreachable = append(unreachable, clientSabnzbd)
			}
		}
	}
	if len(unreachable) > 0 {
		// A named list rather than a count: which client is dark is the whole
		// of what an operator does next with this answer.
		return writeVerdict(stdout, stderr, probeVerdict{
			Verdict: "no",
			Reason:  "configured and not answering: " + strings.Join(unreachable, ", "),
		})
	}
	return writeVerdict(stdout, stderr, probeVerdict{
		Verdict: "yes",
		Reason:  "every configured download client answered its API",
	})
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
