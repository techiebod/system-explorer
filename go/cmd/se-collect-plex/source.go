package main

import (
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

// source is the acquisition seam (DESIGN 20; harness/se_harness/replay.py): with
// SE_REPLAY_DIR set, every native document comes from that directory instead of
// the live API, while the parse, the declared semantics and the stream
// generation run unchanged. The seam is a value chosen at startup, not a build
// flag, so the binary the harness judges is the binary that deploys.
type source interface {
	// bootID names the boot whose clock every `at` reading belongs to; without
	// it the readings are meaningless (DESIGN 09).
	bootID() (string, error)
	// timens is the CLOCK_BOOTTIME namespace offset — stated, never corrected,
	// by whoever compares it (DESIGN 09).
	timens() int64
	// batch mints the batch id — collector-minted by ruling (appendix C): the
	// collector authors the batch, and a transport retry re-sending the same
	// bytes under the same id is what makes retry idempotent. request := batch
	// until a consumer needs them distinct.
	batch() (string, error)
	// declaration is the digest begin carries: the hash of the exact bytes
	// `declare` emits, so an unknown hash triggers a refetch rather than a spawn
	// on every collect (DESIGN 19).
	declaration() string
	// deployment is what this process was told before it asked anything —
	// whether a Plex is addressed at all, and whether the receipts to open it
	// are complete. It is read BEFORE any request because the two answers are
	// different verdicts and only one of them is about the server: a host that
	// names no Plex observes none, and a Plex named with no token is a gap in
	// THIS deployment that the row must state rather than the collection
	// declining.
	deployment() deployment
	// document is one API answer, addressed by the request path that answers it
	// — adapters/plex.py `_plex_get`. Dispatching on the path rather than naming
	// a method per document keeps this seam the same shape as the reference's:
	// the replay shim stubs `_plex_get` and keys the captured documents on its
	// first argument (harness/bin/se-reference-collector, slug()).
	document(path string) (fetched, error)
	// window is the per-section count request: the same path family asked with a
	// zero-size container window, so the server counts and no rows travel. It is
	// its own method because the QUERY differs and nothing else does — and
	// because the query is deliberately not part of the payload key, which is
	// what lets one staged file answer the request the reference made with
	// params attached.
	window(path string) (fetched, error)
	// mark opens a collection. `at` is stamped immediately before the EARLIEST
	// native read that contributes to an object (DESIGN 19), and a library row
	// rests on two documents fetched one after the other, so the boundary is
	// stated by the caller: the first read after a mark takes the clock and every
	// row of that collection shares it.
	mark()
	// ready takes this collection's clock reading without reading the API,
	// for the one row that rests on NO native document: the ConfigMissing row
	// is built from the deployment's receipts alone, so the read path that
	// normally takes the stamp never runs and `at` stayed 0 — a value the
	// contract refuses (0 < at <= 1e9). Replay cannot reach that branch,
	// because the seam pins the receipts so a replaying host cannot decide a
	// committed row; the live comparator caught it with a URL set and the
	// token withheld, which is the venue plex's own residual named.
	ready() error
	// stamp is `at` for the i-th emitted object.
	stamp(i int) float64
	// seerr is one GET against the seerr API — the requests collection's
	// whole interface, a different application over a different credential
	// from the Plex the rest of this collector reads. The query rides live
	// requests only; replay keys documents on the path alone, exactly as
	// `document` does, which is what lets one staged page answer the
	// paged walk the live side makes.
	seerr(path, query string) (fetched, error)
	// seerrConfigured is the receipts reading for that second application:
	// (url configured, key configured). Read before any request, because
	// "nobody named a seerr" and "a seerr named with no key" are different
	// statements and only the second is a deployment gap.
	seerrConfigured() (bool, bool)
	// costs are end's advisory self-report (DESIGN 19): bounded by the judge,
	// authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

// deployment is the receipts reading. `absent` means no Plex is addressed by
// this host at all — the collections are genuinely empty here and must retire
// whatever a previous batch published. `missing` names the receipts a Plex that
// IS addressed still needs; it never carries a credential's value, only the
// variable that should have held one.
type deployment struct {
	absent  bool
	missing []string
}

// fetched is one request's outcome. `detail` is the could-not-read text a row
// carries when the API did not answer; empty means the document came back. The
// third outcome — this process cannot continue at all — is the error return
// beside it, never a value here.
type fetched struct {
	doc    *value
	detail string
}

// The four request paths, and they are the reference's own constants —
// adapters/plex.py SESSIONS_PATH, SECTIONS_PATH, the bare root, and the
// per-section listing built from SECTIONS_PATH. The last is a FAMILY rather than
// a constant: how many documents this collector reads is 3 + one per section,
// decided by what /library/sections answers rather than by this file.
const (
	pathRoot     = "/"
	pathSessions = "/status/sessions"
	pathSections = "/library/sections"
)

// The zero-size container window, in the reference's own member order. Asking
// for a window of no rows is how a count is obtained without pulling a library:
// the container answers `size` 0 and `totalSize` with the figure.
const countWindow = "X-Plex-Container-Start=0&X-Plex-Container-Size=0"

// sectionWindowPath is the per-section listing for one section KEY. The key is
// the section's own identifier and not its position: this estate's capture holds
// sections 1 and 3, because a library was created, deleted and recreated, and a
// port that walked the listing by index would ask about a section that does not
// exist.
func sectionWindowPath(key string) string { return pathSections + "/" + key + "/all" }

// How the server is addressed, and how the token travels. Both variables are the
// shipping adapter's own — a collector that invented its own spelling would read
// a different server from the reference on the same host, and the comparator
// would report a difference nobody's machine has.
//
// The token rides a HEADER. That is Plex's own posture and it is the one that
// keeps a 401 from being a credential channel: a token in a query string reaches
// access logs, and the envelope scrubs query strings out of failure text
// precisely because two of this estate's other upstreams take theirs that way.
//
// The Accept header is not decoration either: Plex answers XML by default, and
// every document this collector parses is JSON because it asked for JSON.
const (
	urlVariable   = "SE_PLEX_URL"
	tokenVariable = "SE_PLEX_TOKEN"
	tokenHeader   = "X-Plex-Token"
	acceptHeader  = "application/json"
)

// The reference's own httpx timeout, applied to the whole exchange: a server
// that accepts and then says nothing stalls the sweep exactly as one that never
// accepts does.
const requestTimeout = 10 * time.Second

// A bound on one response, because an unbounded read cannot be allowed to
// exhaust the slice (DESIGN 19). The root document is a few kilobytes, the
// section listing grows with the number of sections rather than with the number
// of items, and the count window is asked for precisely so no library travels;
// eight megabytes is an answer these four requests do not produce.
const responseBound = 8 << 20

// The receipt problem, spelled exactly as the reference spells it: this string
// is a FACT VALUE that travels the wire, so a port that reworded it would
// disagree with the reference on a shape neither the corpus nor a mutation
// operator stages. It names the variable and never its value — the point of the
// refusal is that the value is unfit to put in a header, and repeating it in a
// fact would put it somewhere far worse.
const tokenProblemDetail = "SE_PLEX_TOKEN contains control or" +
	" non-ASCII characters — refusing to send" +
	" it in a header"

// declined is the seam's statement that the interface itself could not be read,
// carried as an error so no caller can forget to route it. The detail is a
// constant, and here that is load-bearing rather than tidy: decline detail
// travels to a hub and out over MCP, and SE_PLEX_URL is a URL — the one shape
// DESIGN 21 calls a credential channel when it carries userinfo. So the endpoint
// goes to stderr, where a person debugging can read it, and never into a record
// that leaves the host.
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
// host which lost this interface would not serve its libraries and sessions forever. The
// second half of that is answered by staleness rather than by retirement: no
// decline but `absent` commits, so prior state STANDS and the collator marks it
// stale — visible as not-fresh, which is the honest rendering of a reading that
// did not happen.
//
// The first half was simply wrong. An unset SE_PLEX_URL is not
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
var declineNoServer = declined{"unavailable", "no plex api configured for this process"}

// The server is addressed and this deployment cannot open it. The `server` row
// states this as ConfigMissing and stays — the standing signal that the estate
// asked for a Plex and gave this process no way in — while `libraries` and
// `sessions` decline, because guessing at a token would only manufacture 401s
// and a config gap must not dress as an outage. Neither commits, so whatever a
// previous batch published for those two stands rather than being retired over a
// missing variable.
var declineNoReceipts = declined{
	"unavailable",
	"the plex server is configured and this deployment holds no usable token; " +
		"plex answers 401 without one, so this collection is not asked rather " +
		"than asked and refused",
}

// The server is addressed, the receipts are complete, and the reading did not
// come back: nothing listening, a timeout, a proxy error, a status this
// collector cannot read.
//
// `unavailable` rather than `unsupported`, and the choice is deliberate — the
// same one the traefik and unbound ports made. Only the response body could tell
// a permanent refusal from a transient one, and reading intent out of prose is
// exactly what this product does not do, so the honest reason is the one that
// says "configured, not answering" and leaves the question open. Neither commits.
//
// The `server` collection deliberately does NOT take this path: its row stays
// and carries StatusUnobservable instead, because every stream in the house
// depends on that server answering and a row that vanished would say nothing at
// all about why.
var declineServerSilent = declined{
	"unavailable",
	"the configured plex API did not answer; the server may be restarting, or " +
		"the endpoint may no longer be where the deployment says it is",
}

// errUncaptured marks a document the variant did not stage. It must never fall
// back to the live interface of the machine REPLAYING the corpus — that seam
// escape once put a replaying workstation's filesystem into committed facts —
// and it must not become a decline either, which would state something about a
// machine nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

// The three things that can go wrong on one request, said in words that name the
// request and nothing else. They become the StatusUnobservable and
// ItemCountUnobservable facts, which travel to a hub exactly as a decline detail
// does — so no URL, no errno and no library message reaches them.
//
// This is a stated divergence from the reference, which spells these values
// `f"{type(exc).__name__}: {exc}"` over a Python exception. No port in another
// language can reproduce that text, and it carries the request URL, so the
// corpus does not enshrine it and the live comparator adjudicates the difference
// rather than treating either side as wrong.
func detailNoAnswer(path string) string {
	return "the plex API did not answer GET " + path
}

func detailStatusCode(path string, code int) string {
	return "the plex API answered GET " + path + " with HTTP " + strconv.Itoa(code)
}

func detailUnreadable(path string) string {
	return "the plex API answered GET " + path + " with a document this collector cannot read"
}

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is deliberately not consulted. The two timestamps this
		// collector publishes are converted from epoch seconds the SERVER
		// stated, not derived against wall-clock now — no age, no elapsed time —
		// so the pin has nothing to freeze and reading it would invent a
		// dependency the declaration does not admit to.
		return replaySource{dir: dir}
	}
	live := &liveSource{
		started: time.Now(),
		// rstrip("/"), the reference's own: an operator who wrote a trailing
		// slash addresses the same server, and `<url>//library/sections` is a
		// path Plex does not serve.
		url: strings.TrimRight(getenv(urlVariable), "/"),
		// The requests collection's own pair — a second application over a
		// second credential, which is exactly why its receipts are read
		// separately from Plex's.
		seerrURL: strings.TrimRight(getenv("SE_SEERR_URL"), "/"),
		seerrKey: getenv("SE_SEERR_API_KEY"),
		client: &http.Client{
			Timeout: requestTimeout,
			// httpx does not follow redirects unless told to, and neither does
			// this — for a better reason than parity. The request carries a Plex
			// token in a header, and Go's default policy would re-send that
			// header to whatever host a 302 named.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
	if token := getenv(tokenVariable); token != "" {
		if isASCIIPrintable(token) {
			live.token = token
		} else {
			live.tokenProblem = tokenProblemDetail
		}
	}
	return live
}

// isASCIIPrintable is Python's `token.isascii() and token.isprintable()` over a
// token that has already been found non-empty. Restricted to ASCII, "printable"
// is exactly the 0x20–0x7e band: a DEL or a control character in a header value
// is a request-smuggling shape, and a token carrying one is a deployment error to
// report rather than a header to send.
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
	started      time.Time
	url          string
	token        string
	tokenProblem string
	seerrURL     string
	seerrKey     string
	client       *http.Client
	at           float64
	stamped      bool
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

func (s *liveSource) mark() { s.stamped = false }

// stamp is the reading taken before this collection's first request, shared by
// every row that collection produced (DESIGN 19).
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

func (s *liveSource) deployment() deployment {
	if s.url == "" {
		return deployment{absent: true}
	}
	// The token refusal comes first: a token unfit to send is a worse gap than a
	// token nobody set, and it is the one whose reason a person needs spelled out.
	if s.tokenProblem != "" {
		return deployment{missing: []string{s.tokenProblem}}
	}
	if s.token == "" {
		return deployment{missing: []string{tokenVariable}}
	}
	return deployment{}
}

// ready is this collection's clock reading, taken once per mark and before the
// earliest read the collection's rows will rest on.
func (s *liveSource) ready() error {
	if !s.stamped {
		at, err := bootClock()
		if err != nil {
			return err
		}
		s.at, s.stamped = at, true
	}
	return nil
}

func (s *liveSource) document(path string) (fetched, error) { return s.get(path, "") }

func (s *liveSource) seerrConfigured() (bool, bool) {
	return s.seerrURL != "", s.seerrKey != ""
}

func (s *liveSource) seerr(path, query string) (fetched, error) {
	address := s.seerrURL + path
	if query != "" {
		address += "?" + query
	}
	request, err := http.NewRequest(http.MethodGet, address, nil)
	if err != nil {
		return fetched{detail: detailNoAnswer(path)}, nil
	}
	request.Header.Set("X-Api-Key", s.seerrKey)
	response, err := s.client.Do(request)
	if err != nil {
		return fetched{detail: detailNoAnswer(path)}, nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fetched{detail: fmt.Sprintf("seerr answered %d for %s",
			response.StatusCode, path)}, nil
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, responseBound))
	if err != nil {
		return fetched{detail: detailNoAnswer(path)}, nil
	}
	document, err := decodeDocument(raw)
	if err != nil {
		return fetched{detail: fmt.Sprintf("seerr answered %s with something "+
			"that is not a document", path)}, nil
	}
	return fetched{doc: document}, nil
}

func (s *liveSource) window(path string) (fetched, error) { return s.get(path, countWindow) }

// get is one GET. Its outcomes are the three the row model needs kept apart: a
// document, a could-not-read statement about the request, and an inability to
// run at all.
func (s *liveSource) get(path, query string) (fetched, error) {
	if err := s.ready(); err != nil {
		return fetched{}, err
	}
	address := s.url + path
	if query != "" {
		address += "?" + query
	}
	request, err := http.NewRequest(http.MethodGet, address, nil)
	if err != nil {
		// A URL this side cannot even form is a configuration this collector
		// cannot ask with, which reads the same way to whoever must fix it as a
		// server that did not answer.
		return fetched{detail: detailNoAnswer(path)}, nil
	}
	request.Header.Set("Accept", acceptHeader)
	request.Header.Set(tokenHeader, s.token)
	response, err := s.client.Do(request)
	if err != nil {
		return fetched{detail: detailNoAnswer(path)}, nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fetched{detail: detailStatusCode(path, response.StatusCode)}, nil
	}
	// One byte past the bound, so a reply AT the bound is told from one that ran
	// over it rather than being silently trimmed to fit — a document cut in half
	// parses into a row of plausible half-facts, which is the one outcome worse
	// than an error.
	raw, err := io.ReadAll(io.LimitReader(response.Body, responseBound+1))
	if err != nil {
		return fetched{detail: detailNoAnswer(path)}, nil
	}
	if len(raw) > responseBound {
		return fetched{detail: detailUnreadable(path)}, nil
	}
	document, err := decodeDocument(raw)
	if err != nil {
		return fetched{detail: detailUnreadable(path)}, nil
	}
	return fetched{doc: document}, nil
}

// ── replay ──────────────────────────────────────────────────────────────

// A replay has no boot, so the fixed v4-shaped id — "5e" up front so no reader
// mistakes it for a capture. The shape rule refuses the old "replay" stub and the
// nil UUID; that this constant itself passes is DESIGN 19's named deferral, the
// live comparator's to catch.
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

// The real digest, under replay as much as live: the declaration identifies THIS
// collector's contract, and a replay does not change which contract this binary
// holds. It is rule-governed rather than byte-compared (DESIGN 19's two regimes),
// so the honest value costs nothing.
func (replaySource) declaration() string { return declarationDigest }

// Nothing to open: a replay reads files, and the pinned stamp below is a function
// of emission order alone.
func (replaySource) mark() {}

// Nothing to take: replay's `at` is the reference constant below, a function of
// emission order alone, so there is no clock for a stampless row to miss.
func (replaySource) ready() error { return nil }

func (replaySource) stamp(i int) float64 {
	// The reference constant, 1.0 + 0.001*i in emission order and one counter
	// across the whole batch: finite, positive, boot-scale and advancing, so the
	// structural rule that governs `at` is exercised by replay instead of
	// satisfied by a hardcoded zero. Rounded because the reference rounds, and
	// past a few hundred rows the float noise is the difference between 1.126
	// and 1.1260000000000001 in a file people read.
	return float64(int64((1.0+0.001*float64(i))*1000+0.5)) / 1000
}

func (replaySource) costs() (float64, float64) { return 0.5, 1.0 }

// payloadStem is the replay shim's slug() for an API path: strip the surrounding
// slashes, map every character that is not alphanumeric, '-', '_' or '.' to '-',
// collapse a doubled dash, and answer "root" for what is left of "/".
// "/library/sections/1/all" is committed as library-sections-1-all.json, which is
// what makes this reversible enough to read — a reviewer looking at the file can
// see which request it answers.
//
// The QUERY is not part of it, and that is the seam's own rule rather than a
// convenience: the reference passes the container window as httpx params, so the
// two requests to one section's listing would key five files onto one name if it
// were.
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

// The three documents every plex capture stages, whatever its sections are. They
// are what absence is decided over: a variant staging none of them staged no
// Plex at all, and one staging some of them staged a Plex whose other documents
// this collector cannot see — a broken capture, and not a statement about a
// machine.
//
// The per-section documents are deliberately not here. How many there are is
// decided by what /library/sections answers, so they are checked as they are
// asked for rather than enumerated in this file.
var stagedPaths = [...]string{pathRoot, pathSessions, pathSections}

// The receipts are NOT consulted under replay, and their absence on the replaying
// machine is not a reading. A capture staged these documents, which is the
// evidence that the API answered on the host it came from with the token that
// host held; re-asking the workstation doing the replay for a token is the seam
// escape this whole mechanism exists to prevent, and it would publish
// `ConfigMissing: ["SE_PLEX_TOKEN"]` from a variant whose payloads are the API
// answering. The reference's seam pins the same attributes for the same reason,
// and corpus/plex/healthy anchors ConfigMissing ABSENT, which is what makes the
// pin load-bearing rather than decorative.
func (r replaySource) deployment() deployment {
	return deployment{absent: !r.staged()}
}

func (r replaySource) document(path string) (fetched, error) {
	stem := payloadStem(path)
	raw, err := os.ReadFile(filepath.Join(r.dir, stem+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		// Never a decline — a decline states something about a machine, and this
		// variant observed a machine that HAD a Plex — and never a fall back to
		// the live API of whatever workstation is replaying.
		return fetched{}, fmt.Errorf("%s %w: a capture that stages plex stages every document this collector reads", stem, errUncaptured)
	}
	if err != nil {
		return fetched{}, fmt.Errorf("%s %w: %v", stem, errUncaptured, err)
	}
	document, err := decodeDocument(raw)
	if err != nil {
		return fetched{}, fmt.Errorf("the staged %s.json is not a document: %v", stem, err)
	}
	return fetched{doc: document}, nil
}

// The container window never reaches the payload's name, so a staged section
// listing answers the windowed request exactly as it answers the plain one —
// which is what the reference's own seam does.
func (r replaySource) window(path string) (fetched, error) { return r.document(path) }

// Replay reads the seerr receipts off the CAPTURE: a variant that stages
// the request document observed a machine with a configured seerr, and one
// that stages none observed a machine without — the same two-state answer
// the live env reading gives, decided by what was actually captured rather
// than by a pin a seerr-less variant would then have to argue with.
func (r replaySource) seerrConfigured() (bool, bool) {
	if _, err := os.Stat(filepath.Join(r.dir, "api-v1-request.json")); err != nil {
		return false, false
	}
	return true, true
}

func (r replaySource) seerr(path, _ string) (fetched, error) {
	return r.document(path)
}

// staged is whether this variant captured ANY of the documents this collector
// always reads. It is the replay half of the absence question, and it is asked
// over the whole acquisition rather than per request because absence is a
// property of the interface: the replay shim decides the same way, declining only
// when the variant staged nothing at all.
func (r replaySource) staged() bool {
	for _, path := range stagedPaths {
		if _, err := os.Stat(filepath.Join(r.dir, payloadStem(path)+".json")); err == nil {
			return true
		}
	}
	return false
}

// ── shared ──────────────────────────────────────────────────────────────

// newUUIDv4 mints a lowercase RFC 4122 v4 id from the kernel's CSPRNG. No
// dependency: sixteen random bytes with the version and variant bits set is the
// whole format, and this binary stays stdlib-only and static.
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

// probe answers "can it run here" as a verdict, never an exit code (DESIGN 18).
// It takes the real reading, because nothing weaker establishes the answer: a URL
// in the environment says nothing about whether anything answers it. A server
// whose receipts are incomplete is still a YES — the `server` collection is
// served and the row it publishes says which receipt is missing, which is a
// reading rather than an inability — and only an absence or a dark API is a no.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes", Reason: "the plex API answers"}
	got := src.deployment()
	switch {
	case got.absent:
		verdict = probeVerdict{Verdict: "no", Reason: declineNoServer.detail}
	case len(got.missing) > 0:
		verdict.Reason = "a plex server is configured and its receipts are incomplete: " +
			strings.Join(got.missing, ", ")
	default:
		answer, err := src.document(pathRoot)
		switch {
		case err != nil:
			// The reason names what this side established and nothing it has
			// not; the error itself goes to stderr, where a person debugging can
			// read the endpoint and the errno.
			verdict = probeVerdict{Verdict: "no", Reason: "the plex API could not be read"}
			fmt.Fprintln(stderr, "probe:", err)
		case answer.detail != "":
			verdict = probeVerdict{Verdict: "no", Reason: answer.detail}
		}
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(verdict); err != nil {
		fmt.Fprintln(stderr, "writing the probe verdict:", err)
		return exitRuntime
	}
	return exitOK
}
