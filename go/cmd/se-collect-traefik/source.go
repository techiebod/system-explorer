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

// source is the acquisition seam (DESIGN 20; harness/se_harness/replay.py):
// with SE_REPLAY_DIR set, every native document comes from that directory
// instead of the live API, while the parse, the declared semantics and the
// stream generation run unchanged. The seam is a value chosen at startup, not a
// build flag, so the binary the harness judges is the binary that deploys.
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
	// document is one API response, addressed by the request path that answers
	// it — adapters/traefik.py `_get`. Dispatching on the path rather than
	// naming five methods keeps this seam the same shape as the reference's:
	// the replay shim stubs `_get` and keys the captured documents on its
	// argument (harness/bin/se-reference-collector, slug()). Its errors carry
	// the decline shape.
	document(path string) (*value, error)
	// list is every PAGE of a list endpoint, concatenated —
	// adapters/traefik.py `_get_list`. It is a second method rather than a flag
	// because the two genuinely differ on the wire: the list endpoints slice at
	// 100 and signal continuation only through X-Next-Page, and a single-page
	// fetch past 100 routers would render absence as a complete healthy
	// listing. Under replay both answer from the same staged document, which is
	// what the reference's own seam does — pagination is a property of the live
	// interface, not of the capture.
	list(path string) (*value, error)
	// reachable is the capability question, asked of the interface rather than
	// of a collection: is there a traefik here this collector may read. It is
	// its own method because the reference's capability() asks one cheap
	// /api/version instead of paying three collections' timeouts against a dark
	// endpoint — and because under replay the answer is the corpus's, not the
	// replaying machine's.
	reachable() error
	// mark opens a collection. `at` is stamped immediately before the EARLIEST
	// native read that contributes to an object (DESIGN 19), and the overview
	// row rests on three documents, so the boundary has to be stated by the
	// caller: the first read after a mark takes the clock and every row of that
	// collection shares it. A per-row reading would report the last row fresher
	// than bytes that arrived together, and a per-batch one would report the
	// services as old as the overview.
	mark()
	// stamp is `at` for the i-th emitted object.
	stamp(i int) float64
	// costs are end's advisory self-report (DESIGN 19): bounded by the judge,
	// authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

// The five request paths, and they are the reference's own constants —
// adapters/traefik.py OVERVIEW_PATH, VERSION_PATH, ENTRYPOINTS_PATH,
// ROUTERS_PATH, SERVICES_PATH. Which fetcher each one goes through is
// collect.go's table; the split matters because only the list endpoints
// paginate.
const (
	pathOverview    = "/api/overview"
	pathVersion     = "/api/version"
	pathEntrypoints = "/api/entrypoints"
	pathRouters     = "/api/http/routers"
	pathServices    = "/api/http/services"
)

// Where the API is, and it is deployment configuration rather than a constant:
// Traefik's dashboard port, its scheme and its bind address are all the
// deployment's decision (this estate publishes it loopback-only), and the
// shipping adapter reads the same variable. A default here would make this
// binary and the reference disagree about a host that configured neither — the
// port would find an API and the reference would not — which is a disagreement
// invented by the port rather than observed on the machine.
const urlVariable = "SE_TRAEFIK_URL"

// declined is the seam's statement that the interface itself could not be
// read, carried as an error so no caller can forget to route it. The detail is
// a constant, and here that is load-bearing rather than tidy: decline detail
// travels to a hub and out over MCP, and SE_TRAEFIK_URL is a URL — the one
// shape DESIGN 21 calls a credential channel when it carries userinfo. So the
// endpoint goes to stderr, where a person debugging can read it, and never into
// a record that leaves the host.
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
// `absent` is the reading, and it is the one decline that commits. The
// configuration IS the statement: a host whose deployment names no Traefik
// endpoint publishes no routes this collector can see — a successful reading
// that establishes something, which is DESIGN 19's own worked example. It must
// commit zero, because a host that HAD an ingress tier and lost it would
// otherwise serve its old routers forever, stale and never retired. The
// unbound port reads its own deployment receipt the same way, and two
// collectors facing one condition must not answer differently.
//
// The wording is the reference's, to the byte: the replay shim and
// se-live-reference both spell it "no <interface> on this host" with the
// interface named "traefik api", and a decline detail that reached an operator
// in three spellings would read as three conditions.
var declineNoAPI = declined{"absent", "no traefik api on this host"}

// The API answered and refused this collector. `unauthorised` is a deployment
// error and never commits: the routes are live right now, so retiring the whole
// ingress map because a reverse proxy in front of the dashboard wants a
// credential would delete a subsystem over a header. Traefik's own API carries
// no credential in the posture this collector is written for, which is why the
// reason exists at all — what refuses is whatever the deployment put in front
// of it.
var declineAPIRefused = declined{
	"unauthorised",
	"the traefik API answered and refused this collector; whatever fronts the " +
		"dashboard wants a credential this collector does not carry, and " +
		"traefik's own API takes none",
}

// The endpoint is configured and the reading did not come back: nothing
// listening, a timeout, a proxy error, a status this collector cannot read.
//
// `unavailable` rather than `unsupported`, and the choice is deliberate — the
// same one the unbound port made for a silent socket. Only the response body
// could tell a permanent refusal from a transient one, and reading intent out
// of prose is exactly what this product does not do, so the honest reason is
// the one that says "configured, not answering" and leaves the question open.
// `unsupported` would tell an operator to stop asking about a proxy that is
// running and may well answer on the next sweep. Neither commits, so prior
// state stands either way.
var declineAPISilent = declined{
	"unavailable",
	"the configured traefik API did not answer; the proxy may be restarting, " +
		"or the endpoint may no longer be where the deployment says it is",
}

// errUncaptured marks a document the variant did not stage. It must never fall
// back to the live interface of the machine REPLAYING the corpus — that seam
// escape once put a replaying workstation's filesystem into committed facts —
// and it must not become a decline either, which would state something about a
// machine nobody observed.
var errUncaptured = errors.New("not captured in this replay directory")

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is deliberately not consulted: every fact here is a
		// figure Traefik stated, and nothing is derived against wall-clock now
		// — not an age, not an elapsed time — so the pin has nothing to freeze
		// and reading it would invent a dependency the declaration does not
		// admit to.
		return replaySource{dir: dir}
	}
	// The reference's own normalisation: trailing slashes are stripped so
	// "http://127.0.0.1:8080/" and "http://127.0.0.1:8080" address one API, and
	// an empty value is no endpoint at all rather than a request to "/api/…".
	return &liveSource{
		started: time.Now(),
		url:     strings.TrimRight(getenv(urlVariable), "/"),
		client:  &http.Client{Timeout: requestTimeout},
	}
}

// ── live ────────────────────────────────────────────────────────────────

// Matching the reference's httpx.AsyncClient(timeout=10.0). It bounds the whole
// exchange rather than the dial alone: an endpoint that accepts and then says
// nothing stalls the sweep exactly as one that never accepts does.
const requestTimeout = 10 * time.Second

// A bound on one response, because an unbounded read cannot be allowed to
// exhaust the slice (DESIGN 19). A page of 100 routers is tens of kilobytes;
// eight megabytes is a response this interface does not produce. Exceeding it
// is "I could not run" rather than a decline or a truncated parse — a document
// cut in half parses into rows of plausible half-facts, which is the one
// outcome worse than an error.
const responseBound = 8 << 20

// The page size the reference asks for, and the header Traefik answers
// continuation with. The header's value is 1 when the listing is exhausted,
// which is why the loop compares it against the page it just asked for rather
// than testing for absence.
const (
	pageSize       = 100
	nextPageHeader = "X-Next-Page"
)

// A bound on the WALK, which the reference does not have: its loop advances
// while the header keeps advancing, so an endpoint that answers a larger page
// number forever holds the sweep forever. An unbounded read cannot be allowed
// to exhaust the slice (DESIGN 19), and the declared record ceiling is 4096
// rows at 100 a page — so a walk past this many pages has already exceeded what
// this collection may commit, whatever the far end thinks. Exceeding it is "I
// could not run" rather than a decline or a short listing: a listing cut in
// half reads as a complete one, which is the outcome the pagination loop exists
// to prevent in the first place.
const pageBound = 64

type liveSource struct {
	started time.Time
	url     string
	client  *http.Client
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

// reachable is adapters/traefik.py's capability(): no endpoint configured is an
// absence, and a configured endpoint that does not answer /api/version is one of
// the two readings that leave prior state standing. One cheap probe, which is
// the reference's own arrangement — three collections each paying the full
// timeout against a dark endpoint buys nothing.
func (s *liveSource) reachable() error {
	if s.url == "" {
		reason := declineNoAPI
		return &reason
	}
	_, _, err := s.get(s.url + pathVersion)
	return err
}

// ready is the absence check and this collection's clock reading, in that
// order. The absence check comes FIRST so the answer is the same on any
// platform — a machine with no CLOCK_BOOTTIME still gets a truthful absence
// rather than a failure to run — and the clock is taken once per mark, before
// the earliest read the collection's rows will rest on.
func (s *liveSource) ready() error {
	if s.url == "" {
		reason := declineNoAPI
		return &reason
	}
	if !s.stamped {
		at, err := bootClock()
		if err != nil {
			return err
		}
		s.at, s.stamped = at, true
	}
	return nil
}

func (s *liveSource) document(path string) (*value, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	raw, _, err := s.get(s.url + path)
	if err != nil {
		return nil, err
	}
	return parseDocument(path, raw)
}

// list is `_get_list`: every page, in order, concatenated into one array. The
// API slices at 100 per page and signals continuation ONLY through
// X-Next-Page (value 1 when exhausted), so a single-page fetch past 100 routers
// would render absence as a complete healthy listing, with an operator reading
// a route map that silently stops.
func (s *liveSource) list(path string) (*value, error) {
	if err := s.ready(); err != nil {
		return nil, err
	}
	items := []*value{}
	for page := 1; ; {
		if page > pageBound {
			return nil, fmt.Errorf("the traefik API's listing of %s ran past %d pages of %d", path, pageBound, pageSize)
		}
		address := fmt.Sprintf("%s%s?page=%d&per_page=%d", s.url, path, page, pageSize)
		raw, next, err := s.get(address)
		if err != nil {
			return nil, err
		}
		document, err := parseDocument(path, raw)
		if err != nil {
			return nil, err
		}
		if document.kind != jsonArray {
			return nil, fmt.Errorf("the traefik API's answer to %s page %d is not a list", path, page)
		}
		items = append(items, document.items...)
		// The reference's own two exits: a header this side cannot read as an
		// integer ends the walk, and so does one that does not advance. Traefik
		// answers 1 on the last page, which is why "does not advance" is the
		// test rather than "absent".
		if next <= page {
			break
		}
		page = next
	}
	return newArray(items), nil
}

// get is one request, with the two non-absent declines mapped where they are
// distinguishable. A transport failure and an unreadable status are the same
// statement — configured, not answering — and only an explicit refusal is told
// apart, because that one names a different fix.
func (s *liveSource) get(address string) ([]byte, int, error) {
	response, err := s.client.Get(address)
	if err != nil {
		reason := declineAPISilent
		return nil, 0, fmt.Errorf("%v: %w", err, &reason)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		reason := declineAPIRefused
		return nil, 0, &reason
	}
	if response.StatusCode != http.StatusOK {
		reason := declineAPISilent
		return nil, 0, fmt.Errorf("status %d: %w", response.StatusCode, &reason)
	}
	// One byte past the bound, so a response AT the bound is told from one that
	// ran over it rather than being silently trimmed to fit.
	body, err := io.ReadAll(io.LimitReader(response.Body, responseBound+1))
	if err != nil {
		reason := declineAPISilent
		return nil, 0, fmt.Errorf("%v: %w", err, &reason)
	}
	if len(body) > responseBound {
		return nil, 0, fmt.Errorf("the traefik API answered %s with more than %d bytes", address, responseBound)
	}
	return body, nextPage(response.Header.Get(nextPageHeader)), nil
}

// nextPage reads the continuation header the way the reference does: absent is
// 1 (exhausted), and a value this side cannot read as an integer ends the walk
// rather than guessing at it.
func nextPage(header string) int {
	if header == "" {
		return 1
	}
	value, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil {
		return 0 // unreadable: stop, exactly as the reference's ValueError break does
	}
	return value
}

func parseDocument(path string, raw []byte) (*value, error) {
	document, err := decodeDocument(raw)
	if err != nil {
		// The API answered with something that is not a document. That is the
		// interface behaving unexpectedly rather than a machine to make a
		// statement about, so it is "I could not run".
		return nil, fmt.Errorf("the traefik API's answer to %s is not a document: %v", path, err)
	}
	return document, nil
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

// Nothing to open: a replay reads files, and the pinned stamp below is a
// function of emission order alone.
func (replaySource) mark() {}

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

// payloadStem is the replay shim's slug() for an API path: strip the leading
// slash, and map every character that is not alphanumeric, '-', '_' or '.' to
// '-'. "/api/http/routers" is committed as api-http-routers.json, which is what
// makes this reversible enough to read — a reviewer looking at that file can
// see which request it answers. The query string is not part of it: the
// reference passes page and per_page as httpx params rather than in the path,
// so pagination never reaches the payload's name.
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
// to want. A variant staging none of them staged no traefik at all; a variant
// staging some of them staged a traefik whose other documents this collector
// cannot see, which is a broken capture and not a statement about a machine.
var acquiredPaths = [...]string{
	pathOverview, pathVersion, pathEntrypoints, pathRouters, pathServices,
}

func (r replaySource) document(path string) (*value, error) {
	stem := payloadStem(path)
	raw, err := os.ReadFile(filepath.Join(r.dir, stem+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		if r.staged() {
			// Some of the interface is here and this document is not. Never a
			// decline — a decline states something about a machine, and this
			// variant observed a machine that HAD traefik — and never a fall
			// back to the live API of whatever workstation is replaying.
			return nil, fmt.Errorf("%s %w, and other API documents are: a capture that stages traefik stages every path this collector acquires", stem, errUncaptured)
		}
		// Nothing at all: the variant records a host with no traefik endpoint.
		// The same reading the live path takes, through the same constant, so
		// the two cannot spell one condition two ways.
		reason := declineNoAPI
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

// A staged listing is already every page: the capture recorded what the
// reference's pagination loop returned, so replaying it is reading the file.
// Pagination itself is a property of the live interface and is judged where a
// second page can exist — which is the live comparator, not a corpus.
func (r replaySource) list(path string) (*value, error) { return r.document(path) }

// reachable under replay is the corpus's answer, not the replaying machine's:
// what the capture establishes is that traefik WAS readable on the host it came
// from, and re-asking the workstation doing the replay is the seam escape this
// whole mechanism exists to prevent.
func (r replaySource) reachable() error {
	if r.staged() {
		return nil
	}
	reason := declineNoAPI
	return &reason
}

// staged is whether this variant captured ANY of the API documents. It is the
// replay half of the absence question, and it is asked over the whole
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
// 18). It asks /api/version, which is the question the reference's capability
// check asks and the only one that separates the readings: an endpoint in the
// deployment's configuration says nothing about whether a proxy answers there,
// and a proxy that answers says nothing about whether this collector may read
// it. A traefik with no dynamic providers still answers, and that is a reading
// of three internal routes rather than an inability.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{Verdict: "yes", Reason: "the traefik API answers " + pathVersion}
	if err := src.reachable(); err != nil {
		// The reason names the decline this side reached and nothing it has
		// not established; the error itself goes to stderr, where a person
		// debugging can read the endpoint and the errno.
		reason := "the traefik API could not be read"
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
