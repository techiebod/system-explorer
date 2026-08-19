package main

import (
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
// instead of the live interface, while the parse, the declared semantics and
// the stream generation run unchanged. The seam is a value chosen at startup,
// not a build flag, so the binary the harness judges is the binary that
// deploys.
//
// This collector fronts a FLEET, so the seam carries one thing the others do
// not: the fleet itself. Which instances exist is configuration rather than an
// interface reading, and under replay it comes from the capture — never from
// the environment of whichever machine is replaying, which would silently
// change what the corpus is a specimen of.
type source interface {
	// bootID names the boot whose clock every `at` reading belongs to;
	// without it the readings are meaningless (DESIGN 09).
	bootID() (string, error)
	// timens is the CLOCK_BOOTTIME namespace offset — stated, never
	// corrected, by whoever compares it (DESIGN 09).
	timens() int64
	// batch mints the batch id — collector-minted by ruling (appendix C):
	// a transport retry re-sending the same bytes under the same id is what
	// makes retry idempotent. request := batch until a consumer needs them
	// distinct.
	batch() (string, error)
	// declaration is the digest begin carries: the hash of the exact bytes
	// `declare` emits, so an unknown hash triggers a refetch rather than a
	// spawn on every collect (DESIGN 19).
	declaration() string
	// fleet is the configured instances, in configuration order — including
	// the ones whose receipts are incomplete, because a named instance that
	// cannot be observed is a row and never a silent skip.
	fleet() ([]instance, error)
	// document is one instance's answer to one API path. Dispatching on the
	// instance AND the path is what keeps this seam the same shape as the
	// reference's: adapters/servarr.py acquires through one `_get(spec, path)`
	// whose first argument is the INSTANCE, so a document is addressed by the
	// pair and by nothing else. Its errors carry the three readings the rows
	// branch on: 404 (this app has no such endpoint), unreadable (this app did
	// not answer), and anything else, which is "I could not run".
	document(app instance, path string, query url.Values) (*value, error)
	// stamp is `at` for the i-th emitted object, one counter across the batch.
	// Taken BEFORE the earliest native read that contributes to it so the tie
	// breaks toward older (DESIGN 19) — per COLLECTION here, matching the
	// live reference, because a collection is one fan-out over the fleet.
	stamp(i int) float64
	// beginCollection is where that reading is taken.
	beginCollection() error
	// costs are end's advisory self-report (DESIGN 19): bounded by the judge,
	// authenticated only by the collator's own slice accounting.
	costs() (cpuMS, wallMS float64)
}

// The paths this collector's acquisition asks for. adapters/servarr.py's
// REFERENCE list, minus /downloadclient — which is the opened object's
// enrichment and is never fetched on the way to a row.
const (
	pathStatus      = "/system/status"
	pathHealth      = "/health"
	pathQueueStatus = "/queue/status"
	pathQueue       = "/queue"
	pathHistory     = "/history"
)

// The queue walk's bounds, the reference's own constants. QUEUE_MAX_PAGES is a
// runaway guard and not a working limit: forty pages is ten thousand tracked
// downloads, far past any real queue, and hitting it stops the walk with the
// rows already gathered rather than looping on a lying totalRecords.
const (
	queuePageSize = 250
	queueMaxPages = 40
	historyPage   = 100
)

// declined is the seam's statement that the interface itself could not be
// reached, carried as an error so no caller can forget to route it. The detail
// is a constant: decline detail travels to a hub and out over MCP, and an
// interpolated error string is a redaction path nobody reviewed — which here
// would be the one carrying an instance URL.
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
// `unavailable` is the reading, and it does NOT commit — RULED 2026-08-19,
// reversing what stood here. The old text argued `absent` on the grounds that
// the configuration IS the statement, and that committing zero was needed so a
// host which lost this interface would not serve its apps, health, queue and history forever. The
// second half of that is answered by staleness rather than by retirement: no
// decline but `absent` commits, so prior state STANDS and the collator marks it
// stale — visible as not-fresh, which is the honest rendering of a reading that
// did not happen.
//
// The first half was simply wrong. An unset SE_SERVARR_INSTANCES is not
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
var declineNoInstances = declined{"unavailable", "no servarr api on this host"}

// errNotFound is one app answering "I have no such endpoint" — prowlarr's
// /queue and /queue/status, which are 404 with no body at all. It is a reading
// and not a failure: the row says nothing about a queue rather than saying the
// queue could not be read, and the difference is the whole of what
// corpus/servarr/healthy's two prowlarr absence anchors pin.
var errNotFound = errors.New("the app has no such endpoint")

// errUncaptured marks a document the variant did not stage. It must never fall
// back to the live interface of the machine REPLAYING the corpus — that seam
// escape once put a replaying workstation's filesystem into committed facts —
// and it must not become a fact either: an app that a capture forgot is not an
// app that did not answer, and publishing "not captured in this variant" as a
// StatusUnobservable reason would put a harness artefact on a row.
var errUncaptured = errors.New("not captured in this replay directory")

// unreadable is one instance that did not answer, live. It narrows the
// observation rather than ending the batch: the apps row states it and goes
// critical, and the other collections serve the instances that did answer.
type unreadable struct{ detail string }

func (u *unreadable) Error() string { return u.detail }

func newSource(getenv func(string) string) source {
	if dir := getenv("SE_REPLAY_DIR"); dir != "" {
		// SE_REPLAY_NOW is deliberately not consulted: no fact here is derived
		// against wall-clock now — every timestamp on a row is one the app
		// stated — so the pin has nothing to freeze and reading it would
		// invent a dependency the declaration does not admit to.
		return replaySource{dir: dir}
	}
	return &liveSource{
		started: time.Now(),
		getenv:  getenv,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

// ── live ────────────────────────────────────────────────────────────────

type liveSource struct {
	started time.Time
	getenv  func(string) string
	client  *http.Client
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

func (s *liveSource) fleet() ([]instance, error) { return instanceSpecs(s.getenv), nil }

func (s *liveSource) stamp(int) float64 { return s.at }

// One reading per collection, taken before the fan-out that collection rests
// on. Not per instance: the rows of one collection are one acquisition of the
// fleet, and a per-instance reading would report the last app fresher than the
// first off bytes gathered in one pass (DESIGN 19).
func (s *liveSource) beginCollection() error {
	at, err := bootClock()
	if err != nil {
		return err
	}
	s.at = at
	return nil
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

// document is one GET against one app. The key rides the X-Api-Key header and
// nothing else — never a query parameter, which is where an upstream's key
// ends up in a 401's own error text (DESIGN 19's named credential channel) —
// and no failure here carries the URL, because a reason travels to a hub.
func (s *liveSource) document(app instance, path string, query url.Values) (*value, error) {
	target := app.url + "/api/" + app.api + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		// A URL this side cannot even build is configuration, not a machine:
		// the instance is named without its value, exactly as a missing
		// receipt is.
		return nil, &unreadable{"SE_" + envBase(app.name) + "_URL is not a usable URL"}
	}
	request.Header.Set("X-Api-Key", app.key)
	response, err := s.client.Do(request)
	if err != nil {
		return nil, &unreadable{app.name + " did not answer " + path}
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%s %s: %w", app.name, path, errNotFound)
	}
	if response.StatusCode != http.StatusOK {
		return nil, &unreadable{fmt.Sprintf("%s answered %d for %s",
			app.name, response.StatusCode, path)}
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, &unreadable{app.name + " answered " + path + " and the body could not be read"}
	}
	document, decodeErr := decodeDocument(body)
	if decodeErr != nil {
		// The app answered with something that is not a document. That is the
		// interface behaving unexpectedly rather than the app being dark, so
		// it narrows this instance rather than ending the batch.
		return nil, &unreadable{app.name + "'s answer to " + path + " is not a document"}
	}
	return document, nil
}

// ── replay ──────────────────────────────────────────────────────────────

// A replay has no boot, so the fixed v4-shaped id — "5e" up front so no reader
// mistakes it for a capture. The shape rule refuses the old "replay" stub and
// the nil UUID; that this constant itself passes is DESIGN 19's named
// deferral, a live comparator's to catch.
const replayBootID = "5e000000-0000-4000-8000-000000000001"

// The two payloads of a fleet capture that are not documents.
//
// `instances` is the fleet receipt — the same shape the packages capture's
// manager.json has, which names WHICH manager answered. It carries each
// instance's name, its API family and which receipts were absent, and it does
// not carry the URL (location) or the key (a credential DESIGN 21 says must
// never have been captured at all).
//
// `response-codes` records the requests that answered with a STATUS and no
// body. prowlarr's /queue is 404 with Content-Length 0, so the response's whole
// content is its status line and a zero-byte payload file could not carry it —
// recording the code is not a transcription of a document, it is the document.
const (
	stemInstances = "instances"
	stemResponses = "response-codes"
)

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

func (replaySource) beginCollection() error { return nil }

func (replaySource) costs() (float64, float64) { return 0.5, 1.0 }

// fleet under replay is the capture's, completed with the two members a public
// corpus may not hold — a replay-invalid URL and a placeholder key, which
// nothing dials because every document comes from the directory. The
// completion is here rather than in the payload for the same reason the
// harness puts it in code (harness/bin/se-reference-collector, fleet_specs):
// a URL is location and a key is a credential, and the honest capture is the
// one that never asked for either.
//
// An instance the capture recorded as MISSING its receipts keeps them missing,
// which is the whole of what that half of the receipt is for.
func (r replaySource) fleet() ([]instance, error) {
	raw, err := os.ReadFile(filepath.Join(r.dir, stemInstances+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		if r.staged() {
			return nil, fmt.Errorf("%s.json %w, and other documents are: a "+
				"capture that stages a fleet stages the receipt that names it",
				stemInstances, errUncaptured)
		}
		reason := declineNoInstances
		return nil, &reason
	}
	if err != nil {
		return nil, fmt.Errorf("%s.json %w: %v", stemInstances, errUncaptured, err)
	}
	var captured []struct {
		Name       string   `json:"name"`
		API        string   `json:"api"`
		Missing    []string `json:"missing"`
		Duplicates []string `json:"duplicates"`
	}
	if err := json.Unmarshal(raw, &captured); err != nil {
		return nil, fmt.Errorf("the staged %s.json is not a list of instance receipts: %v",
			stemInstances, err)
	}
	specs := make([]instance, 0, len(captured))
	for _, entry := range captured {
		app := instance{
			name:       entry.Name,
			api:        entry.API,
			missing:    entry.Missing,
			duplicates: entry.Duplicates,
		}
		if app.api == "" {
			app.api = "v3"
		}
		if len(app.missing) == 0 {
			app.url = "http://" + app.name + ".replay.invalid"
			app.key = "replay-not-a-key"
		}
		specs = append(specs, app)
	}
	return specs, nil
}

func (r replaySource) document(app instance, path string, _ url.Values) (*value, error) {
	stem := payloadStem(app, path)
	raw, err := os.ReadFile(filepath.Join(r.dir, stem+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		status, recorded, codesErr := r.responseCode(stem)
		if codesErr != nil {
			return nil, codesErr
		}
		if recorded {
			if status == http.StatusNotFound {
				return nil, fmt.Errorf("%s %s: %w", app.name, path, errNotFound)
			}
			// Every other status reaches a fact value spelled by the
			// reference's own exception rendering, which no independent
			// implementation can reproduce — so a capture carrying one is an
			// adjudication and not a payload, and both seams refuse it rather
			// than inventing a reading.
			return nil, fmt.Errorf("%s.json records %d for %s, and this seam "+
				"replays 404 only: any other status reaches a fact value only "+
				"the reference can spell", stemResponses, status, stem)
		}
		// Never a fact and never a decline: a capture that staged this fleet
		// and not this document is a broken capture, which is a statement
		// about nobody's machine.
		return nil, fmt.Errorf("%s %w: a capture that stages an instance stages "+
			"every path this collector acquires from it", stem, errUncaptured)
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

// responseCode is what the capture recorded for a request that answered with a
// status and no body. Absence is not 404: an unrecorded request was never
// asked, and turning a capture's omission into "this app has no such endpoint"
// would be absence read as an answer — the founding failure, in the one place
// this collector's rows turn on it.
func (r replaySource) responseCode(stem string) (int, bool, error) {
	raw, err := os.ReadFile(filepath.Join(r.dir, stemResponses+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("%s.json %w: %v", stemResponses, errUncaptured, err)
	}
	var codes map[string]int
	if err := json.Unmarshal(raw, &codes); err != nil {
		return 0, false, fmt.Errorf("the staged %s.json is not a map of request to status: %v",
			stemResponses, err)
	}
	status, recorded := codes[stem]
	return status, recorded, nil
}

// staged is whether this variant captured ANY document. It is the replay half
// of the absence question and it is asked over the whole directory rather than
// per request, because absence is a property of the FLEET: the replay shim
// decides the same way, declining only when the variant staged nothing at all.
func (r replaySource) staged() bool {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			return true
		}
	}
	return false
}

// payloadStem is the replay shim's slug() for a fleet request: the instance
// name and the path the adapter builds under it, with every character that is
// not alphanumeric, '-', '_' or '.' mapped to '-'. "radarr" and
// "/system/status" become radarr-api-v3-system-status, which is what makes the
// addressing reversible enough to read — a reviewer looking at that file can
// see the request it answers and re-run it by hand.
//
// The query is deliberately not part of it. The one call that varies its
// parameters is the queue walk's page number, so a capture whose queue exceeds
// one page would replay page 1 forever until the runaway guard stopped it —
// a bound stated in the corpus rather than a key nobody could read.
func payloadStem(app instance, path string) string {
	trimmed := strings.Trim(app.name+"/api/"+app.api+path, "/")
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
// 18). The question it asks is the reference's capability(): is a fleet
// configured — because that is the whole of what this side can establish
// without spending a round trip on every instance, and an app that is
// configured and dark is a ROW this collector serves rather than a reason it
// cannot run. The verdict names how many instances were configured, so a
// person reading `yes` can tell it apart from a receipt that named one and
// meant five.
func probe(stdout, stderr io.Writer, src source) int {
	verdict := probeVerdict{}
	apps, err := src.fleet()
	switch {
	case err != nil:
		reason := "the servarr fleet could not be read"
		var refused *declined
		if errors.As(err, &refused) {
			reason = refused.detail
		}
		verdict = probeVerdict{Verdict: "no", Reason: reason}
		fmt.Fprintln(stderr, "probe:", err)
	case len(apps) == 0:
		verdict = probeVerdict{Verdict: "no", Reason: declineNoInstances.detail}
	default:
		named := make([]string, 0, len(apps))
		for _, app := range apps {
			named = append(named, app.name)
		}
		verdict = probeVerdict{
			Verdict: "yes",
			Reason: fmt.Sprintf("SE_SERVARR_INSTANCES names %d instance(s): %s",
				len(apps), strings.Join(named, ", ")),
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
