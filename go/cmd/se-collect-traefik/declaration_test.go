package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// The same five documents once a dynamic provider exists: one file provider
// with a TLS'd application on two backends — one of them down — and one route
// whose rule Traefik refused. Measured on a live Traefik 3.1.7 (2026-08-19),
// which is why `serverStatus` appears without a health check, `tls` carries
// `options` beside the resolver, and the refused router keeps its rule while
// losing its `ruleSyntax`. Between this and the bare capture above, every fact
// this collector can emit is reached.
const (
	everythingOverview = `{"http":{"routers":{"total":4,"warnings":0,"errors":1},"services":{"total":4,"warnings":0,"errors":0},"middlewares":{"total":2,"warnings":0,"errors":0}},"tcp":{"routers":{"total":0,"warnings":0,"errors":0},"services":{"total":0,"warnings":0,"errors":0},"middlewares":{"total":0,"warnings":0,"errors":0}},"udp":{"routers":{"total":0,"warnings":0,"errors":0},"services":{"total":0,"warnings":0,"errors":0}},"features":{"tracing":"","metrics":"","accessLog":false},"providers":["File"]}`

	everythingRouters = `[{"entryPoints":["traefik"],"service":"api@internal","rule":"PathPrefix(` + "`/api`" + `)","ruleSyntax":"v3","priority":9223372036854775806,"status":"enabled","using":["traefik"],"name":"api@internal","provider":"internal"},{"entryPoints":["web"],"service":"labapp","rule":"Hostx(` + "`nope.example.com`" + `)","priority":25,"error":["error while parsing rule Hostx(` + "`nope.example.com`" + `): unsupported function: Hostx"],"status":"disabled","using":["web"],"name":"broken@file","provider":"file"},{"entryPoints":["traefik"],"middlewares":["dashboard_redirect@internal"],"service":"dashboard@internal","rule":"PathPrefix(` + "`/`" + `)","ruleSyntax":"v3","priority":9223372036854775805,"status":"enabled","using":["traefik"],"name":"dashboard@internal","provider":"internal"},{"entryPoints":["web"],"service":"labapp","rule":"Host(` + "`labapp.example.com`" + `)","priority":26,"tls":{"options":"default","certResolver":"lab"},"status":"enabled","using":["web"],"name":"labapp@file","provider":"file"}]`

	everythingServices = `[{"status":"enabled","usedBy":["api@internal"],"name":"api@internal","provider":"internal"},{"status":"enabled","usedBy":["dashboard@internal"],"name":"dashboard@internal","provider":"internal"},{"loadBalancer":{"servers":[{"url":"http://172.19.0.4:8080"},{"url":"http://172.19.0.5:8080"}],"passHostHeader":true},"status":"enabled","usedBy":["broken@file","labapp@file"],"serverStatus":{"http://172.19.0.4:8080":"UP","http://172.19.0.5:8080":"DOWN"},"name":"labapp@file","provider":"file","type":"loadbalancer"},{"status":"enabled","name":"noop@internal","provider":"internal"}]`
)

// The one declared fact no staged document here reaches, and the reason is a
// measurement rather than an omission: a traefik SERVICE error is published by
// providers this lab has none of, and on a live Traefik 3.1.7 the file provider
// accepts every malformed service it was offered. It is named in
// corpus.NAMED_RESIDUALS under traefik/rejected-service, with the venue that
// owns it — so this exception is one half of a claim the Python harness makes
// the other half of, rather than a fact quietly dropped from both.
const residualFact = "services/Error"

func stageEverything(t *testing.T) string {
	t.Helper()
	return stage(t, map[string]string{
		"api-overview.json":      everythingOverview,
		"api-version.json":       healthyVersion,
		"api-entrypoints.json":   healthyEntrypoints,
		"api-http-routers.json":  everythingRouters,
		"api-http-services.json": everythingServices,
	})
}

func TestDeclareEmitsTheEmbeddedBytesExactlyAndStably(t *testing.T) {
	code, first, stderr := runWith(t, "declare\n", nil)
	if code != exitOK {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if first != string(declarationBytes) {
		t.Fatal("declare must emit the embedded declaration verbatim — any re-serialisation un-anchors the hash begin carries")
	}
	_, second, _ := runWith(t, "declare\n", nil)
	if first != second {
		t.Fatal("declare is static and must be byte-stable across runs")
	}

	sum := sha256.Sum256([]byte(first))
	if want := "sha256:" + hex.EncodeToString(sum[:]); declarationDigest != want {
		t.Fatalf("begin's declaration digest %q does not cover the declare bytes (%q)", declarationDigest, want)
	}
}

type declaredFact struct {
	Type        string   `json:"type"`
	Unit        string   `json:"unit"`
	Values      []string `json:"values"`
	Temperament string   `json:"temperament"`
	Kind        string   `json:"kind"`
	Discloses   string   `json:"discloses"`
	Sentence    string   `json:"sentence"`
	From        string   `json:"from"`
}

type declaredCollection struct {
	Name       string                  `json:"name"`
	Prefix     string                  `json:"prefix"`
	Freshness  string                  `json:"freshness"`
	Answer     []string                `json:"answer"`
	Facts      map[string]declaredFact `json:"facts"`
	Redactions []struct {
		Path      string `json:"path"`
		Discloses string `json:"discloses"`
	} `json:"redactions"`
	Exemption string `json:"redaction_exemption"`
	Commands  []struct {
		Purpose string   `json:"purpose"`
		Argv    []string `json:"argv"`
	} `json:"reference_commands"`
}

func decodeDeclaration(t *testing.T) map[string]declaredCollection {
	t.Helper()
	var declaration struct {
		Schema      string               `json:"schema"`
		Collector   string               `json:"collector"`
		Probe       string               `json:"probe"`
		Collections []declaredCollection `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "traefik" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	out := map[string]declaredCollection{}
	for _, collection := range declaration.Collections {
		out[collection.Name] = collection
	}
	if len(out) != len(served) {
		t.Fatalf("the declaration carries %d collections and this collector serves %d", len(out), len(served))
	}
	for name := range served {
		if _, ok := out[name]; !ok {
			t.Fatalf("%s is served and not declared", name)
		}
	}
	return out
}

// emittedFacts runs the collector over both staged shapes and returns every
// fact name it published, per collection. Derived from the RUN rather than
// listed here, because a list retyped in a test drifts into agreement with
// whatever the code happens to do — which is the defect this guard exists to
// catch, one level up.
func emittedFacts(t *testing.T) map[string]map[string]bool {
	t.Helper()
	out := map[string]map[string]bool{}
	for _, dir := range []string{stageHealthy(t), stageEverything(t)} {
		code, stdout, stderr := runWith(t, wholeBatch, map[string]string{"SE_REPLAY_DIR": dir})
		if code != exitOK {
			t.Fatalf("exit %d, stderr: %s", code, stderr)
		}
		for _, record := range ofKind(parseRecords(t, stdout), "object") {
			collection := record["collection"].(string)
			facts, _ := record["facts"].(map[string]any)
			if out[collection] == nil {
				out[collection] = map[string]bool{}
			}
			for name := range facts {
				out[collection][name] = true
			}
		}
	}
	return out
}

// The declared set and the set this code can emit are one set. A fact declared
// and never emitted is a promise nothing tests; one emitted and never declared
// has no sentence, no type and no disclosure class, so nothing downstream can
// render it or redact it.
func TestTheDeclaredFactsAreExactlyTheFactsThisCollectorEmits(t *testing.T) {
	declared := decodeDeclaration(t)
	emitted := emittedFacts(t)

	var orphans []string
	for name, collection := range declared {
		for fact := range collection.Facts {
			if !emitted[name][fact] && name+"/"+fact != residualFact {
				orphans = append(orphans, name+"/"+fact)
			}
		}
	}
	for name, facts := range emitted {
		for fact := range facts {
			if _, ok := declared[name].Facts[fact]; !ok {
				orphans = append(orphans, "undeclared "+name+"/"+fact)
			}
		}
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Fatalf("the declaration and the code disagree about what this collector says: %v", orphans)
	}
}

// The pinned members, asserted from the wire side: the schema-validation half
// (se.declaration.1.json is closed) runs in the Python harness, which owns the
// contract registry.
func TestTheDeclarationCarriesThePinnedContract(t *testing.T) {
	declared := decodeDeclaration(t)

	// The prefix and the row's name are what the collator mints the id from,
	// and `overview:traefik`, `router:<name>` and `service:<name>` are the ids
	// the shipping adapter mints — so a port that moved either would publish a
	// second object for one route.
	prefixes := map[string]string{"overview": "overview", "routers": "router", "services": "service"}
	for name, prefix := range prefixes {
		if declared[name].Prefix != prefix {
			t.Errorf("%s declares prefix %q, and the adapter's id is %s:<name>", name, declared[name].Prefix, prefix)
		}
		if declared[name].Freshness == "" || len(declared[name].Answer) == 0 {
			t.Errorf("%s declares no freshness or no answer set", name)
		}
	}

	// Disclosure is required with no default, and these are the values that
	// decide whether a corpus can be published at all: a rule is how an
	// application is reached, a backend URL is where the request goes, and the
	// two error lists quote the operator's own configuration back at them.
	pinned := map[string]string{
		"routers/Rule":            "location",
		"routers/Error":           "content",
		"routers/Middlewares":     "content",
		"services/Servers":        "location",
		"services/DownServers":    "location",
		"services/Error":          "content",
		"overview/EntryPoints":    "content",
		"overview/Version":        "nothing",
		"overview/RoutersErrors":  "nothing",
		"services/ServersUp":      "nothing",
		"services/ServersDown":    "nothing",
	}
	classes := map[string]bool{"nothing": true, "identity": true, "location": true,
		"content": true, "secret": true}
	for name, collection := range declared {
		for fact, spec := range collection.Facts {
			if spec.Sentence == "" {
				t.Errorf("%s/%s has no sentence, and a sentence is what a consumer renders", name, fact)
			}
			if !classes[spec.Discloses] {
				t.Errorf("%s/%s discloses %q, which is not one of the five classes", name, fact, spec.Discloses)
			}
			if spec.Kind != "observed" {
				// Every figure here is read off the API, including the two
				// counts folded from the health map — nothing on these rows is
				// computed from another FACT, which is what `derived` means.
				t.Errorf("%s/%s is kind %q; every fact here is read off the interface", name, fact, spec.Kind)
			}
			if spec.From == "" {
				t.Errorf("%s/%s declares no `from` path, so a reader with the payload cannot check the reading", name, fact)
			}
			if want, ok := pinned[name+"/"+fact]; ok && spec.Discloses != want {
				t.Errorf("%s/%s discloses %q, pinned %q", name, fact, spec.Discloses, want)
			}
		}
	}

	// Traefik's status vocabulary is closed and three-valued, and an enum
	// without its members is an open set a renderer must guess at.
	for _, name := range []string{"routers", "services"} {
		status := declared[name].Facts["Status"]
		if status.Type != "enum" || len(status.Values) != 3 {
			t.Errorf("%s/Status is %q with values %v; traefik's verdict is enabled, warning or disabled", name, status.Type, status.Values)
		}
	}
}

// Exactly one of the two, per collection: declaring neither is a build failure,
// and an exemption asserting no credential surface beside a declared redaction
// list is two rulings contradicting each other in one document.
func TestEachCollectionEitherDeclaresItsRedactionsOrWhyItNeedsNone(t *testing.T) {
	declared := decodeDeclaration(t)
	for name, collection := range declared {
		if (len(collection.Redactions) == 0) == (collection.Exemption == "") {
			t.Errorf("%s declares %d redactions and an exemption of %d characters", name, len(collection.Redactions), len(collection.Exemption))
		}
	}
	// The services document is the one that carries a credential surface, and
	// it is a specific one: a file-provider backend URL can embed basic-auth
	// userinfo, which reaches Servers, DownServers and the evidence payload
	// alike. The paths the reference actually rewrites are the paths declared.
	paths := map[string]bool{}
	for _, redaction := range declared["services"].Redactions {
		paths[redaction.Path] = true
		if redaction.Discloses != "secret" {
			t.Errorf("%s is redacted as %q; what is withheld there is the credential", redaction.Path, redaction.Discloses)
		}
	}
	for _, path := range []string{"/loadBalancer/servers/*/url", "/loadBalancer/servers/*/address", "/serverStatus"} {
		if !paths[path] {
			t.Errorf("the services collection does not declare %s, and _redact_service_evidence rewrites it", path)
		}
	}
}

// The declared commands must be the requests this collector actually makes: a
// reference command is what an administrator re-runs by hand to check the
// reading, and one naming a path the code never fetches documents a collector
// that does not exist.
func TestTheReferenceCommandsNameEveryPathThisCollectorFetches(t *testing.T) {
	declared := decodeDeclaration(t)
	joined := ""
	for _, collection := range declared {
		for _, command := range collection.Commands {
			if command.Purpose == "" {
				t.Errorf("reference command %v states no purpose", command.Argv)
			}
			joined += strings.Join(command.Argv, " ") + "\n"
		}
	}
	for _, path := range acquiredPaths {
		if !strings.Contains(joined, path) {
			t.Errorf("no reference command names %s, which this collector fetches", path)
		}
	}
	// The endpoint is deployment configuration, so the commands name the
	// variable rather than an address this file invented — an estate that
	// publishes the API somewhere else would otherwise be handed a command that
	// reads nothing.
	if !strings.Contains(joined, urlVariable) {
		t.Errorf("the reference commands do not name %s, and the endpoint is not a constant", urlVariable)
	}
}

// The probe prose has to name where the endpoint comes from, for the same
// reason: a probe an operator cannot act on is a probe they will ignore, and
// "no traefik here" and "SE_TRAEFIK_URL is unset" are the same reading with
// very different fixes.
func TestTheProbeProseNamesTheEndpointVariable(t *testing.T) {
	var declaration struct {
		Probe     string `json:"probe"`
		Authority struct {
			ReadPaths []string `json:"read_paths"`
		} `json:"authority"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(declaration.Probe, urlVariable) {
		t.Errorf("the probe prose must name %s, which is where the endpoint comes from", urlVariable)
	}
	for _, path := range declaration.Authority.ReadPaths {
		if !strings.HasPrefix(path, "/proc/") {
			t.Errorf("read path %q: the only paths this collector opens are the two /proc files the envelope needs — the API is reached over HTTP", path)
		}
	}
}
