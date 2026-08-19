package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

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
		Collections []declaredCollection `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "downloaders" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	out := map[string]declaredCollection{}
	for _, collection := range declaration.Collections {
		out[collection.Name] = collection
	}
	if len(out) != 2 {
		t.Fatalf("two collections, clients and transfers; got %v", out)
	}
	return out
}

// The declared set and the set this code can emit are ONE set: a fact declared
// and never emitted is a promise nothing tests, and one emitted and never
// declared has no sentence, no type and no disclosure class. Enumerated here
// from the source rather than derived from a run, because a run over the
// healthy capture reaches neither configuration-fault fact and would let either
// rot out of the declaration unnoticed.
var emittedFacts = map[string][]string{
	collectionClients: {
		"Client", "Version", "Paused", "DownloadRateBytes", "UploadRateBytes",
		"QueueCount", "ActiveTorrentCount", "PausedTorrentCount", "TorrentCount",
		"DiskFreeBytes", "DiskTotalBytes", "ConfigMissing", "StatusUnobservable",
	},
	collectionTransfers: {
		"Client", "Name", "Status", "PercentDone", "RateDownloadBytes",
		"RateUploadBytes", "SizeWhenDoneBytes", "LeftUntilDoneBytes",
		"SizeMB", "LeftMB", "TimeLeft", "Error", "ErrorString", "IsStalled",
	},
}

func TestTheDeclarationCarriesThePinnedContract(t *testing.T) {
	collections := decodeDeclaration(t)
	// The prefix and the row's name are what the collator mints the id from,
	// and `client:transmission` and `transfer:transmission/<hash>` are the ids
	// the shipping adapter mints — so a port that moved either would publish a
	// second object for one client.
	prefixes := map[string]string{collectionClients: "client", collectionTransfers: "transfer"}
	for name, want := range prefixes {
		collection := collections[name]
		if collection.Prefix != want {
			t.Errorf("%s declares prefix %q, and the adapter's id is %s:<name>", name, collection.Prefix, want)
		}
		if collection.Freshness != "60s" {
			t.Errorf("%s at freshness %q", name, collection.Freshness)
		}
		declared := collection.Facts
		emitted := map[string]bool{}
		for _, fact := range emittedFacts[name] {
			emitted[fact] = true
			if _, ok := declared[fact]; !ok {
				t.Errorf("%s/%s is emitted and not declared", name, fact)
			}
		}
		for fact, spec := range declared {
			if !emitted[fact] {
				t.Errorf("%s/%s is declared and this collector cannot emit it", name, fact)
			}
			if spec.Sentence == "" {
				t.Errorf("%s/%s has no sentence, and a sentence is what a consumer renders", name, fact)
			}
			if spec.Kind != "observed" {
				t.Errorf("%s/%s is %q: every figure here is a reading the client stated, including the ones re-expressed in another unit", name, fact, spec.Kind)
			}
		}
		for _, fact := range collection.Answer {
			if _, ok := declared[fact]; !ok {
				t.Errorf("%s names %q in its answer and does not declare it", name, fact)
			}
		}
	}
}

// Temperament decides whether a fact churns the snapshot diff (DESIGN 12),
// which is why it is pinned rather than left to reading: every rate and count
// here moves on every sample and must be a gauge, and the two handles that
// never move must not be — a Client declared `state` would report this host as
// changed on every collect, for ever.
func TestTheTemperamentsArePinned(t *testing.T) {
	collections := decodeDeclaration(t)
	pinned := map[string]map[string]string{
		collectionClients: {
			"Client": "configuration", "Version": "configuration",
			"Paused": "state", "DownloadRateBytes": "gauge",
			"UploadRateBytes": "gauge", "QueueCount": "gauge",
			"ActiveTorrentCount": "gauge", "PausedTorrentCount": "gauge",
			"TorrentCount": "gauge", "DiskFreeBytes": "gauge",
			"DiskTotalBytes": "gauge", "ConfigMissing": "configuration",
			"StatusUnobservable": "state",
		},
		collectionTransfers: {
			"Client": "configuration", "Name": "configuration",
			"Status": "state", "PercentDone": "gauge",
			"RateDownloadBytes": "gauge", "RateUploadBytes": "gauge",
			"SizeWhenDoneBytes": "gauge", "LeftUntilDoneBytes": "gauge",
			"SizeMB": "gauge", "LeftMB": "gauge", "TimeLeft": "gauge",
			"Error": "state", "ErrorString": "state", "IsStalled": "state",
		},
	}
	for collection, facts := range pinned {
		for fact, want := range facts {
			if got := collections[collection].Facts[fact].Temperament; got != want {
				t.Errorf("%s/%s is declared %q, pinned %q", collection, fact, got, want)
			}
		}
	}
}

// The two facts that carry text from outside the estate, and they are the only
// two. `discloses` is what a policy acts on (DESIGN 21), and a media title
// classified `nothing` would travel verbatim to a broker somebody else runs.
func TestOnlyTheTextFromOutsideTheEstateIsContent(t *testing.T) {
	collections := decodeDeclaration(t)
	content := map[string]bool{"transfers/Name": true, "transfers/ErrorString": true}
	for name, collection := range collections {
		for fact, spec := range collection.Facts {
			want := "nothing"
			if content[name+"/"+fact] {
				want = "content"
			}
			if spec.Discloses != want {
				t.Errorf("%s/%s discloses %q, pinned %q", name, fact, spec.Discloses, want)
			}
		}
	}
}

// PercentDone carries NO declared unit, and the omission is the decision.
// `percent` requires a declared denominator, one collection declares one
// denominator, and this fact is a percentage of SizeWhenDoneBytes on a torrent
// and of SizeMB on an nzb — so naming either would be wrong on every row from
// the other client. Pinned because it looks like an oversight and is not.
func TestPercentDoneDeclaresNoUnitBecauseItsDenominatorDiffersByClient(t *testing.T) {
	spec := decodeDeclaration(t)[collectionTransfers].Facts["PercentDone"]
	if spec.Unit != "" {
		t.Fatalf("PercentDone declares unit %q; a percent needs one denominator and this fact has two", spec.Unit)
	}
	if !strings.Contains(spec.Sentence, "denominator") {
		t.Fatal("the sentence must say why the unit is absent, or the next reader adds one back")
	}
}

// The Client enum's members are the two clients this collector reads, and they
// are the same two strings the rows carry — a value outside the declared set is
// refused by contract verification, and a declared member nothing emits is a
// vocabulary nobody checks.
func TestTheClientEnumIsExactlyTheTwoClientsThisCollectorReads(t *testing.T) {
	for name, collection := range decodeDeclaration(t) {
		values := collection.Facts["Client"].Values
		if len(values) != 2 || values[0] != clientTransmission || values[1] != clientSabnzbd {
			t.Errorf("%s declares Client values %v, and the source spells %q and %q",
				name, values, clientTransmission, clientSabnzbd)
		}
	}
}

// No reference command carries a real credential, and every one that reaches
// sabnzbd shows the key as a placeholder. The key travels as a QUERY PARAMETER
// — the only place the API accepts it — so a reference command is exactly the
// artefact where somebody would paste a working one.
func TestNoReferenceCommandCarriesACredential(t *testing.T) {
	for name, collection := range decodeDeclaration(t) {
		if len(collection.Commands) == 0 {
			t.Errorf("%s declares no reference command, so no reading here can be checked by hand", name)
		}
		for _, command := range collection.Commands {
			if command.Purpose == "" {
				t.Errorf("%s: reference command %v states no purpose", name, command.Argv)
			}
			for _, token := range command.Argv {
				if strings.Contains(token, "apikey=") && !strings.Contains(token, "apikey=<key>") {
					t.Errorf("%s: %q carries something other than the <key> placeholder", name, token)
				}
			}
		}
	}
}

// The evidence payloads this collector WOULD serve carry a credential, so the
// declaration names redactions rather than claiming an exemption. sabnzbd's
// status document holds its own `apikey` and a queue slot holds an archive
// password; a `redaction_exemption` would be the reviewed statement that this
// source has no credential surface, and that statement would be false.
func TestTheDeclarationNamesItsSecretPathsRatherThanClaimingAnExemption(t *testing.T) {
	for name, collection := range decodeDeclaration(t) {
		if collection.Exemption != "" {
			t.Errorf("%s claims a no-credential-surface exemption, and sabnzbd serves its own key in the status document", name)
		}
		secrets := 0
		for _, redaction := range collection.Redactions {
			if redaction.Discloses == "secret" {
				secrets++
			}
		}
		if secrets == 0 {
			t.Errorf("%s declares no secret path; the credential surface is the reason this list exists", name)
		}
	}
}

// The receipts are named by environment variable and no URL is declared as an
// authority: which clients exist is deployment configuration, and a URL this
// file invented would point at whatever answers that port on the host.
func TestTheDeclarationAsksForTheKeyAndNoInventedURL(t *testing.T) {
	var declaration struct {
		Authority struct {
			ReadPaths   []string `json:"read_paths"`
			Credentials []string `json:"credentials"`
		} `json:"authority"`
		Probe string `json:"probe"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	for _, path := range declaration.Authority.ReadPaths {
		if !strings.HasPrefix(path, "/proc/") {
			t.Errorf("read path %q: the only paths this collector opens are the two /proc files the envelope needs", path)
		}
	}
	if len(declaration.Authority.Credentials) != 1 || declaration.Authority.Credentials[0] != sabKeyVariable {
		t.Errorf("the declared credentials are %v; the deployment grants %s and nothing else",
			declaration.Authority.Credentials, sabKeyVariable)
	}
	for _, variable := range []string{transmissionVariable, sabURLVariable, sabKeyVariable} {
		if !strings.Contains(declaration.Probe, variable) {
			t.Errorf("the probe prose must name %s, which is where a receipt comes from", variable)
		}
	}
}
