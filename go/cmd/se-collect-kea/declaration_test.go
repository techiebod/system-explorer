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
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "kea" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	out := map[string]declaredCollection{}
	for _, collection := range declaration.Collections {
		out[collection.Name] = collection
	}
	return out
}

// The declared collections and the SERVED ones are one set, in both directions.
// A collection declared and not served is a promise the binary breaks the first
// time somebody asks for it; one served and not declared has no facts, no
// sentences and no prefix, so the collator can neither render it nor mint an id
// for its rows.
func TestTheDeclaredCollectionsAreExactlyTheServedOnes(t *testing.T) {
	declared := decodeDeclaration(t)
	for name := range served {
		if _, ok := declared[name]; !ok {
			t.Errorf("%s is served and not declared", name)
		}
	}
	for name := range declared {
		if _, ok := served[name]; !ok {
			t.Errorf("%s is declared and not served", name)
		}
	}
}

// The prefix and the row's name are what the collator mints the id from, so a
// port that moved either would publish a second object for one thing. These four
// are the prefixes the shipping adapter's own ids carry.
func TestEachCollectionDeclaresThePrefixItsIdsAreMintedFrom(t *testing.T) {
	want := map[string]string{
		collectionDaemon:       "daemon",
		collectionSubnets:      "subnet",
		collectionReservations: "reservation",
		collectionLeases:       "lease",
	}
	declared := decodeDeclaration(t)
	for name, prefix := range want {
		if got := declared[name].Prefix; got != prefix {
			t.Errorf("%s declares prefix %q, and the adapter's id is %s:<name>", name, got, prefix)
		}
	}
}

// Temperament decides whether a fact churns the snapshot diff (DESIGN 12),
// which is why it is pinned rather than left to reading. The split here is the
// whole point of this collector: a subnet's counters move on every lease and its
// configuration does not, so a port that declared ReservationCount a gauge would
// report every DHCP server in the estate as changed on every sweep, and one that
// declared AssignedAddresses configuration would report a pool filling up as no
// change at all.
func TestTheDeclaredTemperamentsSeparateTheCountersFromTheConfiguration(t *testing.T) {
	want := map[string]map[string]string{
		collectionDaemon: {
			"Version": "configuration", "Uptime": "gauge",
			"QueueDepthAverages": "gauge",
		},
		collectionSubnets: {
			"Subnet": "configuration", "SubnetId": "configuration",
			"TotalAddresses": "gauge", "AssignedAddresses": "gauge",
			"DeclinedAddresses": "gauge", "UsedPercent": "gauge",
			"LeaseTimeSeconds": "configuration", "Routers": "configuration",
			"DnsServers": "configuration", "ReservationCount": "configuration",
			"UnlistedReservations": "configuration",
		},
		collectionReservations: {
			"IpAddress": "configuration", "HwAddress": "configuration",
			"Hostname": "configuration", "Subnet": "configuration",
		},
		collectionLeases: {
			"IpAddress": "state", "HwAddress": "state", "Hostname": "state",
			"State": "state", "Subnet": "configuration", "ExpiresAt": "state",
		},
	}
	declared := decodeDeclaration(t)
	for collection, facts := range want {
		if got := len(declared[collection].Facts); got != len(facts) {
			t.Errorf("%s declares %d facts, pinned %d: %v", collection, got,
				len(facts), declared[collection].Facts)
		}
		for fact, temperament := range facts {
			held, ok := declared[collection].Facts[fact]
			if !ok {
				t.Errorf("%s/%s is not declared", collection, fact)
				continue
			}
			if held.Temperament != temperament {
				t.Errorf("%s/%s is declared %q, pinned %q", collection, fact,
					held.Temperament, temperament)
			}
			if held.Sentence == "" {
				t.Errorf("%s/%s has no sentence, and a sentence is what a consumer renders", collection, fact)
			}
		}
	}
}

// The disclosure class is what a public corpus, a hub and an MCP consumer each
// act on (DESIGN 21), and this collector is the first whose native document
// carries a machine's own hardware address. These four are the ones that would
// cost something if they were wrong.
func TestTheIdentifyingFactsAreDeclaredAsSuch(t *testing.T) {
	declared := decodeDeclaration(t)
	want := map[string]map[string]string{
		collectionSubnets:      {"Subnet": "location", "Routers": "location", "DnsServers": "location"},
		collectionReservations: {"HwAddress": "identity", "IpAddress": "location", "Hostname": "content"},
		collectionLeases:       {"HwAddress": "identity", "IpAddress": "location", "Hostname": "content"},
	}
	for collection, facts := range want {
		for fact, discloses := range facts {
			if got := declared[collection].Facts[fact].Discloses; got != discloses {
				t.Errorf("%s/%s discloses %q, pinned %q", collection, fact, got, discloses)
			}
		}
	}
}

// Every collection that serves evidence declares its redactions, or declares
// why it needs none — declaring NEITHER is a build failure (DESIGN 19), and
// declaring both is two rulings contradicting each other in one document. Three
// of these four have a real credential surface: a Kea configuration can carry a
// database password, and its reservations and leases carry the identifiers of
// every machine on the network.
func TestEveryCollectionCarriesExactlyOneRedactionRuling(t *testing.T) {
	for name, collection := range decodeDeclaration(t) {
		hasList, hasExemption := len(collection.Redactions) > 0, collection.Exemption != ""
		if hasList == hasExemption {
			t.Errorf("%s declares %d redactions and an exemption of %d characters — exactly one must",
				name, len(collection.Redactions), len(collection.Exemption))
		}
	}
}

// The one class that is not substituted but WITHHELD. A Kea configured against
// MySQL or PostgreSQL states its password in the running configuration, which is
// exactly what config-get hands back — so the two collections that serve that
// document must name those paths as secret, or the first estate host with a
// database backend puts a credential into an evidence response.
func TestTheDatabasePasswordPathsAreDeclaredSecret(t *testing.T) {
	declared := decodeDeclaration(t)
	for _, name := range []string{collectionSubnets, collectionReservations} {
		secrets := 0
		for _, redaction := range declared[name].Redactions {
			if redaction.Discloses == "secret" {
				secrets++
				if !strings.HasSuffix(redaction.Path, "password") {
					t.Errorf("%s declares %q secret, which is not a credential path", name, redaction.Path)
				}
			}
		}
		if secrets == 0 {
			t.Errorf("%s serves config-get and names no credential path; a Kea with a "+
				"database backend writes its password there", name)
		}
	}
}

// The declared reference commands and the commands in source.go are one set. A
// declaration naming a command this binary never sends documents an interface
// nobody reads, and a command this binary sends that no reference command names
// is a reading an administrator cannot reproduce by hand (DESIGN 25).
func TestTheReferenceCommandsAreTheCommandsThisBinarySends(t *testing.T) {
	sent := map[string]bool{
		collectionDaemon:       true,
		collectionSubnets:      true,
		collectionReservations: true,
		collectionLeases:       true,
	}
	perCollection := map[string][]string{
		collectionDaemon:       {commandVersion, commandStatus},
		collectionSubnets:      {commandStatistics, commandConfig},
		collectionReservations: {commandConfig},
		collectionLeases:       {commandLeases, commandConfig},
	}
	declared := decodeDeclaration(t)
	for collection := range sent {
		named := map[string]bool{}
		for _, command := range declared[collection].Commands {
			if command.Purpose == "" {
				t.Errorf("%s: reference command %v states no purpose", collection, command.Argv)
			}
			for _, token := range command.Argv {
				named[token] = true
			}
		}
		for _, command := range perCollection[collection] {
			if !named[command] {
				t.Errorf("%s reads %q and no reference command names it", collection, command)
			}
		}
		if len(declared[collection].Commands) != len(perCollection[collection]) {
			t.Errorf("%s declares %d reference commands and sends %d",
				collection, len(declared[collection].Commands), len(perCollection[collection]))
		}
	}
}

// The socket path is deployment configuration, so it is named by SE_KEA_SOCKET
// and not declared as a read path: a path invented here would be granted on the
// hosts that put the socket elsewhere and denied on the ones that do not. What
// the deployment must grant is the socket's GROUP — Kea's runtime directory is
// 0750, so a permissions gap is the first failure mode on the target and must
// never read as no-DHCP-here.
func TestTheDeclarationAsksForTheSocketsGroupAndNoInventedPath(t *testing.T) {
	var declaration struct {
		Authority struct {
			ReadPaths []string `json:"read_paths"`
			Groups    []string `json:"groups"`
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
	if len(declaration.Authority.Groups) == 0 {
		t.Error("a control socket this collector may not open is the unauthorised decline; the group is what the deployment grants")
	}
	if !strings.Contains(declaration.Probe, socketVariable) {
		t.Errorf("the probe prose must name %s, which is where the socket's path comes from", socketVariable)
	}
	// The gate that decides a whole collection, stated where a reader of the
	// declaration meets it rather than only in the decline they eventually get.
	if !strings.Contains(declaration.Probe, commandLeases) {
		t.Errorf("the probe prose must name %s: whether this Kea offers it decides whether the leases collection exists here", commandLeases)
	}
}
