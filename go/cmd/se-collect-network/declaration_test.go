package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

type declaredCollection struct {
	Name      string   `json:"name"`
	Question  string   `json:"question"`
	Prefix    string   `json:"prefix"`
	Freshness string   `json:"freshness"`
	Answer    []string `json:"answer"`
	Facts     map[string]struct {
		Type        string   `json:"type"`
		Kind        string   `json:"kind"`
		DerivedFrom []string `json:"derived_from"`
		Discloses   string   `json:"discloses"`
		Sentence    string   `json:"sentence"`
		Values      []string `json:"values"`
	} `json:"facts"`
	Redactions []any  `json:"redactions"`
	Exemption  string `json:"redaction_exemption"`
}

func parseDeclaration(t *testing.T) map[string]declaredCollection {
	t.Helper()
	var declaration struct {
		Schema    string `json:"schema"`
		Collector string `json:"collector"`
		Authority struct {
			ReadPaths    []string `json:"read_paths"`
			Commands     []string `json:"commands"`
			Capabilities []string `json:"capabilities"`
		} `json:"authority"`
		Collections []declaredCollection `json:"collections"`
	}
	if err := json.Unmarshal(declarationBytes, &declaration); err != nil {
		t.Fatal(err)
	}
	if declaration.Schema != "se.declaration/1" || declaration.Collector != "network" {
		t.Fatalf("collector %q under schema %q", declaration.Collector, declaration.Schema)
	}
	// The nft half reads no file — its interface is a subprocess talking
	// netlink — and since R3b the listening collection reads exactly one
	// tree: /proc/net's socket tables. Anything beyond that pair would be
	// a sandbox opening nothing needs.
	wantPaths := []string{"/etc/resolv.conf", "/proc/net"}
	if len(declaration.Authority.ReadPaths) != len(wantPaths) ||
		declaration.Authority.ReadPaths[0] != wantPaths[0] ||
		declaration.Authority.ReadPaths[1] != wantPaths[1] {
		t.Errorf("read_paths is %v, want %v", declaration.Authority.ReadPaths, wantPaths)
	}
	wantCommands := []string{"bridge", "busctl", "ip", "networkctl", "nft"}
	if len(declaration.Authority.Commands) != len(wantCommands) {
		t.Errorf("authority.commands is %v, want %v", declaration.Authority.Commands, wantCommands)
	}
	if len(declaration.Authority.Capabilities) != 1 || declaration.Authority.Capabilities[0] != "CAP_NET_ADMIN" {
		t.Errorf("authority.capabilities is %v", declaration.Authority.Capabilities)
	}
	out := map[string]declaredCollection{}
	for _, collection := range declaration.Collections {
		out[collection.Name] = collection
	}
	if len(out) != 9 {
		t.Fatalf("nine collections — the nft trio, port-exposure, tailscale, routes, listening, resolver, links; got %d", len(out))
	}
	return out
}

// Every fact this collector can emit must be declared, and nothing else: an
// undeclared fact is a value no consumer has a sentence for, and a declared
// fact nothing emits is a promise nobody keeps.
func TestTheDeclarationCoversExactlyTheFactsEitherCollectionEmits(t *testing.T) {
	declared := parseDeclaration(t)
	emitted := map[string][]string{
		"tailscale": {"HostName", "DNSName", "TailscaleIPs", "OS", "Online",
			"LastSeen", "Relay", "CurAddr", "RxBytes", "TxBytes", "ExitNode",
			"ExitNodeOption", "KeyExpiry", "KeyExpiryDays", "MagicDNSSuffix",
			"BackendState", "Health", "PrimaryRoutes", "TailscaleSnapshotAt",
			"TailscaleSnapshotAgeSeconds"},
		"port-exposure": {"Protocol", "LocalAddress", "LocalPort", "Scope",
			"PathCoverage", "AdmittingRules", "AdmittedFromCertain",
			"AdmittedFromPossible", "ClosureGap", "ClosureGapRules"},
		"nft-tables": {"Family", "Chains", "ChainCount", "RuleCount"},
		"nft-chains": {"Family", "Table", "Name", "Handle", "BaseChain", "Hook",
			"Type", "Priority", "Policy", "RuleCount", "JumpedFrom", "Unreferenced"},
		"nft-rules": {"Family", "Table", "Chain", "Handle", "Position", "Rendered",
			"Verdict", "JumpTarget", "Comprehension", "OpaqueReason", "Residue",
			"CounterPackets", "CounterBytes"},
	}
	for collection, facts := range emitted {
		got := declared[collection]
		if len(got.Facts) != len(facts) {
			t.Errorf("%s declares %d facts, emits %d", collection, len(got.Facts), len(facts))
		}
		for _, fact := range facts {
			entry, ok := got.Facts[fact]
			if !ok {
				t.Errorf("%s emits %s and does not declare it", collection, fact)
				continue
			}
			if entry.Sentence == "" {
				t.Errorf("%s.%s has no sentence, and a sentence is what a consumer renders", collection, fact)
			}
			if entry.Discloses == "" {
				t.Errorf("%s.%s declares no disclosure class", collection, fact)
			}
			// Law 4: a derived fact names the facts it consumed, because a
			// derivation with no stated inputs cannot be re-checked.
			if entry.Kind == "derived" && len(entry.DerivedFrom) == 0 {
				t.Errorf("%s.%s is derived and names no inputs", collection, fact)
			}
			if entry.Type == "enum" && len(entry.Values) == 0 {
				t.Errorf("%s.%s is an enum with no members", collection, fact)
			}
		}
		for _, fact := range got.Answer {
			if _, ok := got.Facts[fact]; !ok {
				t.Errorf("%s answers with %s, which it does not declare", collection, fact)
			}
		}
		if got.Question == "" || got.Prefix == "" || got.Freshness == "" {
			t.Errorf("%s: question %q prefix %q freshness %q", collection, got.Question, got.Prefix, got.Freshness)
		}
		// Exactly one of the two, never neither and never both: declaring
		// neither is a build failure, and an exemption beside a redaction
		// list is two rulings contradicting each other in one document.
		if (got.Exemption == "") == (len(got.Redactions) == 0) {
			t.Errorf("%s: exemption %q beside %d redactions", collection, got.Exemption, len(got.Redactions))
		}
	}
}

// The three derived facts the reference's own fact_kinds table pins for each
// collection. Getting one wrong here publishes an observation as a derivation
// or the reverse, which is what law 4's re-checkability rests on.
func TestTheDeclaredFactKindsMatchTheReferences(t *testing.T) {
	declared := parseDeclaration(t)
	derived := map[string]map[string]bool{
		"tailscale": {"KeyExpiryDays": true,
			"TailscaleSnapshotAgeSeconds": true},
		"port-exposure": {"Scope": true, "PathCoverage": true,
			"AdmittingRules": true, "AdmittedFromCertain": true,
			"AdmittedFromPossible": true, "ClosureGap": true,
			"ClosureGapRules": true},
		"nft-tables": {"ChainCount": true},
		"nft-chains": {"JumpedFrom": true, "Unreferenced": true, "BaseChain": true},
		"nft-rules": {"Rendered": true, "Comprehension": true, "OpaqueReason": true,
			"Residue": true, "Position": true},
	}
	for collection, wanted := range derived {
		for fact, entry := range declared[collection].Facts {
			want := "observed"
			if wanted[fact] {
				want = "derived"
			}
			if entry.Kind != want {
				t.Errorf("%s.%s is declared %q, want %q", collection, fact, entry.Kind, want)
			}
		}
	}
}

// Rendered and Residue interpolate match comparands verbatim, and a comparand
// is occasionally a bare address — so both are `location`, and the rule
// comment nobody serves is named as the content surface it is.
func TestTheRuleCollectionDeclaresWhatItsTextCanCarry(t *testing.T) {
	rules := parseDeclaration(t)["nft-rules"]
	for _, fact := range []string{"Rendered", "Residue"} {
		if got := rules.Facts[fact].Discloses; got != "location" {
			t.Errorf("%s discloses %q, want location", fact, got)
		}
	}
	if len(rules.Redactions) != 3 {
		t.Errorf("the three payload paths whose values are not served verbatim; got %d", len(rules.Redactions))
	}
}
