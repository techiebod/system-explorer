// The lookup verb, against documents taken from the lab guest — real
// `ip -j route get` and busctl resolve1 output, so the shapes are the tools'
// own. One hand-made extension is marked where it happens: a link-local
// answer, added to a real reply because the guest's resolver never serves
// one, and the scope-suffix branch has to be reachable somewhere.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The guest's own answer for a documentation address, via the libvirt
// default network. No table, protocol, scope or metric members: `ip route
// get` omits what the route does not carry, and the facts must too.
const labRouteV4 = `[{"dst":"192.0.2.7","gateway":"192.168.122.1","dev":"ens2",` +
	`"prefsrc":"192.168.122.3","flags":[],"uid":1000,"cache":[]}]`

const labBus = `{
 "/org/freedesktop/resolve1 org.freedesktop.resolve1.Manager ResolveHostname isit 0 localhost 0 0":
  {"type":"a(iiay)st","data":[[[1,2,[127,0,0,1]],[1,10,[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]]],"localhost",786945]},
 "/org/freedesktop/resolve1 org.freedesktop.resolve1.Manager ResolveHostname isit 0 se-test-ubuntu2604 0 0":
  {"type":"a(iiay)st","data":[[[0,2,[127,0,1,1]],[2,10,[254,128,0,0,0,0,0,0,0,0,0,0,0,0,0,1]]],"se-test-ubuntu2604",786945]},
 "/org/freedesktop/resolve1 org.freedesktop.resolve1.Manager ResolveAddress iiayt 0 2 4 127 0 0 1 0":
  {"type":"a(is)t","data":[[[1,"localhost"]],786945]},
 "/org/freedesktop/resolve1 org.freedesktop.resolve1.Manager ResolveHostname isit 0 nosuch.invalid 0 0":
  false
}`

// The second ResolveHostname entry above is the guest's real reply plus one
// hand-added address: fe80::1 at ifindex 2, because the scope-suffix rule
// (%ens2 on link-local, nothing on anything else) needs a link-local answer
// to bite on and the lab resolver serves none.

func stageLookup(t *testing.T) map[string]string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range map[string]string{
		"ip-route-get-192-0-2-7.json": labRouteV4,
		// A staged string is the kernel's refusal as captured (source.go).
		"ip-route-get-2001_db8__1.json": `"RTNETLINK answers: Network is unreachable"`,
		"bus.json":                      labBus,
		"ifindex.json":                  `[[1,"lo"],[2,"ens2"]]`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return map[string]string{
		"SE_REPLAY_DIR": dir,
		// Pinned so QueryTimeMs derives to a stable 0.0 — both readings of
		// now() are the capture's own moment.
		"SE_REPLAY_NOW": "2026-08-23T12:00:00Z",
	}
}

func lookupFacts(t *testing.T, request string) (map[string]any, []map[string]any) {
	t.Helper()
	code, stdout, stderr := runWith(t, request+"\n", stageLookup(t))
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one object, got %d", len(objects))
	}
	if terminators := ofKind(records, "verb_end"); len(terminators) != 1 ||
		terminators[0]["verb"] != "lookup" {
		t.Fatalf("every lookup response ends with its terminator: %v", terminators)
	}
	return objects[0]["facts"].(map[string]any), records
}

func TestRouteGetAnswersTheKernelsChoice(t *testing.T) {
	facts, records := lookupFacts(t, "lookup route-get 192.0.2.7")
	object := ofKind(records, "object")[0]
	if object["collection"] != "lookups" || object["name"] != "route-get/192.0.2.7" ||
		object["type"] != "lookup-result" {
		t.Fatalf("%+v", object)
	}
	if facts["RouteFound"] != true || facts["Destination"] != "192.0.2.7" ||
		facts["Gateway"] != "192.168.122.1" || facts["Device"] != "ens2" ||
		facts["PreferredSource"] != "192.168.122.3" {
		t.Fatalf("%+v", facts)
	}
	// Present-only: this route carries no table, protocol, scope or metric
	// member, so no fact invents one.
	for _, absent := range []string{"Table", "Protocol", "Scope", "Metric", "KernelError"} {
		if _, present := facts[absent]; present {
			t.Errorf("%s is served and the document does not carry it", absent)
		}
	}
	// The edge joins the answer to the link the kernel chose.
	edge := ofKind(records, "relation_assertion")[0]
	target := edge["target"].(map[string]any)
	if edge["type"] != "routes-via" || target["kind"] != "link" || target["name"] != "ens2" {
		t.Fatalf("%+v", edge)
	}
}

func TestRouteGetCarriesTheKernelsRefusalAsAnAnswer(t *testing.T) {
	facts, records := lookupFacts(t, "lookup route-get 2001:db8::1")
	if facts["RouteFound"] != false ||
		facts["KernelError"] != "RTNETLINK answers: Network is unreachable" {
		t.Fatalf("%+v", facts)
	}
	if len(ofKind(records, "relation_assertion")) != 0 {
		t.Fatal("no route, no edge")
	}
}

func TestResolveForwardAnswersAddresses(t *testing.T) {
	facts, _ := lookupFacts(t, "lookup resolve localhost")
	addresses := facts["Addresses"].([]any)
	// ::1 sits at ifindex 1 in the reply but is loopback, not link-local, so
	// it carries no scope suffix.
	if len(addresses) != 2 || addresses[0] != "127.0.0.1" || addresses[1] != "::1" {
		t.Fatalf("%v", addresses)
	}
	if facts["Resolved"] != true || facts["CanonicalName"] != "localhost" ||
		facts["Protocol"] != "DNS" || facts["Authenticated"] != true {
		t.Fatalf("%+v", facts)
	}
	if facts["QueryTimeMs"] != float64(0) {
		t.Fatalf("pinned replay must derive a stable elapsed: %v", facts["QueryTimeMs"])
	}
}

func TestResolveScopesOnlyTheLinkLocalAnswer(t *testing.T) {
	facts, _ := lookupFacts(t, "lookup resolve se-test-ubuntu2604")
	addresses := facts["Addresses"].([]any)
	if len(addresses) != 2 || addresses[0] != "127.0.1.1" || addresses[1] != "fe80::1%ens2" {
		t.Fatalf("%v", addresses)
	}
}

func TestResolveReverseAnswersNames(t *testing.T) {
	facts, records := lookupFacts(t, "lookup resolve 127.0.0.1")
	if ofKind(records, "object")[0]["name"] != "resolve/127.0.0.1" {
		t.Fatalf("%+v", records[0])
	}
	names := facts["Names"].([]any)
	if len(names) != 1 || names[0] != "localhost" {
		t.Fatalf("%v", names)
	}
	if facts["Resolved"] != true || facts["Protocol"] != "DNS" {
		t.Fatalf("%+v", facts)
	}
}

func TestResolveCarriesTheDaemonsRefusalAsAnAnswer(t *testing.T) {
	facts, _ := lookupFacts(t, "lookup resolve nosuch.invalid")
	if facts["Resolved"] != false || facts["Result"] != "staged as failed at capture" {
		t.Fatalf("%+v", facts)
	}
	// The live composition: busctl's stderr rides the sentinel and the fact
	// carries the daemon's words with busctl's framing trimmed.
	live := fmt.Errorf("%w: %s", errCallFailed, "Call failed: Name 'nosuch.invalid' not found")
	if got := failureText(live, errCallFailed); got != "Call failed: Name 'nosuch.invalid' not found" {
		t.Fatalf("%q", got)
	}
}

func TestLookupRefusesWhatItCannotAnswer(t *testing.T) {
	for request, detail := range map[string]string{
		"lookup route-get not-an-address": "not an IPv4 or IPv6 address",
		"lookup resolve bad/name":         "not a hostname or IP address",
		"lookup nonesuch anything":        "route-get and resolve",
	} {
		code, stdout, stderr := runWith(t, request+"\n", stageLookup(t))
		if code != exitOK {
			t.Fatalf("%q: a decline is data, not a crash: exit %d, %s", request, code, stderr)
		}
		records := parseRecords(t, stdout)
		decline := ofKind(records, "decline")[0]
		if decline["reason"] != "unsupported" ||
			!strings.Contains(decline["detail"].(string), detail) {
			t.Fatalf("%q: %+v", request, decline)
		}
		if len(ofKind(records, "verb_end")) != 1 {
			t.Fatalf("%q: no terminator", request)
		}
	}
}

func TestLookupRequestShapeIsExactlyThreeTokens(t *testing.T) {
	for _, request := range []string{"lookup route-get", "lookup resolve a b"} {
		code, _, _ := runWith(t, request+"\n", stageLookup(t))
		if code != exitRequest {
			t.Fatalf("%q must be refused whole: %d", request, code)
		}
	}
}
