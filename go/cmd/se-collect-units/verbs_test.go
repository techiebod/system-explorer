// The two verbs, against staged documents whose shapes are captures from
// the lab guest (ssh.service on ubuntu 26.04, 2026-08-21): the density
// facts with their unset sentinels honoured, the dependency edges in
// declared order, the redaction that keeps an Environment= line out of
// evidence, the checkable digest, and the decline paths — a decline is
// data under every verb.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sshPath = "/org/freedesktop/systemd1/unit/ssh_2eservice"

func verbFixture(t *testing.T) string {
	t.Helper()
	unitProps := `{"type":"a{sv}","data":[{
	 "Id":{"type":"s","data":"ssh.service"},
	 "LoadState":{"type":"s","data":"loaded"},
	 "ActiveState":{"type":"s","data":"active"},
	 "SubState":{"type":"s","data":"running"},
	 "Description":{"type":"s","data":"OpenBSD Secure Shell server"},
	 "UnitFileState":{"type":"s","data":"enabled"},
	 "FragmentPath":{"type":"s","data":"/usr/lib/systemd/system/ssh.service"},
	 "ActiveEnterTimestamp":{"type":"t","data":1787323043059815},
	 "LoadError":{"type":"(ss)","data":["",""]},
	 "Requires":{"type":"as","data":["-.mount","sysinit.target","ssh.socket","system.slice"]},
	 "Wants":{"type":"as","data":["sshd-keygen.service"]},
	 "PartOf":{"type":"as","data":[]},
	 "After":{"type":"as","data":["ssh.socket","sysinit.target"]}}]}`
	serviceProps := `{"type":"a{sv}","data":[{
	 "MainPID":{"type":"u","data":1481},
	 "NRestarts":{"type":"u","data":4},
	 "Result":{"type":"s","data":"success"},
	 "TasksCurrent":{"type":"t","data":1},
	 "ExecMainStartTimestamp":{"type":"t","data":1787323043059815},
	 "Environment":{"type":"as","data":["SECRET_TOKEN=hunter2"]},
	 "UnsetEnvironment":{"type":"as","data":[]},
	 "PassEnvironment":{"type":"as","data":["HOME"]}}]}`
	staged := map[string]json.RawMessage{
		loadUnitRequest("ssh.service"): json.RawMessage(
			`{"type":"o","data":["` + sshPath + `"]}`),
		propertiesRequest(sshPath): json.RawMessage(unitProps),
		busRequest(sshPath, propertiesIface, "GetAll", "s",
			"org.freedesktop.systemd1.Service"): json.RawMessage(serviceProps),
	}
	raw, err := json.Marshal(staged)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "verbs.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runVerb(t *testing.T, dir, request string) (int, string, string) {
	t.Helper()
	return runWith(t, request+"\n", map[string]string{"SE_REPLAY_DIR": dir})
}

func TestObjectServesTheDensityTheRowCannotAfford(t *testing.T) {
	code, stdout, stderr := runVerb(t, verbFixture(t), "object units ssh.service")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	records := parseRecords(t, stdout)
	object := ofKind(records, "object")[0]
	if object["type"] != "service" || object["name"] != "ssh.service" {
		t.Fatalf("%+v", object)
	}
	facts := object["facts"].(map[string]any)
	// The pass-through discipline: NRestarts arrives as the wire's own
	// integer token, MainPID beside it, the timestamps at the reference's
	// seconds-precision rendering.
	if facts["NRestarts"] != float64(4) || facts["MainPID"] != float64(1481) {
		t.Fatalf("%+v", facts)
	}
	if facts["ExecMainStartTimestamp"] != "2026-08-21T14:37:23Z" {
		t.Fatalf("%v", facts["ExecMainStartTimestamp"])
	}
	if facts["UnitFileState"] != "enabled" || facts["Result"] != "success" {
		t.Fatalf("%+v", facts)
	}
	// LoadError ("","") is systemd's no-error; it must not become a fact.
	if _, present := facts["LoadError"]; present {
		t.Fatalf("an empty LoadError is no error: %+v", facts)
	}
	// The dependency edges, forward directions only, in declared order.
	var edges []string
	for _, assertion := range ofKind(records, "relation_assertion") {
		target := assertion["target"].(map[string]any)
		edges = append(edges, assertion["type"].(string)+"→"+target["name"].(string))
	}
	want := []string{
		"requires→-.mount", "requires→sysinit.target", "requires→ssh.socket",
		"requires→system.slice", "wants→sshd-keygen.service",
		"after→ssh.socket", "after→sysinit.target",
	}
	if fmt.Sprint(edges) != fmt.Sprint(want) {
		t.Fatalf("edges %v, want %v", edges, want)
	}
	terminator := ofKind(records, "verb_end")[0]
	if terminator["verb"] != "object" || terminator["truncated"] != false {
		t.Fatalf("%+v", terminator)
	}
}

func TestEvidenceWithholdsTheEnvironmentAndTheDigestChecks(t *testing.T) {
	code, stdout, stderr := runVerb(t, verbFixture(t), "evidence units ssh.service")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 3 {
		t.Fatalf("header, payload, terminator: %d lines", len(lines))
	}
	var header evidenceDocumentRecord
	if err := json.Unmarshal([]byte(lines[0]), &header); err != nil {
		t.Fatal(err)
	}
	payload := lines[1]
	if header.Bytes != len(payload) || header.Truncated {
		t.Fatalf("%+v vs %d payload bytes", header, len(payload))
	}
	// The digest is over the bytes AS SERVED — recompute and compare.
	sum := sha256.Sum256([]byte(payload))
	if header.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("the served digest must match the served bytes")
	}
	// The withheld members are GONE, not emptied: an Environment= line is
	// where a credential lives, and this is the last place to show one.
	if strings.Contains(payload, "hunter2") || strings.Contains(payload, "Environment") {
		t.Fatalf("a withheld member reached the evidence payload: %s", payload[:200])
	}
	// What was NOT withheld is served verbatim.
	if !strings.Contains(payload, "NRestarts") || !strings.Contains(payload, "ssh.service") {
		t.Fatalf("%s", payload[:200])
	}
	var terminator verbEndRecord
	if err := json.Unmarshal([]byte(lines[2]), &terminator); err != nil {
		t.Fatal(err)
	}
	if terminator.Verb != "evidence" || terminator.Truncated {
		t.Fatalf("%+v", terminator)
	}
}

func TestAVerbDeclineIsDataNotACrash(t *testing.T) {
	dir := verbFixture(t)
	// A name the capture never staged: under replay that is a broken
	// request — "I could not run" — never a statement about a machine.
	code, _, _ := runVerb(t, dir, "object units ghost.service")
	if code != exitRuntime {
		t.Fatalf("an unstaged name under replay must refuse the run: %d", code)
	}
	// A collection this collector never served declines unsupported, with
	// the terminator still closing the response.
	code, stdout, _ := runVerb(t, dir, "object pools tank")
	if code != exitOK {
		t.Fatalf("%d", code)
	}
	records := parseRecords(t, stdout)
	decline := ofKind(records, "decline")[0]
	if decline["reason"] != "unsupported" {
		t.Fatalf("%+v", decline)
	}
	if len(ofKind(records, "verb_end")) != 1 {
		t.Fatal("every verb response ends with its terminator")
	}
}

func TestTheVerbRequestShapeIsExactlyThreeTokens(t *testing.T) {
	dir := verbFixture(t)
	for _, request := range []string{"object units", "object units a b",
		"evidence units"} {
		code, _, stderr := runVerb(t, dir, request)
		if code != exitRequest {
			t.Fatalf("%q must be refused whole: %d %s", request, code, stderr)
		}
	}
}
