package main

import (
	"strings"
	"testing"
)

// The rendering rules _port_mappings commits to, each held to the shape it
// exists for. The conformance suite holds the Python half to the same cases
// (conformance/test_docker_ports.py); this is the other implementation of one
// contract, and a rule stated in two languages is a rule that has to be right
// in both.
func TestPortRenderings(t *testing.T) {
	cases := []struct {
		name     string
		document string
		want     []string
	}{
		{
			"a published mapping renders host arrow container",
			`[{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}]`,
			[]string{"0.0.0.0:8080->80/tcp"},
		},
		{
			// The daemon lists in arbitrary order; the fold's order is by
			// container port, protocol, host port — stable, so rows diff cleanly
			// across runs. Numeric, not lexical: 53 sorts before 443.
			"mappings sort by container port then protocol",
			`[{"IP": "0.0.0.0", "PrivatePort": 443, "PublicPort": 8443, "Type": "tcp"},
			  {"IP": "0.0.0.0", "PrivatePort": 53, "PublicPort": 53, "Type": "udp"},
			  {"IP": "0.0.0.0", "PrivatePort": 53, "PublicPort": 53, "Type": "tcp"},
			  {"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}]`,
			[]string{"0.0.0.0:53->53/tcp", "0.0.0.0:53->53/udp",
				"0.0.0.0:8080->80/tcp", "0.0.0.0:8443->443/tcp"},
		},
		{
			// Docker lists one `-p 8080:80` twice, once per address family; two
			// rows for one binding would read as two bindings.
			"the dual-stack pair collapses to one entry",
			`[{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"},
			  {"IP": "::", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}]`,
			[]string{"0.0.0.0:8080->80/tcp"},
		},
		{
			// `-p 8080:80` on v4 and `-p 8081:80` on v6 is two bindings, not a
			// duplicate; collapsing here would hide a reachable port.
			"differing host ports are different claims and both stay",
			`[{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"},
			  {"IP": "::", "PrivatePort": 80, "PublicPort": 8081, "Type": "tcp"}]`,
			[]string{"0.0.0.0:8080->80/tcp", "[::]:8081->80/tcp"},
		},
		{
			"a specific host address renders verbatim",
			`[{"IP": "192.0.2.10", "PrivatePort": 5432, "PublicPort": 5432, "Type": "tcp"}]`,
			[]string{"192.0.2.10:5432->5432/tcp"},
		},
		{
			// The "why can't I reach this" case: the port exists and was never
			// published, so it renders marked rather than being dropped. And
			// published entries sort before exposed ones whatever their numbers.
			"an exposed port is marked, and sorts after every published one",
			`[{"IP": "", "PrivatePort": 51413, "Type": "udp"},
			  {"IP": "", "PrivatePort": 51413, "Type": "tcp"},
			  {"IP": "0.0.0.0", "PrivatePort": 9091, "PublicPort": 9091, "Type": "tcp"},
			  {"IP": "::", "PrivatePort": 9091, "PublicPort": 9091, "Type": "tcp"}]`,
			[]string{"0.0.0.0:9091->9091/tcp", "51413/tcp (exposed)", "51413/udp (exposed)"},
		},
		{
			// An entry with no IP is `entry.get("IP") or "0.0.0.0"`, and one with
			// no Type is `or "tcp"` — the daemon's own defaults, spelled here
			// because a blank in a rendering is worse than a wrong guess.
			"a missing address and a missing protocol take the daemon's defaults",
			`[{"PrivatePort": 80, "PublicPort": 8080}]`,
			[]string{"0.0.0.0:8080->80/tcp"},
		},
		{
			// No container port is no claim at all: the entry is skipped rather
			// than rendered with a blank where a number belongs.
			"an entry with no container port is skipped",
			`[{"IP": "0.0.0.0", "PublicPort": 8080, "Type": "tcp"},
			  {"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}]`,
			[]string{"0.0.0.0:8080->80/tcp"},
		},
		{
			// Empty rather than [], so the caller can omit the fact: a portless
			// container says nothing rather than claiming it has no ports.
			"an empty Ports member yields no fact at all",
			`[]`,
			nil,
		},
	}
	for _, c := range cases {
		document, err := decodeDocument([]byte(c.document))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got, err := portMappings(document)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s:\n got %v\nwant %v", c.name, got, c.want)
		}
	}
}

// The state guard on the scope name, both arms and the third one that is not a
// guard at all. A listing entry with no State member says nothing about whether
// the container has processes — the reference's `state is not None` skips the
// check there rather than assuming the worst — and the id is still the scope's
// name if it has one.
func TestScopeUnitFollowsWhetherTheContainerHasProcesses(t *testing.T) {
	const id = "abc123def456789000000000000000000000000000000000000000000000000"
	for state, want := range map[string]string{
		"running":    "docker-" + id + ".scope",
		"restarting": "docker-" + id + ".scope",
		"paused":     "docker-" + id + ".scope",
		"exited":     "",
		"created":    "",
		"dead":       "",
		"removing":   "",
	} {
		got := scopeUnit(id, stringValue(state))
		if want == "" {
			if got != nil {
				t.Errorf("%s: a container with no processes has no scope; got %v", state, got.text)
			}
			continue
		}
		if got == nil || got.text != want {
			t.Errorf("%s: got %v, want %q", state, got, want)
		}
	}
	if got := scopeUnit(id, nil); got == nil || got.text != "docker-"+id+".scope" {
		t.Error("a row that states no state states nothing about the scope either, " +
			"and the id is still its name")
	}
	if got := scopeUnit("", stringValue("running")); got != nil {
		t.Errorf("no id is no scope name; got %v", got.text)
	}
}
