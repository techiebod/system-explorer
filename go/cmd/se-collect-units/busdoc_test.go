package main

import (
	"strings"
	"testing"
)

// The document is self-describing about D-Bus types, and that is the whole
// value of capturing through busctl rather than transcribing a reply: the
// signature travels beside the data, so a reply whose shape moved is caught
// instead of being decoded into a thinner row. Each case below is a reply this
// interface could plausibly grow into, and every one of them must be an error.
func TestADocumentWhoseShapeMovedIsRefusedRatherThanRead(t *testing.T) {
	cases := map[string]struct {
		raw    string
		decode func([]byte) error
	}{
		"a listing under another signature": {
			`{"type":"a(sss)","data":[[]]}`,
			func(raw []byte) error { _, err := decodeListUnits(raw); return err },
		},
		"a listing row that grew a member": {
			`{"type":"a(ssssssouso)","data":[[["a","b","c","d","e","f","/p",0,"","/",1]]]}`,
			func(raw []byte) error { _, err := decodeListUnits(raw); return err },
		},
		"a listing row whose path became a number": {
			`{"type":"a(ssssssouso)","data":[[["a","b","c","d","e","f",7,0,"","/"]]]}`,
			func(raw []byte) error { _, err := decodeListUnits(raw); return err },
		},
		"a reply carrying two arguments": {
			`{"type":"a(ssssssouso)","data":[[],[]]}`,
			func(raw []byte) error { _, err := decodeListUnits(raw); return err },
		},
		"a unit-file listing under another signature": {
			`{"type":"a(ssi)","data":[[]]}`,
			func(raw []byte) error { _, err := decodeUnitFileNames(raw); return err },
		},
		"a property map that is not one": {
			`{"type":"a{sv}","data":[["not","a","map"]]}`,
			func(raw []byte) error { _, err := decodeStringListProperties(raw); return err },
		},
		"a string list that holds numbers": {
			`{"type":"a{sv}","data":[{"After":{"type":"as","data":[1,2]}}]}`,
			func(raw []byte) error { _, err := decodeStringListProperties(raw); return err },
		},
		"a Get that is not a variant": {
			`{"type":"s","data":["system.slice"]}`,
			func(raw []byte) error { _, err := decodeStringProperty(raw); return err },
		},
		"a variant holding something other than a string": {
			`{"type":"v","data":[{"type":"u","data":7}]}`,
			func(raw []byte) error { _, err := decodeStringProperty(raw); return err },
		},
		"bytes that are not a document at all": {
			`Failed to connect to bus: No such file or directory`,
			func(raw []byte) error { _, err := decodeListUnits(raw); return err },
		},
	}
	for label, c := range cases {
		if err := c.decode([]byte(c.raw)); err == nil {
			t.Errorf("%s: decoded without complaint, and a shape nobody expected must be loud", label)
		}
	}
}

// A property of a type this collection does not read is skipped, not refused:
// GetAll on a Unit answers with a hundred properties of eleven signatures, and
// only the string lists carry a reference. Refusing the rest would make every
// systemd release that adds a property a broken collector.
func TestPropertiesOfOtherTypesAreSkippedAndNotRefused(t *testing.T) {
	raw := []byte(`{"type":"a{sv}","data":[{` +
		`"After":{"type":"as","data":["ssh.service"]},` +
		`"JobTimeoutUSec":{"type":"t","data":18446744073709551615},` +
		`"Job":{"type":"(uo)","data":[0,"/"]},` +
		`"InvocationID":{"type":"ay","data":[]},` +
		`"Transient":{"type":"b","data":false}}]}`)
	properties, err := decodeStringListProperties(raw)
	if err != nil {
		t.Fatalf("a full property set must decode: %v", err)
	}
	if len(properties) != 1 || len(properties["After"]) != 1 || properties["After"][0] != "ssh.service" {
		t.Fatalf("only the string lists are lifted, and After is one: %v", properties)
	}
}

// The request key IS the busctl argument line after the destination, which is
// what makes a captured reply checkable: a reader pastes the key, adds
// --json=short, and compares. It is also the seam's index, so the spelling is
// pinned rather than left to whichever call site was edited last.
func TestTheRequestKeyIsTheBusctlArgumentLine(t *testing.T) {
	for request, want := range map[string]string{
		listUnitsRequest():     "/org/freedesktop/systemd1 org.freedesktop.systemd1.Manager ListUnits",
		listUnitFilesRequest(): "/org/freedesktop/systemd1 org.freedesktop.systemd1.Manager ListUnitFiles",
		propertiesRequest("/org/freedesktop/systemd1/unit/ssh_2eservice"):          "/org/freedesktop/systemd1/unit/ssh_2eservice org.freedesktop.DBus.Properties GetAll s org.freedesktop.systemd1.Unit",
		sliceRequest("/org/freedesktop/systemd1/unit/ssh_2eservice", serviceIface): "/org/freedesktop/systemd1/unit/ssh_2eservice org.freedesktop.DBus.Properties Get ss org.freedesktop.systemd1.Service Slice",
	} {
		if request != want {
			t.Errorf("request key %q, want %q", request, want)
		}
	}
	// The path comes FIRST, because that is where busctl wants it and because
	// a key a reader cannot paste is a key that proves nothing.
	if !strings.HasPrefix(listUnitsRequest(), managerPath+" ") {
		t.Error("the key must open with the object path")
	}
}

// The two scope-name derivations, and the asymmetry between them: a container
// id is all docker's naming supports, and libvirt's escaping round-trips to the
// domain an operator typed.
func TestTheScopeNameDerivations(t *testing.T) {
	cases := map[string]map[string]string{
		"docker-0123456789abcdef0123.scope":    {"ContainerID": "0123456789ab"},
		`machine-qemu\x2d3\x2dweb\x2d01.scope`: {"MachineName": "web-01"},
		`machine-qemu\x2d1\x2dplain.scope`:     {"MachineName": "plain"},
		"session-186.scope":                    {},
		"docker.service":                       {},
		"init.scope":                           {},
		// A short id is not a docker scope name: the twelve-hex prefix is what
		// the derivation publishes, and a name with fewer characters would
		// yield a handle no docker row carries.
		"docker-0123456789a.scope": {},
	}
	for name, want := range cases {
		facts := newFactRow()
		workloadFacts(name, facts)
		for fact, value := range want {
			if !facts.has(fact) {
				t.Errorf("%s: no %s", name, fact)
				continue
			}
			if got := string(facts.encode()); !strings.Contains(got, `"`+value+`"`) {
				t.Errorf("%s: %s is not %q in %s", name, fact, value, got)
			}
		}
		if len(want) == 0 && (facts.has("ContainerID") || facts.has("MachineName")) {
			t.Errorf("%s: a scope this collector cannot name must be named by nothing: %s", name, facts.encode())
		}
	}
}

// A slice's parent is in its own name, and the one thing that must NOT be a
// separator is an escaped dash — `system-serial\x2dgetty.slice` lives in
// system.slice, not in `system-serial\x2dgetty`'s imaginary parent.
func TestASlicesParentIsReadOutOfItsName(t *testing.T) {
	for name, want := range map[string]string{
		"-.slice":                      "",
		"system.slice":                 "-.slice",
		"user.slice":                   "-.slice",
		"system-getty.slice":           "system.slice",
		`system-serial\x2dgetty.slice`: "system.slice",
		"user-1000.slice":              "user.slice",
		"system-systemd-fsck.slice":    "system-systemd.slice",
	} {
		if got := sliceParent(name); got != want {
			t.Errorf("%s: parent %q, want %q", name, got, want)
		}
	}
}
