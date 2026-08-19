package main

import (
	"encoding/xml"
	"io"
	"sort"
	"strings"
)

// hostTaps is adapters/vms.py `_devices()`, narrowed to the one member of it
// that reaches a domain ROW: the host-side tap device each NIC is attached to.
//
// Narrowed deliberately. `_devices()` also builds the disk, MAC, bridge and
// hostdev structures, and every one of them belongs to the opened object
// (`get_object`), which this collector does not serve — DESIGN 18's partial
// verb service. Parsing them here to throw them away would be a second
// implementation of a derivation nothing compares, which is how two copies of
// one reading start disagreeing.
//
// HostTaps is on the row because it is the ONLY authoritative answer to "which
// domain owns vnet4": a tap carries no domain identity in sysfs, and the
// fe:54:/52:54: MAC resemblance is a QEMU convention rather than a record. A
// consumer looking at network/links wants every tap from one request, without
// opening each domain.
func hostTaps(document string) []string {
	taps, ok := interfaceTaps(document)
	if !ok {
		// ElementTree raises ParseError before it yields a single element, so
		// the reference's `except ET.ParseError` returns EMPTY device lists —
		// not the elements it managed to read first. Whatever this walk had
		// collected is therefore discarded, because a half-read document is
		// not a partial reading of the domain, it is no reading at all.
		return nil
	}
	sort.Strings(taps)
	return taps
}

// interfaceTaps walks `./devices/interface/target/@dev` the way ElementTree's
// findall and find do, and answers whether the document parsed at all.
//
// The path is literal, not a search: `findall("./devices/interface")` matches
// interfaces that are direct children of a direct-child `devices` element, so
// an <interface> inside a nested <devices> — which a <qemu:commandline> block
// or a malformed definition could carry — is not a NIC of this domain. And
// `iface.find("target")` takes the FIRST direct `target` child, so a second
// one is ignored rather than overwriting the first.
//
// Namespaced names are excluded at every step, because ElementTree spells a
// namespaced tag `{uri}target` and that is not the string `target`. Without
// the check, libvirt's own <qemu:...> extensions would be read as domain
// devices by this port and by nothing else.
func interfaceTaps(document string) ([]string, bool) {
	decoder := xml.NewDecoder(strings.NewReader(document))
	var (
		taps       []string
		seen       = map[string]bool{}
		depth      int
		inDevices  bool
		inNIC      bool
		nicHasTap  bool
		sawElement bool
	)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			// A document with no element at all is `no element found` to
			// ElementTree, which is a ParseError like any other.
			return taps, sawElement
		}
		if err != nil {
			return nil, false
		}
		switch element := token.(type) {
		case xml.StartElement:
			if depth == 0 && sawElement {
				// A second root element is `junk after document element` to
				// ElementTree, which refuses the whole document rather than
				// reading the first half of it.
				return nil, false
			}
			sawElement = true
			switch {
			case depth == 1 && element.Name.Space == "" && element.Name.Local == "devices":
				inDevices = true
			case inDevices && depth == 2 && element.Name.Space == "" && element.Name.Local == "interface":
				inNIC, nicHasTap = true, false
			case inNIC && depth == 3 && element.Name.Space == "" && element.Name.Local == "target" && !nicHasTap:
				nicHasTap = true
				// `if target is not None and target.get("dev")`: a missing or
				// empty dev attribute is no tap, and the NIC contributes
				// nothing rather than an empty name.
				if dev := attribute(element, "dev"); dev != "" && !seen[dev] {
					seen[dev] = true
					taps = append(taps, dev)
				}
			}
			depth++
		case xml.EndElement:
			depth--
			switch {
			case depth == 1:
				inDevices = false
			case depth == 2:
				inNIC = false
			}
		}
	}
}

// attribute reads an unprefixed attribute, which is how every element of a
// libvirt domain definition spells its own.
func attribute(element xml.StartElement, name string) string {
	for _, attr := range element.Attr {
		if attr.Name.Space == "" && attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}
