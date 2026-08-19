package main

import (
	"errors"
	"fmt"
)

// The option dockerd writes for the default bridge, and the first of the two
// authorities on which host device a network is plumbed onto.
// adapters/docker.py BRIDGE_NAME_OPTION.
const bridgeNameOption = "com.docker.network.bridge.name"

// networkRows is adapters/docker.py `_network_items()`: one row per entry of
// /networks, in the order dockerd listed them.
func networkRows(document *value) ([]row, error) {
	if document == nil || document.kind != jsonArray {
		return nil, errors.New("the staged networks payload is not a list of networks")
	}
	rows := make([]row, 0, len(document.items))
	for i, network := range document.items {
		name := network.get("Name")
		if !name.isString() {
			// The reference indexes this member directly, so a network without
			// one is a crash there rather than a degraded row. A refusal
			// reproduces that: no machine was observed to have a nameless
			// network, so there is nothing to decline about.
			return nil, fmt.Errorf("network %d has no name", i)
		}
		facts := newObject()
		facts.set("Driver", network.get("Driver"))
		facts.set("Scope", network.get("Scope"))
		facts.set("Internal", network.get("Internal"))
		facts.set("BridgeInterface", bridgeInterface(network))
		facts.set("ComposeProject", network.dig("Labels", composeProject))
		rows = append(rows, row{name: name.text, facts: facts})
	}
	return rows, nil
}

// bridgeInterface is the host bridge this docker network is plumbed onto, or
// nothing at all. Two sources, in order of authority.
//
// Docker records the name explicitly for the default bridge
// (`com.docker.network.bridge.name: docker0`), and for every other bridge
// network the interface is `br-` plus the first twelve characters of the
// network id — Docker's documented naming, verified at staging against the lab
// guest's own `ip link`, where the committed capture's br-2a0990979cde is a
// real device.
//
// This is the edge that stops network/links being a wall of anonymous
// plumbing: a `br-56a84c7a9838` row means nothing, and "the paperless stack's
// network" means everything. host and null drivers plumb no interface, so they
// get no claim.
//
// The named option is taken only where it is a non-empty STRING, which is the
// reference's `if named:` for every value dockerd produces — network options
// are strings. A named option of some other type would be published verbatim
// by the reference and would then be a BridgeInterface that is not a string,
// against this collector's own declaration; no daemon writes one, and this
// bound is stated rather than emulated.
func bridgeInterface(network *value) *value {
	if named := network.dig("Options", bridgeNameOption); named.isString() && named.text != "" {
		return named
	}
	if driver := network.get("Driver"); !driver.isString() || driver.text != "bridge" {
		return nil
	}
	id := network.get("Id").stringOr("")
	if len(id) < 12 {
		return nil
	}
	return stringValue("br-" + id[:12])
}
