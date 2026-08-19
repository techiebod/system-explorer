package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The live domain walk, over virsh and libvirt's own on-disk documents.
//
// The comment on declineNoLibvirtReader used to say virsh could not stand in
// for the client library, because `virsh list` renders a domain's state as the
// prose "shut off" where this collection's State fact is libvirt's enum word
// "shutoff". That is true of `virsh list` and false of `virsh domstats`, which
// answers `state.state=1` — the same integer the C API returns, so the mapping
// to a word is OURS either way and the two implementations cannot diverge on
// it. Measured on libvirt 12.2.0, 2026-08-19, and ruled the same day.
//
// Every source here is a structured document or a set, never a rendered table.
// That is not fastidiousness: SPEC section 2 rule 8 forbids parsing
// human-readable command output, and virsh has a table for almost everything.
// The routes that avoid one:
//
//	names          `virsh list --all --name`, one name per line
//	persistent     `virsh list --all --name --persistent` — SET MEMBERSHIP,
//	               not the "Persistent: yes" line of `dominfo`
//	autostart      `virsh list --all --name --autostart`, the same way
//	state/memory/  `virsh domstats <name>` — key=value lines, and the only
//	vcpus          place the state ENUM is available
//	uuid, taps,    `virsh dumpxml <name>` — XML, which this collector already
//	MACs           parses for host taps
//	addresses      libvirt's dnsmasq status file, which is JSON
//
// The address source deserves its own note, because it is the one that looks
// like a shortcut and is not. The reference asks libvirt for interface
// addresses from three sources in order — guest agent, DHCP lease, ARP — and
// libvirt REFUSES the agent outright on a read-only connection, which is the
// only kind this collector opens. So the lease is the source that answers in
// practice, and libvirt's dnsmasq status file is that lease, as a document,
// with no table in between. A guest on a bridge this host holds no lease file
// for is invisible here — which is the same guest the reference cannot see
// either, for the same reason.
const (
	virshBinary   = "virsh"
	dnsmasqLeases = "/var/lib/libvirt/dnsmasq"
	virshTimeout  = 20 * time.Second
)

// libvirt's VIR_DOMAIN_* state enum, which is what `domstats` reports and what
// the reference maps from. Restated here rather than derived, exactly as the
// reference restates it: it is an external constant set, published by libvirt,
// and a reader can check any line of it against virDomainState.
var domainStates = map[string]string{
	"0": "nostate", "1": "running", "2": "blocked", "3": "paused",
	"4": "shutdown", "5": "shutoff", "6": "crashed", "7": "pmsuspended",
}

// The note the reference attaches when addresses came from the lease rather
// than the agent. Byte-identical to adapters/vms.py ADDRESS_SOURCE_NOTES,
// because it is a FACT VALUE that travels the wire and two spellings would
// read as two conditions.
const leaseNote = "IP addresses from the DHCP lease libvirt holds for this " +
	"guest (the guest agent needs more than read-only access)."

// And the note when nothing answered at all. Also the reference's, to the byte.
const noAddressNote = "No address source answered: the guest agent is " +
	"unavailable on a read-only libvirt connection, no DHCP lease is held " +
	"for this guest, and the host ARP table has no entry for it (an idle " +
	"guest's entry expires)."

func virsh(args ...string) (string, error) {
	// --connect is explicit: virsh consults LIBVIRT_DEFAULT_URI otherwise, so
	// an environment variable could silently point this collector at another
	// host's hypervisor and publish its domains as this machine's.
	argv := append([]string{"--connect", "qemu:///system"}, args...)
	command := exec.Command(virshBinary, argv...)
	out, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("virsh %s: %v", strings.Join(args, " "), err)
	}
	return string(out), nil
}

func virshNames(args ...string) (map[string]bool, []string, error) {
	out, err := virsh(args...)
	if err != nil {
		return nil, nil, err
	}
	set := map[string]bool{}
	var order []string
	for _, line := range strings.Split(out, "\n") {
		if name := strings.TrimSpace(line); name != "" {
			set[name] = true
			order = append(order, name)
		}
	}
	return set, order, nil
}

// domstats answers `key=value` lines under a `Domain: 'name'` header. Split on
// the FIRST '=' only: a value may contain one and a key never does.
func parseDomstats(out string) map[string]string {
	stats := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		stats[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return stats
}

// kibToMiB matches the reference's round(kib / 1024) on the values libvirt
// reports, which are whole MiB in KiB and so never land on a half.
func kibToMiB(raw string) (int64, bool) {
	kib, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return (kib + 512) / 1024, true
}

// leaseAddresses is mac -> addresses, from every network's status file. Read
// as JSON, because that is what libvirt writes there.
func leaseAddresses() map[string][]string {
	byMAC := map[string][]string{}
	entries, err := os.ReadDir(dnsmasqLeases)
	if err != nil {
		return byMAC
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".status") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dnsmasqLeases, entry.Name()))
		if err != nil {
			continue
		}
		var leases []struct {
			IP  string `json:"ip-address"`
			MAC string `json:"mac-address"`
		}
		if json.Unmarshal(raw, &leases) != nil {
			continue
		}
		for _, lease := range leases {
			if lease.MAC != "" && lease.IP != "" {
				byMAC[lease.MAC] = append(byMAC[lease.MAC], lease.IP)
			}
		}
	}
	return byMAC
}

// domainIdentity pulls the uuid and every interface MAC out of a domain's own
// XML. The taps are read by hostTaps already; this is the same document asked
// two more questions rather than a second acquisition.
func domainIdentity(document string) (uuid string, macs []string) {
	decoder := xml.NewDecoder(strings.NewReader(document))
	depth, inDomain := 0, false
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch element := token.(type) {
		case xml.StartElement:
			depth++
			switch element.Name.Local {
			case "domain":
				inDomain = true
			case "uuid":
				if inDomain && uuid == "" {
					var text string
					if decoder.DecodeElement(&text, &element) == nil {
						uuid = strings.TrimSpace(text)
					}
					depth--
				}
			case "mac":
				if address := attribute(element, "address"); address != "" {
					macs = append(macs, address)
				}
			}
		case xml.EndElement:
			depth--
		}
	}
	return uuid, macs
}

// liveDomains is the whole reading, in the shape adapters/vms.py
// `_domains_raw()` returns — one JSON array, one object per domain. Built as
// Go values and marshalled rather than assembled as a *value tree, so the
// shape cannot drift from the payload the corpus holds.
func liveDomains() (*value, error) {
	_, names, err := virshNames("list", "--all", "--name")
	if err != nil {
		return nil, err
	}
	persistent, _, err := virshNames("list", "--all", "--name", "--persistent")
	if err != nil {
		return nil, err
	}
	autostart, _, err := virshNames("list", "--all", "--name", "--autostart")
	if err != nil {
		return nil, err
	}
	leases := leaseAddresses()

	domains := make([]map[string]any, 0, len(names))
	for _, name := range names {
		statsOut, err := virsh("domstats", name)
		if err != nil {
			return nil, err
		}
		stats := parseDomstats(statsOut)
		document, err := virsh("dumpxml", name)
		if err != nil {
			return nil, err
		}
		uuid, macs := domainIdentity(document)

		state, known := domainStates[stats["state.state"]]
		if !known {
			// An enum member libvirt grew and this table has not. The raw
			// integer is published rather than a guess, exactly as the
			// reference does with STATES.get(state, str(state)) — a word this
			// collector invented would be a claim nobody could check.
			state = stats["state.state"]
		}
		current, _ := kibToMiB(stats["balloon.current"])
		maximum, _ := kibToMiB(stats["balloon.maximum"])
		vcpus, _ := strconv.ParseInt(stats["vcpu.current"], 10, 64)

		// Addresses only for a RUNNING domain, matching the reference: a
		// stopped guest's stale lease is not an address it has.
		addresses := map[string][]string{}
		var note any
		if state == "running" {
			for _, mac := range macs {
				if found := leases[mac]; len(found) > 0 {
					addresses[mac] = found
				}
			}
			if len(addresses) > 0 {
				note = leaseNote
			} else {
				note = noAddressNote
			}
		}

		domains = append(domains, map[string]any{
			"name":           name,
			"uuid":           uuid,
			"state":          state,
			"memory_mib":     current,
			"max_memory_mib": maximum,
			"vcpus":          vcpus,
			"autostart":      autostart[name],
			"persistent":     persistent[name],
			"xml":            document,
			"ips_by_mac":     addresses,
			"ip_note":        note,
		})
	}

	raw, err := json.Marshal(domains)
	if err != nil {
		return nil, err
	}
	return decodeDocument(raw)
}
