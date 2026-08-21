package main

import (
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The scsi collection is the physical path a block device takes — host
// adapter → (expanders) → end device → disk — with enclosure slots mapped
// where an SES device is present, so "which bay is sdX in" is a fact and not a
// guess. The tree comes out of the kernel's own topology rather than a
// driver-name table, which is the only thing that can tell an AHCI port from a
// SAS HBA: the kernel presents SATA and USB storage through the SCSI subsystem
// too, so every one of these is a `scsi_host`.

var (
	// Segments of a sysfs device path that are nodes in the scsi topology.
	scsiSegment = regexp.MustCompile(`^(host\d+|expander-\d+:\d+(?::\d+)?)$`)
	scsiDevice  = regexp.MustCompile(`^\d+:\d+:\d+:\d+$`)
	endDevice   = regexp.MustCompile(`^end_device-[\d:]+$`)
	pciAddress  = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$`)
	ataPort     = regexp.MustCompile(`^ata\d+$`)
)

// Kernel scsi device type codes (include/scsi/scsi_proto.h).
var scsiTypes = map[int64]string{
	0: "disk", 1: "tape", 4: "worm", 5: "cd-dvd", 6: "scanner",
	7: "optical", 8: "changer", 12: "raid", 13: "enclosure", 14: "rbc",
}

// HBA drivers publish firmware under driver-specific attribute names; whichever
// exists is read (mpt3sas: version_fw/version_bios/board_name; qla/lpfc-style:
// fw_version/fwrev/model_name). Ordered, because the first one that answers
// wins and a map would decide that by iteration order.
var scsiHostFirmwareAttrs = [][2]string{
	{"version_fw", "FirmwareVersion"},
	{"fw_version", "FirmwareVersion"},
	{"fwrev", "FirmwareVersion"},
	{"version_bios", "BiosVersion"},
	{"board_name", "BoardName"},
	{"model_name", "BoardName"},
}

// ATA devices reach SCSI with the TRANSPORT in the vendor field; the real
// maker is recoverable from the model string's conventional prefix. This is
// the same derivation udisks applies — deterministic, not a guess.
var ataVendorPrefixes = [][2]string{
	{"ST", "Seagate"}, {"WDC", "Western Digital"}, {"HGST", "HGST"},
	{"SAMSUNG", "Samsung"}, {"Samsung", "Samsung"}, {"MZ", "Samsung"},
	{"KINGSTON", "Kingston"}, {"OCZ", "OCZ"}, {"SanDisk", "SanDisk"},
	{"TOSHIBA", "Toshiba"}, {"HITACHI", "Hitachi"}, {"Hitachi", "Hitachi"},
	{"INTEL", "Intel"}, {"Micron", "Micron"}, {"Crucial", "Crucial"},
}

func ataVendor(model string) (string, bool) {
	for _, pair := range ataVendorPrefixes {
		if model != "" && strings.HasPrefix(model, pair[0]) {
			return pair[1], true
		}
	}
	return "", false
}

// naturalKey sorts 2:0:10:0 after 2:0:9:0 and host10 after host9 — digits
// compare as numbers, everything else as text.
func naturalLess(a, b string) bool {
	ap, bp := splitDigits(a), splitDigits(b)
	for i := 0; i < len(ap) && i < len(bp); i++ {
		x, y := ap[i], bp[i]
		if x.isNumber && y.isNumber {
			if x.number != y.number {
				return x.number < y.number
			}
			continue
		}
		if x.isNumber != y.isNumber {
			// Python compares an int with a str and raises; no real listing
			// mixes the two at one position, so the ordering here only has to
			// be total and stable. Numbers first.
			return x.isNumber
		}
		if x.text != y.text {
			return x.text < y.text
		}
	}
	return len(ap) < len(bp)
}

type keyPart struct {
	text     string
	number   int64
	isNumber bool
}

var digitRun = regexp.MustCompile(`(\d+)`)

func splitDigits(name string) []keyPart {
	parts := []keyPart{}
	for _, chunk := range digitRun.Split(name, -1) {
		parts = append(parts, keyPart{text: chunk})
	}
	numbers := digitRun.FindAllString(name, -1)
	// re.split keeps the captured groups, alternating text/number/text…
	merged := []keyPart{}
	for i, part := range parts {
		merged = append(merged, part)
		if i < len(numbers) {
			n, _ := strconv.ParseInt(numbers[i], 10, 64)
			merged = append(merged, keyPart{number: n, isNumber: true})
		}
	}
	return merged
}

func sortNatural(names []string) {
	sort.SliceStable(names, func(i, j int) bool { return naturalLess(names[i], names[j]) })
}

// chainOf lists the topology nodes along a device's real sysfs path, outermost
// first.
func chainOf(src source, syspath string) []string {
	out := []string{}
	for _, segment := range strings.Split(src.realpath(syspath), "/") {
		if scsiSegment.MatchString(segment) {
			out = append(out, segment)
		}
	}
	return out
}

// pciAddressOf is the deepest PCI function on the device's real path — the
// adapter a controller hangs from.
func pciAddressOf(src source, syspath string) (string, bool) {
	found := ""
	for _, segment := range strings.Split(src.realpath(syspath), "/") {
		if pciAddress.MatchString(segment) {
			found = segment
		}
	}
	return found, found != ""
}

// hostTransport says how a SCSI host actually attaches its devices, from
// native evidence rather than a list of driver names. An ata port in the path
// means SATA; a host_sas_address means SAS.
func hostTransport(src source, base, driver string) (string, bool) {
	if src.exists(path.Join(base, "host_sas_address")) {
		return "SAS", true
	}
	for _, segment := range strings.Split(src.realpath(base), "/") {
		if ataPort.MatchString(segment) {
			return "SATA", true
		}
	}
	switch driver {
	case "usb-storage", "uas":
		return "USB", true
	case "virtio_scsi":
		return "virtio", true
	}
	return "", false
}

// blockByPath maps a kernel name (sdX) to its /dev/disk/by-path alias — the
// human phy/slot route.
func blockByPath(src source) map[string]string {
	out := map[string]string{}
	for _, name := range src.listdir(byPath) {
		if strings.Contains(name, "part") {
			continue
		}
		target := path.Base(src.realpath(path.Join(byPath, name)))
		if target == "" {
			continue
		}
		if _, seen := out[target]; !seen {
			out[target] = name
		}
	}
	return out
}

// byIDNames is every /dev/disk/by-id name udev minted for one block device —
// wwn-<naa>, scsi-3<naa>, ata-<model>_<serial>, nvme-<wwid> — read out of the
// device's own DEVLINKS rather than by listing the by-id directory and
// resolving each link back. One query instead of a listing plus a realpath per
// entry, and the listing would have carried every OTHER disk's identity into
// a payload this row has no business publishing.
func byIDNames(src source, block string) []string {
	links := src.udev(path.Join("/sys/block", block))["DEVLINKS"]
	names := []string{}
	for _, link := range strings.Fields(links) {
		if strings.HasPrefix(link, byID+"/") {
			names = append(names, path.Base(link))
		}
	}
	return names
}

// diskNames is law 1 on a hardware disk: every native name observed, split by
// stability class, so the identity chain closes — the wwid the kernel reports,
// the by-id spellings a pool member is recorded under, the serial, and the
// kernel path a person searches for. The wwid file and udev's wwn-… link are
// two spellings of ONE identity and both are published in the wwn family,
// because the join runs on published values and a spelling nobody publishes
// is a join that silently fails.
func diskNames(f map[string]any, links []string, block string) map[string]any {
	appendNew := func(family []string, value string) []string {
		for _, held := range family {
			if held == value {
				return family
			}
		}
		return append(family, value)
	}
	wwn, devid := []string{}, []string{}
	if value, ok := f["WWN"].(string); ok {
		wwn = appendNew(wwn, value)
	}
	for _, link := range links {
		if strings.HasPrefix(link, "wwn-") {
			wwn = appendNew(wwn, link)
		} else {
			devid = appendNew(devid, link)
		}
	}
	stable := map[string]any{}
	if len(wwn) > 0 {
		stable["wwn"] = wwn
	}
	if len(devid) > 0 {
		stable["devid"] = devid
	}
	if serial, ok := f["Serial"].(string); ok {
		stable["serial"] = []string{serial}
	}
	if len(stable) == 0 {
		return nil
	}
	names := map[string]any{"stable": stable}
	if block != "" {
		names["ephemeral"] = map[string]any{"kernel": []string{"/dev/" + block}}
	}
	return names
}

type enclosureSlot struct {
	enclosure string
	status    string
	slot      string
	device    string
}

// enclosureSlots returns (enclosure id → slot table, scsi device id → its slot
// facts). The slot table is what makes "walk to bay 7" a fact rather than a
// guess, and it exists only where the shelf publishes an SES device.
func enclosureSlots(src source) (map[string]map[string]any, map[string]enclosureSlot) {
	byEnclosure := map[string]map[string]any{}
	byDevice := map[string]enclosureSlot{}
	for _, enc := range src.listdir(enclosures) {
		slots := map[string]any{}
		base := path.Join(enclosures, enc)
		for _, comp := range src.listdir(base) {
			dir := path.Join(base, comp)
			// A component directory is one that carries a `type`; the class
			// directory also holds plain attributes, and reading those as
			// slots would publish bays that do not exist.
			kind, ok := src.read(path.Join(dir, "type"))
			if !ok || kind == "" {
				continue
			}
			status, _ := src.read(path.Join(dir, "status"))
			number, haveNumber := src.read(path.Join(dir, "slot"))
			if !haveNumber || number == "" {
				number = comp
			}
			entry := map[string]any{}
			if status != "" {
				entry["Status"] = status
			}
			entry["Slot"] = number
			occupant := path.Base(src.realpath(path.Join(dir, "device")))
			if scsiDevice.MatchString(occupant) {
				entry["Device"] = occupant
				byDevice[occupant] = enclosureSlot{
					enclosure: enc, status: status, slot: number, device: occupant,
				}
			}
			slots[comp] = entry
		}
		byEnclosure[enc] = slots
	}
	return byEnclosure, byDevice
}

// scsiLinkFacts is the negotiated link rate for a SCSI-attached disk, and the
// maximum where the kernel establishes one.
//
// Worth having because a link that trained low is a real performance fault
// nothing else here would show: a 6 Gbps drive at 1.5 Gbps looks perfectly
// healthy in every other fact. Two native sources, chosen by how the device is
// ACTUALLY attached rather than by a driver-name table — SATA's ata_link
// carries the negotiated speed, SAS's phy carries negotiated and maximum both,
// which is what makes the comparison possible there and not on SATA.
func scsiLinkFacts(src source, f map[string]any, scsiID string) {
	segments := strings.Split(src.realpath(path.Join(scsiDevices, scsiID)), "/")
	for _, segment := range segments {
		if !ataPort.MatchString(segment) {
			continue
		}
		link := path.Join(ataLinks, "link"+segment[3:])
		speed, haveSpeed := sysfsValue(src.read(path.Join(link, "sata_spd")))
		// Usually "<unknown>" on a healthy port, so usually absent: the
		// kernel only fills it when something has limited the link.
		limit, haveLimit := sysfsValue(src.read(path.Join(link, "hw_sata_spd_limit")))
		setString(f, "LinkSpeed", speed, haveSpeed)
		setString(f, "LinkSpeedMax", limit, haveLimit)
		return
	}
	for _, segment := range segments {
		if !strings.HasPrefix(segment, "end_device-") {
			continue
		}
		host := strings.SplitN(strings.TrimPrefix(segment, "end_device-"), ":", 2)[0]
		phyID, ok := sysfsValue(src.read(path.Join(sasDevices, segment, "phy_identifier")))
		if !ok {
			return
		}
		phy := path.Join(sasPhys, "phy-"+host+":"+phyID)
		speed, haveSpeed := sysfsValue(src.read(path.Join(phy, "negotiated_linkrate")))
		limit, haveLimit := sysfsValue(src.read(path.Join(phy, "maximum_linkrate")))
		setString(f, "LinkSpeed", speed, haveSpeed)
		setString(f, "LinkSpeedMax", limit, haveLimit)
		return
	}
}

// scsiItems walks the attachment tree: hosts first, then the expanders and
// devices beneath them, depth-first in natural order.
func scsiItems(src source) []item {
	aliases := blockByPath(src)
	enclosureTables, deviceSlots := enclosureSlots(src)

	items := map[string]*item{}
	order := []string{}

	for _, host := range src.listdir(scsiHosts) {
		base := path.Join(scsiHosts, host)
		address, haveAddress := pciAddressOf(src, base)
		driver, haveDriver := src.read(path.Join(base, "proc_name"))
		state, haveState := src.read(path.Join(base, "state"))
		f := map[string]any{}
		setString(f, "Driver", driver, haveDriver)
		setString(f, "State", state, haveState)
		transport, haveTransport := hostTransport(src, base, driver)
		setString(f, "Transport", transport, haveTransport)
		setString(f, "PCIAddress", address, haveAddress)
		// The controller's own identity, so a host row names its silicon in
		// the shared Vendor/Model columns instead of a wall of dashes. The
		// hwdb has it under the PCI function, not under the scsi host.
		if haveAddress {
			props := src.udev(path.Join(pciDevices, address))
			setString(f, "Vendor", props["ID_VENDOR_FROM_DATABASE"], true)
			setString(f, "Model", props["ID_MODEL_FROM_DATABASE"], true)
		}
		for _, pair := range scsiHostFirmwareAttrs {
			if _, already := f[pair[1]]; already {
				continue
			}
			value, ok := src.read(path.Join(base, pair[0]))
			setString(f, pair[1], value, ok)
		}
		// hwdb has gaps; the driver's board name is the next best label.
		if _, haveModel := f["Model"]; !haveModel {
			if board, ok := f["BoardName"]; ok {
				f["Model"] = board
			}
		}
		items[host] = &item{name: host, kind: "scsi-host", facts: f, parent: ""}
		order = append(order, host)
	}

	for _, expander := range src.listdir(sasExpanders) {
		base := path.Join(sasExpanders, expander)
		f := map[string]any{}
		// vendor_id/product_id ARE the vendor and model — the shared column
		// names, so expander rows read like everything else.
		vendor, haveVendor := src.read(path.Join(base, "vendor_id"))
		setString(f, "Vendor", vendor, haveVendor)
		model, haveModel := src.read(path.Join(base, "product_id"))
		setString(f, "Model", model, haveModel)
		f["Transport"] = "SAS"
		level, haveLevel := src.read(path.Join(base, "level"))
		setString(f, "Level", level, haveLevel)
		// Expanders publish their address via the sas_device class, the same
		// as end devices (verified on a NetApp shelf).
		address, haveAddress := src.read(path.Join(sasDevices, expander, "sas_address"))
		setString(f, "SASAddress", address, haveAddress)
		parent := ""
		chain := chainOf(src, path.Join(base, "device"))
		for i := len(chain) - 1; i >= 0; i-- {
			if chain[i] != expander {
				parent = chain[i]
				break
			}
		}
		items[expander] = &item{name: expander, kind: "expander", facts: f, parent: parent}
		order = append(order, expander)
	}

	for _, dev := range src.listdir(scsiDevices) {
		if !scsiDevice.MatchString(dev) {
			continue
		}
		base := path.Join(scsiDevices, dev)
		typeCode, haveType := intOrNone(src.read(path.Join(base, "type")))
		kind := "device"
		if haveType {
			if named, ok := scsiTypes[typeCode]; ok {
				kind = named
			}
		}
		// The wire type again, as a FACT, because a rule condition names
		// facts and nothing else — the closed vocabulary has no way to say
		// "disks only", and the device-state rule must not judge a host or
		// an expander the reference deliberately leaves unjudged. The links
		// collection's Kind is the precedent.
		f := map[string]any{"DeviceType": kind}
		block := ""
		if blocks := src.listdir(path.Join(base, "block")); len(blocks) > 0 {
			block = blocks[0]
		}
		segments := strings.Split(src.realpath(base), "/")
		end := ""
		for _, segment := range segments {
			if endDevice.MatchString(segment) {
				end = segment
				break
			}
		}
		// libata and usb-storage fill the SCSI vendor field with the TRANSPORT
		// name — a protocol fact, not a manufacturer. The maker comes back via
		// the model-prefix convention (ATA) or stays the genuine SCSI vendor.
		rawVendor, haveRawVendor := src.read(path.Join(base, "vendor"))
		model, haveModel := src.read(path.Join(base, "model"))
		transport, haveTransport := "", false
		switch rawVendor {
		case "ATA", "USB", "SATA", "NVMe":
			transport, haveTransport = rawVendor, haveRawVendor
		}
		vendor, haveVendor := rawVendor, haveRawVendor
		if haveTransport {
			vendor, haveVendor = ataVendor(model)
		}
		sasAddress, haveSAS := "", false
		if end != "" {
			sasAddress, haveSAS = src.read(path.Join(sasDevices, end, "sas_address"))
		}
		if !haveTransport && haveSAS {
			transport, haveTransport = "SAS", true
		}

		setString(f, "Vendor", vendor, haveVendor)
		setString(f, "Transport", transport, haveTransport)
		setString(f, "Model", model, haveModel)
		revision, haveRevision := src.read(path.Join(base, "rev"))
		setString(f, "Revision", revision, haveRevision)
		state, haveState := src.read(path.Join(base, "state"))
		setString(f, "State", state, haveState)
		setString(f, "Block", block, block != "")
		// Serial and WWN need no daemon: SCSI VPD page 0x80 and the kernel's
		// wwid file are sysfs reads.
		if serial, ok := vpdSerial(src, base); ok {
			f["Serial"] = serial
		}
		if block != "" {
			// Capacity from the kernel's sector count — the same read the
			// storage subsystem trusts for md arrays; 512-byte units by sysfs
			// contract regardless of the device's logical block size.
			if sectors, ok := intOrNone(src.read(path.Join("/sys/block", block, "size"))); ok && sectors != 0 {
				f["SizeBytes"] = sectors * 512
			}
		}
		wwn, haveWWN := src.read(path.Join(base, "wwid"))
		setString(f, "WWN", wwn, haveWWN)
		if alias, ok := aliases[block]; ok && block != "" {
			f["ByPath"] = alias
		}
		setString(f, "SASAddress", sasAddress, haveSAS)
		// Negotiated link rate, so a drive that trained low is visible. A link
		// at half speed reports nothing else wrong.
		scsiLinkFacts(src, f, dev)
		if slot, ok := deviceSlots[dev]; ok {
			f["Enclosure"] = slot.enclosure
			if digitsOnly(slot.slot) {
				number, _ := strconv.ParseInt(slot.slot, 10, 64)
				f["EnclosureSlot"] = number
			} else {
				f["EnclosureSlot"] = slot.slot
			}
			if slot.status != "" {
				f["SlotStatus"] = slot.status
			}
		}
		if kind == "enclosure" {
			table, ok := enclosureTables[dev]
			if !ok {
				table = map[string]any{}
			}
			f["Slots"] = table
		}
		parent := ""
		if chain := chainOf(src, base); len(chain) > 0 {
			parent = chain[len(chain)-1]
		}
		row := &item{name: dev, kind: kind, facts: f, parent: parent}
		if block != "" {
			row.names = diskNames(f, byIDNames(src, block), block)
		}
		items[dev] = row
		order = append(order, dev)
	}

	// Devices behind each host, so a consumer can hide childless controllers
	// by default — an empty SATA port is noise, not information.
	counts := map[string]int64{}
	for _, name := range order {
		if parent := items[name].parent; parent != "" {
			counts[parent]++
		}
	}
	for _, name := range order {
		if items[name].kind == "scsi-host" {
			items[name].facts["Devices"] = counts[name]
		}
	}

	// Depth-first walk, hosts first — the physical attachment tree. A parent
	// this walk never found is treated as a root, so a device whose chain
	// names something outside the listing is published rather than dropped.
	children := map[string][]string{}
	for _, name := range order {
		parent := items[name].parent
		if _, known := items[parent]; !known {
			parent = ""
		}
		children[parent] = append(children[parent], name)
	}
	for parent := range children {
		sortNatural(children[parent])
	}
	ordered := []item{}
	seen := map[string]bool{}
	var walk func(name string)
	walk = func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		ordered = append(ordered, *items[name])
		for _, child := range children[name] {
			walk(child)
		}
	}
	for _, root := range children[""] {
		walk(root)
	}
	return ordered
}

// vpdSerial reads SCSI VPD page 0x80, whose first four bytes are the page
// header and whose remainder is the drive's serial. Read as BYTES because the
// page is binary and a text read would mangle a non-ASCII octet before the
// slice could drop it.
func vpdSerial(src source, base string) (string, bool) {
	raw, ok := src.readBytes(path.Join(base, "vpd_pg80"))
	if !ok || len(raw) <= 4 {
		return "", false
	}
	ascii := make([]byte, 0, len(raw)-4)
	for _, octet := range raw[4:] {
		// errors="ignore" on an ascii decode drops every octet above 0x7f.
		if octet < 0x80 {
			ascii = append(ascii, octet)
		}
	}
	serial := strings.TrimSpace(string(ascii))
	return serial, serial != ""
}
