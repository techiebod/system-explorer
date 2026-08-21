package main

import (
	"fmt"
	"path"
	"regexp"
)

// PCIe throughput of ONE lane, in bytes per second each way, keyed on the
// kernel's own current_link_speed / max_link_speed label. These are the rates
// AFTER line encoding — 8b/10b through Gen2, 128b/130b from Gen3, the
// 242B/256B FLIT at Gen6 — so they are what the link actually carries, not the
// raw transfer rate the label names.
//
// Exact labels only. A generation this table has not met yet must produce
// SILENCE rather than a plausible wrong number, so there is no parsing of the
// leading float and no interpolation. This is the one place the product turns
// a kernel label into a quantity, and it stays here rather than spreading into
// a rule: ranking the labels as strings would invent precision, and converting
// an exact match does not.
var pcieLaneBytes = map[string]int64{
	"2.5 GT/s PCIe":  250_000_000,
	"5.0 GT/s PCIe":  500_000_000,
	"8.0 GT/s PCIe":  984_615_384,
	"16.0 GT/s PCIe": 1_969_230_769,
	"32.0 GT/s PCIe": 3_938_461_538,
	"64.0 GT/s PCIe": 7_562_500_000,
}

func pcieBandwidth(speed string, haveSpeed bool, lanes int64, haveLanes bool) (int64, bool) {
	perLane, known := pcieLaneBytes[speed]
	if !haveSpeed || !haveLanes || !known || perLane == 0 || lanes == 0 {
		return 0, false
	}
	return perLane * lanes, true
}

// nvmeLinkFacts is the PCIe link speed and width for an NVMe controller: what
// it negotiated, what the DEVICE can do, and what the SLOT can do.
//
// The third one is the point. A drive running x2 of its own x4 is either wired
// that way or trained down, and those are completely different statements: the
// first is an immutable property of the board, the second is a fault. Without
// the upstream bridge's capability there is no way to tell, and warning about
// the first is warning about something no operator can act on.
func nvmeLinkFacts(src source, f map[string]any, controller string) {
	base := path.Join(nvmeDevices, controller, "device")
	speed, haveSpeed := sysfsValue(src.read(path.Join(base, "current_link_speed")))
	speedMax, haveSpeedMax := sysfsValue(src.read(path.Join(base, "max_link_speed")))
	width, haveWidth := laneCount(src.read(path.Join(base, "current_link_width")))
	widthMax, haveWidthMax := laneCount(src.read(path.Join(base, "max_link_width")))
	setString(f, "LinkSpeed", speed, haveSpeed)
	setString(f, "LinkSpeedMax", speedMax, haveSpeedMax)
	if haveWidth && width != 0 {
		f["LinkWidth"] = width
	}
	if haveWidthMax && widthMax != 0 {
		f["LinkWidthMax"] = widthMax
	}
	// The bridge immediately above shares this link, so its max_link_* is the
	// SLOT's capability while the device's is the card's.
	bridge := path.Dir(src.realpath(base))
	if slotWidth, ok := laneCount(src.read(path.Join(bridge, "max_link_width"))); ok && slotWidth != 0 {
		f["SlotLinkWidthMax"] = slotWidth
	}
	slotSpeed, haveSlotSpeed := sysfsValue(src.read(path.Join(bridge, "max_link_speed")))
	setString(f, "SlotLinkSpeedMax", slotSpeed, haveSlotSpeed)
	// Derived, not read — and the reason the four facts above stop reading as
	// four unrelated numbers. Speed is the rate of ONE lane and width is how
	// many are active, so the figure a reader is actually after is the
	// product; asked what "x2 of x4" cost them, nobody could answer from the
	// four alone. It is a fact rather than prose so a rule can CITE it, a UI
	// can draw it without carrying a PCIe table of its own, and an agent
	// consumer gets the same arithmetic.
	if bandwidth, ok := pcieBandwidth(speed, haveSpeed, width, haveWidth); ok {
		f["LinkBandwidthBytesPerSec"] = bandwidth
	}
	if bandwidth, ok := pcieBandwidth(speedMax, haveSpeedMax, widthMax, haveWidthMax); ok {
		f["LinkBandwidthMaxBytesPerSec"] = bandwidth
	}
}

// nvmeWWN is the device's world-wide name, which on NVMe belongs to the
// NAMESPACE.
//
// A kernel name renumbers: `nvme0n1` can come back as `nvme1n1` when
// enumeration order shifts, which on a four-drive host is not hypothetical.
// The wwid does not, and it is what a join survives a reboot on.
//
// NOT taken from udisks2, which is where it looks like it should come from:
// measured on the estate, org.freedesktop.UDisks2.Drive.WWN is the empty
// string on every NVMe drive there, so reading it would publish "" — a fact
// that asserts an identity and carries none, which is worse than the gap it
// would appear to close.
//
// A controller with SEVERAL namespaces has several wwids and no single one of
// its own, so it says that rather than picking the first.
func nvmeWWN(src source, f map[string]any, namespaces []string) {
	if len(namespaces) == 0 {
		return
	}
	present := []string{}
	byNamespace := map[string]string{}
	for _, ns := range namespaces {
		if value, ok := src.read(path.Join("/sys/block", ns, "wwid")); ok {
			byNamespace[ns] = value
			present = append(present, value)
		}
	}
	if len(namespaces) == 1 {
		setString(f, "WWN", byNamespace[namespaces[0]], true)
		return
	}
	distinct := map[string]bool{}
	for _, value := range present {
		distinct[value] = true
	}
	if len(distinct) == 1 {
		f["WWN"] = present[0]
		return
	}
	f["WWNUnobservable"] = fmt.Sprintf(
		"This controller exposes %d namespaces and a wwid belongs to a "+
			"namespace, not a controller, so no single world-wide name "+
			"identifies it. The per-namespace names are on the block devices "+
			"themselves.", len(namespaces))
}

func nvmeItems(src source) []item {
	items := []item{}
	for _, controller := range src.listdir(nvmeDevices) {
		base := path.Join(nvmeDevices, controller)
		namespacePattern := regexp.MustCompile(`^` + regexp.QuoteMeta(controller) + `n\d+$`)
		namespaces := []string{}
		for _, entry := range src.listdir(base) {
			if namespacePattern.MatchString(entry) {
				namespaces = append(namespaces, entry)
			}
		}
		f := map[string]any{}
		model, haveModel := src.read(path.Join(base, "model"))
		setString(f, "Model", model, haveModel)
		firmware, haveFirmware := src.read(path.Join(base, "firmware_rev"))
		setString(f, "FirmwareRev", firmware, haveFirmware)
		nvmeLinkFacts(src, f, controller)
		serial, haveSerial := src.read(path.Join(base, "serial"))
		setString(f, "Serial", serial, haveSerial)
		state, haveState := src.read(path.Join(base, "state"))
		setString(f, "State", state, haveState)
		transport, haveTransport := src.read(path.Join(base, "transport"))
		setString(f, "Transport", transport, haveTransport)
		if address, ok := pciAddressOf(src, path.Join(base, "device")); ok {
			f["PCIAddress"] = address
		}
		// The namespaces this controller exposes — the block devices a
		// filesystem can actually sit on. An empty list is still a statement,
		// which is why it is published rather than dropped: a controller with
		// no namespace is a real and worrying shape.
		f["Namespaces"] = namespaces
		nvmeWWN(src, f, namespaces)
		// Law 1 on a controller: serial and wwid where they exist. The by-id
		// links belong to the NAMESPACE block devices, the same reasoning as
		// nvmeWWN — a controller with several namespaces has several and no
		// one of its own — so they are published by the storage subsystem's
		// rows, not manufactured here.
		stable := map[string]any{}
		if serial, ok := f["Serial"].(string); ok {
			stable["serial"] = []string{serial}
		}
		if wwn, ok := f["WWN"].(string); ok {
			stable["wwn"] = []string{wwn}
		}
		row := item{name: controller, kind: "nvme-controller", facts: f}
		if len(stable) > 0 {
			row.names = map[string]any{"stable": stable}
		}
		items = append(items, row)
	}
	return items
}

// mergeNVMeHealth folds the three health depths onto the controller rows.
func mergeNVMeHealth(src source, items []item) {
	health, _ := src.drives()
	temperatures := hwmonTemperatures(src)
	candidates := map[string][]string{}
	for _, row := range items {
		candidates[row.name] = nvmeCandidatePaths(row.name, namespacesOf(row))
	}
	deep := smartDeep(src, candidates)
	for i := range items {
		namespaces := namespacesOf(items[i])
		first := ""
		if len(namespaces) > 0 {
			first = namespaces[0]
		}
		mergeHealth(items[i].facts, health, first)
		if _, already := items[i].facts["SmartTemperatureC"]; !already {
			if celsius, ok := temperatures[items[i].name]; ok {
				items[i].facts["SmartTemperatureC"] = celsius
			}
		}
		for name, value := range deep[items[i].name] {
			items[i].facts[name] = value
		}
		applyUnobservable("nvme", items[i].kind, items[i].facts)
	}
}

func namespacesOf(row item) []string {
	names, _ := row.facts["Namespaces"].([]string)
	return names
}

// mergeSCSIHealth is the same three depths against the scsi tree, keyed on the
// block device a row backs — a host or an expander backs none and takes none.
func mergeSCSIHealth(src source, items []item) {
	health, _ := src.drives()
	temperatures := hwmonTemperatures(src)
	candidates := map[string][]string{}
	for _, row := range items {
		if block, ok := row.facts["Block"].(string); ok && block != "" {
			candidates[block] = []string{"/dev/" + block}
		}
	}
	deep := smartDeep(src, candidates)
	for i := range items {
		block, _ := items[i].facts["Block"].(string)
		mergeHealth(items[i].facts, health, block)
		if block != "" {
			if _, already := items[i].facts["SmartTemperatureC"]; !already {
				if celsius, ok := temperatures[block]; ok {
					items[i].facts["SmartTemperatureC"] = celsius
				}
			}
			for name, value := range deep[block] {
				items[i].facts[name] = value
			}
		}
		applyUnobservable("scsi", items[i].kind, items[i].facts)
	}
}
