package main

import (
	"path"
	"regexp"
	"strconv"
	"strings"
)

// item is one row: the native name it is published under, the object type
// (on the wire since the 2026-08-21 ruling — it decides which health
// statement a row is entitled to), its facts, and the name families law 1
// asks for where the thing has more than one native name.
type item struct {
	name     string
	kind     string
	facts    map[string]any
	names    map[string]any // law 1: {"stable": {...}, "ephemeral": {...}}, nil for most rows
	parent   string         // scsi only: the topology node this hangs from
	hasChild bool
}

// setString publishes a reading only where there was one. A fact's value is
// never null (DESIGN 19), and on this interface most readings are a sysfs file
// or a hwdb property that may simply not be there — so absence is expressed by
// the key never appearing, which is what the reference's own row builder does.
func setString(f map[string]any, key, value string, ok bool) {
	if ok && value != "" {
		f[key] = value
	}
}

// sysfs says "<unknown>" or "Unknown" where a value is not established. Both
// read as data if passed through, so they become absence.
var sysfsUnknown = map[string]bool{
	"": true, "<unknown>": true, "unknown": true, "Unknown": true, "none": true,
}

func sysfsValue(raw string, ok bool) (string, bool) {
	value := strings.TrimSpace(raw)
	if !ok || sysfsUnknown[value] {
		return "", false
	}
	return value, true
}

// digitsOnly mirrors the reference's `str.isdigit()` gate, which is what
// decides whether a sysfs string becomes a number here. Not ParseInt on its
// own: "007" is digits and parses to 7, and " 7" and "-7" are neither digits
// nor a count this interface produces.
func digitsOnly(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// A lane count is a NUMBER and was once carried as the sysfs string, which
// silently disabled the "x2 lanes" rendering that exists precisely so a bare 2
// beside a bare 4 is not read as a speed.
func laneCount(raw string, ok bool) (int64, bool) {
	value, present := sysfsValue(raw, ok)
	if !present || !digitsOnly(value) {
		return 0, false
	}
	n, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func intOrNone(raw string, ok bool) (int64, bool) {
	if !ok || !digitsOnly(raw) {
		return 0, false
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ── platform ─────────────────────────────────────────────────────────────

// platformItems is the one row this collection ever has: the machine itself,
// named for its own hostname, with what DMI, lscpu and /proc/meminfo say about
// it. lscpu failing is a NOTE and not a failure — a host without util-linux
// still has firmware identity and memory — which is why the error arm here
// simply carries no CPU facts.
func platformItems(src source, hostname string) []item {
	cpu, err := src.lscpu()
	if err != nil {
		cpu = map[string]string{}
	}
	f := map[string]any{}
	// Ordered pairs and not a map literal: Go randomises map iteration, and a
	// collector whose native reads happen in a different order on every run is
	// one whose seam failures and whose journal are unreproducible.
	for _, pair := range [][2]string{
		{"SysVendor", "sys_vendor"},
		{"ProductName", "product_name"},
		{"BoardName", "board_name"},
		{"BiosVersion", "bios_version"},
		{"BiosDate", "bios_date"},
	} {
		value, ok := src.read(path.Join(dmi, pair[1]))
		setString(f, pair[0], value, ok)
	}
	setString(f, "CPUModel", cpu["Model name"], true)
	setString(f, "Architecture", cpu["Architecture"], true)
	for _, pair := range [][2]string{
		{"CPUs", "CPU(s)"},
		{"Sockets", "Socket(s)"},
		{"CoresPerSocket", "Core(s) per socket"},
		{"ThreadsPerCore", "Thread(s) per core"},
	} {
		raw, present := cpu[pair[1]]
		if n, ok := intOrNone(raw, present); ok {
			f[pair[0]] = n
		}
	}
	if total, ok := memTotalBytes(src); ok {
		f["MemoryTotalBytes"] = total
	}
	return []item{{name: hostname, kind: "platform", facts: f}}
}

// memTotalBytes reads /proc/meminfo, which is a kernel interface with a stated
// format: `MemTotal:  16265256 kB`. The file is read through the same primitive
// every other file is, so the parse is what a port has to reproduce rather
// than a number somebody pinned.
func memTotalBytes(src source) (int64, bool) {
	raw, ok := src.read("/proc/meminfo")
	if !ok {
		return 0, false
	}
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || parts[1] != strconv.FormatInt(kb, 10) {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}

// ── pci ──────────────────────────────────────────────────────────────────

func pciItems(src source) []item {
	addresses := src.listdir(pciDevices)
	items := make([]item, 0, len(addresses))
	for _, address := range addresses {
		props := src.udev(path.Join(pciDevices, address))
		f := map[string]any{}
		// Subclass first: "IDE interface" is what a reader wants, and the
		// class-level name is the fallback for a subclass the hwdb has no
		// entry for.
		class := props["ID_PCI_SUBCLASS_FROM_DATABASE"]
		if class == "" {
			class = props["ID_PCI_CLASS_FROM_DATABASE"]
		}
		setString(f, "Class", class, true)
		setString(f, "Vendor", props["ID_VENDOR_FROM_DATABASE"], true)
		setString(f, "Model", props["ID_MODEL_FROM_DATABASE"], true)
		setString(f, "Driver", props["DRIVER"], true)
		setString(f, "PCIID", props["PCI_ID"], true)
		items = append(items, item{name: address, kind: "pci-device", facts: f})
	}
	return items
}

// ── usb ──────────────────────────────────────────────────────────────────

// A USB device name is bus-port(.port…); an INTERFACE carries a ':config.iface'
// suffix and is the same physical device again, so the listing is filtered
// rather than published whole.
var usbDeviceName = regexp.MustCompile(`^(usb\d+|\d+-\d+(\.\d+)*)$`)

func usbItems(src source) []item {
	items := []item{}
	for _, name := range src.listdir(usbDevices) {
		if !usbDeviceName.MatchString(name) {
			continue
		}
		base := path.Join(usbDevices, name)
		props := src.udev(base)
		f := map[string]any{}
		// The hwdb name where udev has one, the device's own string where it
		// does not — a machine with no usb.ids installed has the second and
		// not the first, and a reader wants a maker either way.
		vendor := props["ID_VENDOR_FROM_DATABASE"]
		if vendor == "" {
			vendor, _ = src.read(path.Join(base, "manufacturer"))
		}
		setString(f, "Vendor", vendor, true)
		product := props["ID_MODEL_FROM_DATABASE"]
		if product == "" {
			product, _ = src.read(path.Join(base, "product"))
		}
		setString(f, "Product", product, true)
		for _, pair := range [][2]string{
			{"VendorID", "idVendor"},
			{"ProductID", "idProduct"},
			{"SpeedMbps", "speed"},
			{"USBVersion", "version"},
			// bcdDevice: the device's own firmware/release version.
			{"DeviceVersion", "bcdDevice"},
		} {
			value, ok := src.read(path.Join(base, pair[1]))
			setString(f, pair[0], value, ok)
		}
		deviceClass, _ := src.read(path.Join(base, "bDeviceClass"))
		kind := "usb-device"
		if deviceClass == "09" {
			kind = "usb-hub"
		}
		items = append(items, item{name: name, kind: kind, facts: f})
	}
	return items
}
