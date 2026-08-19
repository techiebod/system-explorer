package main

import (
	"encoding/json"
	"math"
	"path"
	"strings"
)

// driveHealth is one drive's SMART and identity facts, already keyed by the
// fact names they are published under and already free of the readings that
// were not there — a fact's value is never null (DESIGN 19), so a property
// udisks answered with an empty string or a zero kelvin never enters the map.
type driveHealth = map[string]any

// udisks2 is read through `busctl call --json=short`, which is systemd's own
// JSON rendering of a D-Bus reply and carries the type signature beside the
// data. That is the ruling of 2026-08-19 (DESIGN, adjudication queue, "what a
// captured payload IS for a non-document interface"): the native document for
// a bus interface is not a transcription this repository invents, it is the
// one the tool that ships with the bus produces — reproducible by hand, which
// is what makes a reading checkable at all.
const (
	udisksService   = "org.freedesktop.UDisks2"
	udisksPath      = "/org/freedesktop/UDisks2"
	objectManager   = "org.freedesktop.DBus.ObjectManager"
	udisksDrive     = udisksService + ".Drive"
	udisksDriveAta  = udisksService + ".Drive.Ata"
	udisksNVMeCtrl  = udisksService + ".NVMe.Controller"
	udisksBlock     = udisksService + ".Block"
	getManagedNouns = "GetManagedObjects"
)

// A busctl variant: the signature and the value, which is exactly what makes
// the document self-describing about D-Bus types rather than needing a
// convention this repository would have to defend.
type variant struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type managedObjects struct {
	Data []map[string]map[string]map[string]variant `json:"data"`
}

func (s *liveSource) drives() (map[string]driveHealth, bool) {
	if s.udisksOnce {
		return s.udisksMap, s.udisksOK
	}
	s.udisksOnce = true
	// Where the daemon is not running these facts are simply absent — noted,
	// never faked. The second return value is what carries that note.
	out, err := runCommand(commandTimeout, "busctl", "call", "--json=short",
		udisksService, udisksPath, objectManager, getManagedNouns)
	if err != nil {
		return nil, false
	}
	var reply managedObjects
	if err := json.Unmarshal(out, &reply); err != nil || len(reply.Data) == 0 {
		return nil, false
	}
	s.udisksMap = driveHealthByBlock(reply.Data[0])
	s.udisksOK = true
	return s.udisksMap, true
}

// driveHealthByBlock folds the managed-object tree into {block name → facts}.
//
// Two passes and not one, because the two halves live on different objects:
// the SMART properties hang off a Drive, and the kernel name that every other
// collection joins on hangs off a Block that points at it. A single pass over
// Blocks would have to re-find the Drive each time, and one over Drives would
// never learn a name.
func driveHealthByBlock(objects map[string]map[string]map[string]variant) map[string]driveHealth {
	drives := map[string]driveHealth{}
	for objectPath, interfaces := range objects {
		drive, ok := interfaces[udisksDrive]
		if !ok {
			continue
		}
		info := driveHealth{}
		setNonEmpty(info, "Serial", drive["Serial"])
		setNonEmpty(info, "Vendor", drive["Vendor"])
		setNonEmpty(info, "Firmware", drive["Revision"])

		// udisks speaks ATA SMART only on this interface, and only where the
		// drive says it supports it — a SAS drive has none here at all, which
		// is why the SmartUnobservable reason names the transport.
		if ata, ok := interfaces[udisksDriveAta]; ok && boolOf(ata["SmartSupported"]) {
			if failing, ok := boolValue(ata["SmartFailing"]); ok {
				info["SmartFailing"] = failing
			}
			if sectors, ok := u64Value(ata["SmartNumBadSectors"]); ok && sectors != unsetU64 {
				info["SmartBadSectors"] = sectors
			}
			setNonEmpty(info, "SmartSelftestStatus", ata["SmartSelftestStatus"])
			if celsius, ok := kelvinToCelsius(ata["SmartTemperature"]); ok {
				info["SmartTemperatureC"] = celsius
			}
			if seconds, ok := intValue(ata["SmartPowerOnSeconds"]); ok && seconds > 0 {
				// Banker's rounding, because the reference's round() is: an
				// exact half hour lands on the even hour, and a port that
				// rounded away from zero would disagree with it on precisely
				// one drive in seven thousand.
				info["SmartPowerOnHours"] = int64(math.RoundToEven(float64(seconds) / 3600))
			}
		}

		// The NVMe branch carries the device self-test verdict under the same
		// property name the ATA one does, and for a while only the ATA branch
		// lifted it — a real drive's known_seg_fail sat in raw evidence,
		// invisible in facts. One fact name, both transports.
		if nvme, ok := interfaces[udisksNVMeCtrl]; ok {
			if warnings := stringsValue(nvme["SmartCriticalWarning"]); len(warnings) > 0 {
				info["SmartCriticalWarning"] = warnings
			}
			setNonEmpty(info, "SmartSelftestStatus", nvme["SmartSelftestStatus"])
			if celsius, ok := kelvinToCelsius(nvme["SmartTemperature"]); ok {
				info["SmartTemperatureC"] = celsius
			}
			if hours, ok := intValue(nvme["SmartPowerOnHours"]); ok && hours > 0 {
				info["SmartPowerOnHours"] = hours
			}
		}
		drives[objectPath] = info
	}

	health := map[string]driveHealth{}
	for _, interfaces := range objects {
		block, ok := interfaces[udisksBlock]
		if !ok {
			continue
		}
		owner, _ := stringValue(block["Drive"])
		info, ok := drives[owner]
		if !ok || len(info) == 0 {
			continue
		}
		name := path.Base(byteStringOf(block["Device"]))
		if name == "" || name == "." || name == "/" {
			continue
		}
		if _, seen := health[name]; !seen {
			health[name] = info
		}
	}
	return health
}

// The u64 sentinel systemd and udisks use for "not set". Passing it through
// would publish 18446744073709551615 bad sectors on a healthy drive.
const unsetU64 = uint64(1<<64 - 1)

func setNonEmpty(into driveHealth, key string, v variant) {
	if value, ok := stringValue(v); ok && value != "" {
		into[key] = value
	}
}

func stringValue(v variant) (string, bool) {
	if len(v.Data) == 0 {
		return "", false
	}
	var out string
	if json.Unmarshal(v.Data, &out) != nil {
		return "", false
	}
	return out, true
}

func boolValue(v variant) (bool, bool) {
	if len(v.Data) == 0 {
		return false, false
	}
	var out bool
	if json.Unmarshal(v.Data, &out) != nil {
		return false, false
	}
	return out, true
}

func boolOf(v variant) bool {
	value, _ := boolValue(v)
	return value
}

func intValue(v variant) (int64, bool) {
	if len(v.Data) == 0 {
		return 0, false
	}
	var out int64
	if json.Unmarshal(v.Data, &out) != nil {
		return 0, false
	}
	return out, true
}

func u64Value(v variant) (uint64, bool) {
	if len(v.Data) == 0 {
		return 0, false
	}
	var out uint64
	if json.Unmarshal(v.Data, &out) != nil {
		return 0, false
	}
	return out, true
}

func stringsValue(v variant) []string {
	if len(v.Data) == 0 {
		return nil
	}
	var out []string
	if json.Unmarshal(v.Data, &out) != nil {
		return nil
	}
	return out
}

// byteStringOf decodes a D-Bus `ay`, which busctl renders as an array of byte
// values and udisks uses for every device path. NUL-terminated, so the
// terminator is trimmed rather than carried into a name nothing would match.
func byteStringOf(v variant) string {
	if len(v.Data) == 0 {
		return ""
	}
	var octets []byte
	if json.Unmarshal(v.Data, &octets) != nil {
		return ""
	}
	return strings.TrimRight(string(octets), "\x00")
}

// kelvinToCelsius converts udisks's temperatures, where 0 means unknown.
//
// Whole kelvin in, whole degrees out. Subtracting 273.15 from an integer
// always lands on .85, so rounding to one decimal made every udisks reading
// end in .9 — a digit the sensor never measured. A drive reporting 300 K knows
// it is 27 °C, not 26.9 °C, and inventing precision is the same class of error
// as inventing a value. A fractional reading keeps its one decimal, because
// there the precision is real.
func kelvinToCelsius(v variant) (any, bool) {
	if len(v.Data) == 0 {
		return nil, false
	}
	var kelvin float64
	if json.Unmarshal(v.Data, &kelvin) != nil || kelvin <= 0 {
		return nil, false
	}
	celsius := kelvin - 273.15
	if kelvin == math.Trunc(kelvin) {
		return int64(math.RoundToEven(celsius)), true
	}
	return math.RoundToEven(celsius*10) / 10, true
}
