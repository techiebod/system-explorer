package main

import (
	"encoding/json"
	"fmt"
	"math"
	"path"
	"strconv"
	"strings"
	"time"
)

// Drive health arrives in DEPTH ORDER, and all three depths are read because
// each sees something the others cannot: hwmon sysfs temperatures (the
// zero-privilege floor, present with no daemon and no grant), udisks2 over
// D-Bus (unprivileged ATA SMART where the daemon runs), and smartctl --json
// where the operator granted raw device access. udisks2's NVMe interface has
// no endurance property at all, so a drive past its rated life is invisible
// without the third.

// hwmonTemperatures maps a device name — an nvme controller, or the sdX a
// SATA drive backs — to degrees Celsius. The nvme driver and drivetemp
// register sensors readable by anyone, which is the floor a host with no
// udisks2 and no disk grant still has.
func hwmonTemperatures(src source) map[string]float64 {
	out := map[string]float64{}
	for _, hw := range src.listdir(hwmon) {
		name, haveName := src.read(path.Join(hwmon, hw, "name"))
		raw, haveRaw := src.read(path.Join(hwmon, hw, "temp1_input"))
		if !haveRaw || !haveName || (name != "nvme" && name != "drivetemp") {
			continue
		}
		millidegrees, err := strconv.Atoi(raw)
		if err != nil {
			continue
		}
		// One decimal, and it is real: hwmon reports millidegrees, so unlike
		// the udisks kelvin conversion there is precision here to keep.
		celsius := math.RoundToEven(float64(millidegrees)/1000*10) / 10
		device := src.realpath(path.Join(hwmon, hw, "device"))
		if name == "nvme" {
			out[path.Base(device)] = celsius
			continue
		}
		if blocks := src.listdir(path.Join(device, "block")); len(blocks) > 0 {
			out[blocks[0]] = celsius
		}
	}
	return out
}

// smartDeep is the smartctl --json depth, per device.
//
// The primary source is the root collector's snapshots: smartctl's admin
// ioctls need CAP_SYS_ADMIN regardless of device-node permissions, so the
// module's grantDiskAccess timer writes them out and the agent reads them.
// Direct execution stays as the fallback for an ad-hoc run that happens to
// hold the access.
func smartDeep(src source, candidates map[string][]string) map[string]map[string]any {
	out := map[string]map[string]any{}
	for device, paths := range candidates {
		info := map[string]any{}
		// Read unconditionally, because the interesting case is a reason with
		// NO snapshot: the collector garbage-collects a snapshot that carries
		// no reading, so a drive left asleep long enough ends up with the
		// reason alone. Attaching it only alongside a snapshot would blame
		// grantDiskAccess on a host whose collector is working correctly.
		reason, haveReason := src.smartReason(device)
		if haveReason {
			info["SmartSnapshotReason"] = reason
		}
		var document map[string]json.RawMessage
		snapshot, mtime, haveSnapshot := src.smartSnapshot(device)
		if haveSnapshot {
			document = snapshot
			// Snapshot facts are only as fresh as the file: stamp when the
			// collector wrote it and how old that is right now. The age is
			// computed here so the staleness rule stays pure — rules never
			// read clocks — and a direct run below is observed_at-fresh and
			// carries neither fact.
			info["SmartSnapshotAt"] = epochISO(mtime)
			age := int64(src.now() - mtime)
			if age < 0 {
				age = 0
			}
			info["SmartSnapshotAgeSeconds"] = age
		} else {
			// One bail-out point rather than three, because each of them has
			// to preserve a recorded reason: dropping the device silently
			// would discard the only explanation an operator can get for why
			// a drive shows no health at all.
			for _, devicePath := range paths {
				if !src.smartctlUsable(devicePath) {
					continue
				}
				parsed, err := src.smartctlJSON(devicePath)
				if err == nil {
					document = parsed
				}
				break
			}
			if document == nil {
				if haveReason {
					out[device] = info
				}
				continue
			}
		}
		mergeSmartDocument(info, document)
		out[device] = info
	}
	return out
}

// mergeSmartDocument lifts the members smartctl's JSON carries, keeping each
// number spelled exactly as the tool wrote it: `12` and `12.0` are different
// answers to a typed reader (DESIGN 19), so these travel as raw tokens rather
// than through any Go numeric type.
func mergeSmartDocument(info map[string]any, document map[string]json.RawMessage) {
	if log, ok := object(document["nvme_smart_health_information_log"]); ok {
		passThrough(info, "SmartPercentUsed", log["percentage_used"])
		passThrough(info, "SmartAvailableSparePct", log["available_spare"])
		passThrough(info, "SmartSpareThresholdPct", log["available_spare_threshold"])
		passThrough(info, "SmartMediaErrors", log["media_errors"])
	}
	if status, ok := object(document["smart_status"]); ok {
		passThrough(info, "SmartOverallPassed", status["passed"])
	}
	if temperature, ok := object(document["temperature"]); ok {
		passThrough(info, "SmartTemperatureC", temperature["current"])
	}
	if power, ok := object(document["power_on_time"]); ok {
		passThrough(info, "SmartPowerOnHours", power["hours"])
	}
}

func object(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	out := map[string]json.RawMessage{}
	if json.Unmarshal(raw, &out) != nil || len(out) == 0 {
		return nil, false
	}
	return out, true
}

// passThrough carries one member onto the row verbatim, and drops a null: a
// member the document spells as null is a reading smartctl did not take, and
// a fact's value is never null.
func passThrough(info map[string]any, name string, raw json.RawMessage) {
	if len(raw) == 0 || string(raw) == "null" {
		return
	}
	info[name] = raw
}

func epochISO(seconds float64) string {
	return time.Unix(int64(seconds), 0).UTC().Format("2006-01-02T15:04:05Z")
}

// Every fact that constitutes an actual health READING
// (agent/rules/hardware.py). Deliberately excludes SmartSnapshotAt and
// SmartSnapshotAgeSeconds: those say the collector RAN, not that it read
// anything, and conflating the two is how five raidz1 members displayed a
// vouched-for "ok" while their snapshots held nothing but an smartctl error.
var smartHealthFacts = []string{
	"SmartFailing", "SmartOverallPassed", "SmartCriticalWarning",
	"SmartSelftestStatus", "SmartPercentUsed", "SmartAvailableSparePct",
	"SmartMediaErrors", "SmartBadSectors", "SmartTemperatureC",
	"SmartPowerOnHours",
}

func hasSmartReading(f map[string]any) bool {
	for _, name := range smartHealthFacts {
		if _, ok := f[name]; ok {
			return true
		}
	}
	return false
}

// noReadingReason says why this drive carries no health reading, as
// specifically as can be said.
//
// Order matters: smartctl's own words beat any inference. A drive whose
// snapshot was garbage-collected for carrying no reading has no
// SmartSnapshotAt at all, so without checking the recorded reason first this
// would blame grantDiskAccess on a host where the collector is installed,
// running, and correctly declining to wake a sleeping disk.
func noReadingReason(f map[string]any) string {
	if recorded, ok := f["SmartSnapshotReason"].(string); ok && recorded != "" {
		return fmt.Sprintf("the root smartctl collector got no reading — %s", recorded)
	}
	if _, ok := f["SmartSnapshotAt"]; ok {
		return "the root smartctl snapshot for this device carried no reading " +
			"(smartctl declined the drive, or it was asleep and left alone)."
	}
	return "no root smartctl snapshot exists for this device (grantDiskAccess " +
		"off?) and udisks2 exposed no SMART for this transport — udisks " +
		"speaks ATA SMART only, so SAS drives have none."
}

// mergeHealth folds udisks2's view of one block device onto a row.
func mergeHealth(f map[string]any, health map[string]driveHealth, block string) {
	if block == "" {
		return
	}
	for name, value := range health[block] {
		f[name] = value
	}
}

// applyUnobservable is the one severity-adjacent statement that reaches the
// wire. The rest of _apply_severity — the worst_opinion_level and the carried
// opinion subset — is a ROW property of the shipping agent's HTTP surface and
// is not a stream record at all, so a port that computed it would be emitting
// something no consumer of this contract reads.
//
// A disk or controller that yielded no health reading says so, so a rule can
// decline to vouch for it instead of calling it healthy. State == running is
// the kernel having enumerated the device, not a measurement of its health.
func applyUnobservable(collection, objectType string, f map[string]any) {
	if collection != "nvme" && objectType != "disk" {
		return
	}
	if hasSmartReading(f) {
		return
	}
	if _, already := f["SmartUnobservable"]; already {
		return
	}
	f["SmartUnobservable"] = noReadingReason(f)
}

// nvmeCandidatePaths is where smartctl would find one controller's device
// node, in the order the reference tries them: the generic character device
// of the first namespace, then the namespace block device, then the
// controller itself.
func nvmeCandidatePaths(controller string, namespaces []string) []string {
	paths := []string{}
	if len(namespaces) > 0 {
		paths = append(paths, "/dev/"+strings.Replace(namespaces[0], "nvme", "ng", 1))
		paths = append(paths, "/dev/"+namespaces[0])
	}
	return append(paths, "/dev/"+controller)
}
