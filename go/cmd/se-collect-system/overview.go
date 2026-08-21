package main

// The overview collection: the per-host summary the old UI opened on
// (register row 9, R3b), ported member-for-member from the reference's
// _overview_facts. Ten world-readable proc documents, one object, and the
// discipline that carries the whole file: a source that could not be read
// takes exactly its own facts to the absent list — grouped by source,
// because that is the granularity at which they genuinely go missing
// together — and never a zero, because a zero is a measurement.
//
// Counters stay counters: this collector holds no previous sample, so a
// client derives rates across the window it actually observed. The judge
// exempts declared counters and gauges by value; everything here that
// moves is declared as what it is.

import (
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Synthetic block devices whose I/O is noise at host scale — the
// reference's own skip list, verbatim.
var diskstatsSkip = regexp.MustCompile(`^(loop|ram|zram|sr|fd)\d`)

// floatToken renders a reading as the JSON number it travels as: a
// trailing ".0" where integral, because the reference emits 0.0 and typed
// equality holds 0 and 0.0 to be different answers — which they are to
// any consumer in a typed language (the resources collector's rule).
func floatToken(value float64) string {
	text := strconv.FormatFloat(value, 'f', -1, 64)
	if !strings.ContainsAny(text, ".eE") {
		text += ".0"
	}
	return text
}

// jsonFloat wraps a float for the facts map so it marshals via floatToken.
type jsonFloat float64

func (f jsonFloat) MarshalJSON() ([]byte, error) {
	return []byte(floatToken(float64(f))), nil
}

// roundEven mirrors Python's round(): half-even, the reference's own
// rounding for every percentage here.
func roundEven(v float64) int64 { return int64(math.RoundToEven(v)) }

func collectOverview(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	at, err := src.stamp(*objects)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}

	facts := map[string]any{}
	var absent []string
	missing := func(names ...string) { absent = append(absent, names...) }

	// uptime — and BootedAt derived against the one wall reading, which
	// replay pins (SE_REPLAY_NOW) so the derivation is the same number on
	// every machine that replays.
	if fields := strings.Fields(src.proc("proc-uptime")); len(fields) > 0 {
		seconds, err := strconv.ParseFloat(fields[0], 64)
		if err == nil {
			facts["UptimeSeconds"] = int64(seconds)
			if now := src.wallNow(); now > 0 {
				facts["BootedAt"] = time.Unix(int64(now-seconds), 0).UTC().
					Format("2006-01-02T15:04:05Z")
			} else {
				missing("BootedAt")
			}
		} else {
			missing("UptimeSeconds", "BootedAt")
		}
	} else {
		missing("UptimeSeconds", "BootedAt")
	}

	// loadavg + the cpu count it is judged against.
	if fields := strings.Fields(src.proc("proc-loadavg")); len(fields) >= 3 {
		load1, e1 := strconv.ParseFloat(fields[0], 64)
		load5, e2 := strconv.ParseFloat(fields[1], 64)
		load15, e3 := strconv.ParseFloat(fields[2], 64)
		if e1 == nil && e2 == nil && e3 == nil {
			facts["LoadAvg1"] = jsonFloat(load1)
			facts["LoadAvg5"] = jsonFloat(load5)
			facts["LoadAvg15"] = jsonFloat(load15)
			if cpus := src.cpus(); cpus > 0 {
				facts["CpuCount"] = int64(cpus)
				facts["LoadPerCpu1"] = jsonFloat(
					math.RoundToEven(load1/float64(cpus)*100) / 100)
			} else {
				missing("CpuCount", "LoadPerCpu1")
			}
		} else {
			missing("LoadAvg1", "LoadAvg5", "LoadAvg15", "CpuCount", "LoadPerCpu1")
		}
	} else {
		missing("LoadAvg1", "LoadAvg5", "LoadAvg15", "CpuCount", "LoadPerCpu1")
	}

	// meminfo — the kB-suffixed members, in bytes, and the two derived
	// percentages. The ARC-adjusted one exists so the memory rules can be
	// DATA (DESIGN 17): the old evaluator computed used-minus-ARC inline,
	// and a rule table cannot do arithmetic, so the collector derives the
	// number once and both rule and reader see the same fact.
	mem := meminfoBytes(src.proc("proc-meminfo"))
	arcSize, arcTarget, arcPresent := arcFacts(src.proc("proc-arcstats"))
	// The combined guards mirror the reference's own exactly — the memory
	// family stands or falls together, and so does swap — because a finer
	// split here would be a parity divergence over a case (MemTotal
	// without MemAvailable) no supported kernel produces.
	total, hasTotal := mem["MemTotal"]
	available, hasAvailable := mem["MemAvailable"]
	if hasTotal && hasAvailable && total > 0 {
		used := total - available
		facts["MemTotalBytes"] = total
		facts["MemAvailableBytes"] = available
		facts["MemUsedBytes"] = used
		facts["MemUsedPercent"] = roundEven(float64(used) * 100 / float64(total))
		adjusted := used - arcSize
		if adjusted < 0 {
			adjusted = 0
		}
		facts["MemUsedPercentAdjusted"] = roundEven(
			float64(adjusted) * 100 / float64(total))
	} else {
		missing("MemTotalBytes", "MemAvailableBytes", "MemUsedBytes",
			"MemUsedPercent", "MemUsedPercentAdjusted")
	}
	swapTotal, hasSwapTotal := mem["SwapTotal"]
	swapFree, hasSwapFree := mem["SwapFree"]
	if hasSwapTotal && hasSwapFree {
		facts["SwapTotalBytes"] = swapTotal
		facts["SwapUsedBytes"] = swapTotal - swapFree
		if swapTotal > 0 {
			facts["SwapUsedPercent"] = roundEven(
				float64(swapTotal-swapFree) * 100 / float64(swapTotal))
		} else {
			// A swapless host has no swap pressure to be innocent of:
			// absent, never 0%.
			missing("SwapUsedPercent")
		}
	} else {
		missing("SwapTotalBytes", "SwapUsedBytes", "SwapUsedPercent")
	}
	if arcPresent {
		facts["ArcSizeBytes"] = arcSize
		facts["ArcTargetBytes"] = arcTarget
	} else {
		// Absent without the zfs module — absence is the fact; zero would
		// read as an empty cache.
		missing("ArcSizeBytes", "ArcTargetBytes")
	}

	if times := cpuTimes(src.proc("proc-stat")); len(times) > 0 {
		facts["CpuTimes"] = times
	} else {
		missing("CpuTimes")
	}

	// PSI — the kernel's own decaying averages. A kernel without
	// CONFIG_PSI has no /proc/pressure: the facts are absent, never zero.
	psi := psiFacts(src)
	for _, name := range psiFactNames {
		if value, ok := psi[name]; ok {
			facts[name] = jsonFloat(value)
		} else {
			missing(name)
		}
	}

	if net := netCounters(src.proc("proc-net-dev")); len(net) > 0 {
		facts["NetCounters"] = net
	} else {
		missing("NetCounters")
	}
	if disk := diskCounters(src.proc("proc-diskstats"), src.sysBlock()); len(disk) > 0 {
		facts["DiskCounters"] = disk
	} else {
		missing("DiskCounters")
	}

	sort.Strings(absent)
	out.emit(objectRecord{
		Record:     "object",
		Type:       "overview",
		Collection: collection,
		// The reference's own constant: one summary object per host,
		// named "host", id overview:host once the collator mints it.
		Name:   "host",
		Facts:  facts,
		Absent: absent,
		At:     at,
	})
	*objects++
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    1,
	})
	return exitOK
}

func meminfoBytes(text string) map[string]int64 {
	out := map[string]int64{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[2] == "kB" {
			if v, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
				out[strings.TrimSuffix(fields[0], ":")] = v * 1024
			}
		}
	}
	return out
}

func arcFacts(text string) (size, target int64, present bool) {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		v, err := strconv.ParseInt(fields[2], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "size":
			size, present = v, true
		case "c":
			target = v
		}
	}
	return size, target, present
}

// cpuTimeFields is /proc/stat's aggregate line in the kernel's documented
// order; steal and the guest fields matter on a VM and are carried when
// present rather than assumed.
var cpuTimeFields = [...]string{"User", "Nice", "System", "Idle", "Iowait",
	"Irq", "Softirq", "Steal", "Guest", "GuestNice"}

func cpuTimes(text string) map[string]int64 {
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[0] == "cpu" {
			out := map[string]int64{}
			for i, name := range cpuTimeFields {
				if i+1 >= len(fields) {
					break
				}
				if v, err := strconv.ParseInt(fields[i+1], 10, 64); err == nil {
					out[name] = v
				}
			}
			return out
		}
	}
	return nil
}

// psiFactNames is the closed set the declaration carries, in declaration
// order — cpu has no "full" line by kernel definition, so it is absent
// from both the set and the parse.
var psiFactNames = [...]string{
	"PsiCpuSomeAvg10", "PsiCpuSomeAvg60", "PsiCpuSomeAvg300",
	"PsiMemorySomeAvg10", "PsiMemorySomeAvg60", "PsiMemorySomeAvg300",
	"PsiMemoryFullAvg10", "PsiMemoryFullAvg60", "PsiMemoryFullAvg300",
	"PsiIoSomeAvg10", "PsiIoSomeAvg60", "PsiIoSomeAvg300",
	"PsiIoFullAvg10", "PsiIoFullAvg60", "PsiIoFullAvg300",
}

func psiFacts(src source) map[string]float64 {
	out := map[string]float64{}
	for _, resource := range [...]string{"cpu", "memory", "io"} {
		text := src.proc("proc-pressure-" + resource)
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || (resource == "cpu" && fields[0] == "full") {
				continue
			}
			share := strings.ToUpper(fields[0][:1]) + fields[0][1:]
			for _, token := range fields[1:] {
				key, value, found := strings.Cut(token, "=")
				if !found || !strings.HasPrefix(key, "avg") {
					continue
				}
				if v, err := strconv.ParseFloat(value, 64); err == nil {
					out["Psi"+strings.ToUpper(resource[:1])+resource[1:]+
						share+"Avg"+key[3:]] = v
				}
			}
		}
	}
	return out
}

func netCounters(text string) map[string]map[string]int64 {
	out := map[string]map[string]int64{}
	lines := strings.Split(text, "\n")
	if len(lines) <= 2 {
		return out
	}
	for _, line := range lines[2:] {
		name, rest, found := strings.Cut(line, ":")
		fields := strings.Fields(rest)
		if !found || len(fields) < 9 {
			continue
		}
		rx, e1 := strconv.ParseInt(fields[0], 10, 64)
		tx, e2 := strconv.ParseInt(fields[8], 10, 64)
		if e1 == nil && e2 == nil {
			out[strings.TrimSpace(name)] = map[string]int64{
				"RxBytes": rx, "TxBytes": tx}
		}
	}
	return out
}

func diskCounters(text string, wholeDevices map[string]bool) map[string]map[string]int64 {
	out := map[string]map[string]int64{}
	for _, line := range strings.Split(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}
		name := fields[2]
		// Whole devices only — partition rows double-count their parent —
		// with membership read from /sys/block, exactly as the reference
		// reads it.
		if diskstatsSkip.MatchString(name) || !wholeDevices[name] {
			continue
		}
		sectorsRead, e1 := strconv.ParseInt(fields[5], 10, 64)
		sectorsWritten, e2 := strconv.ParseInt(fields[9], 10, 64)
		ioTicks, e3 := strconv.ParseInt(fields[12], 10, 64)
		weighted, e4 := strconv.ParseInt(fields[13], 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
			continue
		}
		out[name] = map[string]int64{
			// Sector fields × 512 by kernel contract.
			"ReadBytes":    sectorsRead * 512,
			"WriteBytes":   sectorsWritten * 512,
			"IoTicksMs":    ioTicks,
			"WeightedIoMs": weighted,
		}
	}
	return out
}
