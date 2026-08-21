// The overview parse against realistic proc content: the derived numbers,
// the ARC discount that keeps a cache-warm ZFS host from reading as
// pressure, the swapless absence, and the source-grouped absent list when
// a document is dark.
package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const statDoc = `cpu  10000 200 3000 500000 400 0 100 50 0 0
cpu0 5000 100 1500 250000 200 0 50 25 0 0
cpu1 5000 100 1500 250000 200 0 50 25 0 0
intr 0
`

func overviewFixture() map[string]string {
	return map[string]string{
		"proc-uptime":  "9000.13 17000.50\n",
		"proc-loadavg": "0.52 0.40 0.30 1/223 4321\n",
		"proc-stat":    statDoc,
		"proc-meminfo": "MemTotal:        4000000 kB\nMemAvailable:    1000000 kB\n" +
			"SwapTotal:       2000000 kB\nSwapFree:         500000 kB\n" +
			"HugePages_Total:       0\n",
		"proc-pressure-cpu": "some avg10=1.10 avg60=0.80 avg300=0.40 total=1\n" +
			"full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
		"proc-pressure-memory": "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n" +
			"full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
		"proc-pressure-io": "some avg10=2.00 avg60=1.00 avg300=0.50 total=9\n" +
			"full avg10=1.50 avg60=0.75 avg300=0.25 total=8\n",
		"proc-net-dev": "Inter-|   Receive                                                |  Transmit\n" +
			" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
			"    lo:  111111     100    0    0    0     0          0         0   111111     100    0    0    0     0       0          0\n" +
			"enp1s0: 2222222    2000    0    0    0     0          0         0  3333333    1500    0    0    0     0       0          0\n",
		"proc-diskstats": " 254       0 vda 100 0 20000 50 200 0 40000 80 0 130 200 0 0 0 0 0 0\n" +
			" 254       1 vda1 90 0 18000 45 190 0 39000 75 0 120 180 0 0 0 0 0 0\n" +
			"   7       0 loop0 5 0 100 1 0 0 0 0 0 1 1 0 0 0 0 0 0\n",
	}
}

func overviewObject(t *testing.T, src *fakeSource) (map[string]any, []string) {
	t.Helper()
	var out, errs bytes.Buffer
	if code := collect(&out, &errs, src, []string{"overview"},
		map[string]uint64{"overview": 3}); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record["record"] == "object" {
			var listed []string
			for _, name := range record["absent"].([]any) {
				listed = append(listed, name.(string))
			}
			return record["facts"].(map[string]any), listed
		}
	}
	t.Fatal("no object emitted")
	return nil, nil
}

func has(list []string, name string) bool {
	for _, item := range list {
		if item == name {
			return true
		}
	}
	return false
}

func TestOverviewDerivesTheReferencesNumbers(t *testing.T) {
	src := &fakeSource{procs: overviewFixture(), ncpu: 2,
		blocks: map[string]bool{"vda": true},
		now:    1787323727.0} // 2026-08-21T14:48:47Z
	facts, absent := overviewObject(t, src)

	if facts["UptimeSeconds"] != float64(9000) {
		t.Fatalf("%v", facts["UptimeSeconds"])
	}
	// now - uptime = 1787314726.87 → floor to whole seconds via int64.
	if facts["BootedAt"] != "2026-08-21T12:18:46Z" {
		t.Fatalf("BootedAt: %v", facts["BootedAt"])
	}
	if facts["LoadAvg1"] != 0.52 || facts["LoadPerCpu1"] != 0.26 ||
		facts["CpuCount"] != float64(2) {
		t.Fatalf("%v %v %v", facts["LoadAvg1"], facts["LoadPerCpu1"], facts["CpuCount"])
	}
	// 4000000kB total, 1000000kB available: 75% used, kB → bytes.
	if facts["MemTotalBytes"] != float64(4096000000) ||
		facts["MemUsedPercent"] != float64(75) {
		t.Fatalf("%v %v", facts["MemTotalBytes"], facts["MemUsedPercent"])
	}
	// No ARC on this host: adjusted equals raw, and the ARC facts are absent.
	if facts["MemUsedPercentAdjusted"] != float64(75) {
		t.Fatalf("%v", facts["MemUsedPercentAdjusted"])
	}
	if !has(absent, "ArcSizeBytes") {
		t.Fatalf("%v", absent)
	}
	if facts["SwapUsedPercent"] != float64(75) {
		t.Fatalf("%v", facts["SwapUsedPercent"])
	}
	cpu := facts["CpuTimes"].(map[string]any)
	if cpu["Iowait"] != float64(400) || cpu["Steal"] != float64(50) {
		t.Fatalf("%v", cpu)
	}
	if facts["PsiIoFullAvg60"] != 0.75 || facts["PsiCpuSomeAvg10"] != 1.1 {
		t.Fatalf("%v %v", facts["PsiIoFullAvg60"], facts["PsiCpuSomeAvg10"])
	}
	net := facts["NetCounters"].(map[string]any)
	if net["enp1s0"].(map[string]any)["TxBytes"] != float64(3333333) {
		t.Fatalf("%v", net)
	}
	disk := facts["DiskCounters"].(map[string]any)
	if len(disk) != 1 {
		t.Fatalf("whole devices only — the partition and loop rows must not "+
			"count: %v", disk)
	}
	vda := disk["vda"].(map[string]any)
	if vda["ReadBytes"] != float64(20000*512) || vda["WeightedIoMs"] != float64(200) {
		t.Fatalf("%v", vda)
	}
}

func TestTheArcDiscountSeparatesOccupancyFromPressure(t *testing.T) {
	// 95% raw usage, but 2.4GB of it is ARC: adjusted lands at 36%, which
	// is the whole reason MemUsedPercentAdjusted exists as a fact — the
	// memory rules judge it, and the occupancy rule fires instead of the
	// critical one.
	procs := overviewFixture()
	procs["proc-meminfo"] = "MemTotal:        4000000 kB\nMemAvailable:     200000 kB\n"
	procs["proc-arcstats"] = "name type data\nsize 4 2400000000\nc 4 3000000000\n"
	src := &fakeSource{procs: procs, ncpu: 2, now: 1787323727.0}
	facts, absent := overviewObject(t, src)
	if facts["MemUsedPercent"] != float64(95) {
		t.Fatalf("%v", facts["MemUsedPercent"])
	}
	if facts["MemUsedPercentAdjusted"] != float64(36) {
		t.Fatalf("adjusted: %v", facts["MemUsedPercentAdjusted"])
	}
	if facts["ArcSizeBytes"] != float64(2400000000) {
		t.Fatalf("%v", facts["ArcSizeBytes"])
	}
	// This fixture has no swap lines at all: the whole swap family is
	// absent, grouped by its source.
	for _, name := range []string{"SwapTotalBytes", "SwapUsedBytes", "SwapUsedPercent"} {
		if !has(absent, name) {
			t.Fatalf("%s must be absent: %v", name, absent)
		}
	}
}

func TestSwaplessServesNoPercentAndDarkSourcesGoAbsentTogether(t *testing.T) {
	procs := overviewFixture()
	procs["proc-meminfo"] = "MemTotal:        4000000 kB\nMemAvailable:    1000000 kB\n" +
		"SwapTotal:             0 kB\nSwapFree:              0 kB\n"
	delete(procs, "proc-pressure-cpu")
	delete(procs, "proc-pressure-memory")
	delete(procs, "proc-pressure-io")
	src := &fakeSource{procs: procs, ncpu: 2, now: 1787323727.0}
	facts, absent := overviewObject(t, src)
	// A swapless host has no swap pressure to be innocent of.
	if _, present := facts["SwapUsedPercent"]; present || !has(absent, "SwapUsedPercent") {
		t.Fatalf("%v %v", facts["SwapUsedPercent"], absent)
	}
	if facts["SwapTotalBytes"] != float64(0) {
		t.Fatalf("%v", facts["SwapTotalBytes"])
	}
	// No CONFIG_PSI: all fifteen stall facts absent, never zero.
	for _, name := range psiFactNames {
		if !has(absent, name) {
			t.Fatalf("%s must be absent without /proc/pressure: %v", name, absent)
		}
	}
}

func TestUnpinnedReplayLeavesBootedAtAbsentNotMoving(t *testing.T) {
	src := &fakeSource{procs: overviewFixture(), ncpu: 2, now: 0}
	facts, absent := overviewObject(t, src)
	if _, present := facts["BootedAt"]; present || !has(absent, "BootedAt") {
		t.Fatal("no wall pin must mean no BootedAt, not one derived from " +
			"the replaying machine's clock")
	}
}

func TestOverviewFloatsTravelAsTheReferenceSpellsThem(t *testing.T) {
	// 0.00 must reach the wire as 0.0, not 0: typed equality holds int and
	// float to be different answers, and the reference emits floats.
	src := &fakeSource{procs: overviewFixture(), ncpu: 2, now: 1787323727.0}
	var out, errs bytes.Buffer
	if code := collect(&out, &errs, src, []string{"overview"},
		map[string]uint64{"overview": 3}); code != exitOK {
		t.Fatal(errs.String())
	}
	if !strings.Contains(out.String(), `"PsiMemoryFullAvg60":0.0`) {
		t.Fatalf("integral floats must keep their point: %s", out.String())
	}
}
