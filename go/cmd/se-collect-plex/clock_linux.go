//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// CLOCK_BOOTTIME, not CLOCK_MONOTONIC: `at` must keep aging across suspend,
// because a machine that slept six hours did not stay six hours fresh
// (DESIGN 09). The constant is uapi (linux/time.h) and identical on every
// architecture; the raw syscall keeps the binary pure-Go and static.
const clockBoottime = 7

func bootClock() (float64, error) {
	var ts syscall.Timespec
	if _, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockBoottime, uintptr(unsafe.Pointer(&ts)), 0); errno != 0 {
		return 0, errno
	}
	return float64(ts.Sec) + float64(ts.Nsec)/1e9, nil
}

// timensOffset reads the boottime row of /proc/self/timens_offsets, present
// only inside a time namespace. It is reported in begin and never corrected
// by anyone — a mismatch with the collator is stated (DESIGN 09). The wire
// unit is nanoseconds, the file's full resolution; DESIGN does not yet name
// one, which is filed for adjudication rather than resolved here silently.
func timensOffset() int64 {
	raw, err := os.ReadFile("/proc/self/timens_offsets")
	if err != nil {
		return 0 // no namespace: the offset genuinely is zero
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "boottime" {
			secs, secErr := strconv.ParseInt(fields[1], 10, 64)
			nsecs, nsecErr := strconv.ParseInt(fields[2], 10, 64)
			if secErr == nil && nsecErr == nil {
				return secs*1e9 + nsecs
			}
		}
	}
	return 0
}
