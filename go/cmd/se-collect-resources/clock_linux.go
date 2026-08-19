//go:build linux

package main

import (
	"encoding/binary"
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

// AT_CLKTCK is the auxiliary-vector entry glibc's sysconf(_SC_CLK_TCK) reads,
// and reading it here is what keeps this binary pure-Go: USER_HZ is a property
// of the kernel that is running, not of the architecture this was built for,
// and /proc/stat counts in exactly these ticks while every fact derived from
// it is microseconds. The fallback is 100, which is USER_HZ on every Linux
// this product deploys to — a fallback rather than a constant because a wrong
// multiplier would scale the host denominator silently, and silence is the
// failure this collection exists to prevent.
const auxvClockTick = 17

func userHZ() int64 {
	raw, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return 100
	}
	// The vector is pairs of native words, terminated by a zero key. 64-bit
	// is the only word size this binary is built for; a short read leaves the
	// fallback standing rather than half-decoding a pair.
	for i := 0; i+16 <= len(raw); i += 16 {
		key := binary.LittleEndian.Uint64(raw[i : i+8])
		value := binary.LittleEndian.Uint64(raw[i+8 : i+16])
		if key == 0 {
			break
		}
		if key == auxvClockTick && value > 0 && value <= 1_000_000 {
			return int64(value)
		}
	}
	return 100
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
