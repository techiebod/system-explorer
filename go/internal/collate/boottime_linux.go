//go:build linux

package collate

import "golang.org/x/sys/unix"

// BootNow reads CLOCK_BOOTTIME — the clock every stream's at is stamped
// on (DESIGN §09: one host, one kernel clock, so ages are exact and no
// wall clock is involved).
func BootNow() float64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		// CLOCK_BOOTTIME cannot fail on a kernel new enough to run this
		// product; if it somehow does, an age of zero is a visible lie
		// where a panic would take the read API down with it.
		return 0
	}
	return float64(ts.Sec) + float64(ts.Nsec)/1e9
}
