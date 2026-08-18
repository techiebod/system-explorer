//go:build darwin

package collate

import "golang.org/x/sys/unix"

// BootNow on darwin is a development stand-in: CLOCK_MONOTONIC here does
// not advance across sleep the way linux's CLOCK_BOOTTIME does, so ages
// computed on a laptop that napped are understated. The deploy target is
// linux; tests that assert on ages inject their own clock and never
// reach this.
func BootNow() float64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return float64(ts.Sec) + float64(ts.Nsec)/1e9
}
