//go:build !linux

package main

import "errors"

// Live acquisition runs on Linux, the deploy target: there is no
// CLOCK_BOOTTIME and no /proc boot_id anywhere else, so live mode on
// another OS honestly cannot run — while replay mode, which pins both, runs
// everywhere the toolchain does. That split is what lets the harness judge
// this binary on a development machine.
func bootClock() (float64, error) {
	return 0, errors.New("CLOCK_BOOTTIME is a Linux clock; live collection runs on Linux — set SE_REPLAY_DIR to replay")
}

func timensOffset() int64 { return 0 }

// USER_HZ is a Linux number and /proc/stat is a Linux file, so off-Linux this
// is only ever reached by a replay — where the pinned 100 governs anyway.
func userHZ() int64 { return 100 }
