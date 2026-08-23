//go:build linux

package collate

import (
	"os"
	"strconv"
	"strings"
)

// timensOffset reads the boottime row of /proc/self/timens_offsets, the
// collator's own side of the comparison every collector already reports in
// `begin`. Parsed identically to the collectors' copy, deliberately: two
// spellings of one file format is how the two sides come to disagree about
// what the same file says.
//
// Absent file means no time namespace, so the offset genuinely is zero —
// which is the ONE case where "cannot read" and "is zero" are the same
// answer, because the file exists only inside a namespace.
func timensOffset() int64 {
	raw, err := os.ReadFile("/proc/self/timens_offsets")
	if err != nil {
		return 0
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
