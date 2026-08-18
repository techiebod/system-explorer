//go:build linux

package collate

import (
	"os"
	"strings"
)

// platformBootID reads the kernel's boot id — the same source a
// collector's begin.boot_id comes from on this host, which is what makes
// equality mean "same clock domain".
func platformBootID() (string, error) {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}
