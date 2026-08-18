//go:build darwin

package collate

import "golang.org/x/sys/unix"

// platformBootID on darwin is the kernel's boot-session UUID — a real
// per-boot identity, unlike BootNow's development stand-in clock. The
// comparison in the read API is case-insensitive, so darwin's uppercase
// spelling and linux's lowercase one never masquerade as different boots.
func platformBootID() (string, error) {
	return unix.Sysctl("kern.bootsessionuuid")
}
