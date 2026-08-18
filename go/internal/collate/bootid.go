// The collator's own boot id: the domain its BootNow readings belong to.
// Every stored at stamp carries the boot id of the clock that produced it
// (DESIGN §09), so serving an age is a comparison between two domains —
// and the comparison needs to know this side's.
package collate

import (
	"fmt"
	"os"
)

// OwnBootID learns the collator's boot id at start. SE_BOOT_ID overrides
// — the injection seam the tests and darwin development need — otherwise
// the platform source answers (/proc/sys/kernel/random/boot_id on linux,
// the kernel's boot-session UUID on darwin). An error is fatal to the
// caller: a collator that cannot name its own clock domain would serve
// ages it cannot interpret.
func OwnBootID() (string, error) {
	if v := os.Getenv("SE_BOOT_ID"); v != "" {
		return v, nil
	}
	id, err := platformBootID()
	if err != nil {
		return "", fmt.Errorf("own boot id: %w", err)
	}
	if id == "" {
		return "", fmt.Errorf("own boot id: the platform reported an empty id")
	}
	return id, nil
}
