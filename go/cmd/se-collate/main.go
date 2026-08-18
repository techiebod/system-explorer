// se-collate is the collator core: the validating party of DESIGN §18
// and the batch authority of §19, with the read API of §06. All of it
// lives in internal/collate so the crash harness can spawn the same code
// it tests; this wrapper only exists to give it a binary name.
package main

import (
	"os"

	"github.com/techiebod/system-explorer/go/internal/collate"
)

func main() {
	os.Exit(collate.Main())
}
