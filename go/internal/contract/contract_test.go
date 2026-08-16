// The Go toolchain's first obligation: it can read the contract package.
// Every schema in contract/ must parse, carry an $id equal to its filename,
// and declare the 2020-12 dialect — the same facts the Python suite pins,
// proven from the language the collectors and collator will be written in.
package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func contractDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(filepath.Join("..", "..", "..", "contract"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("contract package not found at %s: %v", dir, err)
	}
	return dir
}

func TestSchemasParseAndSelfIdentify(t *testing.T) {
	dir := contractDir(t)
	entries, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no schemas in contract/: an empty set must not pass")
	}
	for _, path := range entries {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			ID      string `json:"$id"`
			Dialect string `json:"$schema"`
		}
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Errorf("%s: does not parse: %v", filepath.Base(path), err)
			continue
		}
		if schema.ID != filepath.Base(path) {
			t.Errorf("%s: $id %q must equal the filename, so a $ref is a path", filepath.Base(path), schema.ID)
		}
		if schema.Dialect != "https://json-schema.org/draft/2020-12/schema" {
			t.Errorf("%s: dialect %q is not 2020-12", filepath.Base(path), schema.Dialect)
		}
	}
}
