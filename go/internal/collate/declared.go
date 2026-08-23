// Reading the parts of a declaration the RENDERER needs: which facts a
// row carries, and how each one is to be drawn.
//
// Separate from opinions.go, which reads the rule table, because these
// are different questions asked of the same document and folding them
// would make a rendering change able to break judging.
package collate

import (
	"encoding/json"
	"fmt"
)

// CollectionRender is a collection's rendering instructions, as its
// producer declared them.
type CollectionRender struct {
	// Answer is the ordered fact list a ROW carries. §27: a table is
	// scanned, not read, and a row that carries everything carries
	// nothing. The order is the producer's and is preserved — a renderer
	// sorting these would be deciding which fact matters most, which is
	// the producer's call and is why the member is a list.
	Answer []string
	// Facts is every declared fact, for the object density.
	Facts map[string]FactDecl
	// Question is what this collection answers, shown above its table so
	// a page states its own purpose rather than assuming the reader
	// knows why the table is there.
	Question string
	// Prefix is the id prefix this collection's objects carry. Held so a
	// LINK can be minted from the producer's own declaration rather than
	// from a routing table in the renderer — the first of §27's three
	// rotted copies was exactly such a table, 31 prefixes deep, missing
	// the whole application tier.
	Prefix string
}

// RenderFor reads one collection's rendering instructions out of a
// declaration document.
//
// A collection the document does not describe returns nil and no error:
// the caller renders it as undeclared rather than as empty, because "the
// declaration does not cover this" and "this has no facts" are different
// answers and the second one is a lie.
func RenderFor(document, collection string) (*CollectionRender, error) {
	var doc struct {
		Collections []struct {
			Name     string              `json:"name"`
			Answer   []string            `json:"answer"`
			Question string              `json:"question"`
			Prefix   string              `json:"prefix"`
			Facts    map[string]FactDecl `json:"facts"`
		} `json:"collections"`
	}
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		return nil, fmt.Errorf("declaration: %w", err)
	}
	for _, c := range doc.Collections {
		if c.Name != collection {
			continue
		}
		return &CollectionRender{
			Answer: c.Answer, Facts: c.Facts,
			Question: c.Question, Prefix: c.Prefix,
		}, nil
	}
	return nil, nil
}
