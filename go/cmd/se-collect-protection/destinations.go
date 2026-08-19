package main

// destinationRows answers: where do copies land, who may delete them, and what
// protects history from a compromised source. Facts only, and no verdict of
// any kind — whether a destination's posture is adequate is a judgement about
// prose this collector cannot parse, and the estate's own assertions already
// refuse a backup target with no independent destination.
func destinationRows(src source) ([]row, error) {
	manifest, err := readManifest(src)
	if err != nil {
		return nil, err
	}
	destinations := manifest.get("destinations")
	var rows []row
	for _, name := range destinations.sortedKeys() {
		raw := destinations.get(name)
		if !raw.isObject() {
			continue
		}
		rows = append(rows, row{name: name, facts: destinationFacts(raw)})
	}
	return rows, nil
}

func destinationFacts(raw *value) *value {
	facts := newObject()
	for _, pair := range [...][2]string{{"Kind", "kind"}, {"PruneAuthority", "pruneAuthority"}} {
		if member := raw.get(pair[1]); member.truthy() {
			facts.set(pair[0], member)
		}
	}
	// STATED, not truthy. `independent: false` is the reading that decides
	// whether a copy survives losing the site, and a falsy test drops exactly
	// the destination an operator most needs to see — publishing the fact only
	// where it is true would leave the nearline replica silently unclassified
	// and reading like a durable copy.
	if independent := raw.get("independent"); independent.stated() {
		facts.set("Independent", boolValue(independent.truthy()))
	}
	if immutability := raw.get("immutability"); immutability.truthy() {
		// Verbatim, never summarised: this sentence is a security claim a
		// person wrote and corrected, and a paraphrase would be this product
		// making a security claim of its own.
		facts.set("Immutability", immutability)
	}
	return facts
}
