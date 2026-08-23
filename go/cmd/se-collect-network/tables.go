package main

// nft-tables: the table-grained view above nft-chains — one row per table,
// with its chains and how much it holds. The trap in these rows is stated in
// the declaration where they are read: rules are COUNTED here, never read,
// so deleting the one rule that admits sshd moves RuleCount by one and
// changes nothing else on this page.

// tableRow is one table's inventory. The chains list carries each chain's
// name with its policy where one is declared — the reference's own label —
// in DOCUMENT order, which for a ruleset is declaration order.
type tableRow struct {
	name  string
	facts map[string]any
}

func nftTables(doc jsonValue) []tableRow {
	type key struct{ family, name string }
	var order []key
	chains := map[key][]string{}
	ruleCounts := map[key]int{}
	seen := map[key]bool{}

	entries, _ := doc.member("nftables")
	for _, entry := range entries.array {
		switch {
		case entry.has("table"):
			t := entry.get("table")
			k := key{t.stringMember("family"), t.stringMember("name")}
			// First sighting fixes the position: a duplicate (family, name)
			// is ONE table, and an append-only slice would publish it twice.
			if !seen[k] {
				seen[k] = true
				order = append(order, k)
			}
		case entry.has("chain"):
			c := entry.get("chain")
			k := key{c.stringMember("family"), c.stringMember("table")}
			// A chain whose table the document never declared is skipped, as
			// the reference skips it: the row would belong to a table that
			// does not exist, and nft itself refuses such a ruleset.
			if !seen[k] {
				continue
			}
			label := c.stringMember("name")
			if policy := c.stringMember("policy"); policy != "" {
				label += " (" + policy + ")"
			}
			chains[k] = append(chains[k], label)
		case entry.has("rule"):
			r := entry.get("rule")
			k := key{r.stringMember("family"), r.stringMember("table")}
			if seen[k] {
				ruleCounts[k]++
			}
		}
	}

	rows := make([]tableRow, 0, len(order))
	for _, k := range order {
		labels := chains[k]
		if labels == nil {
			// [] is a reading — a table with no chains — never an absence.
			labels = []string{}
		}
		rows = append(rows, tableRow{
			// The two-part native name, a space between, matching the
			// member-of target every chain row asserts: the collator
			// resolves an edge against the name AS PUBLISHED, so a spelling
			// only one side uses is a tree that never joins.
			name: k.family + " " + k.name,
			facts: map[string]any{
				"Family":     k.family,
				"Chains":     labels,
				"ChainCount": len(labels),
				"RuleCount":  ruleCounts[k],
			},
		})
	}
	return rows
}
