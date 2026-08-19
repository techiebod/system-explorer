package main

import (
	"math/big"
	"regexp"
	"sort"
	"strconv"
)

// subnet[<id>].<statistic> — the spelling Kea uses in statistic-get-all. The
// tail is captured whole and matched against the wanted set afterwards, which
// is what keeps `subnet[1].pool[0].total-addresses` out of the subnet row: a
// pattern that stopped at the first dot would fold a POOL's counters into its
// subnet's and report the pool arithmetic twice.
var subnetStat = regexp.MustCompile(`^subnet\[(\d+)\]\.(.+)$`)

var wantedStats = map[string]string{
	"total-addresses":    "TotalAddresses",
	"assigned-addresses": "AssignedAddresses",
	"declined-addresses": "DeclinedAddresses",
}

// subnetRows joins statistic-get-all's flat key space to the per-subnet config
// facts. Two documents, one row per subnet: the counters say how full the pool
// is and the configuration says which network that is, and a row carrying only
// one half answers half the question.
func subnetRows(src source) ([]row, error) {
	statistics, err := src.document(commandStatistics)
	if err != nil {
		return nil, err
	}
	config, err := src.document(commandConfig)
	if err != nil {
		return nil, err
	}
	return buildSubnetRows(statistics.get("arguments"),
		configSubnetFacts(config.dig("arguments", "Dhcp4"))), nil
}

func buildSubnetRows(statistics *value, configFacts map[string]*members) []row {
	// Kea files every statistic as [[value, timestamp]] lists; the newest value
	// is the first element of the first sample. Walked in DOCUMENT order so two
	// runs of one payload fold the same way.
	byID := map[string]*members{}
	if statistics.isObject() {
		for _, key := range statistics.members.keys {
			match := subnetStat.FindStringSubmatch(key)
			if match == nil {
				continue
			}
			fact, wanted := wantedStats[match[2]]
			if !wanted {
				continue
			}
			samples := statistics.get(key)
			if samples == nil || samples.kind != jsonArray || len(samples.items) == 0 {
				continue
			}
			newest := samples.items[0]
			if newest.kind != jsonArray || len(newest.items) == 0 {
				continue
			}
			holder, seen := byID[match[1]]
			if !seen {
				holder = newMembers()
				byID[match[1]] = holder
			}
			holder.set(fact, newest.items[0])
		}
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	// `sorted(by_subnet, key=int)`: NUMERIC order, so subnet 2 sorts before
	// subnet 10. big.Int rather than a parse, because the key pattern admits any
	// number of digits and an id past 2^63 would sort as a parse failure.
	sort.Slice(ids, func(i, j int) bool {
		a, _ := new(big.Int).SetString(ids[i], 10)
		b, _ := new(big.Int).SetString(ids[j], 10)
		return a.Cmp(b) < 0
	})

	rows := make([]row, 0, len(ids))
	for _, id := range ids {
		facts := newObject()
		// `int(subnet_id)`, so a key written with leading zeros publishes the
		// number it denotes rather than its spelling. The CONFIG lookup keeps
		// the raw key, exactly as the reference does — the two documents join on
		// the string, and a subnet the config spells differently is a subnet
		// with no CIDR in both implementations.
		canonical, _ := new(big.Int).SetString(id, 10)
		facts.set("SubnetId", numberValue(canonical.String()))
		if config, ok := configFacts[id]; ok {
			for _, key := range config.keys {
				facts.set(key, config.byKey[key])
			}
		}
		for _, key := range byID[id].keys {
			// set() drops a null rather than writing one. A statistic whose
			// newest sample is null is not a document Kea produces, and the
			// reference would publish `"TotalAddresses": null` for it — which
			// the contract's recursive fact_value and the replay judge both
			// refuse, so the lawful reading is the fact omitted. Same shape as
			// the null-fact family in the adjudication queue, same resolution.
			facts.set(key, byID[id].byKey[key])
		}
		// UsedPercent exists only when a positive total makes the division
		// meaningful — a subnet with no pool is not 0% used, it is a subnet the
		// question does not apply to.
		total, totalOK := facts.get("TotalAddresses").integer()
		assigned, assignedOK := facts.get("AssignedAddresses").integer()
		if totalOK && total > 0 && assignedOK {
			percent := roundHalfToEven(float64(assigned*100) / float64(total))
			facts.set("UsedPercent", numberValue(strconv.FormatInt(percent, 10)))
		}
		// The row names the NETWORK, not Kea's internal id — falling back to the
		// id only where the config document states no CIDR for it, which is what
		// a subnet whose declaration this walk never found looks like.
		name := facts.get("SubnetId").text
		if cidr := facts.get("Subnet"); cidr.truthy() {
			name = cidr.text
		}
		rows = append(rows, row{name: name, facts: facts})
	}
	return rows
}
