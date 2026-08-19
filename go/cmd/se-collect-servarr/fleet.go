package main

import (
	"sort"
	"strings"
)

// instance is one configured media manager: the deployment receipt for it,
// read exactly as adapters/servarr.py's instance_specs() reads it.
//
// The fleet is CONFIGURATION and not an interface reading, which is why it has
// its own type and its own seam method. Nothing here is probed: the API family
// is stated by the operator (v3 is sonarr's and radarr's; lidarr, readarr and
// prowlarr have only ever served /api/v1), and an instance whose receipts are
// incomplete is RETURNED with the fault stated rather than dropped — a typo
// vanishing into green is the failure this collector is written against.
type instance struct {
	name string
	api  string
	url  string
	key  string
	// missing is what this named instance still needs before it can be
	// observed, in the reference's own spelling: the environment variable
	// NAMES, never their values.
	missing []string
	// duplicates is the entries in SE_SERVARR_INSTANCES that repeated this
	// name and were dropped. The first entry won.
	duplicates []string
}

// ready is whether this instance can be asked anything at all.
//
// The reference spells it as two conditions — no missing receipts AND a client
// in the per-instance map — and the two are the same statement: a client is
// built exactly when the URL and the key are both present and the key can
// survive a header, which is exactly when nothing is missing. Kept as one
// condition here rather than as a second map that could disagree with the
// first.
func (i instance) ready() bool { return len(i.missing) == 0 }

// envBase is the instance name as it appears in its own variable names:
// upper-cased with hyphens normalised to underscores, so readarr-audio reads
// SE_READARR_AUDIO_URL.
func envBase(name string) string {
	return strings.ReplaceAll(strings.ToUpper(name), "-", "_")
}

// instanceSpecs is the configured fleet, in the order SE_SERVARR_INSTANCES
// names it. Pure over the environment as read at call time, like the reference.
//
// The key never leaves this function except into a request header. It is not
// logged, not put in an error, and not carried into any fact — a decline detail
// and a reason both travel to a hub and out over MCP (DESIGN 19), so the only
// safe place for a credential is the one request that needs it.
func instanceSpecs(getenv func(string) string) []instance {
	var specs []instance
	byName := map[string]int{}
	for _, entry := range strings.Split(getenv("SE_SERVARR_INSTANCES"), ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, version, _ := strings.Cut(entry, ":")
		if at, seen := byName[name]; seen {
			specs[at].duplicates = append(specs[at].duplicates, entry)
			continue
		}
		if version == "" {
			version = "v3"
		}
		base := envBase(name)
		url := strings.TrimRight(getenv("SE_"+base+"_URL"), "/")
		key := getenv("SE_" + base + "_API_KEY")
		spec := instance{name: name, api: version, url: url, key: key}
		if url == "" {
			spec.missing = append(spec.missing, "SE_"+base+"_URL")
		}
		if key == "" {
			spec.missing = append(spec.missing, "SE_"+base+"_API_KEY")
		} else if !headerSafe(key) {
			// The paperless posture: a key that cannot survive a header is a
			// config fault named WITHOUT its value.
			spec.missing = append(spec.missing,
				"SE_"+base+"_API_KEY (contains control or non-ASCII characters)")
		}
		if strings.Contains(name, "/") {
			// Ids namespace by instance name WITH '/', so a slash-bearing name
			// cannot mint unambiguous ids — a config fault, stated.
			spec.missing = append(spec.missing,
				"instance name '"+name+"' contains '/'")
		}
		byName[name] = len(specs)
		specs = append(specs, spec)
	}
	return specs
}

// headerSafe is Python's `key.isascii() and key.isprintable()` for the one
// alphabet a header may carry: every byte printable ASCII, so no control
// character and nothing outside 7 bits reaches the wire.
func headerSafe(key string) bool {
	for i := 0; i < len(key); i++ {
		if key[i] < 0x20 || key[i] > 0x7e {
			return false
		}
	}
	return true
}

// sortedMissing is the ConfigMissing fact's value: the reference sorts it, so
// the row is stable whichever order the faults were found in.
func sortedMissing(missing []string) []string {
	out := append([]string(nil), missing...)
	sort.Strings(out)
	return out
}
