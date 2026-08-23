package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// storePath matches a /nix/store entry and captures its NAME — the package
// and version, not the build hash. adapters/nix.py STORE_RE, with the same
// 32-character hash, which is nix's own base32 digest length.
var storePath = regexp.MustCompile(`(/nix/store/[a-z0-9]{32}-([^/]+))`)

// generation is one profile link: its number, the link itself and the closure
// it points at.
type generation struct {
	number int
	link   string
	target string
}

// generationLinks is agent/nixos.py's generation_links(), newest first.
//
// A link whose number does not parse is SKIPPED rather than refused: the
// profile directory holds `system` and `per-user` beside the numbered links,
// and both are ordinary residents rather than a defect. A link that is not a
// symlink is skipped for the same reason — nothing about a stray file there
// is a statement about a generation.
func generationLinks(src source) ([]generation, error) {
	names, err := src.listdir(profilesDir)
	if err != nil {
		return nil, err
	}
	out := make([]generation, 0, len(names))
	for _, name := range names {
		if !strings.HasPrefix(name, "system-") || !strings.HasSuffix(name, "-link") {
			continue
		}
		number, err := strconv.Atoi(name[len("system-") : len(name)-len("-link")])
		if err != nil {
			continue
		}
		path := profilesDir + "/" + name
		target, err := src.readlink(path)
		if err != nil {
			return nil, err
		}
		if target == "" {
			continue
		}
		out = append(out, generation{number: number, link: path, target: target})
	}
	// Newest first, which is the order the rows are published in and
	// therefore the order `at` advances through.
	sort.Slice(out, func(i, j int) bool { return out[i].number > out[j].number })
	return out, nil
}

// pointers are the three closures that can disagree: what is activated now,
// what the last boot activated, and what the next boot would pick. Their
// disagreement is the whole point of this collection.
type pointers struct{ current, booted, profile string }

func readPointers(src source) (pointers, error) {
	var out pointers
	for _, pair := range []struct {
		path string
		into *string
	}{
		{currentSystem, &out.current},
		{bootedSystem, &out.booted},
		{profilesDir + "/system", &out.profile},
	} {
		resolved, err := src.realpath(pair.path)
		if err != nil {
			return pointers{}, err
		}
		*pair.into = resolved
	}
	return out, nil
}

// epochToISO renders a link's mtime the way the reference does: UTC, seconds,
// TRUNCATED rather than rounded, because strftime discards the fraction.
func epochToISO(seconds float64) string {
	return time.Unix(int64(seconds), 0).UTC().Format("2006-01-02T15:04:05Z")
}

// generationRow builds one row's facts. Every fact is omitted where the
// closure does not record it, never emptied and never nulled: a closure built
// without a configuration revision is not a closure with a blank one, and a
// null names none of DESIGN 19's three channels.
func generationRow(src source, gen generation, ptr pointers) (*value, error) {
	facts := newObject()

	release, err := src.read(gen.target + "/nixos-version")
	if err != nil {
		return nil, err
	}
	if release != "" {
		facts.set("NixosVersion", stringValue(release))
	}

	kernel, err := src.realpath(gen.target + "/kernel")
	if err != nil {
		return nil, err
	}
	if match := storePath.FindStringSubmatch(kernel); match != nil {
		facts.set("Kernel", stringValue(match[2]))
	}

	revision, err := src.read(gen.target + "/configuration-revision")
	if err != nil {
		return nil, err
	}
	if revision != "" {
		facts.set("ConfigurationRevision", stringValue(revision))
	}

	seconds, present, err := src.mtime(gen.link)
	if err != nil {
		return nil, err
	}
	if present {
		facts.set("Created", stringValue(epochToISO(seconds)))
	}

	facts.set("Current", boolValue(gen.target == ptr.current))
	facts.set("Booted", boolValue(gen.target == ptr.booted))
	facts.set("Profile", boolValue(gen.target == ptr.profile))

	specialisations, err := src.listdir(gen.target + "/specialisation")
	if err != nil {
		return nil, err
	}
	facts.set("Specialisations", stringArray(specialisations))
	facts.set("StorePath", stringValue(gen.target))

	if err := attachDeployment(src, gen, facts); err != nil {
		return nil, err
	}
	return facts, nil
}

// attachDeployment adds the two deployment facts, and only where BOTH
// conditions hold: the closure must say receipts are expected — an older
// generation predates the workflow, and its lack of one means nothing — and
// this process must be able to see them at all. Without both the facts are
// omitted rather than nulled, because "no receipt exists" and "I cannot see
// receipts" are different statements and only the first is about the
// deployment.
func attachDeployment(src source, gen generation, facts *value) error {
	raw, err := src.read(gen.target + "/" + generationManifest)
	if err != nil {
		return err
	}
	if raw == "" {
		return nil
	}
	var manifest map[string]any
	if json.Unmarshal([]byte(raw), &manifest) != nil {
		// A half-written manifest is not evidence of anything, and the
		// honest answer for both cases is that this generation has none.
		return nil
	}
	schema, _ := manifest["schema"].(float64)
	expected, _ := manifest["receiptsExpected"].(bool)
	directory := src.receiptsDir()
	if !expected || int(schema) < receiptsExpectedSchema || directory == "" {
		return nil
	}
	facts.set("ReceiptsExpected", boolValue(true))

	receiptRaw, err := src.read(fmt.Sprintf("%s/%d.json", directory, gen.number))
	if err != nil {
		return err
	}
	var receipt map[string]any
	if receiptRaw == "" || json.Unmarshal([]byte(receiptRaw), &receipt) != nil {
		// Receipts are expected and this generation has none: the shape that
		// says something activated this closure outside the workflow. The
		// fact is OMITTED, not nulled — the reference reaches the same point
		// with a null and its envelope builder strips it, because a null
		// names none of DESIGN 19's three channels. ReceiptsExpected standing
		// beside an absent Deployment is the whole statement, and it is what
		// rules/nix.py reads to raise `deployment-unattested`.
		return nil
	}
	activation, _ := receipt["activation"].(map[string]any)
	source, _ := receipt["source"].(map[string]any)
	deployment := newObject()
	deployment.set("Mode", anyValue(activation["mode"]))
	deployment.set("Outcome", anyValue(activation["outcome"]))
	deployment.set("VerifiedAt", anyValue(activation["verified_at"]))
	risks, ok := receipt["risks"].([]any)
	if !ok {
		risks = []any{}
	}
	deployment.set("Risks", anyValue(risks))
	deployment.set("SourceRevision", anyValue(source["git_revision"]))
	facts.set("Deployment", deployment)
	// Minted flat on both implementations because the not-verified rule
	// names one fact, and the closed condition vocabulary cannot reach a
	// nested member (register row 8's residue). Only where the receipt
	// states one.
	if outcome, ok := activation["outcome"].(string); ok && outcome != "" {
		facts.set("DeploymentOutcome", anyValue(outcome))
	}
	return nil
}

// collectGenerations emits the collection: one object per generation, newest
// first, then the commit.
func collectGenerations(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	present, err := src.exists(currentSystem)
	var refused *declined
	if err != nil && !errors.As(err, &refused) {
		fmt.Fprintln(stderr, err)
		return exitRuntime
	}
	if refused != nil || !present {
		reason := declineNotNixOS
		if refused != nil {
			reason = *refused
		}
		out.emit(declineRecord{
			Record:     "decline",
			Collection: collection,
			Reason:     reason.reason,
			Detail:     reason.detail,
		})
		// absent is authoritative-empty: it must be able to retire the
		// generations a previous batch published, so it declines AND commits
		// zero. No other reason commits — nothing was established, so prior
		// state stands and the collator marks it stale.
		if reason.reason == "absent" {
			out.emit(commitRecord{Record: "commit", Collection: collection, Generation: generation})
		}
		return exitOK
	}

	links, err := generationLinks(src)
	if err != nil {
		fmt.Fprintln(stderr, "generations:", err)
		return exitRuntime
	}
	ptr, err := readPointers(src)
	if err != nil {
		fmt.Fprintln(stderr, "generations:", err)
		return exitRuntime
	}

	for _, gen := range links {
		facts, err := generationRow(src, gen, ptr)
		if err != nil {
			fmt.Fprintln(stderr, "generations:", err)
			return exitRuntime
		}
		at, err := src.stamp(*objects)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitRuntime
		}
		names := newObject()
		stable := newObject()
		stable.set("store-path", stringValue(gen.target))
		names.set("stable", stable)
		out.emit(objectRecord{
			Record:     "object",
			Type:       "generation",
			Collection: collection,
			Name:       strconv.Itoa(gen.number),
			Facts:      facts.encode(),
			Names:      names.encode(),
			At:         at,
		})
		*objects++
	}
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    len(links),
	})
	return exitOK
}
