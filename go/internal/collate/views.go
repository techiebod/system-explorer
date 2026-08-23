package collate

// The views surface at the collator (DESIGN §1892: `se.views/1` survives
// unchanged, "served by both tiers like every other projection").
//
// **Register row 20 read "built" over half of that.** Its probe reads
// src/system_explorer/hub/routes.py, so it flipped the day the HUB served
// views and could not see that the collator served none — the same
// one-tier probe defect as rows 1, 2, 3 and 17, found by the same audit.
// A host with no hub keeps its own surface in full, which is the founding
// invariant; a view surface only the hub serves is one that disappears
// exactly when the hub does.
//
// **This is a SECOND implementation of one truth, and that is stated
// rather than hidden.** views.py holds the reference; the two toolchains
// cannot read each other's tree, which is the same situation tokens.css
// is in and is handled the same way — a conformance test drives both over
// one corpus of documents and requires identical verdicts. Where they
// disagree, views.py is right and this is wrong: the reference is the
// shipping product's, and an estate already deploys documents against it.
//
// **A configured directory that does not exist is a deployment fault**,
// not an operator who made no views — it happened on the first estate
// deploy, when a module bug handed the build host's path to the target.
// Silent emptiness there is absence-as-health, so the envelope names the
// directory.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// requiredPanelMembers and requiredStageMembers mirror views.py's own
// lists. Named here rather than inlined so the conformance comparison has
// something to point at when the two drift.
var (
	requiredPanelMembers = []string{"key", "title", "subsystem", "collection"}
	requiredStageMembers = []string{"key", "title", "subsystem", "collection"}
)

type viewError struct {
	File  string `json:"file"`
	Error string `json:"error"`
}

type viewsEnvelope struct {
	Schema     string           `json:"schema"`
	ObservedAt string           `json:"observed_at"`
	Site       string           `json:"site,omitempty"`
	Views      []map[string]any `json:"views"`
	Errors     []viewError      `json:"errors,omitempty"`
}

// LoadViews reads every view document a directory holds as one se.views/1
// envelope. An unset directory is a deployment that made no views — an
// empty list, never an error.
func LoadViews(directory, now, site string) viewsEnvelope {
	envelope := viewsEnvelope{Schema: "se.views/1", ObservedAt: now, Site: site,
		Views: []map[string]any{}}
	if directory == "" {
		return envelope
	}
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		envelope.Errors = append(envelope.Errors, viewError{
			File:  directory,
			Error: "configured views directory does not exist"})
		return envelope
	}
	entries, err := filepath.Glob(filepath.Join(directory, "*.json"))
	if err != nil {
		envelope.Errors = append(envelope.Errors, viewError{
			File: directory, Error: err.Error()})
		return envelope
	}
	sort.Strings(entries)
	for _, path := range entries {
		name := filepath.Base(path)
		raw, err := os.ReadFile(path)
		if err != nil {
			envelope.Errors = append(envelope.Errors,
				viewError{File: name, Error: err.Error()})
			continue
		}
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			envelope.Errors = append(envelope.Errors,
				viewError{File: name, Error: err.Error()})
			continue
		}
		if problem := ViewProblem(document); problem != "" {
			envelope.Errors = append(envelope.Errors,
				viewError{File: name, Error: problem})
			continue
		}
		envelope.Views = append(envelope.Views, document)
	}
	return envelope
}

func nonEmptyString(document map[string]any, member string) bool {
	value, held := document[member].(string)
	return held && value != ""
}

// ViewProblem is the first structural reason a document cannot be served,
// or "". Ported from views.py's view_problem; the conformance comparison
// requires the same verdict on the same document, and where they differ
// views.py is right.
func ViewProblem(document map[string]any) string {
	if document == nil {
		return "not a JSON object"
	}
	if !nonEmptyString(document, "name") {
		return "missing name"
	}
	if !nonEmptyString(document, "title") {
		return "missing title"
	}
	if raw, held := document["hosts"]; held && raw != nil {
		// An empty or malformed target list is refused, never treated as
		// "everywhere": a view that tried to narrow itself and failed
		// must not widen silently — that inversion is how the ZFS
		// dashboard became an estate-wide default (2026-08-12).
		hosts, ok := raw.([]any)
		if !ok || len(hosts) == 0 {
			return "hosts must be a non-empty list of host names when given"
		}
		for _, host := range hosts {
			if text, ok := host.(string); !ok || text == "" {
				return "hosts must be a non-empty list of host names when given"
			}
		}
	}
	panels, ok := document["panels"].([]any)
	if !ok || len(panels) == 0 {
		return "panels must be a non-empty list"
	}
	for index, raw := range panels {
		panel, ok := raw.(map[string]any)
		if !ok {
			return fmt.Sprintf("panels.%d: not an object", index)
		}
		if panel["kind"] == "pipeline" {
			// A pipeline panel is stages, not a single collection: each
			// stage is a collection reference of its own, and a join must
			// say both halves — a half-joined stage would silently relate
			// nothing, which is the dropped-panel shape in miniature.
			for _, member := range []string{"key", "title"} {
				if !nonEmptyString(panel, member) {
					return fmt.Sprintf("panels.%d: missing %s", index, member)
				}
			}
			stages, ok := panel["stages"].([]any)
			if !ok || len(stages) < 2 {
				return fmt.Sprintf("panels.%d: a pipeline needs at least two stages", index)
			}
			for at, rawStage := range stages {
				stage, ok := rawStage.(map[string]any)
				if !ok {
					return fmt.Sprintf("panels.%d.stages.%d: not an object", index, at)
				}
				for _, member := range requiredStageMembers {
					if !nonEmptyString(stage, member) {
						return fmt.Sprintf("panels.%d.stages.%d: missing %s",
							index, at, member)
					}
				}
				if rawJoin, held := stage["join"]; held && rawJoin != nil {
					join, ok := rawJoin.(map[string]any)
					if !ok || !nonEmptyString(join, "fact") ||
						!nonEmptyString(join, "targetFact") {
						return fmt.Sprintf(
							"panels.%d.stages.%d: join must carry fact and targetFact",
							index, at)
					}
				}
			}
			continue
		}
		for _, member := range requiredPanelMembers {
			if !nonEmptyString(panel, member) {
				return fmt.Sprintf("panels.%d: missing %s", index, member)
			}
		}
	}
	return ""
}

func registerViews(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/views", func(w http.ResponseWriter, r *http.Request) {
		// Read FRESH per request from the deployed directory, as the hub
		// does: the operator edits a file and refreshes, and a remembered
		// copy would be one more thing to invalidate.
		writeJSON(w, LoadViews(os.Getenv("SE_VIEWS_DIR"),
			time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			os.Getenv("SE_SITE")))
	})
}
