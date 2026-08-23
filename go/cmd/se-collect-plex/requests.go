package main

// requests: who is waiting for what — seerr's queue, one row per request.
// seerr's own document states only IDS: stock overseerr carries no title
// member anywhere (live recon against the estate, 2026-08-13), so the WHAT
// of a request comes from seerr's details endpoints, answered from its local
// TMDB cache. The lookups are bounded per run and a failed one narrows one
// row's enrichment, never the sweep.

import (
	"fmt"
	"strconv"
)

// seerr's MediaRequestStatus, its own documented numbering — failed is the
// one fault-shaped state (dispatch to the managers failed).
// The two receipts verdicts, shared constants for the reason declineNoServer
// is one: the live and replay paths must be unable to spell the same absence
// two ways. The messages are the reference's own.
var (
	declineNoSeerr = declined{reason: "unavailable",
		detail: "SE_SEERR_URL is not configured"}
	declineNoSeerrKey = declined{reason: "unavailable",
		detail: "SE_SEERR_API_KEY is not configured — the URL names a seerr " +
			"this deployment cannot open"}
)

var seerrStatus = map[string]string{
	"1": "pending", "2": "approved", "3": "declined",
	"4": "failed", "5": "completed",
}

// The requests walk is bounded, never silently truncated: pages accumulate
// until seerr's own pageInfo says done, capped so a lying total cannot spin
// the sweep. Title lookups are capped per run for the reference's own
// reason: re-asking everything would turn the collect cadence into a load
// test against seerr's TMDB cache.
const (
	requestsPath         = "/api/v1/request"
	moviePath            = "/api/v1/movie"
	tvPath               = "/api/v1/tv"
	requestPageSize      = 100
	maxRequestPages      = 20
	titleLookupsPerSweep = 50
)

func requestRows(src source) ([]row, error) {
	hasURL, hasKey := src.seerrConfigured()
	if !hasURL {
		refused := declineNoSeerr
		return nil, &refused
	}
	if !hasKey {
		refused := declineNoSeerrKey
		return nil, &refused
	}

	// Every page, to seerr's own pageInfo and bounded.
	var records []*value
	skip := 0
	for page := 0; page < maxRequestPages; page++ {
		reply, err := src.seerr(requestsPath, fmt.Sprintf(
			"take=%d&skip=%d&sort=added", requestPageSize, skip))
		if err != nil {
			return nil, err
		}
		if reply.detail != "" {
			return nil, &declined{reason: "unavailable", detail: reply.detail}
		}
		results := reply.doc.get("results").elements()
		if len(results) == 0 {
			break
		}
		for _, raw := range results {
			if raw.get("id").stated() {
				records = append(records, raw)
			}
		}
		skip += len(results)
		declared := reply.doc.get("pageInfo").get("results")
		if declared.isInteger() {
			if total, err := strconv.Atoi(declared.text); err == nil && skip >= total {
				break
			}
		}
	}

	// The identity memo, per run: a run-and-exit collector re-asks each
	// run, under the same per-sweep bound the reference holds per process.
	type titleKey struct {
		mediaType string
		tmdb      string
	}
	keyOf := func(raw *value) (titleKey, bool) {
		mediaType := raw.get("type")
		tmdb := raw.get("media").get("tmdbId")
		if mediaType != nil && mediaType.kind == jsonString &&
			(mediaType.text == "movie" || mediaType.text == "tv") &&
			tmdb.isInteger() {
			return titleKey{mediaType.text, tmdb.text}, true
		}
		return titleKey{}, false
	}
	var wanted []titleKey
	seen := map[titleKey]bool{}
	for _, raw := range records {
		if key, ok := keyOf(raw); ok && !seen[key] {
			seen[key] = true
			wanted = append(wanted, key)
		}
	}
	if len(wanted) > titleLookupsPerSweep {
		wanted = wanted[:titleLookupsPerSweep]
	}
	titles := map[titleKey]string{}
	for _, key := range wanted {
		path := moviePath
		if key.mediaType == "tv" {
			// The TV endpoint takes the TMDB id as well — its own
			// documented shape, NOT the tvdbId, which is the predictable
			// trap.
			path = tvPath
		}
		reply, err := src.seerr(path+"/"+key.tmdb, "")
		if err != nil {
			return nil, err
		}
		if reply.detail != "" {
			continue // one row's enrichment, never the sweep
		}
		// Movies answer .title, series answer .name — seerr's own shapes.
		title := reply.doc.get("title")
		if !title.truthy() {
			title = reply.doc.get("name")
		}
		if title.truthy() && title.kind == jsonString {
			titles[key] = title.text
		}
	}

	rows := make([]row, 0, len(records))
	for _, raw := range records {
		facts := newObject()
		if status := raw.get("status"); status.isInteger() {
			word, known := seerrStatus[status.text]
			if !known {
				word = status.text
			}
			facts.set("Status", stringValue(word))
		}
		if mediaType := raw.get("type"); mediaType.truthy() {
			facts.set("Type", mediaType)
		}
		if requester := raw.get("requestedBy").get("displayName"); requester.truthy() {
			facts.set("RequestedBy", requester)
		}
		if created := raw.get("createdAt"); created.truthy() {
			facts.set("CreatedAt", created)
		}
		if tmdb := raw.get("media").get("tmdbId"); tmdb.isInteger() {
			facts.set("TmdbId", tmdb)
		}
		var seasonNumbers []*value
		for _, season := range raw.get("seasons").elements() {
			if number := season.get("seasonNumber"); number.isInteger() {
				seasonNumbers = append(seasonNumbers, number)
			}
		}
		if len(seasonNumbers) > 0 {
			facts.set("Seasons", newArray(seasonNumbers))
		}
		if key, ok := keyOf(raw); ok {
			if title, held := titles[key]; held {
				facts.set("Title", stringValue(title))
			}
		}
		rows = append(rows, row{name: raw.get("id").text, facts: facts})
	}
	return rows, nil
}
