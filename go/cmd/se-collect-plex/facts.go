package main

import (
	"strconv"
	"time"
)

// Every fact these three collections can publish, spelled once. The names are
// the shipping adapter's own: a port that renamed one would publish a second
// fact beside the reference's on the same row, and the collator would carry both
// forever.
const (
	factFriendlyName = "FriendlyName"
	factVersion      = "Version"
	factPlatform     = "Platform"
	factSessionCount = "SessionCount"

	factConfigMissing      = "ConfigMissing"
	factStatusUnobservable = "StatusUnobservable"

	factTitle                 = "Title"
	factType                  = "Type"
	factItemCount             = "ItemCount"
	factItemCountUnobservable = "ItemCountUnobservable"
	factRefreshing            = "Refreshing"
	factScannedAt             = "ScannedAt"
	factUpdatedAt             = "UpdatedAt"

	factUser          = "User"
	factPlayer        = "Player"
	factState         = "State"
	factVideoDecision = "VideoDecision"
)

// The root document's members and the fact each becomes, in the REFERENCE'S
// order — server_facts walks this pairing and the row keeps the order it was
// built in.
//
// A member is lifted only when it is TRUTHY, which is the reference's own test
// (`if container.get(member):`). A server that answered `"friendlyName": ""`
// states that it has no name rather than that its name is the empty string, and
// publishing the empty string would put a blank where every Plex client shows a
// word.
var rootMembers = [...]struct{ fact, member string }{
	{factFriendlyName, "friendlyName"},
	{factVersion, "version"},
	{factPlatform, "platform"},
}

// serverFacts folds the root document onto the server row. It reads through
// `MediaContainer`, which is the envelope every Plex answer carries — a document
// without one yields no facts, which is a reading of a server answering
// something this collector does not recognise rather than a failure.
func serverFacts(doc *value, facts *value) {
	container := doc.get("MediaContainer")
	for _, pair := range rootMembers {
		if member := container.get(pair.member); member.truthy() {
			facts.set(pair.fact, member)
		}
	}
}

// sessionCount is the sessions document's own `size`, which is where the SERVER
// row's stream count comes from. The same document feeds the sessions collection
// its rows: one request path, two collections, and the count is published from
// here rather than from the row walk so a server whose session list is empty
// still states zero.
//
// Zero is published like any other reading. A port that lifted the count only
// when it was non-zero would leave the row silent about the one state an
// administrator most often wants confirmed.
func sessionCount(doc *value, facts *value) {
	if size := doc.get("MediaContainer").get("size"); size.isInteger() {
		facts.set(factSessionCount, size)
	}
}

// libraryFacts folds one `/library/sections` directory entry onto a library row.
// Everything here comes from the SECTION LISTING; the item count costs a second
// request per section and is folded by the caller.
func libraryFacts(raw *value, facts *value) {
	// Title and Type are assigned unconditionally by the reference, so a section
	// missing either would put a null on the row — which the contract refuses at
	// any depth (DESIGN 19) and the judge rejects the whole stream for. The
	// member is therefore omitted here instead, which is rule 7's absence: the
	// document did not state it.
	facts.set(factTitle, raw.get("title"))
	facts.set(factType, raw.get("type"))

	// Published whenever the member is STATED, and the value is Python's
	// bool() of it. `false` is a reading — the section is not scanning — and a
	// port that tested truthiness here rather than presence would drop the fact
	// on every idle library, which is every library nearly all of the time.
	if refreshing := raw.get("refreshing"); refreshing.stated() {
		facts.set(factRefreshing, boolValue(refreshing.truthy()))
	}

	for _, pair := range [...]struct{ fact, member string }{
		{factScannedAt, "scannedAt"},
		{factUpdatedAt, "updatedAt"},
	} {
		if stamp := epochToISO(raw.get(pair.member)); stamp != "" {
			facts.set(pair.fact, stringValue(stamp))
		}
	}
}

// epochToISO is the reference's `usec_to_iso(value * 1_000_000)` guarded by
// `isinstance(value, int) and value > 0`: Plex states these in whole seconds, the
// envelope's converter takes microseconds, and the answer is UTC to the second.
// The empty string means "not a stamp this collector will publish" — a missing
// member, a null, a fractional literal, a zero or a negative one.
//
// The int64 bound is this side's own and is stated rather than hidden: Python's
// int is unbounded and would carry a nonsense literal all the way to a
// datetime that raises, where this omits the fact. A stamp outside the year
// range time.Unix can render is not a scan time any Plex has ever reported.
func epochToISO(v *value) string {
	if !v.isInteger() {
		return ""
	}
	seconds, err := strconv.ParseInt(v.text, 10, 64)
	if err != nil || seconds <= 0 || seconds > maxEpochSeconds {
		return ""
	}
	return time.Unix(seconds, 0).UTC().Format("2006-01-02T15:04:05Z")
}

// Year 9999, past which the format above would widen its year field and stop
// being an RFC 3339 timestamp a consumer can parse.
const maxEpochSeconds = 253402300799

// itemCount folds the zero-size container window's answer onto a library row.
//
// `totalSize`, never `size`. The request asks for a window of zero rows
// precisely so the server counts without sending anything, which makes `size` 0
// by construction — a port that read it publishes 0 for every section, which
// reads exactly like the emptied-library shape this fact exists to rule out.
func itemCount(doc *value, facts *value) {
	if total := doc.get("MediaContainer").get("totalSize"); total.isInteger() {
		facts.set(factItemCount, total)
	}
}

// sessionFacts folds one entry of the sessions document's `Metadata` list onto a
// session row: what is playing, who is watching, on what, and whether the server
// is transcoding it.
//
// Reached by no committed capture — nothing was playing when the corpus was
// taken, and a document that names a watcher and what they were watching is not
// one a public corpus can hold (harness/scrub/plex.json says so leaf by leaf).
// The derivation is written from the reference rather than from a payload, and
// that bound is stated here rather than left to be discovered.
func sessionFacts(raw *value, facts *value) {
	title := raw.get("title")
	// An episode titles itself with its series: `f"{grandparentTitle} — {title}"`,
	// with an em dash between them. A movie has no grandparent and keeps its own
	// name — the reference's test is truthiness, so a grandparent stated as the
	// empty string is no grandparent.
	if grandparent := raw.get("grandparentTitle"); grandparent.truthy() {
		facts.set(factTitle, stringValue(pythonStr(grandparent)+" — "+pythonStr(title)))
	} else {
		facts.set(factTitle, title)
	}
	facts.set(factType, raw.get("type"))

	if user := raw.get("User").get("title"); user.truthy() {
		facts.set(factUser, user)
	}
	player := raw.get("Player")
	if product := player.get("product"); product.truthy() {
		facts.set(factPlayer, product)
	}
	if state := player.get("state"); state.truthy() {
		facts.set(factState, state)
	}
	if decision := raw.get("TranscodeSession").get("videoDecision"); decision.truthy() {
		facts.set(factVideoDecision, decision)
	}
}

// sessionName is the row's native name: the session key, or the rating key where
// the server states no session key. `or` in the reference, so a falsy session key
// falls through to the rating key — and a pair that leaves nothing stated is a
// row this collector cannot name and therefore does not publish.
func sessionName(raw *value) (string, bool) {
	chosen := raw.get("sessionKey")
	if !chosen.truthy() {
		chosen = raw.get("ratingKey")
	}
	if !chosen.stated() {
		return "", false
	}
	return pythonStr(chosen), true
}
