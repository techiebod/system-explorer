package main

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The compose project label, which is the whole of this collector's
// cross-subsystem edge: a container carrying it is managed by the
// compose-stack-<project>.service unit, and a row without it is one nothing
// generated. adapters/docker.py COMPOSE_PROJECT.
const composeProject = "com.docker.compose.project"

// The container states that have processes, and therefore a live scope cgroup.
// `restarting` and `paused` keep theirs; `created`, `exited`, `dead` and
// `removing` do not. Docker's own vocabulary, not ours.
// adapters/docker.py _SCOPED_STATES.
var scopedStates = [...]string{"running", "restarting", "paused"}

// row is one object as the collection publishes it: the name the collator keys
// on, and the facts, already free of anything the document did not state.
type row struct {
	name  string
	facts *value
}

// containerRows is adapters/docker.py `_container_items()`: one row per entry
// of /containers/json?all=1, in the order dockerd listed them. The list order
// is the answer's order — nothing sorts the containers — so a port that keyed
// them into a map would publish a different `at` ordering on every run.
func containerRows(document *value) ([]row, error) {
	if document == nil || document.kind != jsonArray {
		return nil, errors.New("the staged containers payload is not a list of containers")
	}
	rows := make([]row, 0, len(document.items))
	for i, container := range document.items {
		built, err := buildContainer(container)
		if err != nil {
			return nil, fmt.Errorf("container %d: %v", i, err)
		}
		rows = append(rows, built)
	}
	return rows, nil
}

func buildContainer(container *value) (row, error) {
	name, err := containerName(container)
	if err != nil {
		return row{}, err
	}
	id := container.get("Id").stringOr("")
	created, err := createdISO(container.get("Created"))
	if err != nil {
		return row{}, err
	}

	facts := newObject()
	// The reference's own dict-literal order, so the two files read side by
	// side. `set` drops anything the document did not state, which is what
	// keeps a null off the row (DESIGN 19) — see jsondoc's set.
	facts.set("State", container.get("State"))
	facts.set("Status", container.get("Status"))
	facts.set("Image", container.get("Image"))
	facts.set("Created", created)
	facts.set("ComposeProject", container.dig("Labels", composeProject))
	// Why a row may carry no Ports: "host" means every port the process binds
	// is open on the host's own addresses, which must never read the same as
	// nothing-reachable.
	facts.set("NetworkMode", container.dig("HostConfig", "NetworkMode"))
	// The instance identity; the name stays the object id because compose
	// names outlive recreations while IDs churn.
	facts.set("ContainerID", shortID(id))
	facts.set("ScopeUnit", scopeUnit(id, container.get("State")))
	// Only when at least one mapping exists: a portless container (host
	// networking, batch jobs) says nothing rather than [] — NetworkMode above
	// states which portless shape this is.
	mappings, err := portMappings(container.get("Ports"))
	if err != nil {
		return row{}, err
	}
	if len(mappings) > 0 {
		facts.set("Ports", stringArray(mappings))
	}
	return row{name: name, facts: facts}, nil
}

// containerName is `(raw.get("Names") or ["?"])[0].lstrip("/")`. Every leading
// slash goes, not one: docker writes "/name" and the reference strips the set.
// A Names list whose first entry is not a string is a document dockerd does not
// produce and the reference would crash on, so it refuses the batch.
func containerName(container *value) (string, error) {
	names := container.get("Names")
	if names == nil || names.kind != jsonArray || len(names.items) == 0 {
		return "?", nil
	}
	if !names.items[0].isString() {
		return "", errors.New("the container's first name is not a string")
	}
	return strings.TrimLeft(names.items[0].text, "/"), nil
}

// shortID is `(raw.get("Id") or "")[:12] or None` — the twelve characters
// docker itself shows, and nothing at all where there was no id. Sliced by
// bytes rather than runes, which is the same slice the reference takes because
// a docker id is hexadecimal ASCII.
func shortID(id string) *value {
	if len(id) > 12 {
		id = id[:12]
	}
	if id == "" {
		return nil
	}
	return stringValue(id)
}

// scopeUnit is the systemd scope a container's processes run in, named from its
// id — the link from a container to its own resource accounting, and the only
// handle that turns a `docker-6abfe5….scope` row in units/units back into
// something a reader recognises.
//
// Omitted while the container has NO processes, which the same row states: the
// scope is transient, systemd deletes it when the last process exits, and a
// created-but-never-started container never had one. Naming it on an exited row
// would hang the runs edge on a unit `systemctl status` answers "could not be
// found" for.
//
// The state guard is skipped where the document does not state a state at all,
// which is the reference's `state is not None` and not a defensive extra: a
// listing entry with no State member says nothing about whether the container
// has processes, and the id is still the scope's name if it has any.
func scopeUnit(id string, state *value) *value {
	if state.stated() && !isScopedState(state) {
		return nil
	}
	if id == "" {
		return nil
	}
	return stringValue("docker-" + id + ".scope")
}

func isScopedState(state *value) bool {
	if !state.isString() {
		return false
	}
	for _, scoped := range scopedStates {
		if state.text == scoped {
			return true
		}
	}
	return false
}

// createdISO is `env.usec_to_iso(int(raw.get("Created", 0)) * 1_000_000)`: the
// listing's epoch SECONDS rendered as a UTC timestamp. Zero is the reference's
// no-value reading and yields no fact — which is also what a missing member
// gives, since `.get("Created", 0)` defaults to it.
//
// The `int()` there accepts an integral or a fractional number and raises on
// anything else, so a member that is present and is not a number refuses the
// batch here: "I could not run", never a decline, because no machine was
// observed to have an unreadable creation time.
func createdISO(created *value) (*value, error) {
	if !created.stated() {
		return nil, nil
	}
	seconds, ok := created.integer()
	if !ok {
		return nil, errors.New("the container's Created member is not a number")
	}
	if seconds == 0 {
		return nil, nil
	}
	return stringValue(time.Unix(seconds, 0).UTC().Format("2006-01-02T15:04:05Z")), nil
}

// publishedKey is one published binding: the container port, the protocol and
// the host port. Docker lists a dual-stack publish twice — once for 0.0.0.0 and
// once for :: — and those three members are what say the two entries are one
// binding rather than two.
type publishedKey struct {
	private int64
	proto   string
	public  int64
	// The tokens the document spelled, kept beside the parsed figures so the
	// rendering is the document's own digits and the ORDER is numeric. Sorting
	// on the token would put 51413 before 9091.
	privateText, publicText string
}

type exposedKey struct {
	private int64
	proto   string
	text    string
}

// portMappings is adapters/docker.py `_port_mappings()`: the Ports member of a
// listing row, rendered as strings an administrator can act on.
// "0.0.0.0:8080->80/tcp" is host address and port -> container port/protocol.
// Empty when the container has no ports at all — the fact is only set when
// there is something to say.
//
// Each decision below drops or reshapes wire data, which is why each is stated:
//
//   - A dual-stack publish collapses into the one 0.0.0.0 rendering when host
//     port, container port and protocol all match. Where they differ the
//     entries are different claims and both stay.
//   - An exposed-but-unpublished port (no PublicPort) renders "80/tcp
//     (exposed)" rather than being omitted: the admin asking "why can't I reach
//     this" is told the port exists but was never published, and hiding that
//     would mask the very absence they are chasing.
//   - Specific host addresses render verbatim; an IPv6 address is bracketed so
//     the string pastes into curl.
//   - Published mappings sort before exposed ones; each group sorts by
//     container port, protocol, host port, then address — the daemon lists in
//     arbitrary order and a stable rendering is what makes rows diffable.
func portMappings(ports *value) ([]string, error) {
	if ports == nil || ports.kind != jsonArray {
		return nil, nil
	}
	published := map[publishedKey]map[string]bool{}
	var publishedOrder []publishedKey
	exposed := map[exposedKey]bool{}
	var exposedOrder []exposedKey

	for _, entry := range ports.items {
		private, stated, err := portNumber(entry.get("PrivatePort"))
		if err != nil {
			return nil, err
		}
		if !stated {
			continue // the reference skips an entry with no container port
		}
		proto := "tcp"
		if named := entry.get("Type"); named.isString() && named.text != "" {
			proto = named.text
		}
		public, publicStated, err := portNumber(entry.get("PublicPort"))
		if err != nil {
			return nil, err
		}
		if !publicStated {
			key := exposedKey{private: private, proto: proto, text: entry.get("PrivatePort").text}
			if !exposed[key] {
				exposed[key] = true
				exposedOrder = append(exposedOrder, key)
			}
			continue
		}
		key := publishedKey{
			private: private, proto: proto, public: public,
			privateText: entry.get("PrivatePort").text,
			publicText:  entry.get("PublicPort").text,
		}
		address := entry.get("IP").stringOr("")
		if address == "" {
			address = "0.0.0.0" // `entry.get("IP") or "0.0.0.0"`
		}
		if published[key] == nil {
			published[key] = map[string]bool{}
			publishedOrder = append(publishedOrder, key)
		}
		published[key][address] = true
	}

	sort.Slice(publishedOrder, func(i, j int) bool {
		return lessPublished(publishedOrder[i], publishedOrder[j])
	})
	sort.Slice(exposedOrder, func(i, j int) bool {
		if exposedOrder[i].private != exposedOrder[j].private {
			return exposedOrder[i].private < exposedOrder[j].private
		}
		return exposedOrder[i].proto < exposedOrder[j].proto
	})

	var out []string
	for _, key := range publishedOrder {
		addresses := published[key]
		if addresses["0.0.0.0"] {
			delete(addresses, "::") // the dual-stack duplicate
		}
		for _, ip := range sortedKeys(addresses) {
			host := ip
			if strings.Contains(ip, ":") {
				host = "[" + ip + "]"
			}
			out = append(out, host+":"+key.publicText+"->"+key.privateText+"/"+key.proto)
		}
	}
	for _, key := range exposedOrder {
		out = append(out, key.text+"/"+key.proto+" (exposed)")
	}
	return out, nil
}

func lessPublished(a, b publishedKey) bool {
	if a.private != b.private {
		return a.private < b.private
	}
	if a.proto != b.proto {
		return a.proto < b.proto
	}
	return a.public < b.public
}

// portNumber is a port as the reference reads one: absent or null means the
// entry does not state it, and anything present that is not a whole number is a
// document dockerd does not produce — refused rather than rendered, because the
// reference would render it with Python's own spelling of the value and the two
// would then disagree on bytes nobody can check.
func portNumber(port *value) (int64, bool, error) {
	if !port.stated() {
		return 0, false, nil
	}
	if port.kind != jsonNumber {
		return 0, false, errors.New("a port in the Ports member is not a number")
	}
	number, err := strconv.ParseInt(port.text, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("a port in the Ports member is not a whole number: %s", port.text)
	}
	return number, true, nil
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
