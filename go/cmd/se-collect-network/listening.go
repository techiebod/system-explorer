package main

// The listening collection (register row 9, R3b): one row per listening
// socket across both stacks and both protocols, ported from the reference
// with its two disciplines intact. Ordered by port then protocol then
// address — the way an operator scans, by the number they are looking for,
// not the order the kernel hashed them into (and the one collection whose
// applied order is deliberately NOT the document's). And an unreadable
// table is a statement every row carries: a host whose udp6 would not open
// has not stopped listening on udp6, and a complete-looking TCP list with
// nothing beside it would be the most confident possible way to be wrong
// about exposure.

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
)

// The two socket states that mean "listening": TCP LISTEN, and for UDP the
// unconnected state — a UDP socket with no peer is one accepting datagrams.
const (
	tcpListen      = "0A"
	udpUnconnected = "07"
)

// One spelling on both implementations (the nix interface-string lesson);
// the reference's constant is this exact sentence.
const processUnobservable = "the listening process cannot be named from " +
	"this reading: the socket-inode to process join reads /proc/<pid>/fd, " +
	"which only the owning user may open, and this observer runs without " +
	"that privilege. The uid beside this fact is from /proc/net itself and " +
	"is what can be said without it."

type listeningRow struct {
	protocol string
	address  string
	port     int
	uid      int
	inode    int64
}

// hexAddr decodes /proc/net's address encoding: 32-bit words in HOST byte
// order, printed big-endian-looking. Word-wise, because reversing the whole
// string silently produces PLAUSIBLE addresses — 0100007F read backwards is
// 1.0.0.127 rather than 127.0.0.1 — and the word form is also correct for
// IPv6's four words.
func hexAddr(raw string) string {
	decode := func(word string) ([]byte, bool) {
		n, err := strconv.ParseUint(word, 16, 32)
		if err != nil {
			return nil, false
		}
		out := make([]byte, 4)
		binary.LittleEndian.PutUint32(out, uint32(n))
		return out, true
	}
	switch len(raw) {
	case 8:
		packed, ok := decode(raw)
		if !ok {
			return ""
		}
		return net.IP(packed).String()
	case 32:
		packed := make([]byte, 0, 16)
		for i := 0; i < 32; i += 8 {
			word, ok := decode(raw[i : i+8])
			if !ok {
				return ""
			}
			packed = append(packed, word...)
		}
		return net.IP(packed).String()
	}
	return ""
}

// listeningScope is what an address binding says about reach, in the words
// an operator would use — the fact the firewall question hangs off.
func listeningScope(address string) string {
	if address == "0.0.0.0" || address == "::" {
		return "all-interfaces"
	}
	if strings.HasPrefix(address, "127.") || address == "::1" {
		return "loopback"
	}
	return "specific-address"
}

func parseProcNet(table, text string) []listeningRow {
	wanted := udpUnconnected
	if strings.HasPrefix(table, "tcp") {
		wanted = tcpListen
	}
	var rows []listeningRow
	lines := strings.Split(text, "\n")
	if len(lines) < 2 {
		return rows
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[3] != wanted {
			continue
		}
		local := fields[1]
		sep := strings.LastIndexByte(local, ':')
		if sep < 0 {
			continue
		}
		address := hexAddr(local[:sep])
		if address == "" {
			continue
		}
		port, portErr := strconv.ParseInt(local[sep+1:], 16, 32)
		uid, uidErr := strconv.Atoi(fields[7])
		inode, inodeErr := strconv.ParseInt(fields[9], 10, 64)
		if portErr != nil || uidErr != nil || inodeErr != nil {
			continue
		}
		rows = append(rows, listeningRow{protocol: table, address: address,
			port: int(port), uid: uid, inode: inode})
	}
	return rows
}

// acquireListening reads the four socket tables once, deduped and sorted —
// shared with port-exposure, whose rows are these sockets under the firewall
// join, so the two collections cannot come to disagree about what is
// listening.
func acquireListening(src source) ([]listeningRow, []string) {
	var rows []listeningRow
	var unread []string
	for _, table := range [...]string{"tcp", "tcp6", "udp", "udp6"} {
		text, readable := src.procNet(table)
		if !readable {
			unread = append(unread, "/proc/net/"+table+" could not be read")
			continue
		}
		rows = append(rows, parseProcNet(table, text)...)
	}
	// SO_REUSEPORT twins collapse to one row: several sockets can listen
	// on one (protocol, address, port) — one inode each — and the wire
	// refuses a native name emitted twice, because two emissions mint one
	// id (law 1). The reference double-emits here, which rule 15 already
	// records as a defect on its side; first row wins, carrying the first
	// inode, exactly as the old get_object's matches[0] already behaved.
	seen := map[string]bool{}
	deduped := rows[:0]
	for _, row := range rows {
		key := fmt.Sprintf("%s %s:%d", row.protocol, row.address, row.port)
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, row)
	}
	rows = deduped
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].port != rows[j].port {
			return rows[i].port < rows[j].port
		}
		if rows[i].protocol != rows[j].protocol {
			return rows[i].protocol < rows[j].protocol
		}
		return rows[i].address < rows[j].address
	})
	return rows, unread
}

func collectListening(out *emitter, stderr io.Writer, src source, collection string, generation uint64, objects *int) int {
	rows, unread := acquireListening(src)
	if len(unread) == 4 {
		// All four dark: what this host is listening on is unobservable,
		// and an empty commit would report a machine accepting no traffic
		// at all — the most confident possible way to be wrong about
		// exposure. No commit; prior state stands, marked stale.
		out.emit(declineRecord{Record: "decline", Collection: collection,
			Reason: "unavailable",
			Detail: "none of the /proc/net socket tables could be read, so " +
				"what this host is listening on is unobservable rather than nothing"})
		fmt.Fprintln(stderr, "listening:", strings.Join(unread, "; "))
		return exitOK
	}
	for _, row := range rows {
		facts := map[string]any{
			"Protocol":     row.protocol,
			"LocalAddress": row.address,
			"LocalPort":    row.port,
			"Uid":          row.uid,
			"SocketInode":  row.inode,
			"Scope":        listeningScope(row.address),
			// On every row rather than once on the collection: a consumer
			// reading one object must not need the collection's source
			// block to know why the process is missing.
			"ProcessUnobservable": processUnobservable,
		}
		if len(unread) > 0 {
			// A table that would not open is not a table with nothing in
			// it: without this a host whose udp6 was unreadable would
			// publish a complete-looking list of TCP sockets.
			facts["TablesUnreadable"] = strings.Join(unread, "; ")
		}
		out.emit(objectRecord{
			Record:     "object",
			Collection: collection,
			Name:       fmt.Sprintf("%s %s:%d", row.protocol, row.address, row.port),
			Type:       "listening-socket",
			Facts:      facts,
			At:         src.stamp(*objects),
		})
		*objects++
	}
	out.emit(commitRecord{
		Record:     "commit",
		Collection: collection,
		Generation: generation,
		Objects:    len(rows),
	})
	return exitOK
}
