// Command se-collect-docker is the docker containers, volumes and networks
// collector. It reads one request line on standard input and writes to
// standard output; under socket activation systemd supplies both from the
// accepted connection, and in a terminal a person does. Those are the same
// contract, which is what makes this binary testable with a pipe and judged by
// the same harness that judges the Python reference it was ported from.
//
// Read-only by construction, like the adapter it reproduces: every request it
// makes is a GET over the daemon's unix socket.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Exit status means one thing only: non-zero is "I could not run", never a
// decline (DESIGN 18) — a collector that ran and found nothing exits zero and
// says so in a record, because a non-zero exit is indistinguishable from a
// crash and both would read as absence.
const (
	exitOK      = 0
	exitRuntime = 1 // a live interface this binary needs and could not reach
	exitRequest = 2 // a request this side could not parse genuinely was not run
)

// The request line is a fixed token count, length-bounded (DESIGN 18). The
// bound refuses a request too large to be legitimate before any token is
// interpreted, so an unbounded line cannot become an unbounded parse.
const requestBound = 64 * 1024

// Mirrors the contract's collection-name pattern (se.stream.1.json): begin
// must echo the request line exactly, so a name this pattern refuses could
// never travel the stream legally — refusing it at the request is "I could
// not run", not a sanitisation.
var collectionName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

func main() {
	os.Exit(run(os.Stdin, os.Stdout, os.Stderr, os.Getenv))
}

// run is main with its edges injected, so every exit path is a unit test
// rather than a subprocess. Diagnostics go to stderr and never payload
// content — stderr lands in the journal and bypasses every redaction path
// (DESIGN 19).
func run(stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	line, err := requestLine(stdin)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitRequest
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		fmt.Fprintln(stderr, "empty request: expected declare, probe, or collect <collection>:<generation>…")
		return exitRequest
	}

	src := newSource(getenv)
	switch fields[0] {
	case "declare":
		if len(fields) != 1 {
			fmt.Fprintln(stderr, "declare takes no arguments")
			return exitRequest
		}
		// The exact embedded bytes, stable across runs: these are the bytes
		// begin's declaration hash covers, so emitting anything re-serialised
		// here would un-anchor the hash.
		if _, err := stdout.Write(declarationBytes); err != nil {
			fmt.Fprintln(stderr, "writing the declaration:", err)
			return exitRuntime
		}
		return exitOK
	case "probe":
		if len(fields) != 1 {
			fmt.Fprintln(stderr, "probe takes no arguments")
			return exitRequest
		}
		return probe(stdout, stderr, src)
	case "collect":
		order, generations, err := parseCollect(fields[1:])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitRequest
		}
		return collect(stdout, stderr, src, order, generations)
	case "object", "evidence":
		// Three tokens exactly: the verb, the collection, the native name
		// (DESIGN 18). Every token is data — refused whole rather than
		// reassembled if whitespace splits it further.
		if len(fields) != 3 {
			fmt.Fprintf(stderr, "%s takes exactly '<collection> <name>'\n", fields[0])
			return exitRequest
		}
		if fields[0] == "object" {
			return serveObject(stdout, stderr, src, fields[1], decodeNameToken(fields[2]))
		}
		return serveEvidence(stdout, stderr, src, fields[1], decodeNameToken(fields[2]))
	default:
		// Every token is data, never an option or a command fragment (DESIGN
		// 18) — an unknown verb is refused whole, not guessed at.
		fmt.Fprintf(stderr, "unknown verb %q: this collector serves declare, probe, collect, object and evidence\n", fields[0])
		return exitRequest
	}
}

// decodeNameToken is the request line's declared whitespace encoding
// (DESIGN 18): a name token travels with each space as %20 and each literal
// percent as %25, so the line stays a fixed whitespace-split token count
// while names carrying spaces — an nft table's "inet filter", a mount point
// under /media — stay addressable. Exactly those two sequences, in this
// order, and nothing else: this is not URL decoding.
func decodeNameToken(token string) string {
	return strings.ReplaceAll(strings.ReplaceAll(token, "%20", " "), "%25", "%")
}

// requestLine reads exactly one line, bounded. Everything after the first
// newline is ignored rather than read: one request, one process, one exit —
// the run-and-exit contract has no second question.
func requestLine(stdin io.Reader) (string, error) {
	reader := bufio.NewReaderSize(io.LimitReader(stdin, requestBound+1), 4096)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("reading the request line: %v", err)
	}
	if len(line) > requestBound {
		return "", fmt.Errorf("request line exceeds the %d-byte bound", requestBound)
	}
	return line, nil
}

// parseCollect parses <collection>:<generation> tokens. The generation is
// everything after the LAST colon, because names in this product legitimately
// contain colons (DESIGN 18). The collator issued it and this side only
// echoes it — in begin's map and on the collection's commit — which is the
// whole of the newest-wins mechanism (DESIGN 19), so a token this side cannot
// parse into an echo is a request that was never run.
func parseCollect(tokens []string) ([]string, map[string]uint64, error) {
	if len(tokens) == 0 {
		return nil, nil, errors.New("empty collect: the request line is 'collect <collection>:<generation>…'")
	}
	order := make([]string, 0, len(tokens))
	generations := make(map[string]uint64, len(tokens))
	for _, token := range tokens {
		cut := strings.LastIndexByte(token, ':')
		if cut < 1 || cut == len(token)-1 {
			return nil, nil, fmt.Errorf("malformed token %q: expected <collection>:<generation>", token)
		}
		name, digits := token[:cut], token[cut+1:]
		// ParseUint base 10 rejects signs, spaces and prefixes, so "digits
		// only" needs no second check — and a generation too large for uint64
		// was not issued by any collator.
		generation, err := strconv.ParseUint(digits, 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("malformed token %q: the generation must be an unsigned integer", token)
		}
		if !collectionName.MatchString(name) {
			return nil, nil, fmt.Errorf("collection %q cannot travel the stream: begin must echo the request line exactly, and the contract's collection names are ^[a-z][a-z0-9-]*$", name)
		}
		if _, dup := generations[name]; dup {
			return nil, nil, fmt.Errorf("collection %q appears twice: one request opens a collection under one generation", name)
		}
		order = append(order, name)
		generations[name] = generation
	}
	return order, generations, nil
}
