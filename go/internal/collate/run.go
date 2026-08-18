// The runtime loop. Configuration comes from the environment because the
// collator's own config is the "reach" kind (DESIGN §08) and the module
// generates it; nothing here is worth a config-file parser.
//
//	SE_COLLECTORS  name=/path/to.sock[,name=/path/to.sock…]
//	SE_STATE_DIR   directory for the durable store (required)
//	SE_LISTEN      read API bind address (default 127.0.0.1:8095)
//	SE_ONESHOT     run one acquisition round and exit — the crash
//	               harness's vehicle, and a person's smoke test
package collate

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/techiebod/system-explorer/go/internal/store"
	"github.com/techiebod/system-explorer/go/internal/wire"
)

// retryInterval paces a collector whose declaration cannot be fetched:
// with no declaration there is no declared freshness to schedule by, so
// a fixed, unhurried retry stands in until one appears.
const retryInterval = time.Minute

// Main is the whole daemon; cmd/se-collate is a one-line wrapper so the
// crash tests can spawn this exact code path as their subject.
func Main() int {
	stateDir := os.Getenv("SE_STATE_DIR")
	if stateDir == "" {
		fmt.Fprintln(os.Stderr, "se-collate: SE_STATE_DIR is required")
		return 2
	}
	collectors, err := parseCollectors(os.Getenv("SE_COLLECTORS"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "se-collate: %v\n", err)
		return 2
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "se-collate: %v\n", err)
		return 1
	}
	st, err := store.Open(filepath.Join(stateDir, "collate.db"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "se-collate: open store: %v\n", err)
		return 1
	}
	defer st.Close()

	// Learned at start, fatally: ages are comparisons between clock
	// domains (DESIGN §09), and a collator that cannot name its own
	// domain would serve ages it cannot interpret.
	bootID, err := OwnBootID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "se-collate: %v\n", err)
		return 1
	}

	if os.Getenv("SE_ONESHOT") != "" {
		// One round, sequential, no listener: the acquisition path with
		// nothing else moving, which is what the crash harness must kill.
		for _, c := range collectors {
			if err := AcquireOnce(context.Background(), st, &wire.Client{Socket: c.socket}); err != nil {
				fmt.Fprintf(os.Stderr, "se-collate: %s: %v\n", c.name, err)
			}
		}
		return 0
	}

	listen := os.Getenv("SE_LISTEN")
	if listen == "" {
		// Loopback by default: the API is unauthenticated by design, so
		// reaching it from elsewhere is a decision, never an accident.
		listen = "127.0.0.1:8095"
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "se-collate: listen %s: %v\n", listen, err)
		return 1
	}
	go func() {
		// The daemon's own boot clock serves ages; see boottime_linux.go.
		if err := http.Serve(ln, NewHandler(st, BootNow, bootID)); err != nil {
			fmt.Fprintf(os.Stderr, "se-collate: serve: %v\n", err)
		}
	}()

	for _, c := range collectors {
		go collectorLoop(st, c)
	}
	select {} // the loops and the listener are the process
}

type collectorConfig struct {
	name   string
	socket string
}

// parseCollectors reads SE_COLLECTORS. An empty value is a valid daemon
// (a collator with only its read API), a malformed one is a refusal —
// half-parsing a fleet list would observe half a fleet and report health.
func parseCollectors(env string) ([]collectorConfig, error) {
	var out []collectorConfig
	if strings.TrimSpace(env) == "" {
		return out, nil
	}
	seen := map[string]bool{}
	for _, entry := range strings.Split(env, ",") {
		entry = strings.TrimSpace(entry)
		name, socket, ok := strings.Cut(entry, "=")
		if !ok || name == "" || socket == "" {
			return nil, fmt.Errorf("SE_COLLECTORS entry %q is not name=/path/to.sock", entry)
		}
		if seen[name] {
			return nil, fmt.Errorf("SE_COLLECTORS names %q twice", name)
		}
		seen[name] = true
		out = append(out, collectorConfig{name: name, socket: socket})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// collectorLoop schedules one collector: acquire on start, then every
// declared-freshness interval. Failures are recorded by AcquireOnce and
// never fatal to the loop — a collector that stops answering is a fact
// to keep observing, not a reason to stop observing it.
func collectorLoop(st *store.Store, c collectorConfig) {
	client := &wire.Client{Socket: c.socket}
	for {
		if err := AcquireOnce(context.Background(), st, client); err != nil {
			fmt.Fprintf(os.Stderr, "se-collate: %s: %v\n", c.name, err)
		}
		time.Sleep(nextInterval(client))
	}
}

// nextInterval re-reads the declaration for its freshness so an upgraded
// collector reschedules without a restart. The tightest collection sets
// the pace: one socket serves the whole batch, so the batch runs at the
// batch's most demanding promise.
func nextInterval(client *wire.Client) time.Duration {
	raw, err := client.Declare(context.Background())
	if err != nil {
		return retryInterval
	}
	_, freshness, err := wire.ParseDeclaration(raw)
	if err != nil {
		return retryInterval
	}
	interval := time.Duration(0)
	for _, d := range freshness {
		if interval == 0 || d < interval {
			interval = d
		}
	}
	if interval <= 0 {
		return retryInterval
	}
	return interval
}
