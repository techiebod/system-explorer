// The runtime loop. Configuration comes from the environment because the
// collator's own config is the "reach" kind (DESIGN §08) and the module
// generates it; nothing here is worth a config-file parser.
//
//	SE_COLLECTORS  name=/path/to.sock[,name=/path/to.sock…]
//	SE_STATE_DIR   directory for the durable store (required)
//	SE_LISTEN      read API bind address (default 127.0.0.1:8095)
//	SE_ONESHOT     run one acquisition round and exit — the crash
//	               harness's vehicle, and a person's smoke test
//	SE_HUB_ADDR    host:port of this site's hub. ABSENT IS A COMPLETE
//	               PRODUCT, not a degraded one: a host with no hub still
//	               serves its own API in full, which is the founding
//	               invariant that aggregation is never a precondition for
//	               observation (DESIGN §08).
//	SE_HOST        this collator's own scope name, required with
//	               SE_HUB_ADDR. Not derived from the connection, because
//	               the transport's idea of who dialled is not a reading of
//	               the machine and a NAT-mode dial makes it wrong.
//	SE_HUB_CA      the hub's certificate authority
//	SE_CLIENT_CERT the collator's own client identity
//	SE_CLIENT_KEY  its key
//	SE_HUB_INSECURE  dial without TLS. Must be asked for BY NAME — an
//	               insecure default would mean a misconfigured estate
//	               streams its state in clear and nothing says so.
package collate

import (
	"context"
	"crypto/tls"
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
		// And then, if a hub is configured, tell it. One round and one
		// session is what a smoke test and the transport suite both need,
		// and it is the same code path the daemon runs.
		if err := dialHubOnce(st, collectors, bootID); err != nil {
			fmt.Fprintf(os.Stderr, "se-collate: hub: %v\n", err)
			return 1
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
	if os.Getenv("SE_HUB_ADDR") != "" {
		go hubLoop(st, collectors, bootID)
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


// dialHubOnce sends one session to the configured hub, or does nothing
// when none is configured — which is a complete product and not a
// degraded one.
func dialHubOnce(st *store.Store, collectors []collectorConfig, bootID string) error {
	addr := os.Getenv("SE_HUB_ADDR")
	if addr == "" {
		return nil
	}
	host := os.Getenv("SE_HOST")
	if host == "" {
		return fmt.Errorf("SE_HUB_ADDR is set and SE_HOST is not; a checkpoint " +
			"names its own scope and the transport cannot name it")
	}
	cfg, err := hubTLS()
	if err != nil {
		return err
	}
	declarers := map[string]Declarer{}
	for _, c := range collectors {
		declarers[c.name] = &wire.Client{Socket: c.socket}
	}
	// The checkpoint id is minted per session from the boot clock: it has
	// to be unique within a connection and nothing more, and a reading
	// the collator already trusts beats inventing a second source of
	// identity for it.
	id := fmt.Sprintf("cp-%s-%d", host, int64(BootNow()*1e6))
	// A one-shot process holds no memory of a previous connection, so its
	// session is a first connection and says so. The daemon's loop below
	// is what carries a gap across reconnects.
	return Session(context.Background(), addr, cfg, st, declarers, id, host, bootID, nil)
}

// hubTLS builds the mutual identity, or refuses. Plaintext must be asked
// for by name: an insecure default would mean a misconfigured estate
// streams its whole state in clear and nothing anywhere says so.
func hubTLS() (*tls.Config, error) {
	if os.Getenv("SE_HUB_INSECURE") != "" {
		return nil, nil
	}
	cert, key, ca := os.Getenv("SE_CLIENT_CERT"), os.Getenv("SE_CLIENT_KEY"), os.Getenv("SE_HUB_CA")
	if cert == "" || key == "" || ca == "" {
		return nil, fmt.Errorf("SE_CLIENT_CERT, SE_CLIENT_KEY and SE_HUB_CA are all " +
			"required to dial a hub (or SE_HUB_INSECURE, deliberately): reversing the " +
			"connection removes the network as a containment layer, so identity is " +
			"the only one left")
	}
	return ClientConfig(cert, key, ca)
}


// hubReconnect paces a collator that cannot reach its hub. Unhurried on
// purpose: the hub being down costs the ESTATE view and costs this host
// nothing, because the collator serves its own API in full either way.
// A tight retry would turn somebody else's outage into this host's load.
const hubReconnect = 30 * time.Second

// hubLoop keeps one session open, and states the gap when it reconnects.
//
// A session that ends for any reason — the hub restarting, the link
// dropping, the hub refusing the checkpoint — is a disconnection, and the
// interval until the next one is what the next checkpoint states. That
// includes a refusal, deliberately: the hub did not take our state, so
// whatever happened next is as unrecorded as if the link had been down.
func hubLoop(st *store.Store, collectors []collectorConfig, bootID string) {
	addr, host := os.Getenv("SE_HUB_ADDR"), os.Getenv("SE_HOST")
	if host == "" {
		fmt.Fprintln(os.Stderr, "se-collate: SE_HUB_ADDR is set and SE_HOST is not; "+
			"not dialling, because a checkpoint names its own scope")
		return
	}
	cfg, err := hubTLS()
	if err != nil {
		fmt.Fprintf(os.Stderr, "se-collate: %v\n", err)
		return
	}
	declarers := map[string]Declarer{}
	for _, c := range collectors {
		declarers[c.name] = &wire.Client{Socket: c.socket}
	}
	link := &HubLink{}
	for {
		now := BootNow()
		gap := link.Gap(now)
		id := fmt.Sprintf("cp-%s-%d", host, int64(now*1e6))
		link.Opened(now)
		if err := Session(context.Background(), addr, cfg, st, declarers,
			id, host, bootID, gap); err != nil {
			fmt.Fprintf(os.Stderr, "se-collate: hub session: %v\n", err)
		}
		link.Closed(BootNow())
		time.Sleep(hubReconnect)
	}
}
