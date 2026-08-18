// A scripted collector on a real unix socket: the tests' side of the
// wire. It answers declare and collect the way the contract says a
// collector must, deterministically per generation, so a re-request of
// the same generation is byte-identical — which is what the equal-
// generation no-op needs a counterparty for. Knobs let each test break
// exactly one promise.
package collate

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/techiebod/system-explorer/go/internal/wire"
)

const fakeBootID = "5e000000-0000-4000-8000-000000000001"

type fake struct {
	Socket   string
	decl     []byte
	declHash string

	mu sync.Mutex
	// declineReason, when set, makes identity decline instead of emit.
	declineReason string
	// fixedBatchID, when set, is used for every generation — the vehicle
	// for testing id-based retry idempotency.
	fixedBatchID string
	// beginDeclaration, when set, overrides the hash begin carries.
	beginDeclaration string
	// tamper edits the outgoing stream lines just before they are sent.
	tamper func(lines []string) []string

	ln net.Listener
}

// newFake serves on a socket under its own short temp dir: sun_path is
// 104 bytes on darwin and t.TempDir() names are long enough to cross it.
func newFake(t testing.TB) *fake {
	t.Helper()
	dir, err := os.MkdirTemp("", "se")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	decl := []byte(`{"schema":"se.declaration/1","collector":"system",` +
		`"collections":[{"name":"identity","freshness":"1h"}]}`)
	f := &fake{
		Socket:   filepath.Join(dir, "c.sock"),
		decl:     decl,
		declHash: wire.DeclarationHash(decl),
	}
	ln, err := net.Listen("unix", f.Socket)
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln
	t.Cleanup(func() { ln.Close() })
	go f.serve()
	return f
}

func (f *fake) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fake) handle(conn net.Conn) {
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return
	}
	verb, rest, _ := strings.Cut(strings.TrimSuffix(line, "\n"), " ")
	switch verb {
	case "declare":
		conn.Write(f.decl)
	case "collect":
		// One collection in every test: parse "identity:<gen>".
		_, genStr, ok := strings.Cut(rest, ":")
		if !ok {
			return
		}
		gen, err := strconv.ParseUint(genStr, 10, 64)
		if err != nil {
			return
		}
		f.mu.Lock()
		lines := f.stream(gen)
		if f.tamper != nil {
			lines = f.tamper(lines)
		}
		f.mu.Unlock()
		conn.Write([]byte(strings.Join(lines, "\n") + "\n"))
	}
}

// stream builds the batch for one generation. Deterministic per
// generation by construction: facts carry the generation, at derives
// from it, and the batch id names it.
func (f *fake) stream(gen uint64) []string {
	batchID := f.fixedBatchID
	if batchID == "" {
		batchID = fmt.Sprintf("batch-%d", gen)
	}
	declHash := f.declHash
	if f.beginDeclaration != "" {
		declHash = f.beginDeclaration
	}
	begin := fmt.Sprintf(`{"record":"begin","request":%q,"batch":%q,"declaration":%q,`+
		`"boot_id":%q,"timens":0,"instance":null,"generations":{"identity":%d}}`,
		batchID, batchID, declHash, fakeBootID, gen)
	end := fmt.Sprintf(`{"record":"end","request":%q,"batch":%q,"cpu_ms":0.5,"wall_ms":1.0}`,
		batchID, batchID)

	if f.declineReason != "" {
		decline := fmt.Sprintf(`{"record":"decline","collection":"identity","reason":%q,"detail":"scripted"}`,
			f.declineReason)
		if f.declineReason == "absent" {
			commit := fmt.Sprintf(`{"record":"commit","collection":"identity","generation":%d,`+
				`"objects":0,"assertions":0,"unobservable":0,"cpu_ms":0.1}`, gen)
			return []string{begin, decline, commit, end}
		}
		return []string{begin, decline, end}
	}

	object := fmt.Sprintf(`{"record":"object","collection":"identity","name":"host1",`+
		`"names":{"stable":{"hostname":"host1"}},"facts":{"Gen":%d},"at":%d.5}`, gen, gen)
	commit := fmt.Sprintf(`{"record":"commit","collection":"identity","generation":%d,`+
		`"objects":1,"assertions":0,"unobservable":0,"cpu_ms":0.5}`, gen)
	return []string{begin, object, commit, end}
}

func (f *fake) set(configure func(*fake)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	configure(f)
}

// scriptedFake is the generic counterpart of fake: any declaration, and
// a collect response built from the parsed issued map — the seam the
// multi-collection scenarios need, where fake scripts exactly one.
type scriptedFake struct {
	Socket  string
	decl    []byte
	respond func(issued map[string]uint64) []string
	ln      net.Listener
}

func newScriptedFake(t testing.TB, decl []byte, respond func(map[string]uint64) []string) *scriptedFake {
	t.Helper()
	dir, err := os.MkdirTemp("", "se")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &scriptedFake{
		Socket:  filepath.Join(dir, "c.sock"),
		decl:    decl,
		respond: respond,
	}
	ln, err := net.Listen("unix", f.Socket)
	if err != nil {
		t.Fatal(err)
	}
	f.ln = ln
	t.Cleanup(func() { ln.Close() })
	go f.serve()
	return f
}

func (f *scriptedFake) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *scriptedFake) handle(conn net.Conn) {
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return
	}
	verb, rest, _ := strings.Cut(strings.TrimSuffix(line, "\n"), " ")
	switch verb {
	case "declare":
		conn.Write(f.decl)
	case "collect":
		issued := map[string]uint64{}
		for _, token := range strings.Fields(rest) {
			name, genStr, ok := strings.Cut(token, ":")
			if !ok {
				return
			}
			gen, err := strconv.ParseUint(genStr, 10, 64)
			if err != nil {
				return
			}
			issued[name] = gen
		}
		conn.Write([]byte(strings.Join(f.respond(issued), "\n") + "\n"))
	}
}
