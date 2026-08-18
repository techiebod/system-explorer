// The transport bounds. A collector that streams forever or hangs must
// cost the collator one bounded read, not the acquisition loop.
package wire

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serveOnce answers exactly one connection with respond's output.
func serveOnce(t *testing.T, respond func(request string, conn net.Conn)) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "se")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "c.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			return
		}
		respond(strings.TrimSuffix(line, "\n"), conn)
	}()
	return socket
}

func TestDeclareReturnsExactBytes(t *testing.T) {
	doc := []byte(`{"collector":"system"}` + "\n")
	socket := serveOnce(t, func(request string, conn net.Conn) {
		if request != "declare" {
			t.Errorf("request line %q", request)
		}
		conn.Write(doc)
	})
	got, err := (&Client{Socket: socket}).Declare(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Exact bytes: the declaration hash is over what declare emits,
	// trailing newline and all.
	if !bytes.Equal(got, doc) {
		t.Fatalf("%q", got)
	}
}

func TestCollectRequestLineNamesEachIssuedGeneration(t *testing.T) {
	var seen string
	socket := serveOnce(t, func(request string, conn net.Conn) {
		seen = request
		// An empty response is an empty stream — rejected, but the
		// request line has been captured by then.
	})
	_, err := (&Client{Socket: socket}).Collect(context.Background(),
		map[string]uint64{"identity": 4, "arrays": 9})
	if v, ok := err.(*Violation); !ok || v.Reason != "empty-stream" {
		t.Fatalf("expected the empty stream to be refused: %v", err)
	}
	if seen != "collect arrays:9 identity:4" {
		t.Fatalf("request line %q", seen)
	}
}

func TestByteCeilingVoidsTheBatch(t *testing.T) {
	socket := serveOnce(t, func(request string, conn net.Conn) {
		// Well-formed lines, endlessly: the ceiling is the only thing
		// that can end this, and it must end it as a violation.
		line := []byte(`{"record":"object","collection":"identity","name":"x","facts":{},"at":1.0}` + "\n")
		for i := 0; i < 3000; i++ {
			if _, err := conn.Write(line); err != nil {
				return
			}
		}
	})
	client := &Client{Socket: socket, ByteCeiling: 64 * 1024}
	_, err := client.Collect(context.Background(), map[string]uint64{"identity": 1})
	v, ok := err.(*Violation)
	if !ok || v.Reason != "byte-ceiling-exceeded" {
		t.Fatalf("an unbounded read must not exhaust the slice: %v", err)
	}
}

func TestDeadlineBoundsAHungCollector(t *testing.T) {
	socket := serveOnce(t, func(request string, conn net.Conn) {
		// Say nothing, hold the connection open: RuntimeMaxSec's silent twin.
		time.Sleep(5 * time.Second)
	})
	client := &Client{Socket: socket, Deadline: 100 * time.Millisecond}
	start := time.Now()
	_, err := client.Collect(context.Background(), map[string]uint64{"identity": 1})
	if err == nil {
		t.Fatal("a hung collector must not hang the collator")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("deadline did not bound the read: %v", time.Since(start))
	}
}
