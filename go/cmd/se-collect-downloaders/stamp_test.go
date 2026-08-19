package main

import (
	"bytes"
	"errors"
	"testing"
)

// A row that rests on no document still carries the batch's clock reading.
//
// This is the bug the live comparator found and nothing else could: a sabnzbd
// configured by URL with no key is a stated-fault row built from the
// environment alone, and a port that took its reading inside the acquisition
// stamped it 0 — which is not a clock reading and which the judge refuses
// (0 < at <= 1e9). Replay cannot reach the shape at all, because the seam pins
// the receipts; the corpus is green either way.

// stubSource is the seam with every reading declared by the test, so the ORDER
// collect() calls things in is what is under test rather than any clock.
type stubSource struct {
	gates   clientGates
	at      float64
	opened  bool
	openErr error
	asked   []string
	staged  *value
}

func (s *stubSource) bootID() (string, error) {
	return "8d5a9a1e-6f50-4a12-9c3b-2b1d0e9f7a44", nil
}
func (*stubSource) timens() int64             { return 0 }
func (*stubSource) batch() (string, error)    { return "stub", nil }
func (*stubSource) declaration() string       { return declarationDigest }
func (s *stubSource) clients() clientGates    { return s.gates }
func (*stubSource) costs() (float64, float64) { return 1, 2 }

func (s *stubSource) openBatch() error {
	if s.openErr != nil {
		return s.openErr
	}
	s.opened = true
	s.at = 4242.5
	return nil
}

func (s *stubSource) stamp(int) float64 { return s.at }

func (s *stubSource) document(call string) (*value, error) {
	s.asked = append(s.asked, call)
	if s.staged == nil {
		return nil, errors.New("this stub stages no document")
	}
	return s.staged, nil
}

func TestAConfigurationOnlyRowStillCarriesTheBatchsReading(t *testing.T) {
	// sabnzbd by URL and no key: the reference builds the row from the
	// environment and asks the API nothing.
	src := &stubSource{gates: clientGates{sab: true}}
	var stdout, stderr bytes.Buffer
	if code := collect(&stdout, &stderr, src, []string{collectionClients},
		map[string]uint64{collectionClients: 3}); code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !src.opened {
		t.Fatal("collect never opened the batch, so nothing took a clock reading")
	}
	if len(src.asked) != 0 {
		t.Fatalf("a keyless sabnzbd row asks the API nothing; it asked %v", src.asked)
	}
	records := parseRecords(t, stdout.String())
	objects := ofKind(records, "object")
	if len(objects) != 1 {
		t.Fatalf("one stated-fault row; got %d", len(objects))
	}
	at, _ := objects[0]["at"].(float64)
	if at <= 0 || at > 1e9 {
		t.Fatalf("`at` is %v; a row built from configuration alone still rests on a reading taken before it", at)
	}
}

// An unreadable clock is "I could not run" and never a batch with an invented
// stamp: `at` is what every reading downstream is dated by, and a stream that
// carried a placeholder would be applied by the collator as though it were
// measured.
func TestAnUnreadableClockRefusesTheBatch(t *testing.T) {
	src := &stubSource{gates: clientGates{sab: true}, openErr: errors.New("no CLOCK_BOOTTIME here")}
	var stdout, stderr bytes.Buffer
	if code := collect(&stdout, &stderr, src, []string{collectionClients},
		map[string]uint64{collectionClients: 3}); code != exitRuntime {
		t.Fatalf("exit %d, want %d", code, exitRuntime)
	}
	if stdout.String() != "" {
		t.Fatalf("a batch that could not be dated must emit no stream: %q", stdout.String())
	}
	if stderr.String() == "" {
		t.Fatal("refusing without saying why tells nobody anything")
	}
}

// The live source takes its reading in openBatch and NOWHERE else. Asserted by
// driving a read that fails and checking the stamp did not move — on Linux the
// old lazy code stamped here, which is exactly the arrangement that left a
// configuration-only row at zero.
func TestTheLiveStampComesFromOpenBatchAndNotFromAFailedRead(t *testing.T) {
	src, ok := newSource(func(key string) string {
		if key == sabURLVariable {
			return "http://127.0.0.1:1"
		}
		return ""
	}).(*liveSource)
	if !ok {
		t.Fatal("an environment with no SE_REPLAY_DIR must give the live source")
	}
	if src.stamp(0) != 0 {
		t.Fatal("the live source starts unstamped")
	}
	if _, err := src.document(callQueue); err == nil {
		t.Skip("something answered 127.0.0.1:1; this test needs a read that fails")
	}
	if src.stamp(0) != 0 {
		t.Fatal("a read stamped the batch — the reading belongs to openBatch, which a configuration-only row also reaches")
	}
}
