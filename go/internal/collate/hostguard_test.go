// The allowlist's promises in both directions: the always-safe forms
// answer, an unclaimed name is refused, and a claimed one answers under
// any spelling of its case and any port.
package collate

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func guarded(allowed string) http.Handler {
	return HostGuard(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), allowed)
}

func askWithHost(t *testing.T, h http.Handler, host string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	req.Host = host
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func TestSafeHostFormsAnswerWithoutBeingClaimed(t *testing.T) {
	h := guarded("")
	for _, host := range []string{
		"127.0.0.1:8095", "127.0.0.1", "[::1]:8095", "192.168.4.20:8081",
		"localhost", "LOCALHOST:8095", "",
	} {
		if code := askWithHost(t, h, host); code != http.StatusOK {
			t.Fatalf("%q must answer: %d", host, code)
		}
	}
}

func TestAnUnclaimedNameIsRefusedAsMisdirected(t *testing.T) {
	// The rebinding shape: a name this deployment never claimed, carried
	// by a victim's browser. Refused whether or not anything is listed —
	// deny-by-default over names.
	for _, allowed := range []string{"", "silo.example"} {
		h := guarded(allowed)
		if code := askWithHost(t, h, "attacker.example:8095"); code != http.StatusMisdirectedRequest {
			t.Fatalf("allowlist %q: unclaimed name answered %d", allowed, code)
		}
	}
}

func TestAClaimedNameAnswersUnderAnySpelling(t *testing.T) {
	h := guarded(" Silo.Example , other.example ")
	for _, host := range []string{
		"silo.example", "SILO.EXAMPLE:8095", "other.example:9000",
	} {
		if code := askWithHost(t, h, host); code != http.StatusOK {
			t.Fatalf("%q is claimed and must answer: %d", host, code)
		}
	}
}
