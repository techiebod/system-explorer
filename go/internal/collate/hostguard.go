// The host-header allowlist on the read listener (register row 15).
//
// The read API is unauthenticated by design and loopback by default, but
// a deployment that binds wider hands every browser on the network a
// vector: DNS rebinding points an attacker-owned NAME at this address,
// and the victim's browser then reads the API from a page origin the
// operator never served — same-origin policy satisfied, data exfiltrated.
// The defence is that a rebound request always CARRIES the attacker's
// name in its Host header, so a listener that only answers to names the
// deployment claimed shuts the vector without authenticating anything.
//
// What is allowed without being listed, and why each is safe: an IP
// literal (rebinding requires a name — a browser at an IP origin carries
// the IP), localhost, and an absent Host (no browser omits it; a plain
// HTTP/1.0 client is not the vector). Every other name must be listed,
// deny-by-default, and the refusal is 421 Misdirected Request — the
// status that says "this server is not the one that name means".
package collate

import (
	"net"
	"net/http"
	"strings"
)

// HostGuard wraps a read handler in the allowlist. allowed is the
// deployment's comma-separated claim (SE_ALLOWED_HOSTS), case-folded;
// empty claims nothing beyond the always-safe forms.
func HostGuard(next http.Handler, allowed string) http.Handler {
	claimed := map[string]bool{}
	for _, name := range strings.Split(allowed, ",") {
		if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
			claimed[name] = true
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hostAllowed(r.Host, claimed) {
			next.ServeHTTP(w, r)
			return
		}
		http.Error(w,
			"this listener does not answer to that name; a deployment claims "+
				"its names in SE_ALLOWED_HOSTS",
			http.StatusMisdirectedRequest)
	})
}

func hostAllowed(hostport string, claimed map[string]bool) bool {
	if hostport == "" {
		return true
	}
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.ToLower(strings.Trim(host, "[]"))
	if host == "localhost" || net.ParseIP(host) != nil {
		return true
	}
	return claimed[host]
}
