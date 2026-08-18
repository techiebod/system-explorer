package main

import "strings"

// parseOsRelease reads os-release per its own spec — KEY=value lines,
// comments, optional single or double quoting, shell-style escapes inside
// double quotes — because the file is the native structured format, and
// text-scraping it would re-implement the spec wrongly one quote at a time.
//
// Unparseable lines are skipped rather than fatal: the document is served
// as evidence verbatim, so a stray line costs a key, never the collection —
// and a distribution that ships one is interface drift for the corpus to
// capture, not a crash to page anyone about.
func parseOsRelease(raw []byte) map[string]string {
	doc := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" || strings.ContainsAny(key, " \t") {
			continue
		}
		doc[key] = unquote(value)
	}
	return doc
}

// unquote strips one level of matched single or double quotes and, inside
// double quotes, resolves backslash escapes (\" \\ \$ \` per the spec's
// shell-compatible subset; an unknown escape keeps its character, which is
// what a shell does too). Single-quoted values escape nothing — that
// asymmetry is the spec's, not ours.
func unquote(value string) string {
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
		return value[1 : len(value)-1]
	}
	if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
		body := value[1 : len(value)-1]
		var out strings.Builder
		escaped := false
		for _, r := range body {
			if escaped {
				out.WriteRune(r)
				escaped = false
				continue
			}
			if r == '\\' {
				escaped = true
				continue
			}
			out.WriteRune(r)
		}
		if escaped { // a trailing lone backslash is literal, not an escape of nothing
			out.WriteByte('\\')
		}
		return out.String()
	}
	return value
}
