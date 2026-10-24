package api

import (
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"net/http"
	"regexp"
)

// The demo page: one self-contained HTML file, no framework or CDN.
//
//go:embed web/index.html
var indexHTML []byte

// pageCSP allows exactly the page's own inline script and style (by hash,
// computed from the embedded file so it can never drift) and requests to
// this origin. Email content is rendered with textContent, and the CSP is
// the second line of defence.
var pageCSP = func() string {
	hash := func(tag string) string {
		m := regexp.MustCompile(`(?s)<` + tag + `>(.*?)</` + tag + `>`).FindSubmatch(indexHTML)
		if m == nil {
			panic("api: embedded page has no <" + tag + ">")
		}
		sum := sha256.Sum256(m[1])
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	return "default-src 'none'; script-src " + hash("script") + "; style-src " + hash("style") +
		"; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}()

func (s *Server) page(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", pageCSP)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-cache")
	w.Write(indexHTML)
}
