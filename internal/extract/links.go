// Package extract pulls analysable artifacts (links, forms) out of a parsed
// message.
//
// HTML is scanned with a small purpose-built tokenizer rather than a full DOM
// parser: we only need anchors and forms, and a scanner that never builds a
// tree has bounded memory on hostile input. If deeper HTML analysis is needed
// later, golang.org/x/net/html is the drop-in upgrade.
package extract

import (
	"html"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/GligorcoGligorov/inspekt/internal/email"
)

// Source says where in the message a link was found.
type Source string

const (
	SourceText Source = "text"
	SourceHTML Source = "html_anchor"
	SourceForm Source = "html_form"
	SourceQR   Source = "qr_code"
)

// Link is one URL found in a message.
type Link struct {
	URL    string `json:"url"`
	Host   string `json:"host"`
	Text   string `json:"text,omitempty"` // visible anchor text, if any
	Source Source `json:"source"`
	IsIP   bool   `json:"is_ip,omitempty"`
}

// MaxLinks caps work per message; newsletters can carry hundreds of links.
const MaxLinks = 500

var textURL = regexp.MustCompile(`(?i)\bhttps?://[^\s<>"'\x60\)\]]+`)

// Links returns the unique links in msg, HTML first (it carries anchor text),
// then plain text.
func Links(msg *email.Message) []Link {
	var out []Link
	seen := map[string]bool{}
	add := func(l Link) {
		key := string(l.Source) + "|" + l.URL + "|" + l.Text
		if len(out) >= MaxLinks || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, l)
	}

	for _, l := range htmlLinks(msg.HTMLBody) {
		add(l)
	}
	for _, raw := range textURL.FindAllString(msg.TextBody, -1) {
		raw = strings.TrimRight(raw, ".,;:!?")
		if l, ok := newLink(raw, "", SourceText); ok {
			add(l)
		}
	}
	return out
}

// NewLink builds a Link from a raw URL. Exported so other extractors
// (QR decoding) produce identical records.
func NewLink(raw string, src Source) (Link, bool) { return newLink(raw, "", src) }

func newLink(raw, text string, src Source) (Link, bool) {
	raw = strings.TrimSpace(html.UnescapeString(raw))
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return Link{}, false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Link{}, false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	return Link{
		URL:    u.String(),
		Host:   host,
		Text:   text,
		Source: src,
		IsIP:   net.ParseIP(host) != nil,
	}, true
}

// htmlLinks scans for <a href>, <area href> and <form action>.
func htmlLinks(doc string) []Link {
	var out []Link
	lower := strings.ToLower(doc)
	i := 0
	for i < len(doc) && len(out) < MaxLinks {
		lt := strings.IndexByte(lower[i:], '<')
		if lt < 0 {
			break
		}
		start := i + lt
		end := strings.IndexByte(lower[start:], '>')
		if end < 0 {
			break
		}
		end += start
		tag := doc[start+1 : end]
		name, attrs := splitTag(tag)
		i = end + 1

		switch name {
		case "a", "area":
			href, ok := attrs["href"]
			if !ok {
				continue
			}
			text := ""
			if name == "a" {
				if close := strings.Index(lower[i:], "</a"); close >= 0 {
					text = visibleText(doc[i : i+close])
				}
			}
			if l, ok := newLink(href, text, SourceHTML); ok {
				out = append(out, l)
			}
		case "form":
			if action, ok := attrs["action"]; ok {
				if l, ok := newLink(action, "", SourceForm); ok {
					out = append(out, l)
				}
			}
		}
	}
	return out
}

// splitTag returns the lower-cased tag name and its attributes.
func splitTag(tag string) (string, map[string]string) {
	tag = strings.TrimSpace(tag)
	n := strings.IndexAny(tag, " \t\r\n/")
	if n < 0 {
		return strings.ToLower(tag), nil
	}
	name := strings.ToLower(tag[:n])
	attrs := map[string]string{}
	rest := tag[n:]
	for {
		rest = strings.TrimLeft(rest, " \t\r\n/")
		if rest == "" {
			return name, attrs
		}
		eq := strings.IndexAny(rest, "= \t\r\n")
		if eq < 0 {
			attrs[strings.ToLower(rest)] = ""
			return name, attrs
		}
		key := strings.ToLower(rest[:eq])
		rest = strings.TrimLeft(rest[eq:], " \t\r\n")
		if !strings.HasPrefix(rest, "=") {
			attrs[key] = ""
			continue
		}
		rest = strings.TrimLeft(rest[1:], " \t\r\n")
		var val string
		if rest != "" && (rest[0] == '"' || rest[0] == '\'') {
			q := rest[0]
			endq := strings.IndexByte(rest[1:], q)
			if endq < 0 {
				val, rest = rest[1:], ""
			} else {
				val, rest = rest[1:1+endq], rest[2+endq:]
			}
		} else {
			sp := strings.IndexAny(rest, " \t\r\n")
			if sp < 0 {
				val, rest = rest, ""
			} else {
				val, rest = rest[:sp], rest[sp:]
			}
		}
		if _, dup := attrs[key]; !dup { // first value wins, like browsers
			attrs[key] = val
		}
	}
}

// visibleText strips tags and collapses whitespace.
func visibleText(s string) string {
	var b strings.Builder
	in := false
	for _, r := range s {
		switch {
		case r == '<':
			in = true
		case r == '>':
			in = false
		case !in:
			b.WriteRune(r)
		}
	}
	return strings.Join(strings.Fields(html.UnescapeString(b.String())), " ")
}
