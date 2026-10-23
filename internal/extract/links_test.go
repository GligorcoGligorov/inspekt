package extract

import (
	"testing"

	"github.com/GligorcoGligorov/inspekt/internal/email"
)

func TestLinks(t *testing.T) {
	msg := &email.Message{
		TextBody: "Visit https://example.com/a. Or (http://198.51.100.7/x)",
		HTMLBody: `<p><A HREF='https://evil.example/login?a=1&amp;b=2'>https://<b>bank</b>.example</A>
<a href=mailto:x@y.com>mail</a>
<form method="post" action="https://collect.example/p"><input></form>`,
	}
	links := Links(msg)

	want := []struct {
		host   string
		text   string
		source Source
		isIP   bool
	}{
		{"evil.example", "https://bank.example", SourceHTML, false},
		{"collect.example", "", SourceForm, false},
		{"example.com", "", SourceText, false},
		{"198.51.100.7", "", SourceText, true},
	}
	if len(links) != len(want) {
		t.Fatalf("got %d links: %+v", len(links), links)
	}
	for i, w := range want {
		l := links[i]
		if l.Host != w.host || l.Text != w.text || l.Source != w.source || l.IsIP != w.isIP {
			t.Errorf("link %d = %+v, want %+v", i, l, w)
		}
	}
	if links[0].URL != "https://evil.example/login?a=1&b=2" {
		t.Errorf("entities not decoded: %s", links[0].URL)
	}
}

func TestLinksCap(t *testing.T) {
	body := ""
	for i := 0; i < MaxLinks+50; i++ {
		body += "https://example.com/" + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + " "
	}
	if n := len(Links(&email.Message{TextBody: body})); n > MaxLinks {
		t.Fatalf("cap not enforced: %d", n)
	}
}

// Regression: strings.ToLower changes the byte length of invalid UTF-8 and
// of some letters, which shifted offsets and panicked (56 messages in the
// Nazario phishing corpus).
func TestHTMLLinksNonASCIIDoesNotShiftOffsets(t *testing.T) {
	for _, doc := range []string{
		"\xff\xfe<a href=\"https://a.example/\">x</a>",
		"İİİİ<A HREF=\"https://b.example/\">click</A>",
		"<a href=\"https://c.example/\">\xc3</a",
	} {
		links := htmlLinks(doc)
		if len(links) != 1 {
			t.Errorf("%q: got %+v", doc, links)
		}
	}
}

// FuzzLinks: link extraction must never panic, whatever the HTML.
func FuzzLinks(f *testing.F) {
	for _, seed := range []string{
		`<a href="https://x.example/">t</a>`,
		"\xff<A HREF=x>İ</a",
		`<form action='https://y.example'><a href=`,
		"<<<>>><a",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, doc string) {
		Links(&email.Message{HTMLBody: doc, TextBody: doc})
	})
}
