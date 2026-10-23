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
