package campaign

import (
	"fmt"
	"strings"
	"testing"

	"github.com/GligorcoGligorov/inspekt/internal/analyze"
	"github.com/GligorcoGligorov/inspekt/internal/email"
	"github.com/GligorcoGligorov/inspekt/internal/extract"
)

func TestNormalizeSubject(t *testing.T) {
	for in, want := range map[string]string{
		"Invoice 4471 overdue":              "invoice # overdue",
		"RE: Invoice 12 overdue":            "invoice # overdue",
		"Fwd: re: FW:  Invoice  9  overdue": "invoice # overdue",
		"Your code is 123-456":              "your code is #-#",
		"  Mailbox   FULL  ":                "mailbox full",
		"Report Q3 2026":                    "report q# #",
		"re:re: hi":                         "hi",
	} {
		if got := NormalizeSubject(in); got != want {
			t.Errorf("NormalizeSubject(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFirstExternalIP(t *testing.T) {
	cases := []struct {
		name     string
		received []string
		want     string
	}{
		{"public client of our MX", []string{"from mail.example.org (mail.example.org [185.199.108.4]) by mx.inspekt.local"}, "185.199.108.4"},
		{"skips internal hops first", []string{
			"from relay.internal (relay.internal [10.0.0.5]) by mx.inspekt.local",
			"from gw (gw [100.64.3.2]) by relay.internal",
			"from out.sender.example (out.sender.example [151.101.1.69]) by gw"}, "151.101.1.69"},
		{"IPv6", []string{"from x ([IPv6:2a00:1450:4001:82b::200e]) by mx"}, "2a00:1450:4001:82b::200e"},
		{"bare IPv4 in parentheses", []string{"from host (151.101.65.69) by mx"}, "151.101.65.69"},
		{"by-clause IP is ours, not the sender's", []string{"from host (unknown) by mx [151.101.1.1]"}, ""},
		{"documentation and private ranges only", []string{"from a ([192.0.2.7]) by b", "from c ([172.16.0.9]) by d", "from e ([127.0.0.1]) by f"}, ""},
		{"none", nil, ""},
	}
	for _, c := range cases {
		if got := FirstExternalIP(c.received); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func report(subject string, links []string, received []string, attachments ...string) *analyze.Report {
	msg := &email.Message{Subject: subject, Received: received}
	for _, a := range attachments {
		msg.Attachments = append(msg.Attachments, email.Attachment{SHA256: a})
	}
	rep := &analyze.Report{Message: msg}
	for _, u := range links {
		if l, ok := extract.NewLink(u, extract.SourceText); ok {
			rep.Links = append(rep.Links, l)
		}
	}
	return rep
}

func TestExtract(t *testing.T) {
	got := Extract(report("RE: Invoice 4471 overdue",
		[]string{"https://login.evil-login.xyz/a", "https://www.evil-login.xyz/b", "https://www.google.com/search", "https://docs.google.com/x", "https://pub-1.r2.dev/p"},
		[]string{"from out.sender.example ([151.101.1.69]) by mx"}, "aa11", "aa11"))
	want := []Indicator{
		{AttachmentSHA, "aa11"},
		{FullURL, "https://pub-1.r2.dev/p"}, // shared hosting: the page, not the host
		{LinkHost, "evil-login.xyz"},
		{SenderIP, "151.101.1.69"},
		{SubjectFP, sha("invoice # overdue")},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("got  %v\nwant %v", got, want)
	}
	if ind := Extract(report("Hi #5", nil, nil)); len(ind) != 0 {
		t.Errorf("short subject must not become an indicator: %v", ind)
	}
	var many []string
	for i := range 300 {
		many = append(many, fmt.Sprintf("https://h%d.example/x", i))
	}
	if n := len(Extract(report("", many, nil))); n != maxIndicators {
		t.Errorf("%d indicators, want the cap %d", n, maxIndicators)
	}
}

func TestAllowlist(t *testing.T) {
	for _, d := range []string{"google.com", "microsoft.com", "apple.com", "facebook.com", "linkedin.com", "youtube.com", "w3.org"} {
		if !Allowlist[d] {
			t.Errorf("%s should be allowlisted", d)
		}
	}
	for _, d := range []string{"googleapis.com", "windows.net", "r2.dev", "web.app", "ipfs.io"} {
		if Allowlist[d] {
			t.Errorf("%s is abused hosting and must not be allowlisted", d)
		}
	}
}

func sha(s string) string {
	return Extract(&analyze.Report{Message: &email.Message{Subject: s}})[0].Value
}

func TestDomainUsesFullPublicSuffixList(t *testing.T) {
	for host, want := range map[string]string{
		"shop.co.za": "shop.co.za", "www.bank.co.za": "bank.co.za", "co.za": "",
		"mail.example.co.il": "example.co.il", "a.b.ne.jp": "b.ne.jp", "login.evil-login.xyz": "evil-login.xyz",
		"151.101.1.69": "151.101.1.69", "": "",
	} {
		if got := Domain(host); got != want {
			t.Errorf("Domain(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestExtractStrongAndExclusions(t *testing.T) {
	rep := report("Hello there friend",
		[]string{"https://bit.ly/3xYz?utm=1#top", "https://www.monkey.org/~jose/unsub", "https://shop.co.za/a", "https://bank.co.za/b"}, nil)
	rep.Message.To = []email.Address{{Email: "jose@monkey.org", Domain: "monkey.org"}}
	got := fmt.Sprint(Extract(rep))
	for _, want := range []string{"{full_url https://bit.ly/3xYz}", "{link_host shop.co.za}", "{link_host bank.co.za}"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "monkey.org") || strings.Contains(got, "{link_host co.za}") || strings.Contains(got, "bit.ly}") {
		t.Errorf("recipient domain, public suffix or bare shortener host leaked: %s", got)
	}
	rep.Message.To = nil
	rep.Message.DeliveredTo = []email.Address{{Email: "jose@monkey.org", Domain: "monkey.org"}}
	if strings.Contains(fmt.Sprint(Extract(rep)), "monkey.org") {
		t.Error("Delivered-To domain not excluded")
	}
	if !Strong(AttachmentSHA) || !Strong(FullURL) || Strong(LinkHost) || Strong(SenderIP) || Strong(SubjectFP) {
		t.Error("strong/weak classification")
	}
}
