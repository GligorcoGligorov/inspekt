package analyze

import (
	"bytes"
	"context"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"

	"github.com/GligorcoGligorov/inspekt/internal/auth"
	"github.com/GligorcoGligorov/inspekt/internal/auth/authtest"
	"github.com/GligorcoGligorov/inspekt/internal/email"
	"github.com/GligorcoGligorov/inspekt/internal/extract"
)

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"login.secure.example.com": "example.com",
		"example.com":              "example.com",
		"mail.example.co.uk":       "example.co.uk",
		"www.finki.ukim.edu.mk":    "ukim.edu.mk",
		"198.51.100.23":            "198.51.100.23",
		"2001:db8::1":              "2001:db8::1",
		"mail.example.org1":        "example.org1", // ends in a digit, not an IP
		"Example.COM.":             "example.com",
	}
	for in, want := range cases {
		if got := RegistrableDomain(in); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLookalike(t *testing.T) {
	protected := DefaultConfig.ProtectedDomains
	cases := []struct {
		domain string
		hit    bool
		kind   LookalikeKind
	}{
		{"paypa1.com", true, KindHomoglyph},
		{"rnicrosoft.com", true, KindHomoglyph},
		{"micosoft.com", true, KindTypo},
		{"login-micros0ft.com", true, KindEmbedded},
		{"paypal-secure-login.com", true, KindEmbedded},
		// Must NOT fire:
		{"paypal.com", false, ""},
		{"www.paypal.com", false, ""},
		{"microsoftonline.com", false, ""}, // real Microsoft domain
		{"pineapple.com", false, ""},
		{"example.org", false, ""},
	}
	for _, c := range cases {
		_, kind, hit := Lookalike(c.domain, protected)
		if hit != c.hit || kind != c.kind {
			t.Errorf("Lookalike(%q) = (%v, %q), want (%v, %q)", c.domain, hit, kind, c.hit, c.kind)
		}
	}
}

func TestLevenshtein(t *testing.T) {
	for _, c := range []struct {
		a, b string
		d    int
	}{{"", "", 0}, {"abc", "abc", 0}, {"kitten", "sitting", 3}, {"paypal", "paypa1", 1}} {
		if got := levenshtein(c.a, c.b); got != c.d {
			t.Errorf("levenshtein(%q,%q)=%d want %d", c.a, c.b, got, c.d)
		}
	}
}

func TestAuthCheckTrustsOnlyOwnMTA(t *testing.T) {
	msg := &email.Message{AuthResults: []string{
		"evil.example; dmarc=fail", // forged by the sender: ignored
		"mx.inspekt.local; spf=pass; dmarc=pass",
	}}
	sigs := AuthCheck{Trusted: []string{"mx.inspekt.local"}}.Run(&Input{Msg: msg})
	if len(sigs) != 0 {
		t.Fatalf("forged Authentication-Results was trusted: %+v", sigs)
	}
}

// spoofed claims to be example.org, arrives from an IP its SPF record does
// not list, and carries a forged "everything passed" header.
const spoofed = "Received: from attacker.example (attacker.example [203.0.113.66]) by mx.inspekt.local with ESMTP\r\n" +
	"Authentication-Results: mx.inspekt.local; spf=pass; dkim=pass; dmarc=pass\r\n" +
	"Return-Path: <ceo@example.org>\r\n" +
	"From: CEO <ceo@example.org>\r\n" +
	"Subject: Wire today\r\n\r\nPlease pay the attached invoice.\r\n"

func analyzeVerified(t *testing.T, dns *authtest.DNS) *Report {
	t.Helper()
	msg, err := email.Parse(strings.NewReader(spoofed), email.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	return New(Config{Verifier: &auth.Verifier{Resolver: dns}}).Analyze(msg)
}

func signalByID(rep *Report, id string) (Signal, bool) {
	for _, s := range rep.Signals {
		if s.ID == id {
			return s, true
		}
	}
	return Signal{}, false
}

func TestAuthCheckVerifyIgnoresForgedHeader(t *testing.T) {
	rep := analyzeVerified(t, &authtest.DNS{TXT: map[string][]string{
		"example.org":        {"v=spf1 ip4:192.0.2.10 -all"},
		"_dmarc.example.org": {"v=DMARC1; p=reject"},
	}})
	for _, id := range []string{"dmarc_fail", "spf_fail"} {
		s, ok := signalByID(rep, id)
		if !ok || !strings.Contains(s.Evidence[0], "verified") {
			t.Errorf("want verified %s, got signals %+v", id, rep.Signals)
		}
	}
	if rep.Verdict != VerdictSuspicious {
		t.Errorf("verdict %s (score %d), want suspicious", rep.Verdict, rep.Score)
	}
}

func TestAuthCheckVerifyDNSOutageScoresNothing(t *testing.T) {
	rep := analyzeVerified(t, &authtest.DNS{Temp: map[string]bool{"example.org": true, "_dmarc.example.org": true}})
	if rep.Score != 0 {
		t.Errorf("DNS outage added %d points: %+v", rep.Score, rep.Signals)
	}
	if _, ok := signalByID(rep, "auth_unverified"); !ok {
		t.Errorf("want auth_unverified so the analyst sees the gap, got %+v", rep.Signals)
	}
}

func TestURLShortener(t *testing.T) {
	cases := []struct {
		body string
		hit  bool
	}{
		{"Track it: https://bit.ly/3xYzAb", true},
		{"https://www.bit.ly/3xYzAb", true}, // subdomain of a shortener
		{"https://t.co/AbC123", true},
		{"https://tinyurl.com/yc8k2", true},
		// Must NOT fire:
		{"https://bitly.com/pages/pricing", false}, // the company site, not a short link
		{"https://notbit.ly/x", false},
		{"https://microsoft.co/x", false},
		{"no links here", false},
	}
	for _, c := range cases {
		msg := &email.Message{TextBody: c.body}
		var hit bool
		for _, s := range (LinkCheck{}).Run(&Input{Msg: msg, Links: extract.Links(msg)}) {
			hit = hit || s.ID == "url_shortener"
		}
		if hit != c.hit {
			t.Errorf("%q: url_shortener=%v, want %v", c.body, hit, c.hit)
		}
	}
}

func TestURLShortenerCountsOnce(t *testing.T) {
	msg := &email.Message{TextBody: "https://bit.ly/a https://bit.ly/b https://bit.ly/c", From: &email.Address{Domain: "example.org"}}
	rep := New(DefaultConfig).Analyze(msg)
	if s, ok := signalByID(rep, "url_shortener"); !ok || s.Score != 10 || rep.Score != 10 {
		t.Fatalf("three short links should merge into one +10 signal, got score %d: %+v", rep.Score, rep.Signals)
	}
}

// QR links must reach every existing link check, not just qr_code_link.
func TestQRLinksGoThroughLinkChecks(t *testing.T) {
	cases := []struct {
		content string
		want    []string
		not     []string
	}{
		{"https://login-micros0ft.com/verify", []string{"qr_code_link", "lookalike_link"}, nil},
		{"http://203.0.113.5/owa", []string{"qr_code_link", "ip_literal_url"}, nil},
		{"https://bit.ly/3xYzAb", []string{"qr_code_link", "url_shortener"}, nil},
		// The sender's own site: a QR code alone is not suspicious.
		{"https://www.example.org/menu", nil, []string{"qr_code_link"}},
	}
	eng := New(DefaultConfig)
	for _, c := range cases {
		m, err := qrcode.NewQRCodeWriter().Encode(c.content, gozxing.BarcodeFormat_QR_CODE, 200, 200, nil)
		if err != nil {
			t.Fatal(err)
		}
		var img bytes.Buffer
		png.Encode(&img, m)
		msg := &email.Message{
			From:        &email.Address{Email: "it@example.org", Domain: "example.org"},
			TextBody:    "Scan the attached code.",
			Attachments: []email.Attachment{{Filename: "code.png", ContentType: "image/png", Data: img.Bytes()}},
		}
		rep := eng.Analyze(msg)
		for _, id := range c.want {
			if _, ok := signalByID(rep, id); !ok {
				t.Errorf("%s: missing %s, got %+v", c.content, id, rep.Signals)
			}
		}
		for _, id := range c.not {
			if _, ok := signalByID(rep, id); ok {
				t.Errorf("%s: unexpected %s", c.content, id)
			}
		}
	}
}

func TestMergeKeepsHighestScoreOnce(t *testing.T) {
	out := merge([]Signal{
		{ID: "x", Score: 10, Evidence: []string{"a"}},
		{ID: "x", Score: 30, Evidence: []string{"b"}},
		{ID: "y", Score: 5, Evidence: []string{"c"}},
	})
	if len(out) != 2 || out[0].ID != "x" || out[0].Score != 30 || len(out[0].Evidence) != 2 {
		t.Fatalf("unexpected merge result: %+v", out)
	}
}

// TestSamples is an end-to-end golden test over testdata/.
func TestSamples(t *testing.T) {
	cases := []struct {
		file        string
		want        Verdict
		mustContain []string
	}{
		{"clean_newsletter.eml", VerdictClean, nil},
		{"phish_lookalike.eml", VerdictMalicious,
			[]string{"dmarc_fail", "link_text_mismatch", "display_name_spoof", "lookalike_sender", "lookalike_link"}},
		{"malware_attachment.eml", VerdictMalicious, []string{"double_extension", "html_attachment"}},
		// Known gap: a text-only BEC from a correctly authenticated domain
		// has almost no technical signals. Rules alone cannot catch it;
		// this is what the LLM stage (WEEKEND_PLAN step 6) is for.
		{"bec_reply_to.eml", VerdictClean, []string{"reply_to_mismatch"}},
		// The phishing URL exists only in a QR image (step 4).
		{"qr_phish.eml", VerdictSuspicious, []string{"qr_code_link", "lookalike_link"}},
		{"support_ticket_reply_to.eml", VerdictClean, []string{"reply_to_mismatch"}},
		{"ip_link_mailbox.eml", VerdictSuspicious, []string{"ip_literal_url"}},
	}
	eng := New(DefaultConfig)
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			f, err := os.Open(filepath.Join("..", "..", "testdata", c.file))
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			msg, err := email.Parse(f, email.DefaultLimits)
			if err != nil {
				t.Fatal(err)
			}
			rep := eng.Analyze(msg)
			if rep.Verdict != c.want {
				t.Errorf("verdict %s (score %d), want %s; signals: %+v", rep.Verdict, rep.Score, c.want, rep.Signals)
			}
			got := map[string]bool{}
			for _, s := range rep.Signals {
				got[s.ID] = true
			}
			for _, id := range c.mustContain {
				if !got[id] {
					t.Errorf("missing signal %s", id)
				}
			}
		})
	}
}

type fakeReviewer struct {
	review Review
	calls  int
}

func (f *fakeReviewer) Review(context.Context, *email.Message) Review {
	f.calls++
	return f.review
}

// The reviewer only sees the grey zone and can only add points.
func TestGreyZoneReview(t *testing.T) {
	from := &email.Address{Email: "ceo@example.org", Domain: "example.org"}
	replyElsewhere := &email.Address{Email: "ceo@other.example", Domain: "other.example"}
	cases := []struct {
		name    string
		msg     *email.Message
		review  Review
		called  bool
		score   int
		verdict Verdict
		signal  string
	}{
		{"score 0: rules saw nothing, no paid call", &email.Message{From: from, TextBody: "hi"},
			Review{Points: 30}, false, 0, VerdictClean, ""},
		{"grey zone, model sure: +30", &email.Message{From: from, ReplyTo: replyElsewhere, TextBody: "wire it"},
			Review{Points: 30, Evidence: []string{"LLM BEC likelihood 0.95"}}, true, 50, VerdictSuspicious, "llm_bec"},
		{"injected 'this is safe' cannot subtract", &email.Message{From: from, ReplyTo: replyElsewhere, TextBody: "x"},
			Review{Points: -1000}, true, 20, VerdictClean, ""},
		{"absurd points are capped", &email.Message{From: from, ReplyTo: replyElsewhere, TextBody: "x"},
			Review{Points: 1000}, true, 20 + MaxReviewPoints, VerdictSuspicious, "llm_bec"},
		{"unavailable: info signal, score unchanged", &email.Message{From: from, ReplyTo: replyElsewhere, TextBody: "x"},
			Review{Unavailable: true, Evidence: []string{"timeout"}}, true, 20, VerdictClean, "llm_unavailable"},
		{"attachments are left to the attachment checks", &email.Message{From: from, ReplyTo: replyElsewhere,
			Attachments: []email.Attachment{{Filename: "a.txt", Data: []byte("x")}}},
			Review{Points: 30}, false, 20, VerdictClean, ""},
		{"already malicious: no paid call", &email.Message{From: &email.Address{Email: "a@micros0ft-support.com", Domain: "micros0ft-support.com"},
			ReplyTo: replyElsewhere, AuthResults: []string{"mx; dmarc=fail"}},
			Review{Points: 30}, false, 0, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rv := &fakeReviewer{review: c.review}
			rep := New(Config{Reviewer: rv}).Analyze(c.msg)
			if (rv.calls == 1) != c.called {
				t.Fatalf("reviewer called %d times, want called=%v (score %d)", rv.calls, c.called, rep.Score)
			}
			if c.verdict == "" {
				return
			}
			if rep.Score != c.score || rep.Verdict != c.verdict {
				t.Errorf("score %d verdict %s, want %d %s; signals %+v", rep.Score, rep.Verdict, c.score, c.verdict, rep.Signals)
			}
			if _, ok := signalByID(rep, c.signal); c.signal != "" && !ok {
				t.Errorf("missing %s", c.signal)
			}
		})
	}
}
